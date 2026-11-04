// Kick's official API. The client secret and the webhooks are why this server exists.
import { createHash, createPublicKey, randomBytes, verify } from 'node:crypto';

export const SCOPES = 'user:read chat:write events:subscribe';
const EVENTS = [
  'chat.message.sent',
  'channel.followed',
  'channel.subscription.new',
  'channel.subscription.renewal',
  'channel.subscription.gifts',
  'kicks.gifted',
];
/** Refresh a token this long before it expires. */
const EXPIRY_MARGIN_MS = 60_000;
const KEY_MAX_AGE_MS = 60 * 60 * 1000;

const base64url = (bytes) => Buffer.from(bytes).toString('base64url');

export function newPkce() {
  const verifier = base64url(randomBytes(32));
  const challenge = base64url(createHash('sha256').update(verifier).digest());
  return { verifier, challenge };
}

export class KickError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

export class Kick {
  #config;
  #publicKey = null;
  #publicKeyAt = 0;

  /** `{ clientId, clientSecret, idBase, apiBase }`. */
  constructor(config) {
    this.#config = config;
  }

  authorizeUrl({ state, challenge, redirect }) {
    const url = new URL(`${this.#config.idBase}/oauth/authorize`);
    url.search = new URLSearchParams({
      client_id: this.#config.clientId,
      response_type: 'code',
      redirect_uri: redirect,
      scope: SCOPES,
      code_challenge: challenge,
      code_challenge_method: 'S256',
      state,
    });
    return url.href;
  }

  async #token(form) {
    const response = await fetch(`${this.#config.idBase}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: this.#config.clientId,
        client_secret: this.#config.clientSecret,
        ...form,
      }),
    });
    // Refused means signing in again, whichever way Kick words it. Its own trouble does not.
    if (!response.ok) throw new KickError(response.status < 500 ? 401 : 502, 'token refused');
    const body = await response.json();
    return {
      access: body.access_token,
      refresh: body.refresh_token,
      expiresAt: Date.now() + (body.expires_in ?? 3600) * 1000,
    };
  }

  exchange({ code, verifier, redirect }) {
    return this.#token({
      grant_type: 'authorization_code',
      code,
      code_verifier: verifier,
      redirect_uri: redirect,
    });
  }

  refresh(refreshToken) {
    return this.#token({ grant_type: 'refresh_token', refresh_token: refreshToken });
  }

  needsRefresh(tokens) {
    return Date.now() + EXPIRY_MARGIN_MS >= tokens.expiresAt;
  }

  async #api(path, access, init = {}) {
    const response = await fetch(`${this.#config.apiBase}${path}`, {
      ...init,
      headers: {
        Authorization: `Bearer ${access}`,
        ...(init.body ? { 'Content-Type': 'application/json' } : {}),
      },
    });
    if (!response.ok) throw new KickError(response.status, `kick answered ${response.status}`);
    return response.status === 204 ? null : response.json();
  }

  /** The signed-in account. Kick also returns the email: it is neither kept nor passed on. */
  async me(access) {
    const body = await this.#api('/public/v1/users', access);
    const user = body.data?.[0];
    if (!user) throw new KickError(502, 'no user');
    return { userId: user.user_id, name: user.name };
  }

  /** Subscribing again is how Kick is told to deliver to this app. Returns what it created. */
  async subscribe(access) {
    const body = await this.#api('/public/v1/events/subscriptions', access, {
      method: 'POST',
      body: JSON.stringify({
        events: EVENTS.map((name) => ({ name, version: 1 })),
        method: 'webhook',
      }),
    });
    const items = body.data ?? [];
    for (const item of items.filter((i) => i.error)) {
      console.error(`kick refused the event ${item.name}`);
    }
    return items.filter((item) => !item.error).map((item) => item.subscription_id);
  }

  async unsubscribe(access, ids) {
    if (ids.length === 0) return;
    const query = new URLSearchParams(ids.map((id) => ['id', id]));
    await this.#api(`/public/v1/events/subscriptions?${query}`, access, { method: 'DELETE' });
  }

  sendChat(access, userId, content) {
    return this.#api('/public/v1/chat', access, {
      method: 'POST',
      body: JSON.stringify({ type: 'user', broadcaster_user_id: userId, content }),
    });
  }

  async #key(fresh) {
    if (!fresh && this.#publicKey && Date.now() - this.#publicKeyAt < KEY_MAX_AGE_MS) {
      return this.#publicKey;
    }
    const response = await fetch(`${this.#config.apiBase}/public/v1/public-key`);
    if (!response.ok) throw new KickError(response.status, 'no public key');
    const body = await response.json();
    this.#publicKey = createPublicKey(body.data.public_key);
    this.#publicKeyAt = Date.now();
    return this.#publicKey;
  }

  /** Kick signs `id.timestamp.body` with its private key, and may rotate it. */
  async isAuthentic({ id, timestamp, signature, body }) {
    if (!id || !timestamp || !signature) return false;
    const signed = Buffer.concat([Buffer.from(`${id}.${timestamp}.`), body]);
    const signatureBytes = Buffer.from(signature, 'base64');
    const check = (key) => verify('RSA-SHA256', signed, key, signatureBytes);
    if (check(await this.#key(false))) return true;
    return check(await this.#key(true));
  }
}

const nameOf = (user) => (user?.is_anonymous ? 'Anonymous' : (user?.username ?? 'Anonymous'));

/** What a webhook means, as the apps receive it. `null` for what they have no use for. */
export function toFrame(type, id, event) {
  const alert = (kind, user, extra = {}) => ({
    kind: 'alert',
    id,
    event: kind,
    user: nameOf(user),
    amount: null,
    count: null,
    message: null,
    ...extra,
  });
  switch (type) {
    case 'chat.message.sent': {
      const badges = (event.sender?.identity?.badges ?? []).map((b) => b.type);
      return {
        kind: 'chat',
        id: event.message_id ?? id,
        author: nameOf(event.sender),
        color: event.sender?.identity?.username_color || null,
        content: event.content ?? '',
        is_owner: event.sender?.user_id === event.broadcaster?.user_id,
        is_moderator: badges.includes('moderator'),
        is_member: badges.includes('subscriber'),
      };
    }
    case 'channel.followed':
      return alert('follow', event.follower);
    case 'channel.subscription.new':
      return alert('subscribe', event.subscriber);
    case 'channel.subscription.renewal':
      return alert('resubscribe', event.subscriber, { count: event.duration ?? null });
    case 'channel.subscription.gifts':
      return alert('gifted_subs', event.gifter, { count: event.giftees?.length ?? null });
    case 'kicks.gifted':
      return alert('gift', event.sender, {
        amount: event.gift?.amount != null ? `${event.gift.amount} KICKs` : null,
        message: event.gift?.message || null,
      });
    default:
      return null;
  }
}
