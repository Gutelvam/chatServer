// Sign in with TikTok (Login Kit for Desktop). TikTok's token and revoke addresses ask for the client
// secret, which an installed app cannot keep. This does only those steps: the app keeps its own
// tokens and reads the account's name itself, and nothing is stored here.
const TIMEOUT_MS = 15_000;

export class TikTokLogin {
  #config;

  /** `config`: clientKey, clientSecret, tokenUrl, revokeUrl. */
  constructor(config) {
    this.#config = config;
  }

  #post(url, fields) {
    return fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_key: this.#config.clientKey,
        client_secret: this.#config.clientSecret,
        ...fields,
      }),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
  }

  async #token(fields) {
    const answer = await this.#post(this.#config.tokenUrl, fields);
    const body = await answer.json().catch(() => ({}));
    if (answer.ok && !body.error && typeof body.access_token === 'string') {
      // Only what the app needs: never the scope list, log ids or anything else TikTok adds.
      const pick = (name) => (body[name] === undefined ? {} : { [name]: body[name] });
      return {
        status: 200,
        body: {
          access_token: body.access_token,
          ...pick('expires_in'),
          ...pick('refresh_token'),
          ...pick('refresh_expires_in'),
          ...pick('open_id'),
        },
      };
    }
    // Only this says the person's sign-in is gone (code or refresh token expired, revoked, or not
    // this client's). Anything else is on our side or passing, and must not sign anyone out.
    if (body.error === 'invalid_grant') return { status: 400, body: { error: 'invalid_grant' } };
    const name = /^[a-z_]{1,40}$/.test(body.error ?? '') ? body.error : 'unknown';
    console.error(`tiktok refused: ${answer.status} ${name}`);
    return { status: 502, body: { error: 'failed' } };
  }

  exchange({ code, verifier, redirect }) {
    return this.#token({
      code,
      grant_type: 'authorization_code',
      redirect_uri: redirect,
      code_verifier: verifier,
    });
  }

  refresh(refreshToken) {
    return this.#token({ grant_type: 'refresh_token', refresh_token: refreshToken });
  }

  /** TikTok answers an empty body when it worked. */
  async revoke(token) {
    const answer = await this.#post(this.#config.revokeUrl, { token });
    const body = await answer.json().catch(() => ({}));
    if (answer.ok && !body.error) return { status: 200, body: {} };
    const name = /^[a-z_]{1,40}$/.test(body.error ?? '') ? body.error : 'unknown';
    console.error(`tiktok revoke refused: ${answer.status} ${name}`);
    return { status: 502, body: { error: 'failed' } };
  }
}

/**
 * Several TikTok apps at once (sandbox and production), so the app can change without signing
 * anyone out: an app names the client key it signed in with, and apps that name none keep the
 * first one.
 */
export class TikTokLogins {
  #byKey = new Map();
  #first = null;

  add(clientKey, login) {
    this.#byKey.set(clientKey, login);
    this.#first ??= login;
    return this;
  }

  get size() {
    return this.#byKey.size;
  }

  /** Unknown keys fall back to the first client. */
  for(clientKey) {
    return (typeof clientKey === 'string' && this.#byKey.get(clientKey)) || this.#first;
  }
}
