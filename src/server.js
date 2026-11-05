// The server: signs people in to Kick with the secret the app cannot hold, receives Kick's
// webhooks, and passes everything on to each user's app over a WebSocket.
import { randomBytes } from 'node:crypto';
import { createServer } from 'node:http';
import { WebSocketServer } from 'ws';

import { KickError, newPkce, safeName, toFrame } from './kick.js';
import { newToken } from './store.js';
import { cleanUsername } from './tiktok.js';

const MAX_BODY_BYTES = 1024 * 1024;
const LOGIN_TTL_MS = 10 * 60 * 1000;
/** The app collects its session straight after the browser comes back. */
const HANDOFF_TTL_MS = 2 * 60 * 1000;
/** Kick signs a time: an older message than this is a replay, not a late one. */
const WEBHOOK_MAX_AGE_MS = 10 * 60 * 1000;
const REMEMBER_WEBHOOKS = 5000;
const PING_MS = 30_000;
const MAX_MESSAGE_LETTERS = 500;
const MAX_TITLE_LETTERS = 140;
const MAX_CATEGORY_LETTERS = 100;
/** Sign-ins and TikTok connections allowed from one address, per minute. */
const RATE_PER_MINUTE = 20;
const TIKTOK_PER_ADDRESS = 3;

/** The app listens on this computer's own address, and nothing else may receive a session. */
const isLoopback = (url) => /^http:\/\/127\.0\.0\.1:\d{1,5}\/?$/.test(url ?? '');

function reply(response, status, body) {
  const text = body === undefined ? '' : JSON.stringify(body);
  response.writeHead(status, { 'Content-Type': 'application/json' });
  response.end(text);
}

function readBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    request.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new KickError(413, 'too big'));
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });
    request.on('end', () => resolve(Buffer.concat(chunks)));
    request.on('error', reject);
  });
}

async function readJson(request) {
  try {
    return JSON.parse((await readBody(request)).toString('utf8'));
  } catch (error) {
    if (error instanceof KickError) throw error;
    throw new KickError(400, 'not json');
  }
}

const bearer = (request) => {
  const header = request.headers.authorization ?? '';
  return header.startsWith('Bearer ') ? header.slice(7) : null;
};

/** On Fly the real address comes in this header: the socket is its proxy. */
const addressOf = (request) =>
  request.headers['fly-client-ip'] ?? request.socket.remoteAddress ?? 'unknown';

export function createRelay({ publicUrl, store, kick, rooms }) {
  const logins = new Map();
  const handoffs = new Map();
  const listeners = new Map();
  const seenWebhooks = new Set();
  const seenOrder = [];
  const attempts = new Map();
  const tiktokByAddress = new Map();
  const redirect = `${publicUrl}/kick/callback`;

  const limited = (request) => {
    const address = addressOf(request);
    const minute = Math.floor(Date.now() / 60_000);
    const entry = attempts.get(address);
    if (!entry || entry.minute !== minute) {
      // Only the current minute matters, so the old ones can all go.
      if (attempts.size > 10_000) attempts.clear();
      attempts.set(address, { minute, count: 1 });
      return false;
    }
    entry.count += 1;
    return entry.count > RATE_PER_MINUTE;
  };

  const sendTo = (userId, frame) => {
    const text = JSON.stringify({ platform: 'kick', ...frame });
    const group = listeners.get(userId) ?? new Set();
    for (const socket of group) socket.send(text);
    return group.size;
  };

  /** A token that works, refreshed once at a time per session: Kick's refresh tokens change. */
  const refreshing = new Map();
  const freshAccess = async (session) => {
    const tokens = store.tokensOf(session);
    if (!kick.needsRefresh(tokens)) return tokens.access;
    let pending = refreshing.get(session.hash);
    if (!pending) {
      pending = kick
        .refresh(tokens.refresh)
        .then((next) => {
          store.saveTokens(session.hash, next);
          return next.access;
        })
        .finally(() => refreshing.delete(session.hash));
      refreshing.set(session.hash, pending);
    }
    return pending;
  };

  const startLogin = (url, response, request) => {
    if (limited(request)) return reply(response, 429, { error: 'too many attempts' });
    const appReturn = url.searchParams.get('return');
    const appState = url.searchParams.get('state');
    if (!kick) return reply(response, 503, { error: 'kick is not set up' });
    if (!isLoopback(appReturn) || !appState) return reply(response, 400, { error: 'bad request' });
    const now = Date.now();
    for (const [key, login] of logins) {
      if (now - login.at > LOGIN_TTL_MS) logins.delete(key);
    }
    const state = randomBytes(24).toString('base64url');
    const { verifier, challenge } = newPkce();
    logins.set(state, { appReturn, appState, verifier, at: now });
    response.writeHead(302, { Location: kick.authorizeUrl({ state, challenge, redirect }) });
    response.end();
  };

  const finishLogin = async (url, response) => {
    const state = url.searchParams.get('state');
    const login = logins.get(state);
    if (!login || Date.now() - login.at > LOGIN_TTL_MS) {
      return reply(response, 400, { error: 'this sign-in has expired, try again' });
    }
    logins.delete(state);
    const back = new URL(login.appReturn);
    back.searchParams.set('state', login.appState);
    const code = url.searchParams.get('code');
    if (!code) {
      back.searchParams.set('error', url.searchParams.get('error') ?? 'denied');
      response.writeHead(302, { Location: back.href });
      return response.end();
    }
    try {
      const tokens = await kick.exchange({ code, verifier: login.verifier, redirect });
      const { userId, name } = await kick.me(tokens.access);
      const subscriptionIds = await kick.subscribe(tokens.access);
      // A browser keeps addresses in its history, so this one holds only a code that works once
      // and for a moment. The session itself goes straight to the app.
      const handoff = newToken();
      const now = Date.now();
      for (const [key, entry] of handoffs) {
        if (now - entry.at > HANDOFF_TTL_MS) handoffs.delete(key);
      }
      handoffs.set(handoff, { userId, name, tokens, subscriptionIds, at: now });
      back.searchParams.set('code', handoff);
    } catch (error) {
      // Our own message or a network failure's code: nothing from the request itself.
      const reason =
        error instanceof KickError ? error.message : (error.cause?.code ?? error.name);
      console.error(`sign-in failed: ${reason}`);
      back.searchParams.set('error', 'failed');
    }
    response.writeHead(302, { Location: back.href });
    response.end();
  };

  const claim = async (request, response) => {
    const { code } = await readJson(request);
    const entry = handoffs.get(code);
    handoffs.delete(code);
    if (!entry || Date.now() - entry.at > HANDOFF_TTL_MS) {
      return reply(response, 400, { error: 'this sign-in has expired, try again' });
    }
    const { at: _, ...account } = entry;
    reply(response, 200, { session: store.create(account), name: entry.name });
  };

  const receiveWebhook = async (request, response) => {
    const body = await readBody(request);
    const id = request.headers['kick-event-message-id'];
    const timestamp = request.headers['kick-event-message-timestamp'];
    const authentic = await kick.isAuthentic({
      id,
      timestamp,
      signature: request.headers['kick-event-signature'],
      body,
    });
    if (!authentic) return reply(response, 401, { error: 'bad signature' });
    if (Math.abs(Date.now() - Date.parse(timestamp)) > WEBHOOK_MAX_AGE_MS) {
      return reply(response, 400, { error: 'too old' });
    }
    // Kick may deliver the same message more than once.
    if (!seenWebhooks.has(id)) {
      seenWebhooks.add(id);
      seenOrder.push(id);
      if (seenOrder.length > REMEMBER_WEBHOOKS) seenWebhooks.delete(seenOrder.shift());
      const event = JSON.parse(body.toString('utf8'));
      const frame = toFrame(request.headers['kick-event-type'], id, event);
      const type = request.headers['kick-event-type'];
      const reached = frame ? sendTo(event.broadcaster?.user_id, frame) : 0;
      // Only the kind of event, to see what arrives. Chat would flood it, and says nothing new.
      if (type !== 'chat.message.sent') console.log(`webhook ${safeName(type)}: ${reached} app(s)`);
    }
    reply(response, 200, {});
  };

  const sendChat = async (request, response, session) => {
    const { content } = await readJson(request);
    const text = String(content ?? '')
      .trim()
      .slice(0, MAX_MESSAGE_LETTERS);
    if (!text) return reply(response, 400, { error: 'nothing to send' });
    await kick.sendChat(await freshAccess(session), session.userId, text);
    reply(response, 200, {});
  };

  const searchCategories = async (url, response, session) => {
    const query = (url.searchParams.get('q') ?? '').trim().slice(0, MAX_CATEGORY_LETTERS);
    if (!query) return reply(response, 200, { categories: [] });
    const found = await kick.searchCategories(await freshAccess(session), query);
    reply(response, 200, { categories: found.map((c) => c.name) });
  };

  /**
   * The live's title and category. Kick answers 401 or 403 to a sign-in from before this was asked
   * for. That session still works for everything else, so it answers 403: 401 here means the
   * session itself is gone, and the app would forget the sign-in.
   */
  const updateChannel = async (request, response, session) => {
    const { title, category } = await readJson(request);
    const streamTitle = String(title ?? '')
      .trim()
      .slice(0, MAX_TITLE_LETTERS);
    const wanted = String(category ?? '')
      .trim()
      .slice(0, MAX_CATEGORY_LETTERS);
    const access = await freshAccess(session);
    try {
      const found = wanted
        ? (await kick.searchCategories(access, wanted)).find(
            (c) => c.name.toLowerCase() === wanted.toLowerCase(),
          )
        : null;
      const changes = {
        ...(streamTitle ? { stream_title: streamTitle } : {}),
        ...(found ? { category_id: found.id } : {}),
      };
      if (Object.keys(changes).length > 0) await kick.updateChannel(access, changes);
      reply(response, 200, { category_found: !wanted || Boolean(found) });
    } catch (error) {
      if (error instanceof KickError && [401, 403].includes(error.status)) {
        return reply(response, 403, { error: 'sign in again to allow this' });
      }
      throw error;
    }
  };

  /** Signing out: this app forgets it, and Kick stops sending when no other app needs it. */
  const signOut = async (response, session) => {
    if (store.othersOf(session.userId, session.hash) === 0) {
      await kick
        .unsubscribe(await freshAccess(session), session.subscriptionIds ?? [])
        .catch(() => {});
    }
    store.remove(session.hash);
    for (const socket of listeners.get(session.userId) ?? []) {
      if (socket.sessionHash === session.hash) socket.close(4401, 'signed out');
    }
    reply(response, 200, {});
  };

  const handle = async (request, response) => {
    const url = new URL(request.url, publicUrl);
    const route = `${request.method} ${url.pathname}`;
    if (route === 'GET /health') {
      return reply(response, 200, { ok: true, tiktok: Boolean(rooms), kick: Boolean(kick) });
    }
    if (route === 'GET /kick/login') return startLogin(url, response, request);
    if (!kick && url.pathname.startsWith('/kick')) {
      return reply(response, 503, { error: 'kick is not set up' });
    }
    if (route === 'GET /kick/callback') return await finishLogin(url, response);
    if (route === 'POST /kick/webhook') return await receiveWebhook(request, response);
    if (route === 'POST /kick/claim') return await claim(request, response);
    const token = bearer(request);
    const session = token && store.find(token);
    const needsSession = [
      'POST /kick/chat',
      'DELETE /kick/session',
      'GET /kick/categories',
      'PATCH /kick/channel',
    ];
    if (needsSession.includes(route)) {
      if (!session) return reply(response, 401, { error: 'sign in again' });
      if (route === 'POST /kick/chat') return await sendChat(request, response, session);
      if (route === 'GET /kick/categories') return await searchCategories(url, response, session);
      if (route === 'PATCH /kick/channel') return await updateChannel(request, response, session);
      return await signOut(response, session);
    }
    reply(response, 404, { error: 'not found' });
  };

  const server = createServer((request, response) => {
    handle(request, response).catch((error) => {
      // Only the kind of failure: bodies and tokens stay out of the log.
      const status = error instanceof KickError ? error.status : 500;
      console.error(`request failed: ${request.method} ${request.url.split('?')[0]} ${status}`);
      if (!response.headersSent) {
        // What the caller got wrong or must act on keeps its status; the rest is on our side.
        reply(response, status < 500 ? status : 502, { error: 'failed' });
      } else {
        response.end();
      }
    });
  });

  const sockets = new WebSocketServer({ noServer: true });
  const keepAlive = setInterval(() => {
    for (const socket of sockets.clients) {
      if (socket.alive === false) {
        socket.terminate();
        continue;
      }
      socket.alive = false;
      socket.ping();
      socket.send(JSON.stringify({ kind: 'ping' }));
    }
  }, PING_MS);
  keepAlive.unref();

  sockets.on('connection', (socket) => {
    socket.alive = true;
    socket.on('pong', () => {
      socket.alive = true;
    });
    socket.on('error', () => socket.terminate());
  });

  const refuse = (socket, status) => {
    socket.write(`HTTP/1.1 ${status} Refused\r\nConnection: close\r\n\r\n`);
    socket.destroy();
  };

  server.on('upgrade', (request, raw, head) => {
    const url = new URL(request.url, publicUrl);
    if (url.pathname === '/kick/stream') {
      const token = bearer(request);
      const session = token && store.find(token);
      if (!session) return refuse(raw, 401);
      sockets.handleUpgrade(request, raw, head, (socket) => {
        socket.sessionHash = session.hash;
        const group = listeners.get(session.userId) ?? new Set();
        group.add(socket);
        listeners.set(session.userId, group);
        socket.on('close', () => {
          group.delete(socket);
          if (group.size === 0) listeners.delete(session.userId);
        });
        sockets.emit('connection', socket, request);
        socket.send(JSON.stringify({ kind: 'status', live: true }));
      });
      return;
    }
    if (url.pathname === '/tiktok/stream') {
      if (!rooms) return refuse(raw, 503);
      const username = cleanUsername(url.searchParams.get('username'));
      const address = addressOf(request);
      const held = tiktokByAddress.get(address) ?? 0;
      if (!username) return refuse(raw, 400);
      if (held >= TIKTOK_PER_ADDRESS || limited(request)) return refuse(raw, 429);
      sockets.handleUpgrade(request, raw, head, (socket) => {
        const leave = rooms.join(username, (frame) => {
          if (socket.readyState === socket.OPEN) {
            socket.send(JSON.stringify({ platform: 'tiktok', ...frame }));
          }
        });
        if (!leave) {
          socket.close(4503, 'full');
          return;
        }
        tiktokByAddress.set(address, held + 1);
        socket.on('close', () => {
          leave();
          const now = (tiktokByAddress.get(address) ?? 1) - 1;
          if (now <= 0) tiktokByAddress.delete(address);
          else tiktokByAddress.set(address, now);
        });
        sockets.emit('connection', socket, request);
      });
      return;
    }
    refuse(raw, 404);
  });

  return {
    server,
    close() {
      clearInterval(keepAlive);
      rooms?.closeAll();
      for (const socket of sockets.clients) socket.terminate();
      return new Promise((resolve) => server.close(resolve));
    },
  };
}
