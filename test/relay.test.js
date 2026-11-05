// The whole relay against a stand-in for Kick and for the TikTok library: nothing here reaches the
// internet, and no account is needed.
import assert from 'node:assert/strict';
import { generateKeyPairSync, createSign } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, afterEach, before, test } from 'node:test';
import WebSocket from 'ws';

import { Kick, toFrame as kickFrame } from '../src/kick.js';
import { createRelay } from '../src/server.js';
import { hashToken, Store } from '../src/store.js';
import { cleanUsername, TikTokRooms, toFrame as tiktokFrame } from '../src/tiktok.js';

const frames = JSON.parse(readFileSync(new URL('./frames.json', import.meta.url), 'utf8'));
const KEY = 'ab'.repeat(32);
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const publicPem = publicKey.export({ type: 'spki', format: 'pem' });

function sign(id, timestamp, body) {
  const signer = createSign('RSA-SHA256');
  signer.update(`${id}.${timestamp}.${body}`);
  return signer.sign(privateKey).toString('base64');
}

/** What Kick was asked, and how it answers. */
const fake = { requests: [], tokenStatus: 200, tokenBody: {}, usersStatus: 200, refuseEvent: null, expiresIn: 3600, user: 7, channelStatus: 204 };
let fakeServer;
let fakeBase;
let dir;
let relay;
let base;
let wsBase;
let store;

before(async () => {
  fakeServer = createServer((request, response) => {
    let body = '';
    request.on('data', (c) => (body += c));
    request.on('end', () => {
      const path = request.url.split('?')[0];
      fake.requests.push({
        path,
        method: request.method,
        body,
        auth: request.headers.authorization,
        url: request.url,
      });
      const json = (status, value) => {
        response.writeHead(status, { 'Content-Type': 'application/json' });
        response.end(JSON.stringify(value));
      };
      if (path === '/oauth/token') {
        if (fake.tokenStatus !== 200) return json(fake.tokenStatus, fake.tokenBody);
        const refreshed = body.includes('grant_type=refresh_token');
        return json(200, {
          access_token: refreshed ? 'access-2' : 'access-1',
          refresh_token: refreshed ? 'refresh-2' : 'refresh-1',
          expires_in: fake.expiresIn,
        });
      }
      if (path === '/public/v1/users' && fake.usersStatus !== 200) {
        response.writeHead(fake.usersStatus, { 'Content-Type': 'text/html' });
        return response.end('<html>blocked</html>');
      }
      if (path === '/public/v1/users') {
        return json(200, {
          data: [{ user_id: fake.user, name: 'Streamer', email: 'private@example.com' }],
        });
      }
      if (path === '/public/v1/events/subscriptions' && request.method === 'POST') {
        if (JSON.parse(body).events[0].name === fake.refuseEvent) return json(403, {});
        return json(200, {
          data: JSON.parse(body).events.map((e, i) => ({ name: e.name, subscription_id: `s${i}` })),
        });
      }
      if (path === '/public/v1/events/subscriptions') {
        response.writeHead(204);
        return response.end();
      }
      if (path === '/public/v1/categories') {
        return json(200, {
          data: [
            { id: 1, name: 'Valorant Mobile', thumbnail: 'x' },
            { id: 2, name: 'VALORANT', thumbnail: 'x' },
          ],
        });
      }
      if (path === '/public/v1/channels' && request.method === 'PATCH') {
        response.writeHead(fake.channelStatus);
        return response.end();
      }
      if (path === '/public/v1/chat') return json(200, { data: { is_sent: true } });
      if (path === '/public/v1/public-key') return json(200, { data: { public_key: publicPem } });
      json(404, {});
    });
  });
  await new Promise((resolve) => fakeServer.listen(0, '127.0.0.1', resolve));
  fakeBase = `http://127.0.0.1:${fakeServer.address().port}`;
});

after(() => fakeServer.close());

async function start({ tiktok } = {}) {
  dir = mkdtempSync(join(tmpdir(), 'relay-'));
  store = new Store(dir, KEY);
  const kick = new Kick({
    clientId: 'client',
    clientSecret: 'the-secret',
    idBase: fakeBase,
    apiBase: fakeBase,
  });
  // The address is known only once it listens, so it is reserved first.
  const probe = createServer();
  await new Promise((resolve) => probe.listen(0, '127.0.0.1', resolve));
  const { port } = probe.address();
  await new Promise((resolve) => probe.close(resolve));
  base = `http://127.0.0.1:${port}`;
  wsBase = `ws://127.0.0.1:${port}`;
  relay = createRelay({ publicUrl: base, store, kick, rooms: tiktok ?? null });
  await new Promise((resolve) => relay.server.listen(port, '127.0.0.1', resolve));
}

afterEach(async () => {
  await relay?.close();
  relay = null;
  rmSync(dir, { recursive: true, force: true });
  Object.assign(fake, {
    requests: [],
    tokenStatus: 200,
    tokenBody: {},
    usersStatus: 200,
    refuseEvent: null,
    expiresIn: 3600,
    user: 7,
    channelStatus: 204,
  });
});

const noRedirect = (url) => fetch(url, { redirect: 'manual' });

/** Signs in as a browser would, and returns the session the app receives. */
async function signIn() {
  const start = await noRedirect(
    `${base}/kick/login?state=app-state&return=${encodeURIComponent('http://127.0.0.1:5555/')}`,
  );
  assert.equal(start.status, 302);
  const toKick = new URL(start.headers.get('location'));
  assert.ok(toKick.searchParams.get('code_challenge'), 'uses PKCE');
  const back = await noRedirect(
    `${base}/kick/callback?code=the-code&state=${toKick.searchParams.get('state')}`,
  );
  assert.equal(back.status, 302);
  const toApp = new URL(back.headers.get('location'));
  assert.equal(toApp.origin, 'http://127.0.0.1:5555');
  assert.equal(toApp.searchParams.get('state'), 'app-state');
  return (await claim(toApp.searchParams.get('code'))).session;
}

async function claim(code) {
  const answer = await fetch(`${base}/kick/claim`, {
    method: 'POST',
    body: JSON.stringify({ code }),
  });
  assert.equal(answer.status, 200);
  return answer.json();
}

/** As far as the browser goes: returns the address it was sent back to. */
async function backFromKick() {
  const start = await noRedirect(
    `${base}/kick/login?state=a&return=${encodeURIComponent('http://127.0.0.1:5555/')}`,
  );
  const state = new URL(start.headers.get('location')).searchParams.get('state');
  const back = await noRedirect(`${base}/kick/callback?code=c&state=${state}`);
  return new URL(back.headers.get('location'));
}

/** Delivers a webhook the way Kick does. */
function webhook(type, id, event, { signature, timestamp = new Date().toISOString() } = {}) {
  const body = JSON.stringify(event);
  return fetch(`${base}/kick/webhook`, {
    method: 'POST',
    body,
    headers: {
      'Kick-Event-Message-Id': id,
      'Kick-Event-Message-Timestamp': timestamp,
      'Kick-Event-Type': type,
      'Kick-Event-Version': '1',
      'Kick-Event-Signature': signature ?? sign(id, timestamp, body),
    },
  });
}

function connect(session) {
  const socket = new WebSocket(`${wsBase}/kick/stream`, {
    headers: { Authorization: `Bearer ${session}` },
  });
  const got = [];
  socket.on('message', (data) => got.push(JSON.parse(data.toString())));
  return new Promise((resolve, reject) => {
    socket.on('open', () => resolve({ socket, got }));
    socket.on('error', reject);
  });
}

async function until(what, done) {
  const start = Date.now();
  while (!done()) {
    assert.ok(Date.now() - start < 3000, `timed out: ${what}`);
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

const chatEvent = {
  message_id: 'm1',
  broadcaster: { user_id: 7 },
  sender: {
    user_id: 9,
    username: 'Ana',
    identity: {
      username_color: '#FF0000',
      badges: [{ type: 'moderator' }, { type: 'subscriber' }],
    },
  },
  content: 'hello [emote:37226:KEKW] there',
};

test('signing in keeps the secret here and the email nowhere', async () => {
  await start();
  const session = await signIn();
  const token = fake.requests.find((r) => r.path === '/oauth/token');
  assert.ok(token.body.includes('client_secret=the-secret'));
  assert.ok(token.body.includes('code_verifier='));
  const subscribed = fake.requests.find(
    (r) => r.method === 'POST' && r.path.endsWith('subscriptions'),
  );
  assert.equal(JSON.parse(subscribed.body).method, 'webhook');
  const saved = readFileSync(join(dir, 'sessions.json'), 'utf8');
  assert.ok(!saved.includes('access-1'), 'tokens are encrypted on disk');
  assert.ok(!saved.includes(session), 'only the hash of the session is kept');
  assert.ok(saved.includes(hashToken(session)));
  assert.ok(!saved.includes('private@example.com'), 'the email is not kept');
});

test('the browser never sees the session, and its code works once', async () => {
  await start();
  const back = await backFromKick();
  const code = back.searchParams.get('code');
  assert.equal(store.size, 0, 'nothing is usable until the app collects it');
  const { session, name } = await claim(code);
  assert.equal(name, 'Streamer');
  assert.notEqual(session, code);
  const again = await fetch(`${base}/kick/claim`, {
    method: 'POST',
    body: JSON.stringify({ code }),
  });
  assert.equal(again.status, 400);
  assert.equal(store.size, 1);
});

test('a sign-in Kick refuses goes back to the app as an error', async () => {
  await start();
  fake.tokenStatus = 400;
  const back = await backFromKick();
  assert.equal(back.searchParams.get('error'), 'failed');
  assert.equal(back.searchParams.get('code'), null);
  assert.equal(back.searchParams.get('state'), 'a');
});

test('a failed sign-in logs which step failed and why, and nothing secret', async (t) => {
  await start();
  const log = t.mock.method(console, 'error', () => {});
  const logged = () => log.mock.calls.map((call) => call.arguments.join(' ')).join('\n');

  fake.tokenStatus = 401;
  fake.tokenBody = { error: 'invalid_client', access_token: 'leaked-token' };
  await backFromKick();
  assert.match(logged(), /token endpoint: 401 invalid_client/);
  assert.ok(!logged().includes('leaked-token'));
  assert.ok(!logged().includes('the-secret'));

  // A long or odd message may quote anything, so only its status is kept.
  fake.tokenBody = { error: 'bad token leaked-token '.repeat(10) };
  await backFromKick();
  assert.ok(!logged().includes('leaked-token'));

  fake.tokenStatus = 200;
  fake.usersStatus = 403;
  await backFromKick();
  assert.match(logged(), /\/public\/v1\/users: 403 text\/html/);
});

test('an event Kick refuses costs neither the others nor the sign-in', async (t) => {
  await start();
  const errors = t.mock.method(console, 'error', () => {});
  t.mock.method(console, 'log', () => {});
  fake.refuseEvent = 'channel.reward.redemption.updated';
  const session = await signIn();
  assert.ok(session);
  const asked = fake.requests
    .filter((r) => r.method === 'POST' && r.path.endsWith('subscriptions'))
    .map((r) => JSON.parse(r.body).events[0].name);
  assert.ok(asked.includes('channel.followed'));
  assert.ok(asked.includes('channel.subscription.new'));
  const logged = errors.mock.calls.map((call) => call.arguments.join(' ')).join('\n');
  assert.match(logged, /refused the event channel\.reward\.redemption\.updated: .*403/);
});

test('follows reach the app and the log says so, without saying who', async (t) => {
  await start();
  const logs = t.mock.method(console, 'log', () => {});
  const session = await signIn();
  const { socket, got } = await connect(session);
  await until('hello', () => got.length === 1);
  await webhook('channel.followed', 'f1', {
    broadcaster: { user_id: 7 },
    follower: { username: 'Rui' },
  });
  await until('the follow', () => got.length === 2);
  assert.equal(got[1].event, 'follow');
  const logged = logs.mock.calls.map((call) => call.arguments.join(' ')).join('\n');
  assert.match(logged, /webhook channel\.followed: 1 app/);
  assert.ok(!logged.includes('Rui'));
  socket.close();
});

test('a reward becomes one alert, and a rejected one none', () => {
  const { platform: _, ...expected } = frames.reward;
  const redeemed = (status) =>
    kickFrame('channel.reward.redemption.updated', 'webhook-id', {
      id: 'r1',
      status,
      redeemer: { username: 'Ana' },
      reward: { title: 'Hydrate' },
      user_input: 'agua',
    });
  assert.deepEqual(redeemed('pending'), expected);
  assert.deepEqual(redeemed('accepted'), expected);
  assert.equal(redeemed('rejected'), null);
});

test('a refresh Kick refuses asks the app to sign in again', async () => {
  await start();
  fake.expiresIn = 1;
  const session = await signIn();
  fake.tokenStatus = 400;
  const answer = await fetch(`${base}/kick/chat`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${session}` },
    body: JSON.stringify({ content: 'oi' }),
  });
  assert.equal(answer.status, 401);
});

test('a session is only ever handed to this computer', async () => {
  await start();
  for (const target of [
    'https://evil.example/',
    'http://127.0.0.1.evil.example:80/',
    'http://localhost:5555/',
    'http://127.0.0.1:5555/@evil.example',
  ]) {
    const response = await noRedirect(
      `${base}/kick/login?state=s&return=${encodeURIComponent(target)}`,
    );
    assert.equal(response.status, 400, target);
  }
});

test('a sign-in cannot be finished twice or made up', async () => {
  await start();
  assert.equal((await noRedirect(`${base}/kick/callback?code=c&state=invented`)).status, 400);
  const start2 = await noRedirect(
    `${base}/kick/login?state=a&return=${encodeURIComponent('http://127.0.0.1:5555/')}`,
  );
  const state = new URL(start2.headers.get('location')).searchParams.get('state');
  assert.equal((await noRedirect(`${base}/kick/callback?code=c&state=${state}`)).status, 302);
  assert.equal((await noRedirect(`${base}/kick/callback?code=c&state=${state}`)).status, 400);
});

test('webhooks reach only that channel, once, and only when really from Kick', async () => {
  await start();
  const session = await signIn();
  const { socket, got } = await connect(session);
  await until('hello', () => got.length === 1);

  assert.equal((await webhook('chat.message.sent', 'w1', chatEvent)).status, 200);
  await until('the message', () => got.length === 2);
  assert.deepEqual(got[1], frames.chat);

  await webhook('chat.message.sent', 'w1', chatEvent);
  const forged = await webhook('chat.message.sent', 'w2', chatEvent, { signature: 'AAAA' });
  assert.equal(forged.status, 401);
  const old = new Date(Date.now() - 3_600_000).toISOString();
  assert.equal(
    (await webhook('chat.message.sent', 'w3', chatEvent, { timestamp: old })).status,
    400,
  );
  await webhook('chat.message.sent', 'w4', { ...chatEvent, broadcaster: { user_id: 999 } });
  await new Promise((resolve) => setTimeout(resolve, 100));
  assert.equal(got.length, 2, 'not repeated, not forged, not old, not someone else’s');
  socket.close();
});

test('nothing streams without a session', async () => {
  await start();
  await assert.rejects(connect('invented'));
});

test('events become the frames the app reads', () => {
  const clean = (frame) => {
    const { platform: _, ...rest } = frame;
    return rest;
  };
  assert.deepEqual(
    kickFrame('channel.followed', 'e1', { follower: { username: 'Rui' } }),
    clean(frames.follow),
  );
  assert.deepEqual(
    kickFrame('kicks.gifted', 'e2', {
      sender: { username: 'Bia' },
      gift: { amount: 100, message: 'boa' },
    }),
    clean(frames.gift),
  );
  assert.deepEqual(
    kickFrame('channel.subscription.gifts', 'e3', {
      gifter: { is_anonymous: true, username: null },
      giftees: [{}, {}, {}, {}, {}],
    }),
    clean(frames.gifted_subs),
  );
  assert.equal(kickFrame('livestream.status.updated', 'x', {}), null);
});

test('sending chat uses the account, and an expired token is refreshed once', async () => {
  await start();
  fake.expiresIn = 1;
  const session = await signIn();
  const send = (content) =>
    fetch(`${base}/kick/chat`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${session}` },
      body: JSON.stringify({ content }),
    });
  const answers = await Promise.all([send('um'), send('dois')]);
  assert.deepEqual(
    answers.map((a) => a.status),
    [200, 200],
  );
  const refreshes = fake.requests.filter((r) => r.body.includes('grant_type=refresh_token'));
  assert.equal(refreshes.length, 1, 'refresh tokens change: never two at once');
  const chats = fake.requests.filter((r) => r.path === '/public/v1/chat');
  assert.equal(chats[0].auth, 'Bearer access-2');
  assert.equal(JSON.parse(chats[0].body).broadcaster_user_id, 7);
  assert.equal((await send('   ')).status, 400);
  const stranger = await fetch(`${base}/kick/chat`, {
    method: 'POST',
    headers: { Authorization: 'Bearer invented' },
    body: '{}',
  });
  assert.equal(stranger.status, 401);
});

test('signing out ends the session and Kick stops sending', async () => {
  await start();
  const session = await signIn();
  const { got, socket } = await connect(session);
  await until('hello', () => got.length === 1);
  const closed = new Promise((resolve) => socket.on('close', resolve));
  const out = await fetch(`${base}/kick/session`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${session}` },
  });
  assert.equal(out.status, 200);
  assert.equal(await closed, 4401);
  const removal = fake.requests.find((r) => r.method === 'DELETE');
  assert.ok(removal.url.includes('id=s0'));
  assert.equal(store.size, 0);
});

test('the store survives a restart, and a wrong key cannot read it', () => {
  dir = mkdtempSync(join(tmpdir(), 'relay-'));
  const first = new Store(dir, KEY);
  const token = first.create({
    userId: 1,
    name: 'n',
    tokens: { access: 'a' },
    subscriptionIds: [],
  });
  const again = new Store(dir, KEY);
  assert.deepEqual(again.tokensOf(again.find(token)), { access: 'a' });
  assert.equal(again.find('invented'), null);
  const wrong = new Store(dir, 'cd'.repeat(32));
  assert.throws(() => wrong.tokensOf(wrong.find(token)));
  assert.throws(() => new Store(dir, 'short'));
  relay = null;
});

/** A stand-in for the TikTok library. */
function fakeConnection({ live = true } = {}) {
  const handlers = new Map();
  return {
    on: (type, handler) => handlers.set(type, handler),
    connect: async () => {
      if (!live) throw new Error('offline');
    },
    disconnected: false,
    disconnect() {
      this.disconnected = true;
    },
    fire: (type, data) => handlers.get(type)?.(data),
  };
}

test('tiktok usernames are checked before reaching anything', () => {
  assert.equal(cleanUsername('@Some.User_1'), 'some.user_1');
  assert.equal(cleanUsername('../../etc'), null);
  assert.equal(cleanUsername('a b'), null);
  assert.equal(cleanUsername(''), null);
});

test('tiktok gifts wait for the end of a streak', () => {
  const streak = { user: { nickname: 'Ana' }, giftDetails: { giftType: 1, giftName: 'Rose' } };
  assert.equal(tiktokFrame('gift', { ...streak, repeatCount: 3, repeatEnd: false }), null);
  const end = tiktokFrame('gift', { ...streak, repeatCount: 3, repeatEnd: true });
  assert.equal(end.amount, 'Rose x3');
  assert.equal(end.event, 'gift');
  assert.equal(tiktokFrame('roomUser', {}), null);
});

test('tiktok viewers of a channel share one connection, within a limit', async () => {
  const made = [];
  const tiktok = new TikTokRooms({
    connect: () => {
      const connection = fakeConnection();
      made.push(connection);
      return connection;
    },
    maxRooms: 1,
  });
  await start({ tiktok });
  const open = (username) => {
    const socket = new WebSocket(`${wsBase}/tiktok/stream?username=${username}`);
    const got = [];
    socket.on('message', (d) => got.push(JSON.parse(d.toString())));
    return { socket, got };
  };
  const first = open('someone');
  const second = open('someone');
  await until('both connected', () => first.got.length > 0 && second.got.length > 0);
  assert.equal(made.length, 1);
  await until('live', () => first.got.some((f) => f.live === true));
  made[0].fire('chat', { user: { nickname: 'Ana', userId: '55' }, comment: 'oi' });
  await until('the message', () => second.got.some((f) => f.kind === 'chat'));
  const message = second.got.find((f) => f.kind === 'chat');
  assert.equal(message.platform, 'tiktok');
  assert.equal(message.content, 'oi');
  assert.equal(message.author_id, '55');
  const full = open('another');
  const code = await new Promise((resolve) => full.socket.on('close', resolve));
  assert.equal(code, 4503);
  first.socket.close();
  second.socket.close();
});

test('a channel not live waits, and is told so', async () => {
  const tiktok = new TikTokRooms({
    connect: () => fakeConnection({ live: false }),
    maxRooms: 5,
  });
  await start({ tiktok });
  const socket = new WebSocket(`${wsBase}/tiktok/stream?username=someone`);
  const got = [];
  socket.on('message', (d) => got.push(JSON.parse(d.toString())));
  await until('a status', () => got.length > 0);
  assert.deepEqual(got[0], frames.status);
  socket.close();
});

test('a bad tiktok address is refused', async () => {
  const tiktok = new TikTokRooms({ connect: () => fakeConnection(), maxRooms: 5 });
  await start({ tiktok });
  const socket = new WebSocket(`${wsBase}/tiktok/stream?username=${encodeURIComponent('../x')}`);
  await new Promise((resolve) => socket.on('error', resolve));
});

const setDetails = (session, body) =>
  fetch(`${base}/kick/channel`, {
    method: 'PATCH',
    headers: { Authorization: `Bearer ${session}` },
    body: JSON.stringify(body),
  });

test('the title and category go to Kick, by the id of the same name', async () => {
  await start();
  const session = await signIn();
  const toKick = new URL(
    (await noRedirect(`${base}/kick/login?state=s&return=${encodeURIComponent('http://127.0.0.1:1/')}`))
      .headers.get('location'),
  );
  assert.ok(toKick.searchParams.get('scope').includes('channel:write'));
  const answer = await setDetails(session, { title: ' Ranked ', category: 'valorant' });
  assert.equal(answer.status, 200);
  assert.equal((await answer.json()).category_found, true);
  const patch = fake.requests.find((r) => r.method === 'PATCH');
  assert.deepEqual(JSON.parse(patch.body), { stream_title: 'Ranked', category_id: 2 });
});

test('a category Kick does not have still sends the title, and says so', async () => {
  await start();
  const session = await signIn();
  const answer = await setDetails(session, { title: 'Ranked', category: 'Valo' });
  assert.equal((await answer.json()).category_found, false);
  const patch = fake.requests.find((r) => r.method === 'PATCH');
  assert.deepEqual(JSON.parse(patch.body), { stream_title: 'Ranked' });
});

test('an older sign-in is told to sign in again, without losing its session', async () => {
  await start();
  const session = await signIn();
  fake.channelStatus = 401;
  const answer = await setDetails(session, { title: 'Ranked', category: '' });
  assert.equal(answer.status, 403);
  assert.ok(store.find(session), 'the session stays');
});

test('categories need a session, and only names leave', async () => {
  await start();
  const session = await signIn();
  const without = await fetch(`${base}/kick/categories?q=valo`);
  assert.equal(without.status, 401);
  const answer = await fetch(`${base}/kick/categories?q=valo`, {
    headers: { Authorization: `Bearer ${session}` },
  });
  assert.deepEqual((await answer.json()).categories, ['Valorant Mobile', 'VALORANT']);
});
