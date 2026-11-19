// Starts the relay from its environment. See README.md for what each value is.
import { Google, GoogleClients } from './google.js';
import { Kick } from './kick.js';
import { createRelay } from './server.js';
import { Store } from './store.js';
import { TikTokRooms } from './tiktok.js';

const required = (name) => {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not set`);
  return value;
};

const port = Number(process.env.PORT ?? 8080);
const publicUrl = required('PUBLIC_URL').replace(/\/$/, '');
const store = new Store(process.env.DATA_DIR ?? '/data', required('DATA_KEY'));

const kick =
  process.env.KICK_CLIENT_ID && process.env.KICK_CLIENT_SECRET
    ? new Kick({
        clientId: process.env.KICK_CLIENT_ID,
        clientSecret: process.env.KICK_CLIENT_SECRET,
        idBase: 'https://id.kick.com',
        apiBase: 'https://api.kick.com',
      })
    : null;

const googleTokenUrl = 'https://oauth2.googleapis.com/token';
const googleClients = new GoogleClients();
// GOOGLE_CLIENT_ID stays the default for apps that don't say which client they use; *_2 is the next
// one (EZ Stream project), used by apps that send its id.
for (const suffix of ['', '_2']) {
  const clientId = process.env[`GOOGLE_CLIENT_ID${suffix}`];
  const clientSecret = process.env[`GOOGLE_CLIENT_SECRET${suffix}`];
  if (clientId && clientSecret) {
    googleClients.add(clientId, new Google({ clientId, clientSecret, tokenUrl: googleTokenUrl }));
  }
}
const google = googleClients.size ? googleClients : null;

let rooms = null;
if (process.env.TIKTOK_ENABLED === '1') {
  // Loaded only when used: without it, nothing unofficial runs on this server.
  const { TikTokLiveConnection } = await import('tiktok-live-connector');
  const signApiKey = process.env.TIKTOK_SIGN_API_KEY || undefined;
  rooms = new TikTokRooms({
    connect: (username) => new TikTokLiveConnection(username, { signApiKey }),
    maxRooms: Number(process.env.TIKTOK_MAX_ROOMS ?? 20),
  });
}

const relay = createRelay({ publicUrl, store, kick, rooms, google });
relay.server.listen(port, () => {
  console.log(
    `relay listening on ${port}; kick: ${Boolean(kick)}; tiktok: ${Boolean(rooms)}; google: ${googleClients.size}`,
  );
});

for (const signal of ['SIGTERM', 'SIGINT']) {
  process.on(signal, () => {
    void relay.close().then(() => process.exit(0));
  });
}
