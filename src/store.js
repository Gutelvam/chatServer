// Who is signed in. Kept in one file on the server's disk: small and needs no database. Session
// tokens are stored only as hashes, and Kick's tokens only encrypted, so a copy of the file alone
// gives nobody access to any account.
import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

export const hashToken = (token) => createHash('sha256').update(token).digest('hex');
export const newToken = () => randomBytes(32).toString('base64url');

const DAY_MS = 24 * 60 * 60 * 1000;
/** A session nobody has used for this long is gone: a stolen copy does not work forever. */
export const SESSION_IDLE_MS = 90 * DAY_MS;

export class Store {
  #path;
  #key;
  #sessions = new Map();
  #idleMs;
  #now;

  /** `key`: 32 bytes as hex. `idleMs` and `now` are for tests. */
  constructor(dataDir, key, { idleMs = SESSION_IDLE_MS, now = Date.now } = {}) {
    this.#idleMs = idleMs;
    this.#now = now;
    this.#path = join(dataDir, 'sessions.json');
    this.#key = Buffer.from(key, 'hex');
    if (this.#key.length !== 32) throw new Error('DATA_KEY must be 32 bytes in hex');
    mkdirSync(dirname(this.#path), { recursive: true });
    try {
      for (const [hash, session] of JSON.parse(readFileSync(this.#path, 'utf8'))) {
        // Sessions from before idle expiry start counting from this start.
        this.#sessions.set(hash, { ...session, seenAt: session.seenAt ?? this.#now() });
      }
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
  }

  #seal(value) {
    const nonce = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.#key, nonce);
    const sealed = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final()]);
    return [nonce, cipher.getAuthTag(), sealed].map((b) => b.toString('base64')).join('.');
  }

  #open(text) {
    const [nonce, tag, sealed] = text.split('.').map((b) => Buffer.from(b, 'base64'));
    const decipher = createDecipheriv('aes-256-gcm', this.#key, nonce);
    decipher.setAuthTag(tag);
    return JSON.parse(Buffer.concat([decipher.update(sealed), decipher.final()]).toString('utf8'));
  }

  #save() {
    // A crash in the middle leaves the previous file, not half of one.
    const temporary = `${this.#path}.tmp`;
    writeFileSync(temporary, JSON.stringify([...this.#sessions]), { mode: 0o600 });
    renameSync(temporary, this.#path);
  }

  /** Returns the session token, which only the app ever holds. */
  create({ userId, name, tokens, subscriptionIds }) {
    const token = newToken();
    this.#sessions.set(hashToken(token), {
      userId,
      name,
      tokens: this.#seal(tokens),
      subscriptionIds,
      seenAt: this.#now(),
    });
    this.#save();
    return token;
  }

  find(token) {
    const hash = hashToken(token);
    const session = this.#sessions.get(hash);
    if (!session) return null;
    const now = this.#now();
    if (now - session.seenAt > this.#idleMs) {
      this.remove(hash);
      return null;
    }
    // Written at most once a day per session, not on every message.
    if (now - session.seenAt > DAY_MS) {
      session.seenAt = now;
      this.#save();
    }
    return { hash, ...session };
  }

  tokensOf(session) {
    return this.#open(session.tokens);
  }

  saveTokens(hash, tokens) {
    const session = this.#sessions.get(hash);
    if (!session) return;
    session.tokens = this.#seal(tokens);
    this.#save();
  }

  remove(hash) {
    this.#sessions.delete(hash);
    this.#save();
  }

  /** Other sessions of the same account still need its event subscriptions. */
  othersOf(userId, hash) {
    return [...this.#sessions].filter(([h, s]) => h !== hash && s.userId === userId).length;
  }

  get size() {
    return this.#sessions.size;
  }
}
