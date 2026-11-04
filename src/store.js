// Who is signed in. Kept in one file on the server's disk: small and needs no database. Session
// tokens are stored only as hashes, and Kick's tokens only encrypted, so a copy of the file alone
// gives nobody access to any account.
import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

export const hashToken = (token) => createHash('sha256').update(token).digest('hex');
export const newToken = () => randomBytes(32).toString('base64url');

export class Store {
  #path;
  #key;
  #sessions = new Map();

  /** `key`: 32 bytes as hex. */
  constructor(dataDir, key) {
    this.#path = join(dataDir, 'sessions.json');
    this.#key = Buffer.from(key, 'hex');
    if (this.#key.length !== 32) throw new Error('DATA_KEY must be 32 bytes in hex');
    mkdirSync(dirname(this.#path), { recursive: true });
    try {
      for (const [hash, session] of JSON.parse(readFileSync(this.#path, 'utf8'))) {
        this.#sessions.set(hash, session);
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
    });
    this.#save();
    return token;
  }

  find(token) {
    const hash = hashToken(token);
    const session = this.#sessions.get(hash);
    return session ? { hash, ...session } : null;
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
