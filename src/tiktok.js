// TikTok LIVE. EXPERIMENTAL: TikTok has no official API for this. It runs on an unofficial library,
// which can stop working without notice, and it is here on the server so that it can be fixed
// without a new version of the app. It only reads.
import { randomUUID } from 'node:crypto';

/** People watching the same channel share one connection, which ends this long after the last. */
const LINGER_MS = 60_000;
/** A channel that is not live is looked at again this often. */
const RETRY_MS = 60_000;

export const cleanUsername = (input) => {
  const name = String(input ?? '')
    .trim()
    .replace(/^@/, '')
    .toLowerCase();
  return /^[a-z0-9._]{1,24}$/.test(name) ? name : null;
};

/** What a library event means, as the apps receive it. `null` for what they have no use for. */
export function toFrame(type, data) {
  const user = data.user?.nickname || data.user?.uniqueId || 'Anonymous';
  const id = randomUUID();
  switch (type) {
    case 'chat':
      return {
        kind: 'chat',
        id,
        author: user,
        color: null,
        content: data.comment ?? '',
        is_owner: false,
        is_moderator: false,
        is_member: false,
      };
    case 'gift': {
      // A streak sends an event per tap: only its end says how much it was.
      if (data.giftDetails?.giftType === 1 && !data.repeatEnd) return null;
      const name = data.giftDetails?.giftName ?? 'a gift';
      const times = data.repeatCount ?? 1;
      return {
        kind: 'alert',
        id,
        event: 'gift',
        user,
        amount: times > 1 ? `${name} x${times}` : name,
        count: null,
        message: null,
      };
    }
    case 'follow':
      return {
        kind: 'alert',
        id,
        event: 'follow',
        user,
        amount: null,
        count: null,
        message: null,
      };
    default:
      return null;
  }
}

export class TikTokRooms {
  #rooms = new Map();
  #connect;
  #maxRooms;

  /** `connect(username)` returns a connection with `on`, `connect` and `disconnect`. */
  constructor({ connect, maxRooms }) {
    this.#connect = connect;
    this.#maxRooms = maxRooms;
  }

  /** Returns a function to leave, or `null` when there is no room for another channel. */
  join(username, send) {
    let room = this.#rooms.get(username);
    if (!room) {
      if (this.#rooms.size >= this.#maxRooms) return null;
      room = this.#open(username);
    }
    clearTimeout(room.closing);
    room.listeners.add(send);
    send({ kind: 'status', live: room.live });
    return () => {
      room.listeners.delete(send);
      if (room.listeners.size === 0) {
        room.closing = setTimeout(() => this.#close(username, room), LINGER_MS);
        room.closing.unref?.();
      }
    };
  }

  #open(username) {
    const room = { listeners: new Set(), live: false, closed: false };
    this.#rooms.set(username, room);
    const connection = this.#connect(username);
    room.connection = connection;
    const each = (frame) => {
      for (const send of room.listeners) send(frame);
    };
    for (const type of ['chat', 'gift', 'follow']) {
      connection.on(type, (data) => {
        const frame = toFrame(type, data);
        if (frame) each(frame);
      });
    }
    const attempt = async () => {
      if (room.closed) return;
      try {
        await connection.connect();
        room.live = true;
        each({ kind: 'status', live: true });
      } catch {
        // Usually it is just not live yet. The reason could quote a key: it stays out of the log.
        room.live = false;
        each({ kind: 'status', live: false });
        room.retry = setTimeout(attempt, RETRY_MS);
        room.retry.unref?.();
      }
    };
    const ended = () => {
      if (room.closed || !room.live) return;
      room.live = false;
      each({ kind: 'status', live: false });
      room.retry = setTimeout(attempt, RETRY_MS);
      room.retry.unref?.();
    };
    connection.on('streamEnd', ended);
    connection.on('disconnected', ended);
    void attempt();
    return room;
  }

  #close(username, room) {
    room.closed = true;
    clearTimeout(room.retry);
    this.#rooms.delete(username);
    Promise.resolve(room.connection.disconnect?.()).catch(() => {});
  }

  get size() {
    return this.#rooms.size;
  }

  closeAll() {
    for (const [username, room] of this.#rooms) {
      clearTimeout(room.closing);
      this.#close(username, room);
    }
  }
}
