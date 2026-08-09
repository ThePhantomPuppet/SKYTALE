/**
 * RelayRoom — one Durable Object per inbox (id = SHA-256 of the owner's Ed25519
 * identity key). A store-and-forward mailbox for end-to-end-encrypted messages.
 *
 * THREAT MODEL: still a dumb ciphertext store. Every queued payload is sealed by
 * the sender's Double Ratchet; the DO never holds keys or sees plaintext. It
 * knows only routing metadata (who queues to which inbox, when).
 *
 * Protocol (JSON text frames):
 *   sender  -> {t:'send', b64}            queue a ciphertext for this inbox
 *   owner   -> {t:'hello'}                request an auth challenge
 *   DO      -> {t:'challenge', nonce}
 *   owner   -> {t:'auth', signPub, sig}   Ed25519 sig over the nonce
 *   DO      -> {t:'authed'}               auth is committed; owner ops may follow
 *   DO      -> {t:'msg', id, b64}         a queued/live message (only to owner)
 *   owner   -> {t:'ack', id}              delete a delivered message
 *   owner   -> {t:'unsubscribe',endpoint,rid?}
 *   DO      -> {t:'unsubscribed',rid}      server-confirmed push cleanup
 *
 * Only a socket that proves it holds the private key for hash(signPub)==inbox
 * receives queued messages — so nobody who merely has your code can drain your
 * queue. Delivery is ack-based, so nothing is lost if the owner is offline.
 */
import { DurableObject } from 'cloudflare:workers';

export interface Env {
  RELAY: DurableObjectNamespace<RelayRoom>;
  RELAY_GUARD: DurableObjectNamespace<RelayActorGuard>;
  RELAY_RATE: RateLimit;
  UPLOAD_RATE: RateLimit;
  ASSETS: Fetcher;
  // R2 bucket for large encrypted attachments (see wrangler.toml). Holds ciphertext
  // ONLY — the per-file key never leaves the E2E envelope. Absent => big files disabled.
  BLOBS?: R2Bucket;
  // Web Push (VAPID). PUBLIC + SUBJECT are plain vars; JWK is a secret holding
  // the EC P-256 private key as a JWK JSON string. Absent => push disabled.
  VAPID_PUBLIC?: string;
  VAPID_SUBJECT?: string;
  VAPID_JWK?: string;
}

interface Att {
  room: string;
  owner: boolean;
  actor: string;
  connectedAt: number;
  nonce?: string;
  nonceAt?: number;
}

interface PushSubData {
  endpoint: string;
  keys: {
    p256dh: string;
    auth: string;
  };
}

const enc = new TextEncoder();
// Flood/abuse guards for the store-and-forward mailbox. Sending is deliberately
// auth-less (sealed sender — the relay can't identify who queues), so the mailbox
// is bounded by resource, not by sender. Sizes are measured on the base64 body we
// store (ASCII → chars == bytes); ciphertext is ~3/4 of that.
const MAX_QUEUE = 1000; // max undelivered messages per inbox
const MAX_MSG_B64 = 1_200_000; // ~900 KB ciphertext: the relay carries only SMALL
// messages — large attachments transfer out-of-band, so a single oversized send is
// a misbehaving client and is rejected (see SECURITY.md, groups/attachment limits).
const MAX_QUEUE_B64 = 20 * 1024 * 1024; // ~15 MB ciphertext backlog cap per inbox
// Tighter backlog cap for an inbox no owner has claimed yet (never authenticated on this
// relay instance). Lets a legitimate not-yet-online recipient buffer real traffic — a text
// ciphertext is ~1 KB, so 256 rows is a generous conversation backlog — while capping what
// spraying random inbox ids could ever store to ~2 MB apiece (audit F-08). The full cap
// applies the moment the real owner authenticates and claims the inbox.
const MAX_QUEUE_UNCLAIMED = 256;
const MAX_QUEUE_B64_UNCLAIMED = 2 * 1024 * 1024;
const QUEUE_TTL_MS = 30 * 24 * 60 * 60 * 1000; // sweep undelivered messages after 30 days
const PUSH_COALESCE_MS = 3000; // collapse a burst of sends into ONE wake-up push
const MAX_FRAME_CHARS = MAX_MSG_B64 + 8192; // JSON overhead + bounded metadata
const MAX_CONNECTIONS = 128;
const MAX_UNAUTH_CONNECTIONS = 32;
const MAX_ROOM_ACTOR_FRAMES_PER_MINUTE = 800;
const MAX_ROOM_ACTOR_BYTES_PER_MINUTE = 64 * 1024 * 1024;
const MAX_MID_CHARS = 128;
const MAX_SUBSCRIPTIONS = 16;
const MAX_PUSH_ENDPOINT_CHARS = 2048;
const PUSH_SUB_TTL_MS = 90 * 24 * 60 * 60 * 1000;
const PUSH_TIMEOUT_MS = 5000;
const AUTH_CHALLENGE_TTL_MS = 60_000;
const PUSH_DUE_KEY = 'pushDue';
const ROOM_RE = /^[a-f0-9]{64}$/;
const ACTOR_RE = /^[a-f0-9]{64}$/;
const STANDARD_B64_RE = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const URL_B64_RE = /^[A-Za-z0-9_-]+$/;
const STANDARD_B64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const URL_B64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const SAFE_MID_RE = /^[\x21-\x7e]+$/;

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function hasOnlyKeys(value: Record<string, unknown>, allowed: readonly string[]): boolean {
  return Object.keys(value).every((key) => allowed.includes(key));
}

/** Strict RFC 4648 padded Base64. Besides rejecting characters/whitespace and
 *  malformed padding, check the unused low bits so one byte string has exactly
 *  one canonical wire representation. */
function isCanonicalBase64(value: unknown, maxChars: number, expectedBytes?: number): value is string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > maxChars ||
    value.length % 4 !== 0 ||
    !STANDARD_B64_RE.test(value)
  ) {
    return false;
  }
  const padding = value.endsWith('==') ? 2 : value.endsWith('=') ? 1 : 0;
  const decodedBytes = (value.length / 4) * 3 - padding;
  if (expectedBytes !== undefined && decodedBytes !== expectedBytes) return false;
  const last = STANDARD_B64_ALPHABET.indexOf(value[value.length - padding - 1]);
  if ((padding === 2 && (last & 0x0f) !== 0) || (padding === 1 && (last & 0x03) !== 0)) return false;
  return true;
}

/** Strict unpadded Base64url, as returned by PushSubscription.toJSON(). */
function isCanonicalBase64Url(value: unknown, maxChars: number, expectedBytes?: number): value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > maxChars || !URL_B64_RE.test(value)) {
    return false;
  }
  const remainder = value.length % 4;
  if (remainder === 1) return false;
  const decodedBytes = Math.floor((value.length * 6) / 8);
  if (expectedBytes !== undefined && decodedBytes !== expectedBytes) return false;
  const last = URL_B64_ALPHABET.indexOf(value[value.length - 1]);
  if ((remainder === 2 && (last & 0x0f) !== 0) || (remainder === 3 && (last & 0x03) !== 0)) return false;
  return true;
}

function b64urlDecode(value: string): Uint8Array {
  const padding = '='.repeat((4 - (value.length % 4)) % 4);
  return b64d(value.replace(/-/g, '+').replace(/_/g, '/') + padding);
}

function isSafeAckId(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0;
}

function isSafeMid(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= MAX_MID_CHARS &&
    SAFE_MID_RE.test(value)
  );
}

function isSafeRid(value: unknown): value is string {
  return isSafeMid(value);
}

function isBrowserPushHost(hostname: string): boolean {
  const host = hostname.toLowerCase();
  return (
    host === 'fcm.googleapis.com' ||
    host === 'updates.push.services.mozilla.com' ||
    host === 'push.services.mozilla.com' ||
    host === 'web.push.apple.com' ||
    host.endsWith('.push.apple.com') ||
    host.endsWith('.notify.windows.com')
  );
}

function parseHttpsEndpoint(value: unknown): URL | null {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > MAX_PUSH_ENDPOINT_CHARS ||
    /[\u0000-\u001f\u007f]/.test(value)
  ) {
    return null;
  }
  try {
    const url = new URL(value);
    if (
      url.protocol !== 'https:' ||
      url.hostname.length === 0 ||
      url.username !== '' ||
      url.password !== '' ||
      url.hash !== '' ||
      url.href !== value
    ) {
      return null;
    }
    return url;
  } catch {
    return null;
  }
}

function parsePushEndpoint(value: unknown): URL | null {
  const url = parseHttpsEndpoint(value);
  return url && isBrowserPushHost(url.hostname) ? url : null;
}

function parsePushSubscription(value: unknown): PushSubData | null {
  if (!isPlainRecord(value) || !hasOnlyKeys(value, ['endpoint', 'expirationTime', 'keys'])) return null;
  const endpoint = parsePushEndpoint(value.endpoint);
  if (!endpoint || !isPlainRecord(value.keys) || !hasOnlyKeys(value.keys, ['p256dh', 'auth'])) return null;
  if (
    'expirationTime' in value &&
    value.expirationTime !== null &&
    !(
      typeof value.expirationTime === 'number' &&
      Number.isSafeInteger(value.expirationTime) &&
      value.expirationTime >= 0
    )
  ) {
    return null;
  }
  if (
    !isCanonicalBase64Url(value.keys.p256dh, 96, 65) ||
    !isCanonicalBase64Url(value.keys.auth, 32, 16)
  ) {
    return null;
  }
  // An applicationServerKey is an uncompressed P-256 public point.
  if (b64urlDecode(value.keys.p256dh)[0] !== 0x04) return null;
  return {
    endpoint: endpoint.href,
    keys: { p256dh: value.keys.p256dh, auth: value.keys.auth },
  };
}

function earliestTimestamp(...values: Array<number | null>): number | null {
  let earliest: number | null = null;
  for (const value of values) {
    if (value === null || !Number.isSafeInteger(value) || value < 0) continue;
    if (earliest === null || value < earliest) earliest = value;
  }
  return earliest;
}

function closeSocket(ws: WebSocket, code: number, reason: string): void {
  try {
    ws.close(code, reason);
  } catch {
    /* already closed */
  }
}

function sendJson(ws: WebSocket, value: Record<string, unknown>): boolean {
  try {
    ws.send(JSON.stringify(value));
    return true;
  } catch {
    return false;
  }
}

function b64d(s: string): Uint8Array<ArrayBuffer> {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function b64e(b: Uint8Array): string {
  let s = '';
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return btoa(s);
}
function b64url(b: Uint8Array): string {
  return b64e(b).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function hex(b: Uint8Array): string {
  let s = '';
  for (const x of b) s += x.toString(16).padStart(2, '0');
  return s;
}

interface ActorBudgetRow {
  [column: string]: number;
  minute_start: number;
  minute_frames: number;
  minute_bytes: number;
  day_start: number;
  day_frames: number;
  day_bytes: number;
}

const ACTOR_MINUTE_MS = 60_000;
const ACTOR_DAY_MS = 24 * 60 * 60 * 1000;
const MAX_ACTOR_FRAMES_PER_MINUTE = 4096;
const MAX_ACTOR_BYTES_PER_MINUTE = 256 * 1024 * 1024;
const MAX_ACTOR_FRAMES_PER_DAY = 200_000;
const MAX_ACTOR_BYTES_PER_DAY = 4 * 1024 * 1024 * 1024;
// Distinct inboxes one actor (a hashed client IP) may mark as owner-backed. This only
// scopes per-room actor accounting now — it never gates auth or delivery — so it must be
// generous enough for a carrier-grade NAT where thousands of legitimate users share one IP.
const MAX_ACTOR_ROOM_CLAIMS = 4096;
const ACTOR_ROOM_CLAIM_TTL_MS = 30 * ACTOR_DAY_MS;

/**
 * One strongly-consistent Durable Object per edge actor. Unlike the Workers
 * RateLimit binding, this budget is durable and aggregates frames across every
 * room and socket used by the actor.
 */
export class RelayActorGuard extends DurableObject<unknown> {
  constructor(ctx: DurableObjectState, env: unknown) {
    super(ctx, env);
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS actor_budget (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        minute_start INTEGER NOT NULL,
        minute_frames INTEGER NOT NULL,
        minute_bytes INTEGER NOT NULL,
        day_start INTEGER NOT NULL,
        day_frames INTEGER NOT NULL,
        day_bytes INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS claimed_rooms (
        room TEXT PRIMARY KEY,
        claimed_at INTEGER NOT NULL
      );
    `);
  }

  charge(bytes: number): boolean {
    if (!Number.isSafeInteger(bytes) || bytes < 0 || bytes > MAX_FRAME_CHARS) return false;
    const now = Date.now();
    const minuteStart = Math.floor(now / ACTOR_MINUTE_MS) * ACTOR_MINUTE_MS;
    const dayStart = Math.floor(now / ACTOR_DAY_MS) * ACTOR_DAY_MS;
    return this.ctx.storage.transactionSync(() => {
      this.ctx.storage.sql.exec(
        `INSERT OR IGNORE INTO actor_budget
           (id, minute_start, minute_frames, minute_bytes, day_start, day_frames, day_bytes)
         VALUES (1, ?, 0, 0, ?, 0, 0)`,
        minuteStart,
        dayStart,
      );
      const current = this.ctx.storage.sql
        .exec<ActorBudgetRow>(
          `SELECT minute_start, minute_frames, minute_bytes,
                  day_start, day_frames, day_bytes
             FROM actor_budget WHERE id = 1`,
        )
        .one();
      const minuteFrames = (current.minute_start === minuteStart ? current.minute_frames : 0) + 1;
      const minuteBytes = (current.minute_start === minuteStart ? current.minute_bytes : 0) + bytes;
      const dayFrames = (current.day_start === dayStart ? current.day_frames : 0) + 1;
      const dayBytes = (current.day_start === dayStart ? current.day_bytes : 0) + bytes;
      this.ctx.storage.sql.exec(
        `UPDATE actor_budget
            SET minute_start = ?, minute_frames = ?, minute_bytes = ?,
                day_start = ?, day_frames = ?, day_bytes = ?
          WHERE id = 1`,
        minuteStart,
        minuteFrames,
        minuteBytes,
        dayStart,
        dayFrames,
        dayBytes,
      );
      return (
        minuteFrames <= MAX_ACTOR_FRAMES_PER_MINUTE &&
        minuteBytes <= MAX_ACTOR_BYTES_PER_MINUTE &&
        dayFrames <= MAX_ACTOR_FRAMES_PER_DAY &&
        dayBytes <= MAX_ACTOR_BYTES_PER_DAY
      );
    });
  }

  claimRoom(room: string): boolean {
    if (!ROOM_RE.test(room)) return false;
    const now = Date.now();
    return this.ctx.storage.transactionSync(() => {
      this.ctx.storage.sql.exec(
        'DELETE FROM claimed_rooms WHERE claimed_at <= ?',
        now - ACTOR_ROOM_CLAIM_TTL_MS,
      );
      const existing = this.ctx.storage.sql
        .exec<{ n: number }>('SELECT COUNT(*) AS n FROM claimed_rooms WHERE room = ?', room)
        .one().n;
      if (existing > 0) return true;
      const total = this.ctx.storage.sql.exec<{ n: number }>('SELECT COUNT(*) AS n FROM claimed_rooms').one().n;
      if (total >= MAX_ACTOR_ROOM_CLAIMS) return false;
      this.ctx.storage.sql.exec(
        'INSERT INTO claimed_rooms (room, claimed_at) VALUES (?, ?)',
        room,
        now,
      );
      return true;
    });
  }
}

export class RelayRoom extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.ctx.storage.sql.exec(
      'CREATE TABLE IF NOT EXISTS q (id INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT, ts INTEGER)',
    );
    // Migrate mailboxes created before the TTL column existed. ALTER throws if the
    // column is already there (new DOs) — that's the "already migrated" case.
    try {
      this.ctx.storage.sql.exec('ALTER TABLE q ADD COLUMN ts INTEGER');
    } catch {
      /* column already present */
    }
    // `silent` frames (profile/devlist/sync/recall/… — anything that is NOT a
    // user-visible message) are queued and delivered like any other, but never
    // trigger a wake-up push. Fixes phantom "Neue Nachricht" notifications with no
    // actual message behind them. Old rows default to 0 (treated as a message).
    try {
      this.ctx.storage.sql.exec('ALTER TABLE q ADD COLUMN silent INTEGER DEFAULT 0');
    } catch {
      /* column already present */
    }
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS room_state (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        owner_pub TEXT NOT NULL,
        claimed_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS actor_window (
        actor TEXT PRIMARY KEY,
        window_start INTEGER NOT NULL,
        frames INTEGER NOT NULL,
        bytes INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      );
    `);
    // Give pre-TTL rows a full grace period from their first post-deploy wake;
    // leaving ts=NULL forever would leave abandoned legacy mailboxes unbounded.
    this.ctx.storage.sql.exec('UPDATE q SET ts = ? WHERE ts IS NULL', Date.now());
    // Push subscriptions for this inbox's owner (only ever written after auth).
    this.ctx.storage.sql.exec(
      'CREATE TABLE IF NOT EXISTS subs (endpoint TEXT PRIMARY KEY, sub TEXT, ts INTEGER)',
    );
    try {
      this.ctx.storage.sql.exec('ALTER TABLE subs ADD COLUMN ts INTEGER');
    } catch {
      /* column already present */
    }
    this.ctx.storage.sql.exec('UPDATE subs SET ts = ? WHERE ts IS NULL', Date.now());
    // A pre-hardening owner could have inserted an arbitrary number of rows. Keep
    // the newest bounded set so an old mailbox is safe as soon as it wakes.
    this.ctx.storage.sql.exec(
      'DELETE FROM subs WHERE endpoint NOT IN (SELECT endpoint FROM subs ORDER BY ts DESC, endpoint DESC LIMIT ?)',
      MAX_SUBSCRIPTIONS,
    );
    // A Durable Object has exactly one alarm. Persist the coalesced push deadline
    // separately, then schedule the alarm for min(push deadline, queue expiry).
    this.ctx.storage.sql.exec(
      'CREATE TABLE IF NOT EXISTS alarm_state (name TEXT PRIMARY KEY, value INTEGER NOT NULL)',
    );
    // A hibernated WebSocket can wake a freshly deployed class without passing
    // through fetch(). Seed autonomous TTL cleanup on that path too, while
    // preserving an alarm that may be the event which is currently waking us.
    this.ctx.blockConcurrencyWhile(async () => {
      if ((await this.ctx.storage.getAlarm()) === null) await this.scheduleNextAlarm();
    });
  }

  /** Drop undelivered messages past the TTL — frees storage in mailboxes that are
   *  never drained (an abandoned account). Legacy NULL timestamps receive a full
   *  grace period in the constructor before this predicate can remove them. */
  private sweepExpired(now = Date.now()): void {
    this.ctx.storage.sql.exec('DELETE FROM q WHERE ts IS NOT NULL AND ts <= ?', now - QUEUE_TTL_MS);
  }

  private attachment(ws: WebSocket): Att | null {
    try {
      const value: unknown = ws.deserializeAttachment();
      if (
        !isPlainRecord(value) ||
        typeof value.room !== 'string' ||
        !ROOM_RE.test(value.room) ||
        typeof value.owner !== 'boolean' ||
        typeof value.actor !== 'string' ||
        !ACTOR_RE.test(value.actor) ||
        typeof value.connectedAt !== 'number' ||
        !Number.isSafeInteger(value.connectedAt) ||
        value.connectedAt < 0
      ) {
        return null;
      }
      if (
        value.nonce !== undefined &&
        !isCanonicalBase64(value.nonce, 64, 24)
      ) {
        return null;
      }
      if (
        value.nonceAt !== undefined &&
        !(typeof value.nonceAt === 'number' && Number.isSafeInteger(value.nonceAt) && value.nonceAt >= 0)
      ) {
        return null;
      }
      return {
        room: value.room,
        owner: value.owner,
        actor: value.actor,
        connectedAt: value.connectedAt,
        ...(value.nonce === undefined ? {} : { nonce: value.nonce }),
        ...(value.nonceAt === undefined ? {} : { nonceAt: value.nonceAt }),
      };
    } catch {
      return null;
    }
  }

  private isClaimed(): boolean {
    return this.ctx.storage.sql
      .exec<{ n: number }>('SELECT COUNT(*) AS n FROM room_state WHERE id = 1')
      .one().n > 0;
  }

  private chargeRoomActor(actor: string, bytes: number): boolean {
    const now = Date.now();
    const windowStart = Math.floor(now / ACTOR_MINUTE_MS) * ACTOR_MINUTE_MS;
    return this.ctx.storage.transactionSync(() => {
      const current = this.ctx.storage.sql
        .exec<{ window_start: number; frames: number; bytes: number }>(
          'SELECT window_start, frames, bytes FROM actor_window WHERE actor = ?',
          actor,
        )
        .toArray()[0];
      const frames = (current?.window_start === windowStart ? current.frames : 0) + 1;
      const totalBytes = (current?.window_start === windowStart ? current.bytes : 0) + bytes;
      this.ctx.storage.sql.exec(
        `INSERT INTO actor_window (actor, window_start, frames, bytes, updated_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(actor) DO UPDATE SET window_start = excluded.window_start,
                                          frames = excluded.frames,
                                          bytes = excluded.bytes,
                                          updated_at = excluded.updated_at`,
        actor,
        windowStart,
        frames,
        totalBytes,
        now,
      );
      // Bound rows when a proxy actor identifier churns.
      this.ctx.storage.sql.exec(
        'DELETE FROM actor_window WHERE updated_at <= ?',
        now - 2 * ACTOR_MINUTE_MS,
      );
      return (
        frames <= MAX_ROOM_ACTOR_FRAMES_PER_MINUTE &&
        totalBytes <= MAX_ROOM_ACTOR_BYTES_PER_MINUTE
      );
    });
  }

  private async chargeActor(att: Att, bytes: number): Promise<boolean> {
    // Unclaimed random rooms must not gain durable per-room rows. The global
    // actor DO still charges every frame, including hello/auth/malformed input.
    if (this.isClaimed() && !this.chargeRoomActor(att.actor, bytes)) return false;
    try {
      return await this.env.RELAY_GUARD.getByName(att.actor).charge(bytes);
    } catch {
      return false;
    }
  }

  /**
   * Never let anonymous sockets consume every owner slot. At either cap, evict
   * the oldest unauthenticated peer. Authenticated owners are never evicted.
   */
  private makeConnectionSlot(): boolean {
    const peers = this.ctx.getWebSockets();
    let live = 0;
    const guests: Array<{ ws: WebSocket; connectedAt: number }> = [];
    for (const peer of peers) {
      const att = this.attachment(peer);
      if (!att) {
        closeSocket(peer, 1012, 'reconnect required');
        continue;
      }
      live++;
      if (!att.owner) guests.push({ ws: peer, connectedAt: att.connectedAt });
    }
    if (live < MAX_CONNECTIONS && guests.length < MAX_UNAUTH_CONNECTIONS) return true;
    guests.sort((a, b) => a.connectedAt - b.connectedAt);
    const oldest = guests[0];
    if (!oldest) return false;
    closeSocket(oldest.ws, 1013, 'owner slot reserved');
    return true;
  }

  private trimGuests(keep: number): void {
    const guests = this.ctx.getWebSockets()
      .map((ws) => ({ ws, att: this.attachment(ws) }))
      .filter((entry): entry is { ws: WebSocket; att: Att } => !!entry.att && !entry.att.owner)
      .sort((a, b) => b.att.connectedAt - a.att.connectedAt);
    for (const guest of guests.slice(keep)) closeSocket(guest.ws, 1013, 'owner online');
  }

  private ownerOnline(): boolean {
    return this.ctx.getWebSockets().some((peer) => this.attachment(peer)?.owner === true);
  }

  private pendingVisibleCount(): number {
    return this.ctx.storage.sql
      .exec<{ n: number }>('SELECT COUNT(*) AS n FROM q WHERE silent = 0')
      .one().n;
  }

  private pushDueAt(): number | null {
    const value = this.ctx.storage.sql
      .exec<{ value: number | null }>(
        'SELECT MAX(value) AS value FROM alarm_state WHERE name = ?',
        PUSH_DUE_KEY,
      )
      .one().value;
    return Number.isSafeInteger(value) && value !== null && value >= 0 ? value : null;
  }

  private oldestExpiryAt(): number | null {
    const oldest = this.ctx.storage.sql
      .exec<{ ts: number | null }>('SELECT MIN(ts) AS ts FROM q WHERE ts IS NOT NULL')
      .one().ts;
    if (!Number.isSafeInteger(oldest) || oldest === null || oldest < 0) return null;
    const expiry = oldest + QUEUE_TTL_MS;
    return Number.isSafeInteger(expiry) ? expiry : null;
  }

  private clearPushDueIfIdle(): void {
    if (this.pendingVisibleCount() === 0) {
      this.ctx.storage.sql.exec('DELETE FROM alarm_state WHERE name = ?', PUSH_DUE_KEY);
    }
  }

  /** Recompute the single DO alarm from durable state after every state change.
   *  `setAlarm` replaces the prior alarm, so never schedule the two jobs
   *  independently. */
  private async scheduleNextAlarm(): Promise<void> {
    const next = earliestTimestamp(this.pushDueAt(), this.oldestExpiryAt());
    const current = await this.ctx.storage.getAlarm();
    if (next === null) {
      if (current !== null) await this.ctx.storage.deleteAlarm();
      return;
    }
    if (current !== next) await this.ctx.storage.setAlarm(next);
  }

  /** Arm a single coalescing alarm so a burst of sends (e.g. many small frames)
   *  wakes the owner with ONE push, not one per message. The first message fixes
   *  the deadline; later messages in the burst never move it backwards/forwards. */
  private async scheduleWake(): Promise<void> {
    this.ctx.storage.sql.exec(
      'INSERT OR IGNORE INTO alarm_state (name, value) VALUES (?, ?)',
      PUSH_DUE_KEY,
      Date.now() + PUSH_COALESCE_MS,
    );
    await this.scheduleNextAlarm();
  }

  /** The coalescing alarm: sweep expired messages, then send exactly one wake-up
   *  push if its deadline is due. Always reschedule the next queue expiry/push. */
  async alarm(): Promise<void> {
    const now = Date.now();
    try {
      this.sweepExpired(now);
      const pushDue = this.pushDueAt();
      if (pushDue !== null && pushDue <= now) {
        // Clear before external I/O: if a new send interleaves while push fetches
        // it creates a fresh deadline that this alarm's finally block preserves.
        this.ctx.storage.sql.exec('DELETE FROM alarm_state WHERE name = ?', PUSH_DUE_KEY);
        // Only a pending NON-silent (user-visible) message justifies a wake-up.
        const pending = this.ctx.storage.sql
          .exec<{ n: number }>('SELECT COUNT(*) AS n FROM q WHERE silent = 0')
          .one().n;
        if (pending > 0 && !this.ownerOnline()) await this.notifyOwner();
      }
      this.clearPushDueIfIdle();
    } finally {
      await this.scheduleNextAlarm();
    }
  }

  private expireSubscriptions(now = Date.now()): void {
    this.ctx.storage.sql.exec(
      'DELETE FROM subs WHERE ts IS NOT NULL AND ts <= ?',
      now - PUSH_SUB_TTL_MS,
    );
  }

  private upsertSubscription(sub: PushSubData): void {
    const now = Date.now();
    this.expireSubscriptions(now);
    const exists = this.ctx.storage.sql
      .exec<{ n: number }>('SELECT COUNT(*) AS n FROM subs WHERE endpoint = ?', sub.endpoint)
      .one().n;
    if (exists === 0) {
      const total = this.ctx.storage.sql.exec<{ n: number }>('SELECT COUNT(*) AS n FROM subs').one().n;
      if (total >= MAX_SUBSCRIPTIONS) {
        // The protocol has no subscribe-result frame. Replace the oldest device
        // rather than trapping the newest client in a reconnect/reject loop.
        this.ctx.storage.sql.exec(
          'DELETE FROM subs WHERE endpoint = (SELECT endpoint FROM subs ORDER BY ts, endpoint LIMIT 1)',
        );
      }
    }
    this.ctx.storage.sql.exec(
      'INSERT OR REPLACE INTO subs (endpoint, sub, ts) VALUES (?, ?, ?)',
      sub.endpoint,
      JSON.stringify(sub),
      now,
    );
  }

  async fetch(request: Request): Promise<Response> {
    if (request.method !== 'GET' || request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') {
      return new Response('Erwartet WebSocket-Upgrade.', { status: 426 });
    }
    const room = new URL(request.url).searchParams.get('room') ?? '';
    if (!ROOM_RE.test(room)) return new Response('Ungültige Inbox.', { status: 400 });
    const actor = request.headers.get('x-scytale-relay-actor') ?? '';
    if (!ACTOR_RE.test(actor)) return new Response('Actor fehlt.', { status: 403 });
    if (!this.makeConnectionSlot()) {
      return new Response('Zu viele Verbindungen.', {
        status: 429,
        headers: { 'Cache-Control': 'no-store', 'Retry-After': '5' },
      });
    }
    this.sweepExpired();
    this.clearPushDueIfIdle();
    await this.scheduleNextAlarm();
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    this.ctx.acceptWebSocket(server);
    server.serializeAttachment({ room, owner: false, actor, connectedAt: Date.now() } satisfies Att);
    return new Response(null, { status: 101, webSocket: client });
  }

  async webSocketMessage(ws: WebSocket, raw: string | ArrayBuffer): Promise<void> {
    try {
      // Reject by the allocation-free representation length first. Workers can
      // receive WebSocket frames much larger than this protocol's cap; encoding
      // an attacker-sized string before checking it needlessly pressures the
      // isolate's 128 MiB memory limit.
      if (typeof raw === 'string' && raw.length > MAX_FRAME_CHARS) {
        closeSocket(ws, 1009, 'frame too large');
        return;
      }
      if (raw instanceof ArrayBuffer && raw.byteLength > MAX_FRAME_CHARS) {
        closeSocket(ws, 1009, 'frame too large');
        return;
      }
      const frameBytes = typeof raw === 'string' ? enc.encode(raw).byteLength : raw.byteLength;
      if (frameBytes > MAX_FRAME_CHARS) {
        closeSocket(ws, 1009, 'frame too large');
        return;
      }
      const beforeCharge = this.attachment(ws);
      if (!beforeCharge) {
        closeSocket(ws, 1012, 'reconnect required');
        return;
      }
      if (!(await this.chargeActor(beforeCharge, frameBytes))) {
        closeSocket(ws, 1008, 'actor rate limit');
        return;
      }
      const att = this.attachment(ws);
      if (
        !att ||
        att.room !== beforeCharge.room ||
        att.actor !== beforeCharge.actor ||
        att.connectedAt !== beforeCharge.connectedAt
      ) {
        closeSocket(ws, 1011, 'socket state changed');
        return;
      }
      if (typeof raw !== 'string') {
        closeSocket(ws, 1003, 'text frames only');
        return;
      }
      let parsed: unknown;
      try {
        parsed = JSON.parse(raw);
      } catch {
        closeSocket(ws, 1007, 'invalid json');
        return;
      }
      if (!isPlainRecord(parsed) || typeof parsed.t !== 'string') {
        closeSocket(ws, 1007, 'invalid frame');
        return;
      }
      const m = parsed;

      switch (m.t) {
        case 'ping': {
          if (!hasOnlyKeys(m, ['t'])) {
            closeSocket(ws, 1008, 'invalid ping');
            return;
          }
          if (!sendJson(ws, { t: 'pong' })) closeSocket(ws, 1011, 'send failed');
          return;
        }
        case 'hello': {
          if (!hasOnlyKeys(m, ['t'])) {
            closeSocket(ws, 1008, 'invalid hello');
            return;
          }
          const nonce = b64e(crypto.getRandomValues(new Uint8Array(24)));
          ws.serializeAttachment({ ...att, nonce, nonceAt: Date.now() } satisfies Att);
          if (!sendJson(ws, { t: 'challenge', nonce })) closeSocket(ws, 1011, 'send failed');
          return;
        }
        case 'auth': {
          if (
            !hasOnlyKeys(m, ['t', 'signPub', 'sig']) ||
            !isCanonicalBase64(m.signPub, 64, 32) ||
            !isCanonicalBase64(m.sig, 96, 64) ||
            !att.nonce ||
            att.nonceAt === undefined ||
            Date.now() - att.nonceAt > AUTH_CHALLENGE_TTL_MS
          ) {
            closeSocket(ws, 1008, 'invalid auth');
            return;
          }
          const nonce = att.nonce;
          const signPub = b64d(m.signPub);
          const prefix = enc.encode('scytale-inbox:');
          const material = new Uint8Array(prefix.length + signPub.length);
          material.set(prefix, 0);
          material.set(signPub, prefix.length);
          const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', material));
          if (hex(digest) !== att.room) {
            closeSocket(ws, 1008, 'invalid auth');
            return;
          }
          let valid = false;
          try {
            const key = await crypto.subtle.importKey('raw', signPub, { name: 'Ed25519' }, false, ['verify']);
            valid = await crypto.subtle.verify({ name: 'Ed25519' }, key, b64d(m.sig), b64d(nonce));
          } catch {
            valid = false;
          }
          // A second `hello` supersedes the challenge while Web Crypto is
          // running; never authenticate an old nonce after that interleaving.
          const latest = this.attachment(ws);
          if (!valid || !latest || latest.nonce !== nonce) {
            closeSocket(ws, 1008, 'invalid auth');
            return;
          }
          if (!this.isClaimed()) {
            // Best-effort claim: it only marks the inbox as owner-backed so per-room actor
            // accounting applies to it. It must NEVER gate authentication or delivery — an
            // over-tight / IP-shared claim budget previously rejected legitimate owners with
            // 1013 and, combined with unclaimed inboxes refusing sends, broke messaging fleet-
            // wide. If the claim is unavailable the owner still authenticates and receives.
            let claimAllowed = false;
            try {
              claimAllowed = await this.env.RELAY_GUARD.getByName(att.actor).claimRoom(att.room);
            } catch {
              claimAllowed = false;
            }
            const afterClaim = this.attachment(ws);
            if (claimAllowed && afterClaim && afterClaim.nonce === nonce) {
              this.ctx.storage.sql.exec(
                'INSERT OR IGNORE INTO room_state (id, owner_pub, claimed_at) VALUES (1, ?, ?)',
                m.signPub,
                Date.now(),
              );
            }
          }
          ws.serializeAttachment({
            room: att.room,
            owner: true,
            actor: att.actor,
            connectedAt: att.connectedAt,
          } satisfies Att);
          if (!sendJson(ws, { t: 'authed' })) {
            closeSocket(ws, 1011, 'send failed');
            return;
          }
          this.trimGuests(16);
          this.ctx.storage.sql.exec('DELETE FROM alarm_state WHERE name = ?', PUSH_DUE_KEY);
          this.sweepExpired();
          // Pre-hardening rows may contain malformed Base64. Delete them instead
          // of forwarding a permanent poison pill that crashes every client drain.
          for (const row of this.ctx.storage.sql.exec<{ id: number; body: string }>(
            'SELECT id, body FROM q ORDER BY id',
          )) {
            if (!isSafeAckId(row.id) || !isCanonicalBase64(row.body, MAX_MSG_B64)) {
              if (isSafeAckId(row.id)) this.ctx.storage.sql.exec('DELETE FROM q WHERE id = ?', row.id);
              continue;
            }
            if (!sendJson(ws, { t: 'msg', id: row.id, b64: row.body })) break;
          }
          this.clearPushDueIfIdle();
          this.ctx.waitUntil(this.scheduleNextAlarm());
          return;
        }
        case 'send': {
          if (
            !hasOnlyKeys(m, ['t', 'b64', 'mid', 'silent']) ||
            !isCanonicalBase64(m.b64, MAX_FRAME_CHARS) ||
            ('mid' in m && !isSafeMid(m.mid)) ||
            ('silent' in m && typeof m.silent !== 'boolean')
          ) {
            closeSocket(ws, 1008, 'invalid send');
            return;
          }
          const mid = 'mid' in m ? m.mid : null;
          // Sending is auth-less by design (sealed sender), so the mailbox is
          // bounded by resource, not by sender.
          if (m.b64.length > MAX_MSG_B64) {
            sendJson(ws, { t: 'nack', mid, reason: 'toolarge' });
            return;
          }
          // Sending to an inbox is NOT hard-gated on a prior owner "claim". Requiring one
          // silently broke ALL store-and-forward: a recipient that had not (re-)authenticated
          // on THIS relay instance — the entire fleet after a relay migration, plus anyone
          // offline or behind a shared CGNAT IP that exhausted the per-IP claim budget — could
          // receive nothing. Instead an UNCLAIMED inbox gets a much tighter backlog cap: enough
          // for a legitimate not-yet-online recipient to buffer real traffic, but small enough
          // that spraying random inbox ids can never accumulate meaningful storage (audit F-08).
          // Once the real owner authenticates and claims the inbox, the full cap applies.
          this.sweepExpired();
          this.clearPushDueIfIdle();
          const claimed = this.isClaimed();
          const maxRows = claimed ? MAX_QUEUE : MAX_QUEUE_UNCLAIMED;
          const maxBytes = claimed ? MAX_QUEUE_B64 : MAX_QUEUE_B64_UNCLAIMED;
          const stat = this.ctx.storage.sql
            .exec<{ n: number; bytes: number }>(
              'SELECT COUNT(*) AS n, COALESCE(SUM(LENGTH(body)), 0) AS bytes FROM q',
            )
            .one();
          if (stat.n >= maxRows || stat.bytes + m.b64.length > maxBytes) {
            // Counter only, never the inbox id — Cloudflare logs must not
            // accumulate routing metadata.
            console.warn(`relay: inbox full (rows=${stat.n}, bytes=${stat.bytes}, claimed=${claimed}), rejecting send`);
            sendJson(ws, { t: 'nack', mid, reason: 'full' });
            return;
          }
          // Honour the client's `silent` bit: a silent frame (delivery receipt, device-list gossip,
          // self-sync, profile refresh) must NEVER arm a wake-up push — otherwise every routine
          // control frame to an offline contact fires a content-free "Neue Nachricht" with nothing
          // behind it (the phantom push). Honouring `silent` can only suppress the wake of the
          // SENDER'S OWN frame: it can neither fabricate a wake nor suppress another party's real
          // message (genuine user messages are sent silent:false and are still delivered + shown on
          // next open). NOTE: the send path is auth-less (sealed sender), so `att.owner` is ALWAYS
          // false for a send frame — gating on it (added in the 2026-07-27 remediation) forced
          // silent=0 universally, breaking the feature, while buying no real protection (a sender can
          // just set silent:false). A stricter "only an owner-minted sender may go silent" rule needs
          // a per-recipient sender capability in the wire protocol — a deliberate follow-up.
          const silent = m.silent === true ? 1 : 0;
          const inserted = this.ctx.storage.sql
            .exec<{ id: number }>(
              'INSERT INTO q (body, ts, silent) VALUES (?, ?, ?) RETURNING id',
              m.b64,
              Date.now(),
              silent,
            )
            .one();
          // Positive receipt only after the durable insert.
          sendJson(ws, { t: 'sent', mid });
          let ownerOnline = false;
          for (const peer of this.ctx.getWebSockets()) {
            const peerAtt = this.attachment(peer);
            if (!peerAtt) {
              closeSocket(peer, 1011, 'invalid socket state');
              continue;
            }
            if (peerAtt.owner && sendJson(peer, { t: 'msg', id: inserted.id, b64: m.b64 })) {
              ownerOnline = true;
            }
          }
          // Keep the established source-level protocol invariant: silent frames
          // never arm push. Every other path still arms the queue-expiry alarm.
          if (!ownerOnline && !silent) this.ctx.waitUntil(this.scheduleWake());
          else this.ctx.waitUntil(this.scheduleNextAlarm());
          return;
        }
        case 'ack': {
          if (!hasOnlyKeys(m, ['t', 'id']) || !isSafeAckId(m.id)) {
            closeSocket(ws, 1008, 'invalid ack');
            return;
          }
          // Only the authenticated inbox owner may delete queued messages.
          if (!att.owner) return;
          this.ctx.storage.sql.exec('DELETE FROM q WHERE id = ?', m.id);
          this.clearPushDueIfIdle();
          this.ctx.waitUntil(this.scheduleNextAlarm());
          return;
        }
        case 'subscribe': {
          if (!hasOnlyKeys(m, ['t', 'sub'])) {
            closeSocket(ws, 1008, 'invalid subscription');
            return;
          }
          const sub = parsePushSubscription(m.sub);
          if (!sub) {
            closeSocket(ws, 1008, 'invalid subscription');
            return;
          }
          if (!att.owner) return;
          this.upsertSubscription(sub);
          return;
        }
        case 'unsubscribe': {
          if (
            !hasOnlyKeys(m, ['t', 'endpoint', 'rid']) ||
            ('rid' in m && !isSafeRid(m.rid))
          ) {
            closeSocket(ws, 1008, 'invalid unsubscribe');
            return;
          }
          // Unsubscribe performs only a local DELETE, so permit a canonical
          // legacy HTTPS endpoint even if new subscriptions may no longer use it.
          const endpoint = parseHttpsEndpoint(m.endpoint);
          if (!endpoint) {
            closeSocket(ws, 1008, 'invalid unsubscribe');
            return;
          }
          if (!att.owner) return;
          this.ctx.storage.sql.exec('DELETE FROM subs WHERE endpoint = ?', endpoint.href);
          sendJson(ws, { t: 'unsubscribed', rid: 'rid' in m ? m.rid : null });
          return;
        }
        default:
          closeSocket(ws, 1008, 'unknown frame');
      }
    } catch {
      // Never let attacker-controlled input escape the handler: an uncaught
      // exception can terminate this Durable Object and every connected socket.
      closeSocket(ws, 1011, 'internal error');
    }
  }

  /** Send a content-free VAPID Web Push to every registered subscription. The
   *  payload is empty by design — a bare wake-up that leaks no message content.
   *  Stale endpoints (404/410) are pruned. */
  private async notifyOwner(): Promise<void> {
    const env = this.env;
    this.expireSubscriptions();
    if (!env.VAPID_JWK || !env.VAPID_PUBLIC || !env.VAPID_SUBJECT) return;
    const rows = [...this.ctx.storage.sql.exec<{ endpoint: string }>('SELECT endpoint FROM subs')];
    if (rows.length === 0) return;

    let key: CryptoKey;
    try {
      key = await crypto.subtle.importKey(
        'jwk',
        JSON.parse(env.VAPID_JWK),
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['sign'],
      );
    } catch {
      return; // misconfigured secret — fail silently, never break delivery
    }

    const stale = await Promise.all(rows.map(async ({ endpoint }): Promise<string | null> => {
      const endpointUrl = parsePushEndpoint(endpoint);
      if (!endpointUrl) return endpoint;
      try {
        const aud = endpointUrl.origin;
        const header = b64url(enc.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
        const payload = b64url(
          enc.encode(JSON.stringify({ aud, exp: Math.floor(Date.now() / 1000) + 43200, sub: env.VAPID_SUBJECT })),
        );
        const signingInput = `${header}.${payload}`;
        const sig = new Uint8Array(
          await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, enc.encode(signingInput)),
        );
        const jwt = `${signingInput}.${b64url(sig)}`;
        const res = await fetch(endpointUrl.href, {
          method: 'POST',
          redirect: 'manual',
          signal: AbortSignal.timeout(PUSH_TIMEOUT_MS),
          headers: {
            Authorization: `vapid t=${jwt}, k=${env.VAPID_PUBLIC}`,
            TTL: '2419200',
            Urgency: 'high',
          },
        });
        try {
          await res.body?.cancel();
        } catch {
          /* response body is irrelevant */
        }
        return res.status === 404 || res.status === 410 || (res.status >= 300 && res.status < 400)
          ? endpoint
          : null;
      } catch {
        /* one bad endpoint must not stop the rest */
        return null;
      }
    }));
    for (const endpoint of stale) {
      if (endpoint !== null) this.ctx.storage.sql.exec('DELETE FROM subs WHERE endpoint = ?', endpoint);
    }
  }

  webSocketClose(ws: WebSocket, code: number, _reason: string, wasClean: boolean): void {
    closeSocket(ws, code, wasClean ? 'bye' : 'abnormal');
  }

  webSocketError(ws: WebSocket): void {
    closeSocket(ws, 1011, 'error');
  }
}
