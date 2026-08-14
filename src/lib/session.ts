/**
 * Conversation logic — pure, transport- and storage-agnostic (no IndexedDB
 * import, so it runs in Node tests too). Ties X3DH + Double Ratchet + wire
 * format together into "send this text" / "here's a received envelope".
 */
import {
  initiateX3DH,
  respondX3DH,
  initRatchetInitiator,
  initRatchetResponder,
  ratchetEncrypt,
  ratchetDecrypt,
  serializeState,
  deserializeState,
  encodeEnvelope,
  decodeEnvelope,
  PROTOCOL_VERSION,
  sealPayload,
  openPayload,
  SEALED_ENVELOPE,
  verifyDeviceCert,
  verifyRotation,
  encodeRotation,
  decodeRotation,
  deviceInList,
  verifyDeviceList,
  isNewerDeviceList,
  bundleFromDeviceEntry,
  encodeDeviceList,
  decodeDeviceList,
  encodeBundle,
  decodeBundle,
  encodeInitialHeader,
  decodeInitialHeader,
  identityFingerprint,
  getSodium,
  concatBytes,
  bytesEqual,
  asMasterPub,
  utf8,
  type IdentityKeys,
  type KeyPair,
  type PreKeyBundle,
  type RatchetState,
  type InitialMessageHeader,
  type Envelope,
  type Bytes,
  type MasterPub,
  type DeviceList,
  type RotationStatement,
} from '../crypto';
import { bytesToB64, b64ToBytes } from './bytes';
import type { Quote } from './messages';

export interface Contact {
  roomId: string;
  peerMasterPub: Bytes; // pinned cross-signing master (the stable identity)
  peerEpoch: number; // highest master epoch seen for this contact
  peerSignPub: Bytes; // current device sign key
  peerDhPub: Bytes; // current device DH key
  peerFingerprint: string;
  nickname?: string; // user-chosen local name for this peer (overrides everything)
  peerName?: string; // display name the peer shared via their profile
  peerAvatarB64?: string; // avatar the peer shared via their profile
  verified?: boolean; // local flag: safety number compared out-of-band
  /**
   * Erst-Sync: my OTHER device reported this contact as verified. Carried ONLY as
   * a SUGGESTION — it never sets `verified`. The UI opens the normal safety-number
   * view; the confirming tap must happen on THIS device (a compromised primary must
   * not be able to plant false trust here). Cleared once acted on.
   */
  verifiedSuggestion?: boolean;
  /** The user dismissed the verified suggestion — never re-offer it (survives even a
   *  bootstrap-applied-marker eviction, so a re-delivered snapshot can't re-nag). */
  verifiedSuggestionDismissed?: boolean;
  /**
   * The highest (epoch, version) of MY device list this peer has acknowledged
   * (listack). Legacy single-device watermark; new code keeps the authoritative
   * value per peer device below.
   */
  peerAckedListEV?: { epoch: number; version: number };
  /**
   * Per-target-device acknowledgement of MY current DeviceList. A person-level
   * watermark is insufficient: one secondary device acknowledging a revocation
   * must not stop retries to another device that never received it.
   */
  peerAckedListByDevice?: Record<string, { epoch: number; version: number }>;
  hidden?: boolean; // group-member-only contact — kept out of the 1:1 list
  /**
   * Explicit local simulation contact used only by the provisioned decoy
   * account. It is never connected to a relay and text sends are local echoes.
   * An explicit bit is safer than inferring this from "no bundle/session",
   * because legitimate bootstrap contacts can temporarily have that shape.
   */
  localOnly?: boolean;
  /**
   * This contact predates a device-linking identity swap: they still have our
   * OLD master pinned. Sending is blocked (see sendContent) because anything we
   * send over the surviving session would implicitly claim an identity we no
   * longer hold — the peer would attribute it to the old, *verified* master.
   * Receiving stays open: their identity is unchanged, their messages are real.
   */
  staleIdentity?: boolean;
  /**
   * A DIFFERENT identity was claimed for this contact and rejected by the
   * pinning rule. Kept here so the user can deliberately accept it — a block
   * without a path to acceptance would make the door one-sided. Only recorded
   * when the claim is internally consistent (its device cert verifies under the
   * claimed master); never applied automatically.
   */
  pendingMaster?: { masterPub: Bytes; epoch: number; signPub: Bytes; dhPub: Bytes };
  /**
   * Masters this contact has DEMONSTRABLY left behind (base64 of the pub key),
   * appended whenever we accept a replacement. An abandoned master is the most
   * likely compromised key in the whole system — it lingers in old backups and
   * on discarded devices, which is usually why it was abandoned. So it is never
   * offered again: a downgrade back to it is the first thing an attacker with
   * access to old material would try, and the safety number would look
   * *familiar* to the user rather than alarming. Growth is one entry per real
   * identity change of this contact.
   */
  retiredMasters?: string[];
  /**
   * A message under a retired master was rejected for this contact at least
   * once. Persistent CONTACT STATE, not an event — whoever holds the abandoned
   * key can replay forever, and one warning per delivered message would be a
   * harassment lever: it either annoys the user or, worse, trains them to wave
   * warnings away until a real one goes unread. Warning fatigue is an attack on
   * the human part of the system. So the notice fires once, then lives here.
   */
  retiredAttempt?: boolean;
  /**
   * The MASTER under which THIS contact knows us — the local half of the
   * master-based conversation key: roomId = computeMasterRoomId(ownMasterPub,
   * peerMasterPub). Normally our current master; for a staleIdentity contact it
   * is our PRE-LINK master (snapshotted at installGrant BEFORE the identity
   * swap, because the peer still pins that one — losing it makes the stale
   * conversation permanently un-addressable). Optional only on pre-3c records;
   * the boot migration fills it.
   */
  ownMasterPub?: MasterPub;
  /**
   * The peer's most recently accepted, master-signed device list. The device-
   * revocation guard checks presence here: a device whose cert verifies under
   * the pinned master but which is absent from this list is refused. Absent on
   * pre-3c records and at first contact (an implicit single-device list is
   * synthesized until a devlist update arrives). Kept current via gossip.
   */
  peerDeviceList?: DeviceList;
  /**
   * Which roomId regime this record's `roomId` was derived under. Absent means
   * the pre-3c device-DH regime (the migration default: "no marker = old"), so
   * the boot migration knows to re-key it; 'master' means already migrated, so a
   * second run is a no-op. This is the idempotency anchor — without it, an
   * already-migrated contact cannot be told apart from an unmigrated one.
   */
  regime?: 'device' | 'master';
  bundle?: PreKeyBundle; // present when WE hold their code (needed to initiate)
  /**
   * Per-DEVICE Double-Ratchet sessions, keyed by the peer device's sign key
   * (base64). A conversation is one PERSON (roomId/verified/peerDeviceList stay
   * singular), but each of the peer's authorised devices gets its OWN X3DH+ratchet
   * session — Stage 3d fan-out. INVARIANT I HOLDS PER SESSION: each Session owns
   * its own RatchetState (and skipped-key map); a message key is used exactly once
   * PER session. A RatchetState is NEVER shared/aliased across two map entries —
   * that would join two chains and turn a key-reuse into a two-time-pad. In Stage
   * 3d step 1 there is at most ONE entry (the primary/pinned device), so behaviour
   * is identical to the old single `ratchet` field.
   */
  sessions: Map<string, Session>;
}

/** One peer device's Double-Ratchet session. Keyed in Contact.sessions by
 *  base64(deviceSignPub). Each carries its OWN ratchet state — never shared. */
export interface Session {
  ratchet: RatchetState | null; // null until this device's session is established
  pendingHeader: InitialMessageHeader | null; // initiator attaches until first reply
  deviceSignPub: Bytes; // the peer device behind this session (prune/route key)
  /**
   * The peer device's advertised protocol version, learned ONLY from a message
   * that authenticated over this session (so it's as trustworthy as the message).
   * Undefined until we've received from this device; a legacy client stays
   * undefined. Gates forward-compatible sends that a stale device must not get.
   */
  pv?: number;
}

// ── Per-device session helpers (Stage 3d) ───────────────────────────────
/** Map key for a peer device's session (base64 of its sign key). */
export function deviceKey(deviceSignPub: Bytes): string {
  return bytesToB64(deviceSignPub);
}
/** Does this contact have ANY established (ratchet-bearing) session? Replaces the
 *  old `contact.ratchet !== null` test now that sessions are per-device. */
export function hasSession(contact: Contact): boolean {
  for (const s of contact.sessions.values()) if (s.ratchet) return true;
  return false;
}
/** The session for a specific peer device, if present. */
export function sessionFor(contact: Contact, deviceSignPub: Bytes): Session | undefined {
  return contact.sessions.get(deviceKey(deviceSignPub));
}
/** The protocol version learned for a peer device (0 = legacy/never-heard-from).
 *  Only ever set from an authenticated message, so a sender may safely gate a
 *  forward-compatible feature on `deviceProtocolVersion(...) >= N` — a stale or
 *  unknown device stays 0 and keeps the backward-compatible path. */
export function deviceProtocolVersion(contact: Contact, deviceSignPub: Bytes): number {
  const authenticatedSession = sessionFor(contact, deviceSignPub)?.pv;
  if (authenticatedSession !== undefined) return authenticatedSession;
  const certifiedDirectory = contact.peerDeviceList?.devices.find((device) =>
    bytesEqual(device.signPub, deviceSignPub),
  )?.protocolVersion;
  return certifiedDirectory ?? 0;
}

/** Sending to a contact that still pins our pre-linking master is refused: the
 *  message would claim an identity we no longer hold. Re-connect first. */
export class StaleIdentityError extends Error {
  constructor() {
    super('Dieser Kontakt kennt noch deine frühere Identität — bitte neu verbinden, bevor du schreibst.');
    this.name = 'StaleIdentityError';
  }
}

/**
 * The X3DH handshake completed but its FIRST message would not decrypt — both
 * sides derived different shared secrets. Typical cause: a one-time prekey the
 * peer already consumed (so we computed DH1–DH4 and they DH1–DH3), or a stale
 * signed prekey. Named explicitly because this class of bug otherwise surfaces
 * as an anonymous decryption failure with no diagnostic trail.
 */
export class HandshakeMismatchError extends Error {
  constructor() {
    super(
      'Handshake passt nicht zusammen (vermutlich verbrauchter oder veralteter Prekey) — Verbindung muss neu aufgebaut werden.',
    );
    this.name = 'HandshakeMismatchError';
  }
}

/**
 * A prekey arrived from a device whose cert verifies under the pinned master but
 * which is NOT in the contact's accepted device list — a REVOKED device. This is
 * the receive half of device revocation (Stage 3c). Distinct from a "not my
 * conversation" rejection: the master is right, the device is retired.
 */
export class RevokedDeviceError extends Error {
  constructor() {
    super('Nachricht von einem Gerät, das nicht in der Geräteliste dieses Kontakts steht (widerrufen) — abgelehnt.');
    this.name = 'RevokedDeviceError';
  }
}

/**
 * A message arrived under a master this contact has already left behind. Never
 * offered for acceptance again: the abandoned key is the most likely
 * compromised one, and its old safety number would look reassuringly familiar
 * to the user. Surfaced (not swallowed) — it is either an attack worth knowing
 * about, or the contact must learn that only a fresh identity setup works.
 */
export class RetiredIdentityError extends Error {
  /** False for every repeat — the UI must alert only on the transition, never
   *  once per delivered message (see Contact.retiredAttempt). */
  readonly firstOccurrence: boolean;
  constructor(firstOccurrence: boolean) {
    super('Nachricht einer früheren, bereits ersetzten Identität dieses Kontakts — abgelehnt.');
    this.name = 'RetiredIdentityError';
    this.firstOccurrence = firstOccurrence;
  }
}

/** A pinned contact presented a different master without a valid rotation chain
 *  — a possible MITM. The message is dropped and the contact drops verified. */
export class MasterChangedError extends Error {
  /** False when this exact claim is already pending — the alert must fire on a
   *  NEW claim, not once per delivered copy of the same one. */
  readonly firstOccurrence: boolean;
  constructor(firstOccurrence: boolean) {
    super('Master-Schlüssel dieses Kontakts hat sich geändert — möglicher MITM. Nicht automatisch übernommen.');
    this.name = 'MasterChangedError';
    this.firstOccurrence = firstOccurrence;
  }
}

/** Responder-side lookup into the local prekey store. */
export interface PreKeyLookup {
  signedPreKey(id: number): KeyPair | undefined;
  /** Speculative, NON-MUTATING lookup. Required for envelopes that name an OPK. */
  oneTimePreKey?(id: number): Bytes | undefined;
  /** @deprecated Unsafe destructive lookup retained only for source compatibility.
   * receiveEnvelope never calls it. */
  consumeOneTimePreKey?(id: number | undefined): Bytes | undefined;
}

function cmp(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

/** Deterministic per-pair relay room: both sides derive the same id.
 *  DEVICE-DH based (the pre-3c regime). Kept because migration must recompute the
 *  old id from device keys, and group/member rooms still use it until 3d. */
export async function computeRoomId(a: Bytes, b: Bytes): Promise<string> {
  const s = await getSodium();
  const [x, y] = cmp(a, b) <= 0 ? [a, b] : [b, a];
  return s.to_hex(s.crypto_generichash(16, concatBytes(x, y), null));
}

/**
 * Master-based conversation id (Stage 3c). A conversation is a property of the
 * two PERSONS, so it is derived from both Ed25519 MASTER keys, sorted so both
 * sides land on the same value — never from the device pair (which would
 * fragment n×m across devices).
 *
 * `MasterPub` (not `Bytes`) on purpose: passing a device key here would compile
 * cleanly and silently key the conversation off the wrong material. The brand
 * turns that into a compile error — same guard as linkingSas.
 *
 * DOMAIN SEPARATION is not cosmetic: the old device-DH id and the new master id
 * share one IndexedDB keyspace during migration. Without the context prefix a
 * master id could (however improbably) collide with a not-yet-migrated device id
 * and cross-link two conversations' history and ratchet state. The prefix makes
 * the two derivations disjoint by construction.
 */
const MASTER_ROOM_CTX = utf8.encode('SCYTALE-master-room-v1');
export async function computeMasterRoomId(a: MasterPub, b: MasterPub): Promise<string> {
  const s = await getSodium();
  const [x, y] = cmp(a, b) <= 0 ? [a, b] : [b, a];
  return s.to_hex(s.crypto_generichash(16, concatBytes(MASTER_ROOM_CTX, x, y), null));
}

/**
 * Is this SENDER device allowed to reach this contact? — the device-revocation
 * check (Stage 3c).
 *
 * With an accepted master-signed device list, presence in it is the answer:
 * a device whose cert is valid under the pinned master but which was removed
 * from the list is REVOKED. Without a list (first contact, or a pre-3c record),
 * the rule is "implicit single-device": only the pinned device is allowed.
 *
 * ⚠️ The list is NEVER synthesized from the device under test — that would be a
 * self-referential guard (the v0.16.1 verifyLinkGrant class), green while
 * checking nothing. A second device can only be admitted by a real, master-
 * signed devlist update (Stage 8). Until then the implicit rule holds.
 */
export function deviceAuthorized(contact: Contact, deviceSignPub: Bytes): boolean {
  if (contact.peerDeviceList) return deviceInList(contact.peerDeviceList, deviceSignPub);
  return bytesEqual(deviceSignPub, contact.peerSignPub);
}

/**
 * Learn a peer's newer, MASTER-SIGNED device list (Stage 3c/3d gossip). This is
 * the ONLY way a second device of a peer becomes authorised — never by an
 * implicit list synthesized from the device itself (that would be
 * self-referential; see deviceAuthorized). Returns true if adopted.
 *
 * Refuses, in order: a master that isn't the pinned one; a RETIRED master
 * (denylist first); a list that doesn't verify against the pinned master + epoch
 * floor; and a ROLLBACK (not strictly newer than the stored list). Only then is
 * the list stored — so a downgrade or a forged list can never widen the set.
 */
export async function applyDeviceListUpdate(
  contact: Contact,
  list: DeviceList,
  retired: Set<string>,
): Promise<boolean> {
  if (!bytesEqual(list.masterPub, contact.peerMasterPub)) return false;
  if (retired.has(await masterKeyB64(list.masterPub))) return false;
  if (!(await verifyDeviceList(list, contact.peerMasterPub, contact.peerEpoch))) return false;
  if (contact.peerDeviceList && !isNewerDeviceList(list, contact.peerDeviceList)) return false;
  contact.peerDeviceList = list;
  // Device revocation on the MESSAGE path (Review C): the guard in receiveEnvelope
  // only gates PREKEY envelopes, so a revoked device could keep sending accepted
  // 'msg' over its already-established session indefinitely. Prune EVERY session
  // whose peer device is no longer in the accepted list — that device's ratchet
  // stops receiving, and it drops out of the fan-out target set. Any further
  // traffic from it re-handshakes through the prekey gate, where deviceAuthorized
  // rejects it (RevokedDeviceError).
  for (const [key, s] of contact.sessions) {
    if (!deviceInList(list, s.deviceSignPub)) contact.sessions.delete(key);
  }
  return true;
}

/**
 * Resolve which contact an inbound envelope's `conv` refers to, tolerant of the
 * DUAL REGIME during migration (Stage 3c). A migrated sender routes with a
 * master-based conv, a not-yet-migrated one with a device-based conv, and the
 * receiver may be in either state — so a direct `roomId === conv` match misses
 * exactly when the two sides are out of step. This also tries the OTHER regime's
 * derivation for each contact. Domain separation (computeMasterRoomId's prefix)
 * makes a hit unambiguous: a device id can never equal a master id.
 *
 * ⚠️ RESOLUTION ONLY, NEVER AUTHORISATION. Identifying the contact does not
 * authorise the envelope — receiveEnvelope re-checks the master afterwards. A
 * legacy (device-derivation) match must never become a trust decision; that
 * would be the v0.16.4 downgrade, a second weaker path an attacker would pick.
 *
 * TODO(stage-3c-cleanup): once the boot migration guarantees every contact has
 * regime==='master', the legacy branch is dead code and pure attack surface —
 * remove it. `legacy-resolve.test` goes red the moment it is no longer
 * exercised, forcing that removal to be a deliberate commit.
 */
export async function resolveContactByConv(
  contacts: Contact[],
  conv: string,
  myDhPub: Bytes,
  myMasterPub: MasterPub,
): Promise<Contact | undefined> {
  const direct = contacts.find((c) => c.roomId === conv);
  if (direct) return direct;
  for (const c of contacts) {
    if (c.regime === 'master') {
      // stored master, sender may still be on device-DH
      if ((await computeRoomId(myDhPub, c.peerDhPub)) === conv) return c;
    } else {
      // stored device (or pre-3c), sender may have migrated to master
      if ((await computeMasterRoomId(myMasterPub, asMasterPub(c.peerMasterPub))) === conv) return c;
    }
  }
  return undefined;
}

/** Our inbox room: SHA-256 of our Ed25519 identity pub. Derived from our OWN
 *  identity, so we can listen without knowing anyone else; whoever holds our
 *  code can send here. The relay verifies inbox ownership by checking this hash
 *  and an Ed25519 signature — so only we can drain our own queue. SHA-256 (not
 *  BLAKE2b) so the Worker can recompute it natively. */
export async function inboxRoom(signPub: Bytes): Promise<string> {
  const material = concatBytes(utf8.encode('scytale-inbox:'), signPub);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', material));
  let hex = '';
  for (const b of digest) hex += b.toString(16).padStart(2, '0');
  return hex;
}

/** Initiator side: we hold their code (bundle). Verify the device cert against
 *  the master BEFORE trusting any of the bundle's keys, then pin the master.
 *  `myMasterPub` (branded) anchors the master-based roomId — see computeMasterRoomId. */
export async function makeContact(myMasterPub: MasterPub, bundle: PreKeyBundle): Promise<Contact> {
  const certOk = await verifyDeviceCert(
    bundle.masterPub,
    bundle.epoch,
    bundle.identitySignPub,
    bundle.identityDhPub,
    bundle.deviceCert,
  );
  if (!certOk) throw new Error('Device-Zertifikat ungültig — Gerät nicht vom Master signiert (möglicher MITM).');
  return {
    roomId: await computeMasterRoomId(myMasterPub, asMasterPub(bundle.masterPub)),
    peerMasterPub: bundle.masterPub,
    peerEpoch: bundle.epoch,
    peerSignPub: bundle.identitySignPub,
    peerDhPub: bundle.identityDhPub,
    peerFingerprint: await identityFingerprint(bundle.masterPub, bundle.masterPub),
    ownMasterPub: myMasterPub,
    regime: 'master',
    // peerDeviceList intentionally UNSET → implicit single-device (only the
    // pinned device is allowed) until a real master-signed devlist arrives. We
    // never synthesize a list from the very device we are about to trust.
    bundle,
    sessions: new Map(),
  };
}

/**
 * Merge ONE bootstrap roster entry into my contact set (Erst-Sync). PURE &
 * transport-/storage-agnostic → Node-testable. Returns the contact to persist, or
 * null to SKIP. Hard rules baked in:
 *  - roomId + fingerprint are ALWAYS derived LOCALLY from (myMaster, entry.pm),
 *    never taken from the wire (the entry carries neither) → no attacker-steered
 *    room / mis-routing / overwrite.
 *  - NO ratchet or live bundle/session is imported. An optional peer DeviceList
 *    is decoded and master-signature/epoch/rollback verified before adoption; if
 *    absent or invalid the contact remains send-blocked. Either way no ratchet
 *    state is cloned onto the linked device.
 *  - `vf` is carried ONLY as a suggestion (verifiedSuggestion), NEVER as verified.
 *  - FILL GAPS ONLY on an existing contact — never overwrite pinned identity, keys,
 *    or verified (TOFU on this device wins).
 */
export async function mergeRosterEntry(
  contacts: Contact[],
  entry: RosterEntry,
  myMaster: MasterPub,
  retired: Set<string>,
): Promise<Contact | null> {
  // SKIP: the entry is my own self-contact, or an abandoned (denylisted) master.
  if (bytesEqual(entry.pm, myMaster)) return null;
  if (retired.has(await masterKeyB64(entry.pm))) return null;

  const derivedRoom = await computeMasterRoomId(myMaster, asMasterPub(entry.pm));

  // Collision guard: a DIFFERENT contact already occupies this locally-derived room
  // → refuse (never mis-route or overwrite). A same-pm contact shares the room (ok).
  const roomHolder = contacts.find((c) => c.roomId === derivedRoom);
  if (roomHolder && !bytesEqual(roomHolder.peerMasterPub, entry.pm)) return null;

  const existing = contacts.find((c) => bytesEqual(c.peerMasterPub, entry.pm));

  // Adopt the peer's MASTER-SIGNED device list if the entry carries one — re-verified via
  // applyDeviceListUpdate (peer-master signature + epoch + no-rollback), so it is NEVER
  // trusted blindly. This lifts the send-block: the contact gains the per-device signed
  // prekeys the device needs to INITIATE X3DH (the OTP-free path, so no prekey reuse).
  const adoptDl = async (c: Contact): Promise<Contact> => {
    if (entry.dl) {
      try {
        await applyDeviceListUpdate(c, await decodeDeviceList(entry.dl), retired);
      } catch {
        /* a corrupt/unverifiable list just leaves the contact send-blocked — no throw */
      }
    }
    return c;
  };

  if (!existing) {
    // NEW contact: metadata + (if provided) the re-verified device list → send-capable.
    const created: Contact = {
      roomId: derivedRoom,
      peerMasterPub: entry.pm,
      peerEpoch: entry.pe,
      peerSignPub: entry.psp,
      peerDhPub: entry.pdp,
      peerFingerprint: await identityFingerprint(entry.pm, entry.pm),
      nickname: entry.nick ?? undefined,
      peerName: entry.pn ?? undefined,
      verified: false,
      verifiedSuggestion: entry.vf === true || undefined,
      ownMasterPub: myMaster,
      regime: 'master',
      bundle: undefined,
      sessions: new Map(),
    };
    return adoptDl(created);
  }

  if (existing.staleIdentity) {
    // A stale contact still addresses the room under our PRE-LINK master. Lifting
    // the block without re-keying that room would be silent data loss: sends would
    // go to a room the peer resolves to the abandoned identity and discards, the
    // relay would still ack (✓ "sent"), and the explicit "reconnect" button —
    // gated on staleIdentity — would disappear. Re-keying storage is the caller's
    // job (reKeyContactInMemory), not a pure function's, so refuse here and leave
    // the door intact.
    if (existing.roomId !== derivedRoom) return null;
    // Room already matches (nothing to re-key): lift the block, refresh the device
    // keys, drop the dead old-master sessions. verified STAYS (device-local).
    existing.staleIdentity = undefined;
    existing.peerSignPub = entry.psp;
    existing.peerDhPub = entry.pdp;
    existing.peerEpoch = entry.pe;
    existing.peerFingerprint = await identityFingerprint(entry.pm, entry.pm);
    existing.sessions = new Map();
    if (existing.nickname === undefined && entry.nick) existing.nickname = entry.nick;
    if (existing.peerName === undefined && entry.pn) existing.peerName = entry.pn;
    return adoptDl(existing);
  }

  // EXISTING, non-stale: FILL GAPS ONLY. Never touch pinned identity/keys/verified.
  if (existing.nickname === undefined && entry.nick) existing.nickname = entry.nick;
  if (existing.peerName === undefined && entry.pn) existing.peerName = entry.pn;
  if (
    entry.vf === true &&
    existing.verified !== true &&
    !existing.verifiedSuggestionDismissed &&
    !existing.verifiedSuggestion
  ) {
    existing.verifiedSuggestion = true;
  }
  return adoptDl(existing);
}

/** Responder side: a stranger who holds OUR code just messaged us. Verify their
 *  device cert against their master, then TOFU-pin the master. */
export async function makeContactFromHeader(
  myMasterPub: MasterPub,
  header: InitialMessageHeader,
): Promise<Contact> {
  const certOk = await verifyDeviceCert(
    header.masterPub,
    header.epoch,
    header.identitySignPub,
    header.identityDhPub,
    header.deviceCert,
  );
  if (!certOk) throw new Error('Device-Zertifikat des Absenders ungültig (möglicher MITM).');
  return {
    roomId: await computeMasterRoomId(myMasterPub, asMasterPub(header.masterPub)),
    peerMasterPub: header.masterPub,
    peerEpoch: header.epoch,
    peerSignPub: header.identitySignPub,
    peerDhPub: header.identityDhPub,
    peerFingerprint: await identityFingerprint(header.masterPub, header.masterPub),
    ownMasterPub: myMasterPub,
    regime: 'master',
    bundle: undefined,
    sessions: new Map(),
  };
}

/**
 * PEER SIDE of the door: deliberately accept a claimed new identity for this
 * contact (explicit user action only). Re-pins the master, drops the session so
 * a fresh X3DH runs under the new identity, and clears `verified` — the safety
 * number MUST be compared again. Returns false if nothing was pending.
 */
/**
 * The "hint BEHAVES as claimed" half of the door: the user deliberately accepts
 * a claimed new identity (from an unproven previousMaster merge affordance).
 * Unlike acceptRotation (chain-proven, keeps verified), this is a TOFU break —
 * `verified` is cleared, a fresh safety-number compare is mandatory.
 *
 * Returns {oldRoomId, newRoomId, retiredMaster} so the caller can move storage
 * + maps AND add the abandoned master to the GLOBAL denylist (no longer a
 * per-contact field). Null if nothing was pending.
 */
export async function acceptMasterChange(
  contact: Contact,
): Promise<{ oldRoomId: string; newRoomId: string; retiredMaster: string } | null> {
  const p = contact.pendingMaster;
  if (!p) return null;
  if (!contact.ownMasterPub) throw new Error('Identitätswechsel ohne ownMasterPub — roomId nicht ableitbar.');
  const retiredMaster = await b64(contact.peerMasterPub); // now abandoned → global denylist
  const oldRoomId = contact.roomId;
  contact.peerMasterPub = p.masterPub;
  contact.peerEpoch = p.epoch;
  contact.peerSignPub = p.signPub;
  contact.peerDhPub = p.dhPub;
  contact.peerFingerprint = await identityFingerprint(p.masterPub, p.masterPub);
  contact.bundle = undefined; // the stored bundle belonged to the old identity
  contact.sessions.clear(); // drop ALL per-device sessions — fresh handshake under the new identity
  // The pinned device list was signed by the ABANDONED master; keeping it would
  // make deviceAuthorized() reject EVERY device of the freshly-accepted identity
  // as revoked (it is absent from the old list), and isNewerDeviceList could keep
  // a new M_new list out forever (it ignores the master swap). Drop it → implicit
  // single-device (the new primary) until an M_new-signed devlist gossip arrives.
  // Same reasoning as acceptRotation, which clears it too.
  contact.peerDeviceList = undefined;
  contact.verified = false; // TOFU break — re-verification is mandatory
  contact.pendingMaster = undefined;
  contact.roomId = await computeMasterRoomId(contact.ownMasterPub, asMasterPub(p.masterPub));
  contact.regime = 'master';
  return { oldRoomId, newRoomId: contact.roomId, retiredMaster };
}

/**
 * OUR SIDE of the door: leave the stale-identity state after a device linking
 * swap. Drops the session so the next message runs a fresh X3DH under our
 * CURRENT (linked) master and lifts the send block. The peer will see an
 * identity warning and must accept us — that is the pinning working, not a bug.
 */
export async function reconnectContact(
  contact: Contact,
  myMasterPub: MasterPub,
): Promise<{ oldRoomId: string; newRoomId: string }> {
  contact.staleIdentity = undefined;
  contact.sessions.clear(); // drop ALL per-device sessions — the next send runs a fresh X3DH
  // The stored bundle's ONE-TIME prekey was consumed by the session we are
  // resetting. Reusing it would make us derive DH1–DH4 while the peer (who no
  // longer holds that key) derives DH1–DH3 — different shared secrets, and the
  // handshake fails silently. Drop it and fall back to the standard no-OPK
  // X3DH, exactly as Signal does when a peer has no one-time prekeys left.
  if (contact.bundle?.oneTimePreKey) {
    contact.bundle = { ...contact.bundle, oneTimePreKey: undefined };
  }
  // We changed identity (device linking), so this contact now knows us under
  // our CURRENT master — update the local half of the room key and re-derive it.
  const oldRoomId = contact.roomId;
  contact.ownMasterPub = myMasterPub;
  contact.roomId = await computeMasterRoomId(myMasterPub, asMasterPub(contact.peerMasterPub));
  contact.regime = 'master';
  return { oldRoomId, newRoomId: contact.roomId };
}

/**
 * Re-derive a contact's roomId under the master-based regime (Stage 3c). PURE
 * and IDEMPOTENT: `regime` is the anchor — a contact already 'master' is
 * returned unchanged, which the crash-safe re-key routine relies on to resume a
 * half-done migration without double-applying. Needs `ownMasterPub` (the master
 * THIS contact knows us under); the boot migration fills it before calling. A
 * staleIdentity contact whose old master was never snapshotted (pre-v0.18.7)
 * has none and cannot be migrated — the caller routes it to "reconnect".
 *
 * This only computes and re-labels; moving the stored record, messages and
 * in-memory maps under the new id is the caller's crash-safe routine (it must
 * RE-ENCRYPT under the new AAD, never rename — see store.ts contactAad).
 */
export async function migrateContactRoomId(
  contact: Contact,
): Promise<{ oldRoomId: string; newRoomId: string }> {
  const oldRoomId = contact.roomId;
  if (contact.regime === 'master') return { oldRoomId, newRoomId: oldRoomId };
  if (!contact.ownMasterPub) {
    throw new Error('Migration ohne ownMasterPub — der Master, unter dem uns dieser Kontakt kennt, fehlt.');
  }
  const newRoomId = await computeMasterRoomId(contact.ownMasterPub, asMasterPub(contact.peerMasterPub));
  contact.roomId = newRoomId;
  contact.regime = 'master';
  return { oldRoomId, newRoomId };
}

/**
 * The "chain PROVES continuity" half of the door (Stage 3c): accept a
 * dual-signed master ROTATION on an existing contact. Unlike acceptMasterChange
 * (a user-confirmed TOFU break that clears `verified`), a valid rotation chain
 * is cryptographic proof that the new master succeeds the pinned one — so
 * `verified` is KEPT and the room re-keys automatically.
 *
 * ⚠️ ORDER IS SECURITY-CRITICAL (Runde-3 conditions):
 *  1. DENYLIST FIRST — a claimed master on the global retired-set is refused
 *     BEFORE any lookup or state touch. Otherwise the rotation path is a
 *     downgrade onto an abandoned key, and the denylist would guard only
 *     auto-create while the attacker takes this path.
 *  2. REJECT BEFORE ANY STATE TOUCH — an invalid chain leaves verified,
 *     peerMasterPub, peerEpoch and roomId untouched (the v0.16.0 trust-DoS, a
 *     rule that applies afresh because this path is new).
 *
 * The contact is resolved elsewhere by the CLAIMED old master; authorisation is
 * the chain's two signatures (verifyRotation), never the match.
 */
export async function acceptRotation(
  contact: Contact,
  statement: RotationStatement,
  retired: Set<string>,
): Promise<{ oldRoomId: string; newRoomId: string }> {
  if (retired.has(await b64(statement.oldMasterPub)) || retired.has(await b64(statement.newMasterPub))) {
    throw new RetiredIdentityError(true);
  }
  if (!(await verifyRotation(contact.peerMasterPub, contact.peerEpoch, statement))) {
    throw new Error('Rotations-Kette ungültig — Kontakt unverändert.');
  }
  if (!contact.ownMasterPub) {
    throw new Error('Rotation ohne ownMasterPub — roomId nicht ableitbar.');
  }
  const oldRoomId = contact.roomId;
  contact.peerMasterPub = statement.newMasterPub;
  contact.peerEpoch = statement.epoch;
  contact.bundle = undefined;
  contact.sessions.clear(); // drop ALL per-device sessions — fresh X3DH under the new master
  // The old device list was signed under the OLD master; keeping it would make
  // deviceAuthorized revoke every real device of the NEW master (RevokedDeviceError)
  // until fresh gossip. Drop it → implicit single-device until a new master-signed
  // list arrives. NOTE: this receive path is currently DORMANT — no automatic
  // producer creates a real rotation chain (the co-signed linking producer was
  // dropped after the design-lock; every rotation collapses to acceptMasterChange).
  // Full post-rotation device REACHABILITY (which device backs the new session)
  // is producer-dependent and intentionally out of scope here.
  contact.peerDeviceList = undefined;
  const newRoomId = await computeMasterRoomId(contact.ownMasterPub, asMasterPub(statement.newMasterPub));
  contact.roomId = newRoomId;
  contact.regime = 'master';
  // verified DELIBERATELY unchanged — the chain proved continuity.
  return { oldRoomId, newRoomId };
}

/** Encrypt outgoing text into a wire envelope; establishes the session if needed. */
/**
 * A group's roster, shared inside an authenticated pairwise ratchet.
 *
 * v3 identifies a PERSON by their stable master key and carries that master's
 * signed device directory. Every recipient can therefore initiate an
 * independent X3DH/Double-Ratchet session to every authorised device even when
 * the two people never saved one another as normal contacts. Optional fields
 * keep old, already-sealed v1/v2 groups importable; new writers always emit v3.
 */
export interface GroupInvite {
  v?: 1 | 4;
  id: string;
  name: string;
  revision?: number;
  createdAt?: number;
  ownerMasterPub?: string | null;
  /** Owner-master signature over the global, personalization-independent state. */
  stateSignature?: string | null;
  previousStateHash?: string | null;
  stateHash?: string | null;
  dissolved?: boolean;
  /** Complete, personalization-independent set of member master identities. */
  roster?: string[] | null;
  members: {
    masterPub?: string | null;
    epoch?: number | null;
    signPub: string;
    dhPub: string;
    bundle: string | null;
    deviceList?: string | null;
    name: string | null;
  }[];
}

/** Compact signed owner state carried to a member that is no longer in the
 * roster. It proves removal without disclosing or trusting directory overlays. */
export interface GroupStateProof {
  v: 4;
  id: string;
  name: string;
  revision: number;
  createdAt: number;
  ownerMasterPub: string;
  stateSignature: string;
  previousStateHash: string;
  stateHash: string;
  dissolved: boolean;
  roster: string[];
}

export interface BootstrapGroupTombstone {
  groupId: string;
  ownerMasterPub: Bytes;
  revision: number;
  stateHash: Bytes;
  blockReadd: boolean;
}

/** One stage of a bootstrap snapshot sent to a freshly linked OWN device (Erst-Sync). */
export type BootstrapPart =
  | { t: 'profile'; name?: string; avatar?: string } // avatar = avatarB64 (JPEG)
  | { t: 'roster'; contacts: RosterEntry[] }
  | { t: 'avatars'; avatars: BootstrapAvatar[] } // contact avatars, gap-filled on the new device
  | { t: 'groups'; groups: GroupInvite[] }
  | { t: 'gtombstones'; tombstones: BootstrapGroupTombstone[] }
  | { t: 'history'; pm: Bytes; idx: number; total: number; msgs: HistoryMessage[] }
  | { t: 'ghistory'; groupId: string; idx: number; total: number; msgs: HistoryMessage[] }
  // Closes an initial sync: only THIS part stops the receiver from re-pulling,
  // so an interrupted transfer is retried until every chunk actually arrived.
  | { t: 'done'; skipped: number };

/**
 * One past message as carried in a history chunk. The DISPLAY ROOM is never on the
 * wire — the receiver derives it from (my master, `pm`) exactly like a roster
 * entry, so a manipulated snapshot cannot file history into a foreign conversation.
 *
 * Delivery state is deliberately absent: `status`/`deliveries` describe what THIS
 * device saw of a relay hand-off and mean nothing on another device — carrying
 * them would leave permanent "pending" ticks on copies that were long delivered.
 */
/** Wire shape of one history message (short keys keep a chunk small). */
interface WireHistoryMsg {
  i?: boolean;
  t?: number;
  d?: string;
  x?: string;
  s?: string | null;
}

export interface HistoryMessage {
  mine: boolean;
  ts: number;
  mid: string;
  text: string;
  sender?: string; // group messages keep their authenticated display name
}

/**
 * A contact as carried in a bootstrap roster: METADATA ONLY. Deliberately no
 * ratchet/bundle/deviceList/roomId/ownMaster — the receiving device pins `pm` via
 * TOFU-from-P, derives roomId + fingerprint LOCALLY, and builds its OWN sessions
 * (no clone → no shared ratchet → no two-time-pad). `vf` is the sender's verified
 * flag, carried ONLY as a suggestion (never blindly adopted).
 */
export interface RosterEntry {
  pm: Bytes; // peerMasterPub
  pe: number; // peerEpoch
  psp: Bytes; // peerSignPub
  pdp: Bytes; // peerDhPub
  nick: string | null;
  pn: string | null; // peerName (learned from the peer's own profile)
  vf: boolean; // verified on the sending device
  // The peer's MASTER-SIGNED device list (encoded), if we hold one. Carrying it lets the
  // newly linked device INITIATE X3DH to the contact via the per-device signed prekeys —
  // so it isn't send-blocked. It is NOT trusted blindly: the receiver re-verifies the
  // peer-master signature + epoch (applyDeviceListUpdate) before adopting it.
  dl?: Bytes | null;
}

/**
 * A contact's avatar as carried in a bootstrap, keyed by peerMasterPub (the receiver
 * matches the contact + derives its roomId LOCALLY, exactly like a roster entry).
 * Sent in SEPARATE byte-budgeted frames from the roster, so a large avatar can never
 * bloat the single unchunked roster frame past the relay cap. Gap-filled on apply:
 * an avatar the device already learned live is never overwritten. This is my OWN
 * avatar copy of what the peer already shared with this account — no new exposure.
 */
export interface BootstrapAvatar {
  pm: Bytes; // peerMasterPub
  av: string; // avatarB64 (JPEG)
}

/** Defensive per-avatar ceiling when decoding a bootstrap avatar frame. */
export const BOOTSTRAP_AVATAR_WIRE_MAX = 128 * 1024;

/** Message payload framed into the ratchet plaintext. */
export type MessageContent =
  | { kind: 'text'; text: string }
  | { kind: 'file'; name: string; mime: string; data: Bytes; viewOnce?: boolean }
  | { kind: 'profile'; name?: string; avatar?: Bytes }
  | { kind: 'group'; groupId: string; revision?: number; stateHash?: Bytes; senderName?: string; inner: MessageContent }
  | { kind: 'ginvite'; group: GroupInvite }
  | { kind: 'gremove'; state: GroupStateProof } // signed "you were removed"
  | { kind: 'gremoveLegacy'; groupId: string; revision?: number }
  | { kind: 'gleave'; groupId: string; revision?: number; stateHash?: Bytes } // owner-coordinated leave request
  // A copy of my own outgoing group message for sibling devices. The complete
  // tailored roster lets a newly linked device install the group atomically
  // with the message. Self-gated on receive and pv>=5-gated on send.
  | { kind: 'groupsync'; group: GroupInvite; innerMid: string; ts: number; inner: MessageContent }
  | { kind: 'devlist'; list: DeviceList } // E2E gossip of my updated device list
  | { kind: 'rotation'; statement: RotationStatement } // dual-signed master rotation (proven door)
  // Self-sync (Stage 3d): a copy of a message I sent, mirrored to my OWN other
  // devices so they show it in the right conversation. Carries the TARGET peer's
  // master (the display room is computeMasterRoomId(myMaster, targetPeerMaster),
  // NOT the self-room it authenticates under), the origin, the original message's
  // mid (for dedup against the peer's own fan-out copy), the compose timestamp,
  // and the inner content. A sync frame is TERMINAL: never re-fanned, never
  // re-synced, its inner effect never re-dispatched — only appended to history.
  | { kind: 'sync'; targetPeerMaster: Bytes; origin: 'sent' | 'recv'; innerMid: string; ts: number; inner: MessageContent }
  // Erst-Sync (link initial state): `bootstrap` carries the account snapshot (profile
  // + roster now; history later) to a freshly linked OWN device; `bootreq` PULLS it
  // (N asks P after installGrant, so it can't be delivered-and-lost before N has an
  // identity); `listack` acks a peer's device list to drive reliable re-gossip.
  // bootstrap + bootreq are self-gated (peerMaster == my master) and TERMINAL;
  // listack is NOT self-gated (an ack over MY list is legitimate from any peer).
  | { kind: 'bootstrap'; bid: string; parts: BootstrapPart[] }
  | { kind: 'listack'; epoch: number; version: number }
  | { kind: 'bootreq'; requestId: string }
  // A reply carries a self-contained QUOTE of the message it answers plus the
  // actual content as `inner` (text or file). Wraps like `group`/`sync`.
  | { kind: 'reply'; quote: Quote; inner: MessageContent }
  // One piece of a large attachment sent out-of-band of the inline path. Every chunk
  // carries the full transfer descriptor (tid/total/size/name/mime) so it is
  // self-describing and order-independent. Gated on the peer device's pv (>= 2): a
  // stale device is never sent a byte-14 frame, which it would throw on and lose.
  | { kind: 'chunk'; tid: string; idx: number; total: number; size: number; name: string; mime: string; data: Bytes; viewOnce?: boolean }
  // Recall ("unsend"): retract a previously-sent message, referenced by its E2E mid.
  // Cooperative — the recipient's client tombstones its copy; no guarantee (SECURITY.md).
  | { kind: 'recall'; targetMid: string }
  // Large-attachment OFFER (hybrid path, > auto-push cap): announce a file the peer can
  // pull on demand. No data — just the descriptor; the recipient sees a download
  // affordance and requests it deliberately (attreq → chunk stream).
  | { kind: 'attoffer'; tid: string; name: string; mime: string; size: number; total: number }
  // A LARGE attachment stored encrypted in R2 (videos up to ~1 GB). Carries the R2 object
  // key + the per-file key (keyB64) end-to-end; the recipient downloads the ciphertext and
  // decrypts. `chunk` is the plaintext chunk size the blob was sealed with. See crypto/blob.ts.
  | { kind: 'r2'; key: string; keyB64: string; name: string; mime: string; size: number; chunk: number; viewOnce?: boolean }
  // A linked device asking its PRIMARY to unlink (revoke) it — sent over the self-contact
  // just before the device wipes itself. Payload-free; the sender device is read off the
  // authenticated envelope, so it can't be forged to revoke a different device.
  | { kind: 'unlinkreq' }
  // PULL request for an offered attachment. The sender streams its chunks in reply —
  // but only for a tid it actually offered to THIS contact (amplification guard).
  | { kind: 'attreq'; tid: string };

/** A decrypted inbound message plus its sender-stamped E2E dedup id. */
/**
 * A successfully authenticated ratchet message either carries an application
 * frame we may dispatch, or is an authenticated drop. The latter is deliberately
 * a normal result rather than an exception: the caller must still durably commit
 * the advanced ratchet and (for a first X3DH message) the OPK removal before
 * acknowledging and discarding an invalid/unauthorised frame.
 */
export type ReceivedMessage =
  | {
      outcome: 'message';
      mid: string;
      content: MessageContent;
      /**
       * Present only after an OPK-backed X3DH header and the first message AEAD
       * authenticated. The storage boundary must atomically persist this OPK
       * removal together with the newly committed contact session.
       */
      authenticatedOneTimePreKeyId?: number;
    }
  | {
      outcome: 'authenticated-drop';
      reason: 'invalid-frame' | 'unauthorised-self-frame';
      /** Available when the authenticated plaintext contained a complete mid. */
      mid?: string;
      authenticatedOneTimePreKeyId?: number;
    };

// ── E2E message id (Stage 3d dedup) ─────────────────────────────────────
// A random 16-byte id the SENDER stamps into the AEAD-protected plaintext, the
// SAME across every fan-out copy and every self-sync copy of one message. On
// receipt it dedups a message that arrives via more than one path (direct fan-out
// + a self-sync copy from another of my devices + a re-delivery). It MUST be
// authenticated (inside the ratchet AEAD): an attacker who could forge a colliding
// mid on an injected message would suppress a real future message (self-censorship)
// — so it is NOT the relay-chosen ackId and NOT an outer envelope field.
const MID_LEN = 16;
export function randomMid(): string {
  const b = crypto.getRandomValues(new Uint8Array(MID_LEN));
  let h = '';
  for (const x of b) h += x.toString(16).padStart(2, '0');
  return h;
}
function midToBytes(mid: string): Bytes {
  const b = new Uint8Array(MID_LEN);
  for (let i = 0; i < MID_LEN; i++) b[i] = parseInt(mid.slice(i * 2, i * 2 + 2), 16);
  return b;
}
function bytesToMid(b: Bytes): string {
  let h = '';
  for (const x of b) h += x.toString(16).padStart(2, '0');
  return h;
}

function prefixed(type: number, body: Uint8Array): Bytes {
  const out = new Uint8Array(1 + body.length);
  out[0] = type;
  out.set(body, 1);
  return out;
}

// Frame: byte0 = 0 (text) | 1 (file) | 2 (profile).
//   file:    [nameLen(2)][name][mimeLen(2)][mime][data]
//   profile: [nameLen(2)][name][avatarLen(4)][avatar]
export async function frameContent(c: MessageContent): Promise<Bytes> {
  if (c.kind === 'text') {
    const t = utf8.encode(c.text);
    const out = new Uint8Array(1 + t.length);
    out[0] = 0;
    out.set(t, 1);
    return out;
  }
  if (c.kind === 'file') {
    const name = utf8.encode(c.name);
    const mime = utf8.encode(c.mime);
    const out = new Uint8Array(1 + 2 + name.length + 2 + mime.length + c.data.length);
    const dv = new DataView(out.buffer);
    let o = 0;
    // Byte 18 = a view-once file: same payload as a normal file (byte 1), but the tag
    // tells the recipient to treat it as single-view + self-destruct. Old clients that
    // don't know byte 18 simply drop it, so a view-once photo only lands on a peer new
    // enough to honour the semantics — a normal file (byte 1) stays fully compatible.
    out[o++] = c.viewOnce ? 18 : 1;
    dv.setUint16(o, name.length);
    o += 2;
    out.set(name, o);
    o += name.length;
    dv.setUint16(o, mime.length);
    o += 2;
    out.set(mime, o);
    o += mime.length;
    out.set(c.data, o);
    return out;
  }
  if (c.kind === 'profile') {
    const name = utf8.encode(c.name ?? '');
    const avatar = c.avatar ?? new Uint8Array(0);
    const out = new Uint8Array(1 + 2 + name.length + 4 + avatar.length);
    const dv = new DataView(out.buffer);
    let o = 0;
    out[o++] = 2;
    dv.setUint16(o, name.length);
    o += 2;
    out.set(name, o);
    o += name.length;
    dv.setUint32(o, avatar.length);
    o += 4;
    out.set(avatar, o);
    return out;
  }
  if (c.kind === 'group') {
    const json = JSON.stringify({
      g: c.groupId,
      r: c.revision ?? null,
      h: c.stateHash ? bytesToB64(c.stateHash) : null,
      s: c.senderName ?? '',
      i: bytesToB64(await frameContent(c.inner)),
    });
    return prefixed(3, utf8.encode(json));
  }
  if (c.kind === 'gremove') {
    return prefixed(5, utf8.encode(JSON.stringify(c.state)));
  }
  if (c.kind === 'gremoveLegacy') {
    return prefixed(5, utf8.encode(c.groupId));
  }
  if (c.kind === 'gleave') {
    return prefixed(
      6,
      utf8.encode(
        JSON.stringify({
          g: c.groupId,
          r: c.revision ?? null,
          h: c.stateHash ? bytesToB64(c.stateHash) : null,
        }),
      ),
    );
  }
  if (c.kind === 'devlist') return prefixed(7, await encodeDeviceList(c.list));
  if (c.kind === 'rotation') return prefixed(8, encodeRotation(c.statement));
  if (c.kind === 'sync') {
    const json = JSON.stringify({
      m: bytesToB64(c.targetPeerMaster),
      o: c.origin,
      id: c.innerMid,
      t: c.ts,
      i: bytesToB64(await frameContent(c.inner)),
    });
    return prefixed(9, utf8.encode(json));
  }
  if (c.kind === 'bootstrap') {
    const parts = c.parts.map((p) =>
      p.t === 'profile'
        ? { t: 'profile', n: p.name ?? '', a: p.avatar ?? '' }
        : p.t === 'history'
          ? {
              t: 'history',
              m: bytesToB64(p.pm),
              n: p.idx,
              o: p.total,
              h: p.msgs.map((x) => ({ i: x.mine, t: x.ts, d: x.mid, x: x.text, s: x.sender ?? null })),
            }
          : p.t === 'ghistory'
            ? {
                t: 'ghistory',
                g: p.groupId,
                n: p.idx,
                o: p.total,
                h: p.msgs.map((x) => ({ i: x.mine, t: x.ts, d: x.mid, x: x.text, s: x.sender ?? null })),
              }
          : p.t === 'groups'
            ? { t: 'groups', g: p.groups }
          : p.t === 'gtombstones'
            ? {
                t: 'gtombstones',
                z: p.tombstones.map((tombstone) => ({
                  g: tombstone.groupId,
                  o: bytesToB64(tombstone.ownerMasterPub),
                  r: tombstone.revision,
                  h: bytesToB64(tombstone.stateHash),
                  b: tombstone.blockReadd,
                })),
              }
          : p.t === 'done'
            ? { t: 'done', k: p.skipped }
          : p.t === 'avatars'
            ? {
                t: 'avatars',
                a: p.avatars.map((x) => ({ m: bytesToB64(x.pm), v: x.av })),
              }
          : {
            t: 'roster',
            c: p.contacts.map((e) => ({
              m: bytesToB64(e.pm),
              e: e.pe,
              s: bytesToB64(e.psp),
              d: bytesToB64(e.pdp),
              nk: e.nick,
              pn: e.pn,
              vf: e.vf,
              dl: e.dl ? bytesToB64(e.dl) : null,
            })),
          },
    );
    return prefixed(10, utf8.encode(JSON.stringify({ v: 1, bid: c.bid, parts })));
  }
  if (c.kind === 'listack') return prefixed(11, utf8.encode(JSON.stringify({ e: c.epoch, v: c.version })));
  if (c.kind === 'bootreq') return prefixed(12, utf8.encode(JSON.stringify({ q: c.requestId })));
  if (c.kind === 'reply') {
    return prefixed(13, utf8.encode(JSON.stringify({ q: c.quote, i: bytesToB64(await frameContent(c.inner)) })));
  }
  if (c.kind === 'chunk') {
    // [14][headerLen u32][header JSON][raw data]: JSON for the tiny descriptor, raw
    // bytes for the payload so the bulk isn't base64-inflated on the wire.
    const header = utf8.encode(
      JSON.stringify({ t: c.tid, i: c.idx, n: c.total, s: c.size, nm: c.name, m: c.mime, vo: c.viewOnce ? 1 : undefined }),
    );
    const out = new Uint8Array(1 + 4 + header.length + c.data.length);
    new DataView(out.buffer).setUint32(1, header.length);
    out[0] = 14;
    out.set(header, 5);
    out.set(c.data, 5 + header.length);
    return out;
  }
  if (c.kind === 'recall') return prefixed(15, utf8.encode(JSON.stringify({ m: c.targetMid })));
  if (c.kind === 'attoffer') {
    return prefixed(16, utf8.encode(JSON.stringify({ t: c.tid, n: c.name, m: c.mime, s: c.size, o: c.total })));
  }
  if (c.kind === 'attreq') return prefixed(17, utf8.encode(JSON.stringify({ t: c.tid })));
  if (c.kind === 'unlinkreq') return prefixed(20, new Uint8Array(0));
  if (c.kind === 'groupsync') {
    return prefixed(
      21,
      utf8.encode(
        JSON.stringify({
          g: c.group,
          id: c.innerMid,
          t: c.ts,
          i: bytesToB64(await frameContent(c.inner)),
        }),
      ),
    );
  }
  if (c.kind === 'r2')
    return prefixed(
      19,
      utf8.encode(JSON.stringify({ k: c.key, kf: c.keyB64, n: c.name, m: c.mime, s: c.size, c: c.chunk, vo: c.viewOnce ? 1 : undefined })),
    );
  // ginvite
  return prefixed(4, utf8.encode(JSON.stringify(c.group)));
}

export async function unframeContent(bytes: Bytes): Promise<MessageContent> {
  if (bytes[0] === 0) return { kind: 'text', text: utf8.decode(bytes.slice(1)) };
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

  if (bytes[0] === 2) {
    let o = 1;
    const nameLen = dv.getUint16(o);
    o += 2;
    const name = utf8.decode(bytes.slice(o, o + nameLen));
    o += nameLen;
    const avLen = dv.getUint32(o);
    o += 4;
    return { kind: 'profile', name: name || undefined, avatar: avLen > 0 ? bytes.slice(o, o + avLen) : undefined };
  }
  if (bytes[0] === 3) {
    const j = JSON.parse(utf8.decode(bytes.slice(1)));
    return {
      kind: 'group',
      groupId: j.g,
      revision: Number.isSafeInteger(j.r) && j.r >= 0 ? Number(j.r) : undefined,
      stateHash: typeof j.h === 'string' ? b64ToBytes(j.h) : undefined,
      senderName: j.s || undefined,
      inner: await unframeContent(b64ToBytes(j.i)),
    };
  }
  if (bytes[0] === 4) {
    return { kind: 'ginvite', group: JSON.parse(utf8.decode(bytes.slice(1))) as GroupInvite };
  }
  if (bytes[0] === 5) {
    const raw = utf8.decode(bytes.slice(1));
    if (!raw.startsWith('{')) {
      return { kind: 'gremoveLegacy', groupId: raw };
    }
    const parsed = JSON.parse(raw) as GroupStateProof & {
      g?: unknown;
      r?: unknown;
    };
    if (parsed.v !== 4) {
      return {
        kind: 'gremoveLegacy',
        groupId: String(parsed.g),
        revision:
          Number.isSafeInteger(parsed.r) && Number(parsed.r) >= 0
            ? Number(parsed.r)
            : undefined,
      };
    }
    return {
      kind: 'gremove',
      state: parsed,
    };
  }
  if (bytes[0] === 6) {
    const raw = utf8.decode(bytes.slice(1));
    let groupId = raw;
    let revision: number | undefined;
    let stateHash: Bytes | undefined;
    if (raw.startsWith('{')) {
      const parsed = JSON.parse(raw) as { g?: unknown; r?: unknown; h?: unknown };
      groupId = String(parsed.g);
      revision =
        Number.isSafeInteger(parsed.r) && Number(parsed.r) >= 0
          ? Number(parsed.r)
          : undefined;
      stateHash =
        typeof parsed.h === 'string' ? b64ToBytes(parsed.h) : undefined;
    }
    return { kind: 'gleave', groupId, revision, stateHash };
  }
  if (bytes[0] === 7) return { kind: 'devlist', list: await decodeDeviceList(bytes.slice(1)) };
  if (bytes[0] === 8) return { kind: 'rotation', statement: decodeRotation(bytes.slice(1)) };
  if (bytes[0] === 9) {
    const j = JSON.parse(utf8.decode(bytes.slice(1)));
    return {
      kind: 'sync',
      targetPeerMaster: b64ToBytes(j.m),
      origin: j.o === 'recv' ? 'recv' : 'sent',
      innerMid: String(j.id),
      ts: Number(j.t),
      inner: await unframeContent(b64ToBytes(j.i)),
    };
  }

  if (bytes[0] === 10) {
    // JSON.parse on a PRESENT byte-10 frame throws on corruption → the frame is
    // dropped, never silently imported as empty. An unknown part.t is SKIPPED
    // (forward-compat: a future history part must not break profile+roster).
    const j = JSON.parse(utf8.decode(bytes.slice(1)));
    const parts: BootstrapPart[] = [];
    for (const p of Array.isArray(j.parts) ? j.parts : []) {
      if (p.t === 'profile') parts.push({ t: 'profile', name: p.n || undefined, avatar: p.a || undefined });
      else if (p.t === 'history') {
        const rawH: WireHistoryMsg[] = Array.isArray(p.h) ? p.h : [];
        // Harden: a non-finite ts would make the sort implementation-defined, and a
        // missing mid would collapse every such message onto ONE dedup slot.
        const msgs: HistoryMessage[] = rawH
          .filter((x) => typeof x.d === 'string' && x.d.length > 0 && Number.isFinite(Number(x.t)))
          .map((x) => ({
            mine: x.i === true,
            ts: Number(x.t),
            mid: String(x.d),
            text: String(x.x ?? ''),
            sender: x.s ?? undefined,
          }));
        parts.push({ t: 'history', pm: b64ToBytes(p.m), idx: Number(p.n) || 0, total: Number(p.o) || 0, msgs });
      } else if (p.t === 'ghistory') {
        const rawH: WireHistoryMsg[] = Array.isArray(p.h) ? p.h : [];
        const msgs: HistoryMessage[] = rawH
          .filter((x) => typeof x.d === 'string' && x.d.length > 0 && Number.isFinite(Number(x.t)))
          .map((x) => ({
            mine: x.i === true,
            ts: Number(x.t),
            mid: String(x.d),
            text: String(x.x ?? ''),
            sender: x.s ?? undefined,
          }));
        parts.push({
          t: 'ghistory',
          groupId: String(p.g),
          idx: Number(p.n) || 0,
          total: Number(p.o) || 0,
          msgs,
        });
      } else if (p.t === 'groups' && Array.isArray(p.g)) {
        parts.push({ t: 'groups', groups: p.g as GroupInvite[] });
      } else if (p.t === 'gtombstones' && Array.isArray(p.z)) {
        if (p.z.length > 64) {
          throw new Error('Zu viele Gruppen-Tombstones in einem Bootstrap-Frame.');
        }
        const tombstones: BootstrapGroupTombstone[] = [];
        for (const raw of p.z) {
          const ownerMasterPub = b64ToBytes(raw.o);
          const stateHash = b64ToBytes(raw.h);
          if (
            typeof raw.g !== 'string' ||
            !/^grp_[0-9a-f]{32}$/.test(raw.g) ||
            ownerMasterPub.length !== 32 ||
            !Number.isSafeInteger(raw.r) ||
            Number(raw.r) < 1 ||
            stateHash.length !== 32 ||
            typeof raw.b !== 'boolean'
          ) {
            throw new Error('Ungültiger Gruppen-Tombstone im Bootstrap.');
          }
          tombstones.push({
            groupId: raw.g,
            ownerMasterPub,
            revision: Number(raw.r),
            stateHash,
            blockReadd: raw.b,
          });
        }
        parts.push({ t: 'gtombstones', tombstones });
      } else if (p.t === 'done') {
        parts.push({ t: 'done', skipped: Number(p.k) || 0 });
      } else if (p.t === 'avatars' && Array.isArray(p.a)) {
        // peerMasterPub-keyed; the receiver matches the contact locally. Per-avatar
        // size is bounded so a manipulated snapshot can't inflate one frame; an
        // oversized or malformed entry is dropped, never imported empty.
        const avatars: BootstrapAvatar[] = [];
        for (const raw of p.a) {
          if (!raw || typeof raw.v !== 'string' || !raw.v || raw.v.length > BOOTSTRAP_AVATAR_WIRE_MAX) continue;
          const pm = b64ToBytes(raw.m);
          if (pm.length !== 32) continue;
          avatars.push({ pm, av: raw.v });
        }
        parts.push({ t: 'avatars', avatars });
      } else if (p.t === 'roster') {
        const rawContacts = (Array.isArray(p.c) ? p.c : []) as Array<{
          m: string;
          e: number;
          s: string;
          d: string;
          nk: string | null;
          pn: string | null;
          vf: boolean;
          dl?: string | null;
        }>;
        const contacts: RosterEntry[] = rawContacts.map((e) => ({
          pm: b64ToBytes(e.m),
          pe: Number(e.e),
          psp: b64ToBytes(e.s),
          pdp: b64ToBytes(e.d),
          nick: e.nk ?? null,
          pn: e.pn ?? null,
          vf: e.vf === true,
          dl: e.dl ? b64ToBytes(e.dl) : null,
        }));
        parts.push({ t: 'roster', contacts });
      }
    }
    return { kind: 'bootstrap', bid: String(j.bid), parts };
  }
  if (bytes[0] === 11) {
    const j = JSON.parse(utf8.decode(bytes.slice(1)));
    return { kind: 'listack', epoch: Number(j.e), version: Number(j.v) };
  }
  if (bytes[0] === 12) {
    const j = JSON.parse(utf8.decode(bytes.slice(1)));
    return { kind: 'bootreq', requestId: String(j.q) };
  }

  // Only type 1 is a real file. Anything else is a corrupt/unknown frame — throw
  // so it's dropped, never rendered as a junk "file" in the chat (e.g. a mangled
  // profile update must not surface as a downloadable attachment).
  if (bytes[0] === 13) {
    const j = JSON.parse(utf8.decode(bytes.slice(1)));
    // The quote is attacker-controlled and only a POINTER (mid) plus a fallback preview:
    // the receiver rebinds text/author/perspective from its own stored original at render
    // (audit LBB-09). Still bound the fields on decode so a hostile frame can't bloat storage.
    const rq = (j.q && typeof j.q === 'object' ? j.q : {}) as Record<string, unknown>;
    const quote: Quote = {
      mid: typeof rq.mid === 'string' ? rq.mid.slice(0, 128) : '',
      text: typeof rq.text === 'string' ? rq.text.slice(0, 280) : '',
      sender: typeof rq.sender === 'string' ? rq.sender.slice(0, 128) : undefined,
      mine: rq.mine === true,
    };
    return { kind: 'reply', quote, inner: await unframeContent(b64ToBytes(j.i)) };
  }
  if (bytes[0] === 14) {
    const hlen = dv.getUint32(1);
    const j = JSON.parse(utf8.decode(bytes.slice(5, 5 + hlen)));
    return {
      kind: 'chunk',
      tid: String(j.t),
      idx: Number(j.i),
      total: Number(j.n),
      size: Number(j.s),
      name: String(j.nm),
      mime: String(j.m),
      data: bytes.slice(5 + hlen),
      viewOnce: j.vo === 1 || undefined,
    };
  }

  if (bytes[0] === 15) {
    const j = JSON.parse(utf8.decode(bytes.slice(1)));
    // A real MID is exactly the sender-generated 128-bit lowercase hex value.
    // Reject before the UI/storage layer: otherwise an authenticated peer could
    // persist arbitrarily long or endlessly varied tombstone identifiers.
    if (typeof j.m !== 'string' || !/^[a-f0-9]{32}$/.test(j.m)) {
      throw new Error('Ungültige Recall-Nachrichten-ID.');
    }
    return { kind: 'recall', targetMid: j.m };
  }
  if (bytes[0] === 16) {
    const j = JSON.parse(utf8.decode(bytes.slice(1)));
    return { kind: 'attoffer', tid: String(j.t), name: String(j.n), mime: String(j.m), size: Number(j.s), total: Number(j.o) };
  }
  if (bytes[0] === 17) {
    const j = JSON.parse(utf8.decode(bytes.slice(1)));
    return { kind: 'attreq', tid: String(j.t) };
  }
  if (bytes[0] === 20) return { kind: 'unlinkreq' };
  if (bytes[0] === 21) {
    const j = JSON.parse(utf8.decode(bytes.slice(1)));
    return {
      kind: 'groupsync',
      group: j.g as GroupInvite,
      innerMid: String(j.id),
      ts: Number(j.t),
      inner: await unframeContent(b64ToBytes(j.i)),
    };
  }
  if (bytes[0] === 19) {
    const j = JSON.parse(utf8.decode(bytes.slice(1)));
    return {
      kind: 'r2',
      key: String(j.k),
      keyB64: String(j.kf),
      name: String(j.n),
      mime: String(j.m),
      size: Number(j.s),
      chunk: Number(j.c),
      viewOnce: j.vo === 1 || undefined,
    };
  }

  if (bytes[0] !== 1 && bytes[0] !== 18) throw new Error('Unbekannter Frame-Typ: ' + bytes[0]);

  let o = 1;
  const nameLen = dv.getUint16(o);
  o += 2;
  const name = utf8.decode(bytes.slice(o, o + nameLen));
  o += nameLen;
  const mimeLen = dv.getUint16(o);
  o += 2;
  const mime = utf8.decode(bytes.slice(o, o + mimeLen));
  o += mimeLen;
  return { kind: 'file', name, mime, data: bytes.slice(o), viewOnce: bytes[0] === 18 || undefined };
}

interface DeviceTarget {
  signPub: Bytes;
  dhPub: Bytes;
  bundle?: PreKeyBundle; // needed only to INITIATE (no session yet)
}

/** Encrypt `content` for ONE peer device, establishing its session if needed, and
 *  seal it to that device. Invariant I holds per session (each device its own
 *  ratchet). Throws if no session exists AND no bundle is available to initiate. */
async function encryptForDevice(
  me: IdentityKeys,
  contact: Contact,
  target: DeviceTarget,
  content: MessageContent,
  mid: string,
  senderDeviceList?: DeviceList,
): Promise<Bytes> {
  const key = deviceKey(target.signPub);
  let session = contact.sessions.get(key);
  if (!session?.ratchet) {
    if (!target.bundle) throw new Error('Kein Code/Prekey zum Initiieren an dieses Gerät.');
    const { header, session: x3dh } = await initiateX3DH(
      me,
      target.bundle,
      senderDeviceList,
    );
    const ratchet = await initRatchetInitiator(x3dh.sharedSecret, target.bundle.signedPreKey.pub, x3dh.associatedData);
    session = { ratchet, pendingHeader: header, deviceSignPub: target.signPub };
    contact.sessions.set(key, session);
  }
  // Stamp the E2E mid into the AEAD plaintext: mid(16) ‖ frameContent(content).
  const message = await ratchetEncrypt(session.ratchet!, concatBytes(midToBytes(mid), await frameContent(content)));
  const conv = contact.roomId;
  // `dev` (our device) lets the recipient route a 'msg' to the right per-sender-
  // device session when WE have several devices; a prekey carries it in the x3dh.
  const envelope = session.pendingHeader
    ? ({
        type: 'prekey',
        conv,
        x3dh: senderDeviceList
          ? { ...session.pendingHeader, senderDeviceList }
          : session.pendingHeader,
        message,
        pv: PROTOCOL_VERSION,
      } as const)
    : ({ type: 'msg', conv, message, dev: me.sign.publicKey, pv: PROTOCOL_VERSION } as const);
  // Sealed Sender: wrap the whole envelope in an anonymous box to the recipient,
  // so the relay never sees the sender's X3DH identity keys or the conv id.
  return sealPayload(target.dhPub, SEALED_ENVELOPE, await encodeEnvelope(envelope));
}

async function sendContent(me: IdentityKeys, contact: Contact, content: MessageContent, mid: string = randomMid()): Promise<Bytes> {
  // Enforced HERE, not in the UI: after a device-linking identity swap the peer
  // still has our OLD master pinned, so any message over the surviving session
  // would assert an identity we no longer hold — a false authenticity claim.
  if (contact.staleIdentity) throw new StaleIdentityError();
  // Single primary/pinned device. fanoutDeliveries covers every authorised device.
  return encryptForDevice(
    me,
    contact,
    { signPub: contact.peerSignPub, dhPub: contact.peerDhPub, bundle: contact.bundle },
    content,
    mid,
  );
}

/** One sealed copy of a message for one peer device, plus which device it's for. */
export interface FanoutDelivery {
  deviceSignPub: Bytes; // target inbox = inboxRoom(deviceSignPub)
  sealed: Bytes;
}

/** Encrypt `content` for EVERY authorised device of the peer — Stage 3d fan-out.
 *  The SAME `mid` is shared across all copies so the peer's devices dedup. A device
 *  we can't initiate to (no session AND no signed prekey in the list) is skipped
 *  and returned in `unreachable`, so the caller can mark that delivery "no longer
 *  valid" rather than failed. Each device is a separate session — Invariant I per
 *  session — and a per-device throw isolates that device (does not drop the rest). */
export async function fanoutDeliveries(
  me: IdentityKeys,
  contact: Contact,
  content: MessageContent,
  mid: string,
  exclude?: Bytes,
  only?: Bytes,
  minPv = 0,
  senderDeviceList?: DeviceList,
): Promise<{ deliveries: FanoutDelivery[]; unreachable: Bytes[] }> {
  if (contact.staleIdentity) throw new StaleIdentityError();
  const deliveries: FanoutDelivery[] = [];
  const unreachable: Bytes[] = [];
  for (const t of authorisedTargets(contact, exclude, only)) {
    // Protocol gate: never send a device a frame its version can't parse (it would
    // throw-and-drop it, silently). A below-version device is `unreachable`, not sent.
    if (minPv > 0 && deviceProtocolVersion(contact, t.signPub) < minPv) {
      unreachable.push(t.signPub);
      continue;
    }
    try {
      deliveries.push({
        deviceSignPub: t.signPub,
        sealed: await encryptForDevice(
          me,
          contact,
          t,
          content,
          mid,
          senderDeviceList,
        ),
      });
    } catch {
      unreachable.push(t.signPub); // no session + no bundle → can't reach this device yet
    }
  }
  return { deliveries, unreachable };
}

/** Every authorised peer device to send to (with the bundle needed to initiate). A
 *  bare contact (no accepted device list) is its single pinned device. */
function authorisedTargets(contact: Contact, exclude?: Bytes, only?: Bytes): DeviceTarget[] {
  return (
    contact.peerDeviceList
      ? contact.peerDeviceList.devices.map((d) => ({
          signPub: d.signPub,
          dhPub: d.dhPub,
          // Prefer our stored bundle for the primary (it may still hold a one-time
          // prekey → better forward secrecy); a silent device uses its list SPK.
          bundle:
            bytesEqual(d.signPub, contact.peerSignPub) && contact.bundle
              ? contact.bundle
              : (bundleFromDeviceEntry(contact.peerMasterPub, contact.peerEpoch, d) ?? undefined),
        }))
      : [{ signPub: contact.peerSignPub, dhPub: contact.peerDhPub, bundle: contact.bundle }]
  )
    .filter((t) => !exclude || !bytesEqual(t.signPub, exclude)) // self-sync: never send to my own device
    .filter((t) => !only || bytesEqual(t.signPub, only)); // bootstrap reply: target exactly ONE device
}

/** One device's ordered, sealed chunk stream for a large attachment. */
export interface FanoutChunkDelivery {
  deviceSignPub: Bytes;
  sealed: Bytes[]; // one sealed 'chunk' frame per index, in order
}

/**
 * Encrypt a large attachment as an ordered stream of `chunk` frames, fanned out to
 * every authorised device that advertises it can RECEIVE chunks (`pv >= minPv`). Each
 * chunk is its own ratchet message (its own per-message mid); a device's ratchet
 * advances once per chunk.
 *
 * INVARIANT II is the CALLER's contract: persist the contact (the advanced ratchet
 * state) BEFORE putting any sealed frame on the wire — otherwise a crash mid-send
 * could replay a chain key already on the wire = two-time pad.
 *
 * A device below the pv gate goes in `incapable` (we never send it a byte-14 frame it
 * would throw on and lose); one we can't initiate to goes in `unreachable`. Holds
 * every sealed frame in memory — sized for the auto-push cap; large files stream via
 * offer+pull instead.
 */
export async function fanoutChunks(
  me: IdentityKeys,
  contact: Contact,
  desc: { tid: string; total: number; size: number; name: string; mime: string; viewOnce?: boolean },
  data: Bytes,
  chunkBytes: number,
  minPv = 2,
  senderDeviceList?: DeviceList,
): Promise<{ perDevice: FanoutChunkDelivery[]; incapable: Bytes[]; unreachable: Bytes[] }> {
  if (contact.staleIdentity) throw new StaleIdentityError();
  const perDevice: FanoutChunkDelivery[] = [];
  const incapable: Bytes[] = [];
  const unreachable: Bytes[] = [];
  for (const t of authorisedTargets(contact)) {
    if (deviceProtocolVersion(contact, t.signPub) < minPv) {
      incapable.push(t.signPub); // stale/unknown receiver — must not be sent chunk frames
      continue;
    }
    try {
      const sealed: Bytes[] = [];
      for (let idx = 0; idx < desc.total; idx++) {
        const chunk: MessageContent = {
          kind: 'chunk',
          tid: desc.tid,
          idx,
          total: desc.total,
          size: desc.size,
          name: desc.name,
          mime: desc.mime,
          data: data.slice(idx * chunkBytes, (idx + 1) * chunkBytes),
          viewOnce: desc.viewOnce,
        };
        sealed.push(await encryptForDevice(
          me,
          contact,
          t,
          chunk,
          randomMid(),
          senderDeviceList,
        ));
      }
      perDevice.push({ deviceSignPub: t.signPub, sealed });
    } catch {
      unreachable.push(t.signPub); // can't initiate to this device yet
    }
  }
  return { perDevice, incapable, unreachable };
}

export async function sendMessage(me: IdentityKeys, contact: Contact, text: string, mid?: string): Promise<Bytes> {
  return sendContent(me, contact, { kind: 'text', text }, mid);
}

export async function sendFile(
  me: IdentityKeys,
  contact: Contact,
  name: string,
  mime: string,
  data: Bytes,
  mid?: string,
): Promise<Bytes> {
  return sendContent(me, contact, { kind: 'file', name, mime, data }, mid);
}

export async function sendProfile(
  me: IdentityKeys,
  contact: Contact,
  name: string | undefined,
  avatar: Bytes | undefined,
): Promise<Bytes> {
  return sendContent(me, contact, { kind: 'profile', name, avatar });
}

export async function sendGroupMessage(
  me: IdentityKeys,
  contact: Contact,
  groupId: string,
  senderName: string | undefined,
  inner: MessageContent,
  revision?: number,
  stateHash?: Bytes,
): Promise<Bytes> {
  return sendContent(me, contact, {
    kind: 'group',
    groupId,
    revision,
    stateHash,
    senderName,
    inner,
  });
}

export async function sendGroupInvite(me: IdentityKeys, contact: Contact, group: GroupInvite): Promise<Bytes> {
  return sendContent(me, contact, { kind: 'ginvite', group });
}

export async function sendGroupRemove(
  me: IdentityKeys,
  contact: Contact,
  state: GroupStateProof,
): Promise<Bytes> {
  return sendContent(me, contact, { kind: 'gremove', state });
}

export async function sendGroupLeave(
  me: IdentityKeys,
  contact: Contact,
  groupId: string,
  revision?: number,
  stateHash?: Bytes,
): Promise<Bytes> {
  return sendContent(me, contact, {
    kind: 'gleave',
    groupId,
    revision,
    stateHash,
  });
}

/** Gossip our updated, master-signed device list to a contact (revocation). */
export async function sendDeviceList(me: IdentityKeys, contact: Contact, list: DeviceList): Promise<Bytes> {
  return sendContent(me, contact, { kind: 'devlist', list });
}

/** Acknowledge the (epoch, version) of a peer's device list we now hold. The
 *  sender keeps re-offering its list until this ack catches up, which is what
 *  makes a newly linked device reliably reachable for peers that were offline
 *  when it was added. Carries no state a peer could abuse — it only ever moves
 *  the sender's per-contact watermark forward. */
export async function sendListAck(
  me: IdentityKeys,
  contact: Contact,
  epoch: number,
  version: number,
): Promise<Bytes> {
  return sendContent(me, contact, { kind: 'listack', epoch, version });
}

/** Gossip a dual-signed master rotation to a contact that still pins our OLD
 *  master. Unlike the unproven previousMaster hint, this PROVES continuity, so
 *  the receiver's acceptRotation keeps `verified`. The producer (a co-signed
 *  chain from device linking) is separate; this is the transport. */
export async function sendRotation(me: IdentityKeys, contact: Contact, statement: RotationStatement): Promise<Bytes> {
  return sendContent(me, contact, { kind: 'rotation', statement });
}

/** Decrypt an incoming envelope; establishes the responder session on first contact. */
export async function receiveMessage(
  me: IdentityKeys,
  contact: Contact,
  bytes: Bytes,
  lookup: PreKeyLookup,
): Promise<ReceivedMessage> {
  const opened = await openPayload(me, bytes);
  if (!opened || opened.type !== SEALED_ENVELOPE) {
    throw new Error('Kein Nachrichten-Envelope (falscher Nutzlast-Typ).');
  }
  return receiveEnvelope(me, contact, await decodeEnvelope(opened.payload), lookup);
}

export async function receiveEnvelope(
  me: IdentityKeys,
  contact: Contact,
  envelope: Envelope,
  lookup: PreKeyLookup,
): Promise<ReceivedMessage> {
  // ── AUTHORISE every prekey — master-based, at the TOP, before any mutation ──
  // `conv` is a pure routing field: the sender picks it freely and the relay
  // accepts unauthenticated sends into any inbox, so being matched to `contact`
  // proves nothing. The peer's device DH key is public (it travels in group
  // rosters), so it CANNOT bind — only the MASTER can, because only the peer's
  // own devices hold a cert under it (respondX3DH re-checks that cert).
  //
  // (1) MASTER binding: the claimed master must be the pinned one. Regime-
  //     independent — it compares the masters directly, so it works whether this
  //     contact's roomId is still device-DH (pre-migration) or already master.
  //     A mismatch is REJECTED here, never routed into the master-change branch
  //     below: routing it there would reopen the v0.16.4 injection — an attacker
  //     with a victim's rostered dhPub could otherwise smuggle in a pendingMaster.
  //     Legitimate master changes are handled deliberately (Stage 3c door), not
  //     off an unauthenticated prekey.
  //
  // (2) DEVICE revocation: the sending device must be authorised for this
  //     contact (present in an accepted master-signed list, or the pinned device
  //     when none exists). This sits BEFORE the simultaneous-init tie-break that
  //     nulls our ratchet — otherwise a revoked device could destroy a live
  //     session via that path before the guard ever runs.
  if (envelope.type === 'prekey') {
    const x = envelope.x3dh;
    if (!bytesEqual(x.masterPub, contact.peerMasterPub)) {
      throw new Error('Nachricht gehört nicht zu dieser Unterhaltung — verworfen.');
    }
    if (x.senderDeviceList) {
      // A valid, strictly newer list is an independently authenticated
      // directory checkpoint. Adopt it on the isolated receive candidate before
      // testing device presence; the caller persists the candidate only after
      // the first ratchet ciphertext authenticates.
      await applyDeviceListUpdate(contact, x.senderDeviceList, new Set());
    }
    if (!deviceAuthorized(contact, x.identitySignPub)) {
      throw new RevokedDeviceError();
    }
  }

  // (The old master-mismatch branch that recorded pendingMaster and threw
  // MasterChangedError/RetiredIdentityError from a bare prekey is GONE. Under
  // master-based roomId the top-of-function authorisation already rejects any
  // envelope whose master isn't the pinned one — a different master derives a
  // different room and never reaches here as this contact. A legitimate master
  // change is now handled deliberately, off two explicit paths, not off an
  // unauthenticated prekey:
  //   • a dual-signed ROTATION chain proves continuity → acceptRotation (keeps
  //     verified, re-keys); and
  //   • an UNPROVEN previousMaster hint surfaces a merge affordance the user
  //     confirms → acceptMasterChange (clears verified).
  // The retired-master defence moved to the GLOBAL, master-indexed denylist,
  // checked before those paths and before auto-create — see lib/denylist.ts.)

  // We DECIDE the path and BUILD any new session into LOCALS, mutating live
  // contact state only AFTER the message authenticates (respondX3DH's cert check
  // and the AEAD decrypt both pass) — the v0.17.1 "commit only after the AEAD
  // check" discipline. The prekey guards above compare only PUBLIC roster values;
  // the secret-binding check lives inside respondX3DH. If we nulled the live
  // ratchet/pendingHeader before it, an attacker who copied a peer's public
  // master + signPub could destroy an in-flight session with a garbage prekey
  // (Devil's-Advocate DA-4), and a forged 'msg' could clear pendingHeader and
  // stall a handshake (Review F). Committing last closes both.

  // Simultaneous initiation: we started a session and haven't heard back
  // (pendingHeader set) AND the peer also sent a prekey. Both can't keep their
  // own session — pick one deterministically by identity order: the lower key
  // stays initiator, the higher adopts the peer's session. Both then converge.
  // Select the session by the SENDER DEVICE. A prekey names it (x3dh.identitySignPub);
  // a 'msg' has no device field yet (Stage 3d step 1 → the primary/pinned device;
  // step 6 adds envelope.dev). Everything below operates on THIS device's session,
  // so Invariant I holds per session — no other device's chain is touched.
  const sessKey =
    envelope.type === 'prekey'
      ? deviceKey(envelope.x3dh.identitySignPub)
      : deviceKey(envelope.dev ?? contact.peerSignPub);
  const existing = contact.sessions.get(sessKey);
  const simInitAdopt = !!existing?.ratchet && !!existing.pendingHeader && envelope.type === 'prekey';
  // The tie-break must be a SYMMETRIC total order over the two DEVICES actually
  // racing — my device vs the peer's SENDING device. contact.peerDhPub is the
  // person-level PRIMARY device (unchanged since single-device 3c); for a secondary
  // peer device it differs, so both endpoints would decide from different keys and
  // could both-win (deadlock) or both-adopt (mismatched secrets). The sending
  // device's own DH is on the wire — x3dh.identityDhPub — and simInitAdopt already
  // implies a prekey, so it is present. (Review fund 2.)
  if (simInitAdopt && cmp(me.dh.publicKey, envelope.x3dh.identityDhPub) < 0) {
    throw new Error('Gleichzeitiger Verbindungsaufbau — Peer-Prekey ignoriert (unsere Session gewinnt).');
  }

  // Build a fresh responder session iff THIS device has no live ratchet, OR we lost
  // the sim-init tie-break and must adopt the peer's (without yet dropping ours).
  // freshHandshake drives the "provably wrong on first decrypt" reporting.
  const buildFresh = !existing?.ratchet || simInitAdopt;
  const freshHandshake = buildFresh;

  let ratchet = existing?.ratchet ?? null;
  let authenticatedOpkId: number | undefined;
  if (buildFresh) {
    if (envelope.type !== 'prekey') {
      throw new Error('Erste Nachricht ohne X3DH-Header — Session kann nicht aufgebaut werden.');
    }
    const spk = lookup.signedPreKey(envelope.x3dh.signedPreKeyId);
    if (!spk) throw new Error('Passender Signed Prekey nicht gefunden (vermutlich rotiert).');
    const opkId = envelope.x3dh.oneTimePreKeyId;
    if (opkId !== undefined && !lookup.oneTimePreKey) {
      throw new Error('Sicherer One-Time-Prekey-Lookup nicht verfügbar — Handshake abgebrochen.');
    }
    const opkPriv = opkId === undefined ? undefined : lookup.oneTimePreKey!(opkId);
    // respondX3DH verifies the sender's device cert — throws X3DHError on a forgery
    // BEFORE we touch any live state.
    const x3dh = await respondX3DH(me, spk.privateKey, opkPriv, envelope.x3dh);
    ratchet = await initRatchetResponder(x3dh.sharedSecret, spk, x3dh.associatedData);
    if (opkPriv && opkId !== undefined) authenticatedOpkId = opkId;
  }
  if (!ratchet) {
    // Unreachable: buildFresh either set ratchet or threw. Kept as a type guard.
    throw new Error('Kein Ratchet-Zustand nach Handshake.');
  }

  let plaintext: Bytes;
  try {
    plaintext = await ratchetDecrypt(ratchet, envelope.message);
  } catch (e) {
    if (freshHandshake) {
      // The derived session is provably wrong — leave the session map untouched (we
      // never committed the fresh ratchet), so the next prekey attempt starts clean
      // AND a forged prekey cannot have destroyed a pre-existing in-flight session.
      throw new HandshakeMismatchError();
    }
    throw e;
  }

  // COMMIT: the message authenticated, so it is now safe to mutate live state. Store
  // it under THIS device's session key — a fresh ratchet replaces our in-flight one
  // for that device (sim-init loss / first contact), and any inbound message means
  // the peer has our session, so we stop attaching the X3DH header.
  const deviceSignPub = envelope.type === 'prekey' ? envelope.x3dh.identitySignPub : (envelope.dev ?? contact.peerSignPub);
  // Learn the sender device's protocol version from THIS authenticated message —
  // the pv rode inside the (now-verified) envelope, so it's as trustworthy as the
  // message itself. Latest wins (it reflects the version currently running there).
  contact.sessions.set(sessKey, { ratchet, pendingHeader: null, deviceSignPub, pv: envelope.pv });
  // Everything below happens AFTER the ratchet AEAD authenticated. Invalid
  // application framing must therefore be reported as an authenticated drop,
  // not thrown: the caller still has to persist the advanced ratchet and consume
  // an authenticated OPK. Throwing here would skip that storage boundary and
  // make the message key (and OPK) reusable after reload.
  const mid = plaintext.length >= MID_LEN ? bytesToMid(plaintext.slice(0, MID_LEN)) : undefined;
  let content: MessageContent;
  try {
    if (plaintext.length <= MID_LEN) throw new Error('Frame fehlt.');
    content = await unframeContent(plaintext.slice(MID_LEN));
  } catch {
    return {
      outcome: 'authenticated-drop',
      reason: 'invalid-frame',
      ...(mid === undefined ? {} : { mid }),
      ...(authenticatedOpkId === undefined
        ? {}
        : { authenticatedOneTimePreKeyId: authenticatedOpkId }),
    };
  }
  // `unframeContent` can only have succeeded when at least one frame byte
  // followed the complete MID. Keep this explicit so the discriminated result
  // never exposes an optional MID on the dispatchable branch.
  if (mid === undefined) {
    return {
      outcome: 'authenticated-drop',
      reason: 'invalid-frame',
      ...(authenticatedOpkId === undefined
        ? {}
        : { authenticatedOneTimePreKeyId: authenticatedOpkId }),
    };
  }
  // A 'sync' frame is ONLY legitimate from one of MY OWN devices — the hidden self-
  // contact, whose peerMaster is my own master. Rejecting it here (at the source)
  // stops a malicious peer from framing a byte-9 'sync' over their authenticated
  // session to inject a fabricated message into an ARBITRARY conversation
  // (targetPeerMaster is attacker-chosen). The self-contact carries peerMaster == me.
  // Erst-Sync frames carry the whole account state (bootstrap) or pull it (bootreq),
  // so they get the SAME self-gate: only my OWN device (peerMaster == my master) may
  // send them. A malicious peer must not smuggle a byte-10/12 frame over its
  // authenticated session. `listack` (byte 11) is intentionally NOT gated — an ack
  // over MY device list is legitimate from any peer and carries no injectable state.
  if (
    (
      content.kind === 'sync' ||
      content.kind === 'groupsync' ||
      content.kind === 'bootstrap' ||
      content.kind === 'bootreq'
    ) &&
    !bytesEqual(contact.peerMasterPub, me.master.publicKey)
  ) {
    return {
      outcome: 'authenticated-drop',
      reason: 'unauthorised-self-frame',
      ...(mid === undefined ? {} : { mid }),
      ...(authenticatedOpkId === undefined
        ? {}
        : { authenticatedOneTimePreKeyId: authenticatedOpkId }),
    };
  }
  return {
    outcome: 'message',
    mid,
    content,
    ...(authenticatedOpkId === undefined
      ? {}
      : { authenticatedOneTimePreKeyId: authenticatedOpkId }),
  };
}

// --- Contact (de)serialisation for the vault (produces plaintext bytes only) ---

interface ContactWire {
  roomId: string;
  peerMasterPub: string;
  peerEpoch: number;
  peerSignPub: string;
  peerDhPub: string;
  peerFingerprint: string;
  nickname: string | null;
  peerName: string | null;
  peerAvatarB64: string | null;
  verified: boolean;
  verifiedSuggestion: boolean;
  verifiedSuggestionDismissed: boolean;
  peerAckedListEV: { epoch: number; version: number } | null;
  peerAckedListByDevice?: Record<string, { epoch: number; version: number }> | null;
  hidden: boolean;
  localOnly?: boolean;
  staleIdentity: boolean;
  pendingMaster: { masterPub: string; epoch: number; signPub: string; dhPub: string } | null;
  retiredMasters: string[];
  retiredAttempt: boolean;
  ownMasterPub: string | null;
  peerDeviceList: string | null; // b64 of encodeDeviceList
  regime: 'device' | 'master' | null; // null = pre-3c device-DH regime
  bundle: string | null; // bundle token (null if we only hold their identity)
  // Per-device sessions (Stage 3d), keyed by base64(deviceSignPub).
  sessions?: {
    [devB64: string]: { ratchet: string | null; pendingHeader: unknown | null; deviceSignPub: string; pv?: number | null };
  };
  // LEGACY (pre-3d) — a record written before 3d has these flat fields and NO
  // `sessions`; deserialize synthesizes a single-entry map from them (one-way).
  ratchet?: string | null;
  pendingHeader?: unknown | null;
  ratchetDeviceSignPub?: string | null;
}

async function b64(b: Bytes): Promise<string> {
  const s = await getSodium();
  return s.to_base64(b, s.base64_variants.ORIGINAL);
}

/** Canonical base64 of a master pub — THE key format of the global denylist.
 *  Exported so every denylist check uses the same encoding as what acceptMaster-
 *  Change/acceptRotation store; a mismatched encoding would silently miss. */
export async function masterKeyB64(masterPub: Bytes): Promise<string> {
  return b64(masterPub);
}
async function unb64(str: string): Promise<Bytes> {
  const s = await getSodium();
  return new Uint8Array(s.from_base64(str, s.base64_variants.ORIGINAL));
}

export async function serializeContact(c: Contact): Promise<Bytes> {
  const wire: ContactWire = {
    roomId: c.roomId,
    peerMasterPub: await b64(c.peerMasterPub),
    peerEpoch: c.peerEpoch,
    peerSignPub: await b64(c.peerSignPub),
    peerDhPub: await b64(c.peerDhPub),
    peerFingerprint: c.peerFingerprint,
    nickname: c.nickname ?? null,
    peerName: c.peerName ?? null,
    peerAvatarB64: c.peerAvatarB64 ?? null,
    verified: c.verified ?? false,
    verifiedSuggestion: c.verifiedSuggestion ?? false,
    verifiedSuggestionDismissed: c.verifiedSuggestionDismissed ?? false,
    peerAckedListEV: c.peerAckedListEV ?? null,
    peerAckedListByDevice: c.peerAckedListByDevice ?? null,
    hidden: c.hidden ?? false,
    localOnly: c.localOnly ?? false,
    staleIdentity: c.staleIdentity ?? false,
    pendingMaster: c.pendingMaster
      ? {
          masterPub: await b64(c.pendingMaster.masterPub),
          epoch: c.pendingMaster.epoch,
          signPub: await b64(c.pendingMaster.signPub),
          dhPub: await b64(c.pendingMaster.dhPub),
        }
      : null,
    retiredMasters: c.retiredMasters ?? [],
    retiredAttempt: c.retiredAttempt ?? false,
    ownMasterPub: c.ownMasterPub ? await b64(c.ownMasterPub) : null,
    peerDeviceList: c.peerDeviceList ? await b64(await encodeDeviceList(c.peerDeviceList)) : null,
    regime: c.regime ?? null,
    bundle: c.bundle ? await encodeBundle(c.bundle) : null,
    sessions: await serializeSessions(c.sessions),
  };
  return utf8.encode(JSON.stringify(wire));
}

async function serializeSessions(
  sessions: Map<string, Session>,
): Promise<{
  [devB64: string]: { ratchet: string | null; pendingHeader: unknown | null; deviceSignPub: string; pv?: number | null };
}> {
  const out: {
    [k: string]: { ratchet: string | null; pendingHeader: unknown | null; deviceSignPub: string; pv?: number | null };
  } = {};
  for (const [k, s] of sessions) {
    out[k] = {
      ratchet: s.ratchet ? await b64(await serializeState(s.ratchet)) : null,
      pendingHeader: s.pendingHeader ? await encodeInitialHeader(s.pendingHeader) : null,
      deviceSignPub: await b64(s.deviceSignPub),
      pv: s.pv ?? null,
    };
  }
  return out;
}

/** Rebuild the per-device session map, migrating a pre-3d record (flat ratchet
 *  fields, no `sessions`) into a single-entry map keyed by the device that backed
 *  the live ratchet — the same fallback (ratchetDeviceSignPub ?? peerSignPub) the
 *  revocation guard used. Idempotent: presence of `sessions` skips migration. */
async function deserializeSessions(wire: ContactWire): Promise<Map<string, Session>> {
  const map = new Map<string, Session>();
  if (wire.sessions) {
    for (const [k, s] of Object.entries(wire.sessions)) {
      map.set(k, {
        ratchet: s.ratchet ? await deserializeState(await unb64(s.ratchet)) : null,
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        pendingHeader: s.pendingHeader ? await decodeInitialHeader(s.pendingHeader as any) : null,
        deviceSignPub: await unb64(s.deviceSignPub),
        pv: s.pv ?? undefined,
      });
    }
    return map;
  }
  if (wire.ratchet) {
    const deviceSignPub = await unb64(wire.ratchetDeviceSignPub ?? wire.peerSignPub);
    map.set(deviceKey(deviceSignPub), {
      ratchet: await deserializeState(await unb64(wire.ratchet)),
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      pendingHeader: wire.pendingHeader ? await decodeInitialHeader(wire.pendingHeader as any) : null,
      deviceSignPub,
    });
  }
  return map;
}

export async function deserializeContact(bytes: Bytes): Promise<Contact> {
  const wire = JSON.parse(utf8.decode(bytes)) as ContactWire;
  return {
    roomId: wire.roomId,
    peerMasterPub: await unb64(wire.peerMasterPub),
    peerEpoch: wire.peerEpoch ?? 1,
    peerSignPub: await unb64(wire.peerSignPub),
    peerDhPub: await unb64(wire.peerDhPub),
    peerFingerprint: wire.peerFingerprint,
    nickname: wire.nickname ?? undefined,
    peerName: wire.peerName ?? undefined,
    peerAvatarB64: wire.peerAvatarB64 ?? undefined,
    verified: wire.verified ?? false,
    verifiedSuggestion: wire.verifiedSuggestion || undefined,
    verifiedSuggestionDismissed: wire.verifiedSuggestionDismissed || undefined,
    peerAckedListEV: wire.peerAckedListEV ?? undefined,
    peerAckedListByDevice: wire.peerAckedListByDevice ?? undefined,
    hidden: wire.hidden || undefined,
    localOnly: wire.localOnly || undefined,
    staleIdentity: wire.staleIdentity || undefined,
    pendingMaster: wire.pendingMaster
      ? {
          masterPub: await unb64(wire.pendingMaster.masterPub),
          epoch: wire.pendingMaster.epoch,
          signPub: await unb64(wire.pendingMaster.signPub),
          dhPub: await unb64(wire.pendingMaster.dhPub),
        }
      : undefined,
    retiredMasters: wire.retiredMasters?.length ? wire.retiredMasters : undefined,
    retiredAttempt: wire.retiredAttempt || undefined,
    ownMasterPub: wire.ownMasterPub ? ((await unb64(wire.ownMasterPub)) as MasterPub) : undefined,
    peerDeviceList: wire.peerDeviceList ? await decodeDeviceList(await unb64(wire.peerDeviceList)) : undefined,
    regime: wire.regime ?? undefined,
    bundle: wire.bundle ? await decodeBundle(wire.bundle) : undefined,
    sessions: await deserializeSessions(wire),
  };
}
