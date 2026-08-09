import {
  useEffect,
  useLayoutEffect,
  useReducer,
  useRef,
  useState,
  type ChangeEvent,
  type ReactNode,
} from 'react';
import { loadOrCreateIdentity, fingerprintOf } from './lib/identity';
import {
  loadOrCreatePreKeys,
  ownSpkPublic,
  currentBundle,
  findSignedPreKey,
  findOneTimePreKey,
  type PreKeyState,
} from './lib/prekeys';
import {
  encodeBundle,
  decodeBundle,
  decodeEnvelope,
  openPayload,
  SEALED_ENVELOPE,
  SEALED_LINK_OFFER,
  SEALED_LINK_GRANT,
  masterSafetyNumber,
  isPrimaryDevice,
  verifyDeviceCert,
  bytesEqual,
  asMasterPub,
  decodeLinkGrant,
  sign,
  type Bytes,
  type IdentityKeys,
  type SasResult,
  isNewerDeviceList,
  compareDeviceList,
  encodeDeviceList,
  deviceInList,
  type DeviceList,
} from './crypto';
import {
  startLinkOnN,
  offerReceivedOnN,
  completeLinkOnN,
  beginLinkOnP,
  confirmLinkSession,
  createConfirmedNewDeviceLinkIntent,
  restoreConfirmedNewDeviceLinkSession,
  restoreDiscardedNewDeviceLinkSession,
  verifyConfirmedNewDeviceLinkGrant,
  verifyDiscardedNewDeviceLinkGrant,
  confirmedLinkGrantRows,
  confirmedLinkGrantAlreadyInstalled,
  completeLinkOnP,
  LinkGrantDeliveryCancelledError,
  LinkGrantDeliveryPendingError,
  type LinkSession,
} from './lib/linkflow';
import {
  loadOrCreateOwnDeviceList,
  adoptDeviceList,
  cancelPendingLinkGrantAndRevokeDevice,
  revokeDevice,
} from './lib/devices';
import {
  makeContact,
  makeContactFromHeader,
  sendMessage,
  sendProfile,
  receiveEnvelope,
  serializeContact,
  deserializeContact,
  resolveContactByConv,
  hasSession,
  randomMid,
  fanoutDeliveries,
  fanoutChunks,
  deviceProtocolVersion,
  acceptMasterChange,
  acceptRotation,
  reconnectContact,
  migrateContactRoomId,
  applyDeviceListUpdate,
  mergeRosterEntry,
  masterKeyB64,
  sendListAck,
  MasterChangedError,
  RetiredIdentityError,
  RevokedDeviceError,
  inboxRoom,
  computeMasterRoomId,
  type Contact,
  type BootstrapPart,
  type RosterEntry,
  type HistoryMessage,
  type MessageContent,
  type GroupInvite,
  type PreKeyLookup,
} from './lib/session';
import {
  randomGroupId,
  toInvite,
  fromInvite,
  saveGroup,
  loadGroups,
  removeGroup,
  isGroupMember,
  isGroupMemberMaster,
  isGroupOwner,
  memberMasterPub,
  nextGroupRevision,
  applyGroupMemberDeviceList,
  groupFanoutToDevices,
  boundedGroupAttachmentPolicy,
  groupBroadcastBundle,
  decideInvite,
  classifyGroupFrame,
  signGroupState,
  toGroupStateProof,
  fromGroupStateProof,
  type Group,
  type GroupMember,
} from './lib/groups';
import {
  saveContact,
  saveContactAndConsumeOneTimePreKey,
  loadContacts,
  removeContact,
} from './lib/store';
import {
  clearPendingGroupMutation,
  commitGroupMutation,
  discardPendingGroupMutation,
  loadPendingGroupMutationSnapshots,
  replacePendingGroupMutation,
  type PendingGroupMutationSnapshot,
} from './lib/groupMutations';
import {
  clearGroupRemovalTombstone,
  loadGroupRemovalTombstone,
  loadGroupRemovalTombstones,
  permitsGroupReadd,
  saveGroupRemovalTombstone,
  type GroupRemovalTombstone,
} from './lib/groupTombstones';
import { StaleAccountGenerationError, currentDbName, pinTaskAccount, clearTaskAccount } from './lib/db';
import {
  clearPendingLinkGrantAndRecover,
  recoverPendingLinkGrantAtBoot,
} from './lib/linkIntent';
import {
  clearConfirmedNewDeviceLinkIntent,
  classifyLinkGrantRelayRow,
  discardConfirmedNewDeviceLinkIntent,
  drainLinkGrantCandidates,
  loadConfirmedNewDeviceLinkIntent,
  loadDiscardedNewDeviceLinkIntents,
  saveConfirmedNewDeviceLinkIntent,
  type ConfirmedNewDeviceLinkIntent,
} from './lib/linkRecovery';
import { moveContactStorage } from './lib/rekey';
import { loadRetiredMasters, addRetiredMaster } from './lib/denylist';
import { loadProfile, saveProfile, type MyProfile } from './lib/profile';
import { wipeAccount } from './lib/wipe';
import { loadDeviceNames, setDeviceName, type DeviceNames } from './lib/devicenames';
import {
  loadStickers,
  saveStickers,
  isSticker,
  STICKER_FILENAME,
  MAX_STICKERS,
  type Sticker,
} from './lib/stickers';
import {
  loadBootstrapApplied,
  saveBootstrapApplied,
  loadBootstrapRequest,
  saveBootstrapRequest,
  requireExactBootstrapDelivery,
  type BootstrapRequest,
} from './lib/bootstrap';
import {
  putAttachment,
  getAttachmentBlob,
  getAttachmentMeta,
  newAttachmentId,
  secureWipeAttachment,
  allAttachmentIds,
  sealAndPutChunk,
  finalizeAttachment,
  putRecvMarker,
  getRecvMarker,
  clearRecvMarker,
  allRecvMarkerIds,
} from './lib/attachments';
import { pushSupported, enablePush, disablePush, currentSubscription } from './lib/push';
import {
  loadMessages,
  saveMessages,
  clearMessages,
  allMessageRoomIds,
  aggregateDelivery,
  hasMessage,
  recallRegistryKey,
  recallRegistryHas,
  migrateLegacyRecalledMids,
  moveRecallRegistryRoom,
  applyRecallRegistry,
  addRecallRegistryEntry,
  prepareRecalledMessageForAppend,
  loadRecalledMids,
  saveRecalledMids,
  MessageCorruptionError,
  type ChatMessage,
  type DeviceDelivery,
  type FileRef,
  type Quote,
} from './lib/messages';
import { prepareOwnerRelaySlot, RelayClient, type RelayStatus } from './lib/relay';
import { makeQr } from './lib/qr';
import {
  ContactCodeError,
  MAX_CONTACT_INPUT_CHARS,
  createContactInvite,
  extractContactCode,
  publishContactInvite,
  resolveContactInvite,
  type ContactInviteDraft,
} from './lib/contactCode';
import {
  OfficialAccountError,
  extractOfficialAccountAlias,
  isOfficialAdminContact,
  isOfficialAdminMaster,
  isRevokedOfficialAdminContact,
  isRevokedOfficialAdminMaster,
  officialAccountConfigured,
  resolveOfficialAccount,
  type TrustedOfficialAccountDocument,
} from './lib/officialAccount';
import {
  loadOfficialAccountTrust,
  saveOfficialAccountTrust,
} from './lib/officialAccountStore';
import {
  OFFICIAL_ACCOUNT_ALIAS,
  OFFICIAL_ACCOUNT_BADGE,
  OFFICIAL_ACCOUNT_CLOCK_SKEW_MS,
  OFFICIAL_ACCOUNT_DISPLAY_NAME,
  base64urlEncode,
} from './lib/officialAccountManifest';
import { bytesToB64, b64ToBytes } from './lib/bytes';
import { compressImage } from './lib/imagecompress';
import { Identicon } from './Identicon';
import { QrScanner } from './QrScanner';
import { CropModal } from './CropModal';
import { BackupModal } from './BackupModal';
import { BiometricEnroll } from './BiometricEnroll';
import { BugReport } from './BugReport';
import { Explainer } from './Explainer';
import { t, useLang, LANGS, getLang, setLang, type Lang } from './lib/i18n';
import { tb } from './lib/tnodes';
import { applyBadge } from './lib/badge';
import { biometricAvailable, biometricEnrolled, disableBiometricUnlock, duressEnabled, openDecoyForPopulate, WrongPassphraseError } from './lib/vaultService';
import { DuressSetup } from './DuressSetup';
import {
  ALWAYS_RECEIVE_INLINE_BYTES,
  AUTO_RECEIVE_CONTACT_CAP_BYTES,
  attachmentRecvReservationBytes,
  automaticRecvReservationBytes,
  hasOriginStorageHeadroom,
  mayAutoReceiveAttachment,
  remainingRecvReservationBytes,
} from './lib/storageQuota';
import { Attachment, LightboxImg } from './Attachment';
import { ViewOnceViewer } from './ViewOnceViewer';
import {
  uploadFileToR2,
  downloadR2ToStore,
  tryValidateR2Descriptor,
  StorageFullError,
  FileReadError,
  readSliceRetry,
} from './lib/blobtransfer';
import { transcodeVideoTo720p } from './lib/transcode';
import { createKeyedSerialQueue } from './lib/keyedQueue';
import { registerVaultRuntimeQuiescer } from './lib/runtimeQuiesce';
import {
  IconLock, IconShield, IconSearch, IconBack, IconPlus, IconSend, IconDoubleCheck, IconInfo, IconCamera, IconAttach, IconMic, IconTrash, IconDots, IconGroup, IconReply, IconForward, IconCopy,
  IconBell, IconDevices, IconArchive, IconChevron,
  IconSticker, IconGraduation, IconGlobe, IconBug, IconBomb,
} from './icons';

const MAX_ATTACH = 600 * 1024; // inline cap — keeps the WS frame under Cloudflare's ~1 MiB limit
const COMPOSER_MAX_HEIGHT = 140; // px — composer grows to ~6 lines, then scrolls (mirrors app.css)
// Chunked attachments. Auto-push path: a file above the inline cap and up to
// AUTOPUSH_CAP is sent as chunk frames straight to the peer's mailbox (works offline);
// larger files will use offer+pull (7d). CHUNK_BYTES stays well under the relay's
// per-message cap even after sealing/base64.
const CHUNK_BYTES = 48 * 1024;
const AUTOPUSH_CAP = 2 * 1024 * 1024; // at/below → chunks auto-pushed to the mailbox
const MAX_BIG_ATTACH = 25 * 1024 * 1024; // above AUTOPUSH_CAP and up to here → offer + pull (relay mailbox)
const CLIENT_MAX_BLOB = 1024 * 1024 * 1024; // above MAX_BIG_ATTACH and up to here (~1 GB) → encrypted R2 upload
const SERVE_COOLDOWN_MS = 30_000; // min gap between serving the SAME offered attachment to a contact (anti-amplification)
const PULL_RETRY_MS = 33_000; // re-request a stalled pull just past the serve cooldown (re-serve is idempotent → fills gaps)
const MAX_PULL_ATTEMPTS = 4; // total attreq attempts before a pull gives up (~2 min)
// RECEIVE caps (sanity bounds; the real flood limit is the relay mailbox byte-cap,
// which rate-limits what a peer can push before we drain it).
const RECV_MAX_BYTES = 30 * 1024 * 1024; // largest attachment we'll reassemble
const RECV_MAX_CHUNKS = 800; // ceiling on a transfer's chunk count (bounds bookkeeping)
const RECV_MAX_CHUNK_BYTES = 256 * 1024; // reject an over-large single chunk payload
const MAX_CONCURRENT_RECV = 6; // cap simultaneous in-progress incoming transfers
const RECV_TTL_MS = 24 * 60 * 60 * 1000; // abandoned incoming transfer (sender vanished) is swept after 24 h
const PUSH_UNSUBSCRIBE_TIMEOUT_MS = 1_500;
const MAX_REC_SECONDS = 180;
// Voice bitrate. Without this the browser default (~128 kbps) makes 30 s of speech
// ~480 KB, so a recording the UI happily allowed could not be sent — MAX_REC_SECONDS
// and MAX_ATTACH contradicted each other. Opus at 24 kbps is plainly enough for
// speech and puts the full 180 s at roughly 540 KB, inside the cap.
const VOICE_BITS_PER_SECOND = 24_000;
// Erst-Sync sizing: keeps a snapshot comfortably under MAX_ATTACH without splitting.
const SWIPE_SLOP = 8; // px of travel before the drag commits to an axis (horizontal vs scroll)
const SWIPE_BIAS = 1.25; // vertical must dominate horizontal by this factor to be treated as scroll
const REPLY_TRIGGER = 52; // px of drag that opens a reply on release
const REPLY_MAX = 96; // soft ceiling; past the trigger the bubble rubber-bands, never a hard wall
const REPLY_DAMP = 0.35; // resistance applied to travel beyond the trigger
const ROSTER_MAX = 512; // metadata-only entries, ~250 B each
const AVATAR_IMPORT_CAP = 96 * 1024; // decoded-ish ceiling for a carried avatar
const HISTORY_CHUNK_BYTES = 64 * 1024; // per history frame; measured in UTF-8 BYTES
const GOSSIP_COOLDOWN_MS = 30_000; // first re-offer delay; doubles per attempt
const GOSSIP_MAX_BACKOFF_MS = 60 * 60_000; // ceiling, so a never-acking peer stays cheap
// Owner-state and member content use independent pairwise inboxes. A content
// frame can therefore beat the just-committed roster frame. Buffer only this
// tightly bounded, authenticated transition window and ACK its relay row.
const GROUP_TRANSITION_MAX_IDS = 8;
const GROUP_TRANSITION_MAX_PER_GROUP = 12;
const GROUP_TRANSITION_MAX_BYTES = 2 * 1024 * 1024;
const GROUP_TRANSITION_TTL_MS = 2 * 60_000;
// Avoid the browser's signed 32-bit timeout edge for long-lived manifests.
const OFFICIAL_TRUST_TIMER_STEP_MS = 24 * 60 * 60_000;
const OFFICIAL_TRUST_REFRESH_INTERVAL_MS = 15 * 60_000;

function pickAudioMime(): string {
  const cands = ['audio/mp4', 'audio/webm;codecs=opus', 'audio/webm', 'audio/ogg;codecs=opus'];
  for (const c of cands) {
    if (typeof MediaRecorder !== 'undefined' && MediaRecorder.isTypeSupported?.(c)) return c;
  }
  return '';
}

const fmtRec = (s: number) => `${Math.floor(s / 60)}:${(s % 60).toString().padStart(2, '0')}`;

function hexOf(b: Uint8Array): string {
  let s = '';
  for (const x of b) s += x.toString(16).padStart(2, '0');
  return s;
}

/** A transient "disk full" from IndexedDB (quota exceeded). It is distinct from a
 *  permanent drop (decrypt failure, duplicate) because a stored-and-forward message
 *  that we FAIL to persist must NOT be acked — acking tells the relay to delete it,
 *  turning a temporary out-of-space into permanent loss. Harmless today, a real
 *  outcome once large attachments exist. */
function isStorageFull(e: unknown): boolean {
  if (typeof DOMException !== 'undefined' && e instanceof DOMException) {
    return e.name === 'QuotaExceededError' || e.name === 'NS_ERROR_DOM_QUOTA_REACHED' || e.code === 22;
  }
  return e instanceof Error && /quota|storage.*full/i.test(e.message);
}

function isTransientStorageFailure(e: unknown): boolean {
  if (isStorageFull(e) || e instanceof StaleAccountGenerationError) return true;
  if (typeof DOMException !== 'undefined' && e instanceof DOMException) {
    return [
      'AbortError',
      'InvalidStateError',
      'UnknownError',
      'TransactionInactiveError',
      'TimeoutError',
    ].includes(e.name);
  }
  return e instanceof Error && /indexeddb|database.*(closed|closing)|transaction.*abort/i.test(e.message);
}

class DeferredGroupTransitionError extends Error {
  constructor() {
    super('Gruppeninhalt wartet auf einen bereits angekündigten Owner-Rosterstand.');
    this.name = 'DeferredGroupTransitionError';
  }
}

class DuplicateGroupTransitionRowError extends Error {
  constructor() {
    super('Zusätzliche Relay-Zeile eines bereits gehaltenen Gruppenframes.');
    this.name = 'DuplicateGroupTransitionRowError';
  }
}

/** Async work from an unmounted/locked Messenger generation must never reopen
 * relays or continue mutating the vault behind the lock screen. */
class MessengerInactiveError extends Error {
  constructor() {
    super('Messenger generation is no longer active.');
    this.name = 'MessengerInactiveError';
  }
}

interface TrackedRuntimeOperation {
  controller: AbortController;
  settled: Promise<void>;
}

async function settleWithin<T>(promise: Promise<T>, timeoutMs: number): Promise<T | undefined> {
  let timer: number | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<undefined>((resolve) => {
        timer = window.setTimeout(resolve, timeoutMs);
      }),
    ]);
  } finally {
    if (timer !== undefined) window.clearTimeout(timer);
  }
}

function incomingMessage(content: MessageContent, mid: string): ChatMessage {
  if (content.kind === 'file') {
    return {
      mine: false,
      ts: Date.now(),
      mid,
      file: { name: content.name, mime: content.mime, dataB64: bytesToB64(content.data) },
    };
  }
  // text (profile is handled separately and never reaches here)
  return { mine: false, text: content.kind === 'text' ? content.text : '', ts: Date.now(), mid };
}

// The delivery indicator for one of MY messages. Stage 3d: derive the honest
// AGGREGATE over per-device deliveries (all sent → ✓✓; some sent → "an N/M
// Geräten"; none → ⚠); a `stale` device (revoked in flight) is out of the
// denominator. Falls back to the legacy single status for groups / pre-3d rows.
function msgStatusEl(m: ChatMessage) {
  let kind: 'sent' | 'pending' | 'partial' | 'failed' = 'sent';
  let text: string | undefined;
  if (m.deliveries && m.deliveries.length) {
    const a = aggregateDelivery(m.deliveries);
    kind = a.label;
    if (a.label === 'partial') text = `an ${a.sent}/${a.total} Geräten`;
  } else if (m.status === 'failed') {
    kind = 'failed';
  } else if (m.status === 'pending') {
    kind = 'pending';
  }
  if (kind === 'failed') {
    return (
      <span className="msg-failed" title="Nicht zugestellt">
        ⚠ nicht zugestellt
      </span>
    );
  }
  return (
    <span className="msg-check" title={text} style={{ opacity: kind === 'pending' ? 0.35 : 1 }}>
      <IconDoubleCheck size={13} />
      {kind === 'partial' && <span className="msg-partial"> {text}</span>}
    </span>
  );
}

interface Props {
  dek: CryptoKey;
  onLock: () => void;
  /** True while this is a deliberate in-app "fill the decoy" session (App-owned, not persisted). */
  populatingDecoy?: boolean;
  /** Enter the decoy account to populate it: hand App the decoy DEK (from openDecoyForPopulate). */
  onEnterDecoy?: (decoyDek: CryptoKey) => void;
  /** Leave the decoy populate session and return to the real account (no wipe, no passphrase). */
  onExitDecoy?: () => void;
}

type View = 'list' | 'chat' | 'add' | 'verify' | 'contact' | 'profile' | 'newgroup' | 'gmanage' | 'learn' | 'devices';

// Navigation tree, so the hardware/gesture Back button steps UP one level inside
// the app instead of leaving the (standalone) PWA — on Android, leaving meant the
// vault re-locked and the user had to unlock again. list(0) → chat/add/profile/
// newgroup(1) → contact/verify/gmanage(2, reached from an open chat) / learn(2,
// reached from profile).
function viewDepth(v: View): number {
  switch (v) {
    case 'list':
      return 0;
    case 'contact':
    case 'verify':
    case 'gmanage':
    case 'learn':
    case 'devices':
      return 2;
    default:
      return 1;
  }
}
function parentView(v: View): View {
  if (v === 'learn' || v === 'devices') return 'profile';
  return v === 'contact' || v === 'verify' || v === 'gmanage' ? 'chat' : 'list';
}

// Frames that are NOT a user-visible message: they must be delivered but must never
// trigger a wake-up push, or the owner gets a "Neue Nachricht" with nothing behind
// it (profile refresh, device-list gossip, self-sync of your own message, a recall
// tombstone, a pull request, roster changes, …). The relay can't see inside the
// seal, so the sender tags these; text/file/group/reply/chunk/attoffer still push.
function isSilentFrame(kind: MessageContent['kind']): boolean {
  switch (kind) {
    case 'profile':
    case 'devlist':
    case 'rotation':
    case 'sync':
    case 'groupsync':
    case 'bootstrap':
    case 'listack':
    case 'bootreq':
    case 'recall':
    case 'attreq':
    case 'unlinkreq':
    case 'ginvite':
    case 'gremove':
    case 'gleave':
      return true;
    default:
      return false;
  }
}

const MSG_WINDOW = 60; // messages rendered initially / added per older-page load

const shortFp = (fp: string) => (fp ? fp.split(' ').slice(0, 3).join(' ') + ' …' : '…');

// WhatsApp-style large emoji: a message that is ONLY one or two emoji (no letters or
// digits) is shown big and without a bubble. Intl.Segmenter counts a ZWJ / skin-tone
// sequence as a single grapheme, so 👍🏽 or 👨‍👩‍👧 count as one.
const graphemeSeg =
  typeof Intl !== 'undefined' && 'Segmenter' in Intl ? new Intl.Segmenter(undefined, { granularity: 'grapheme' }) : null;
function bigEmojiLevel(text: string | undefined): 0 | 1 | 2 {
  if (!text || !graphemeSeg) return 0;
  const t = text.trim();
  if (!t || /[\p{L}\p{N}]/u.test(t)) return 0; // any letter/number → ordinary text
  if (!/\p{Extended_Pictographic}/u.test(t)) return 0; // no emoji at all → ordinary
  let n = 0;
  for (const g of graphemeSeg.segment(t)) {
    if (g.segment.trim() === '') continue; // whitespace between emoji doesn't count
    if (++n > 2) return 0; // three or more → keep normal size
  }
  return n === 1 ? 1 : 2;
}
const ordinaryDisplayName = (c: Contact) =>
  c.nickname?.trim() || c.peerName?.trim() || shortFp(c.peerFingerprint);
const avatarSrc = (b64: string) => `data:image/jpeg;base64,${b64}`;

function OfficialAdminBadge() {
  const label = t('Offizieller SKYTALE-Administrator');
  return (
    <span className="official-admin-badge" aria-label={label} title={label}>
      <IconShield size={12} filled />
      <span>{OFFICIAL_ACCOUNT_BADGE}</span>
    </span>
  );
}

function RevokedOfficialAdminBadge() {
  const label = t('Widerrufener ehemaliger SKYTALE-Administrator');
  return (
    <span
      className="official-admin-badge revoked"
      aria-label={label}
      title={label}
    >
      <IconShield size={12} filled />
      <span>{t('ADMIN WIDERRUFEN')}</span>
    </span>
  );
}

function OfficialAccountRevokedWarning({
  group = false,
  onRecover,
}: {
  group?: boolean;
  onRecover: () => void;
}) {
  return (
    <div className="official-revoked-warning" role="alert">
      <IconShield size={20} filled />
      <div className="official-revoked-copy">
        <b>{t('Früherer SKYTALE-Administrator widerrufen')}</b>
        <span>
          {group
            ? t('Diese Gruppe enthält den widerrufenen früheren SKYTALE-Administrator. Senden ist blockiert, damit keine neuen Nachrichten an diesen Schlüssel gelangen.')
            : t('SKYTALE hat diesen früheren Admin-Schlüssel kryptografisch widerrufen. Senden ist blockiert. Verbinde dich ausschließlich über SKYTALE-SUPPORT neu.')}
        </span>
      </div>
      <button className="btn btn-outline sm" onClick={onRecover}>
        {t('Über SKYTALE-SUPPORT neu verbinden')}
      </button>
    </div>
  );
}

function extractToken(input: string): string {
  const m = input.match(/[#?&]add=([^&\s]+)/);
  return (m ? m[1] : input).trim();
}

function fmtListTs(ts: number | undefined): string {
  if (!ts) return '';
  const d = new Date(ts);
  const now = new Date();
  if (d.toDateString() === now.toDateString()) {
    return `${d.getHours().toString().padStart(2, '0')}:${d.getMinutes().toString().padStart(2, '0')}`;
  }
  const y = new Date(now);
  y.setDate(now.getDate() - 1);
  if (d.toDateString() === y.toDateString()) return 'Gestern';
  return d.toLocaleDateString('de-DE', { day: '2-digit', month: '2-digit' });
}

const fmtClock = (ts: number) => {
  const d = new Date(ts);
  return `${d.getHours().toString().padStart(2, '0')}:${d.getMinutes().toString().padStart(2, '0')}`;
};

export function Messenger({ dek, onLock, populatingDecoy = false, onEnterDecoy, onExitDecoy }: Props) {
  useLang(); // re-render on language change
  // A lock/account switch unmounts this component while its large async boot can
  // still be suspended in IndexedDB/WebCrypto. Every continuation and relay
  // constructor is fenced by this bit; a new Messenger mount gets its own ref.
  const lifecycleActiveRef = useRef(true);
  const identityRef = useRef<IdentityKeys | null>(null);
  const prekeysRef = useRef<PreKeyState | null>(null);
  const lookupRef = useRef<PreKeyLookup | null>(null);
  const relaysRef = useRef<Map<string, RelayClient>>(new Map());
  const contactsRef = useRef<Contact[]>([]);
  // Public, root-signed directory state. It is intentionally kept separate from
  // Contact: neither a profile, a backup nor a peer-controlled field may mint an
  // ADMIN badge. Every stored document is re-verified before reaching this ref.
  const officialAccountTrustRef = useRef<TrustedOfficialAccountDocument | null>(null);
  const officialTrustExpiryTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const officialTrustRefreshRunningRef = useRef(false);
  const messagesRef = useRef<Record<string, ChatMessage[]>>({});
  const unreadRef = useRef<Record<string, number>>({});
  // Scoped (roomId, mine, mid) recall keys — persisted, so a recalled message can't
  // reappear on re-delivery while a peer-known MID can never suppress my opposite-
  // direction self-sync copy or a message in another room.
  const recalledMidsRef = useRef<Set<string>>(new Set());
  const downloadingRef = useRef<Set<string>>(new Set()); // tids currently being pulled (spinner state)
  const pullProgressRef = useRef<Map<string, number>>(new Map()); // tid → percent received (download progress)
  const autoPulledRef = useRef<Set<string>>(new Set()); // tids we already auto-pulled once (don't loop)
  const explicitPullRef = useRef<Set<string>>(new Set()); // user-tapped pulls bypass only the per-contact auto cap
  const droppedRecvRef = useRef<Set<string>>(new Set()); // discard every remaining chunk of a denied transfer
  const r2ReservationsRef = useRef<Map<string, number>>(new Map()); // active R2 downloads, included in origin admission
  const storageGateRef = useRef<Promise<unknown>>(Promise.resolve()); // serialise reservation decisions across inbox/UI
  const servedRef = useRef<Map<string, number>>(new Map()); // (roomId:tid) → last serve time, to rate-limit re-serves
  const sendRoomRef = useRef<Map<string, string>>(new Map());
  const inboxClientRef = useRef<RelayClient | null>(null);
  const seenIdsRef = useRef<Set<number>>(new Set());
  // Serializes ALL inbox processing through one promise chain (see enqueueInbox).
  const inboxQueueRef = useRef<Promise<unknown>>(Promise.resolve());
  const bootTaskRef = useRef<Promise<void> | null>(null);
  // Reversible fence used while an encrypted restore is being prepared. Unlike
  // lifecycleActive=false it can be lifted after a failed import, but while set
  // no relay, queue or UI writer may start against the soon-to-be-replaced DB.
  const runtimeSuspendedRef = useRef(false);
  // Long-running backup KDF/file/storage work must be cancelled and joined just
  // like relay/ratchet work. Otherwise a locked, unmounted generation could
  // still trigger a download or commit a restore behind the lock screen.
  const runtimeOperationsRef = useRef<Set<TrackedRuntimeOperation>>(new Set());
  // Message logs are encrypted whole-room blobs. Serialize the complete
  // read/modify/write/publish operation per room, not merely the final IDB put:
  // otherwise an older ACK/status write can finish after a newer append/recall
  // and silently replace it (last-writer-wins data loss).
  const messageMutationQueueRef = useRef(createKeyedSerialQueue());
  const recallMutationQueueRef = useRef<Promise<unknown>>(Promise.resolve());
  // Serializes only the short, local roster read-modify-write phase. Network
  // delivery deliberately runs after this lock is released, so an inbound leave
  // frame can persist its state without deadlocking against the inbox queue.
  const groupMutationQueueRef = useRef<Promise<unknown>>(Promise.resolve());
  const groupMutationRetryRef = useRef<Promise<void> | null>(null);
  const groupsBootReadyRef = useRef(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const stickerInputRef = useRef<HTMLInputElement>(null);
  const mediaRecorderRef = useRef<MediaRecorder | null>(null);
  const recChunksRef = useRef<Blob[]>([]);
  const recStreamRef = useRef<MediaStream | null>(null);
  const recTimerRef = useRef<number | null>(null);
  const sendOnStopRef = useRef(true);
  const avatarInputRef = useRef<HTMLInputElement>(null);
  const myProfileRef = useRef<MyProfile>({});
  const profileSentRef = useRef<Set<string>>(new Set());
  const retiredMastersRef = useRef<Set<string>>(new Set()); // global master denylist, loaded at boot
  // ── Erst-Sync (link initial state) ──────────────────────────────────
  // Bootstrap ids already imported on THIS device — the idempotency marker, so a
  // re-delivered snapshot is a no-op. Written LAST when applying (crash → the
  // idempotent merge just re-runs on re-delivery).
  const bootstrapAppliedRef = useRef<Set<string>>(new Set());
  // N's pending PULL: after installGrant we keep asking P for the snapshot until
  // one arrives. Persisted so a reload keeps asking.
  const bootstrapRequestRef = useRef<BootstrapRequest | null>(null);
  // My own current device list — the (epoch, version) peers must acknowledge.
  const ownListRef = useRef<DeviceList | null>(null);
  // Per-contact throttle for re-offering my device list (roomId → last attempt).
  const listGossipAttemptRef = useRef<Map<string, { epoch: number; version: number; at: number; tries: number }>>(new Map());
  // Guards against a second history run for the same device while one is still
  // streaming — a repeated pull would otherwise multiply the frames.
  const historySendingRef = useRef<Set<string>>(new Set());
  const groupsRef = useRef<Group[]>([]);
  // Runtime proof that this exact owner revision was durably inserted into every
  // currently known member-device inbox. Cleared on reload on purpose: the first
  // post-reload message re-confirms state before content.
  const confirmedGroupStateRef = useRef<Map<string, string>>(new Map());
  const pendingGroupFramesRef = useRef<
    Map<
      string,
      Array<{
        revision: number;
        stateHash: Bytes;
        ackId: number;
        sender: Contact;
        senderKey: string;
        inner: MessageContent;
        mid: string;
        bytes: number;
        queuedAt: number;
      }>
    >
  >(new Map());
  const pendingGroupBytesRef = useRef(0);
  const expiredGroupTransitionsRef = useRef<Map<string, number>>(new Map());
  const viewRef = useRef<View>('list');
  const activeRoomRef = useRef<string | null>(null);
  const activeGroupRef = useRef<string | null>(null);
  const initedRef = useRef(false);
  const shareBundleTokenRef = useRef('');
  const contactInviteRef = useRef<{
    bundle: string;
    draft: ContactInviteDraft;
    expiresAt?: number;
  } | null>(null);
  const contactInvitePublishRef = useRef<Promise<{
    bundle: string;
    draft: ContactInviteDraft;
    expiresAt: number;
  }> | null>(null);

  function assertMessengerActive(): void {
    if (!lifecycleActiveRef.current) throw new MessengerInactiveError();
  }

  function assertRuntimeAvailable(): void {
    assertMessengerActive();
    if (runtimeSuspendedRef.current) throw new MessengerInactiveError();
  }

  async function runTrackedRuntimeOperation<T>(
    operation: (
      signal: AbortSignal,
      trackedOperation: TrackedRuntimeOperation,
    ) => Promise<T>,
  ): Promise<T> {
    assertMessengerActive();
    const controller = new AbortController();
    let markSettled!: () => void;
    const settled = new Promise<void>((resolve) => {
      markSettled = resolve;
    });
    const tracked: TrackedRuntimeOperation = { controller, settled };
    runtimeOperationsRef.current.add(tracked);
    // The registration happens synchronously before the first await, so a lock
    // can neither miss this operation nor race a later operation into the set.
    try {
      assertMessengerActive();
      return await operation(controller.signal, tracked);
    } finally {
      runtimeOperationsRef.current.delete(tracked);
      markSettled();
    }
  }

  async function runRuntimeOperation<T>(
    operation: (signal: AbortSignal) => Promise<T>,
  ): Promise<T> {
    return runTrackedRuntimeOperation((signal) => operation(signal));
  }

  /** Fire an event-driven writer under the same lifetime fence as backup work.
   * Quiescence aborts and joins it before the active vault DB or Web Lock can be
   * handed to another account/generation. Individual handlers keep their own
   * user-facing errors; lifecycle cancellation is deliberately silent. */
  function launchRuntimeOperation(
    operation: (signal: AbortSignal) => Promise<unknown>,
  ): void {
    if (runtimeSuspendedRef.current) return;
    void runRuntimeOperation(async (signal) => {
      if (signal.aborted) throw new MessengerInactiveError();
      const result = await operation(signal);
      if (signal.aborted) throw new MessengerInactiveError();
      return result;
    }).catch((error) => {
      if (
        error instanceof MessengerInactiveError ||
        !lifecycleActiveRef.current
      ) {
        return;
      }
      setError(
        t('Vorgang fehlgeschlagen: {msg}', {
          msg:
            error instanceof ContactCodeError || error instanceof OfficialAccountError
              ? t(error.message)
              : error instanceof Error
                ? error.message
                : String(error),
        }),
      );
    });
  }

  const [, bump] = useReducer((x: number) => x + 1, 0);
  function trustedOfficialAccountFor(
    contact: Contact,
  ): TrustedOfficialAccountDocument | null {
    const trusted = officialAccountTrustRef.current;
    return isOfficialAdminContact(contact, trusted) ? trusted : null;
  }

  /** A root-signed revocation remains a warning even after its short directory
   * lease expires. `current` controls positive ADMIN authority; it must never
   * erase negative knowledge that this exact former master was revoked. */
  function revokedOfficialAccountForMaster(
    masterPub: Uint8Array,
  ): TrustedOfficialAccountDocument | null {
    const trusted = officialAccountTrustRef.current;
    return isRevokedOfficialAdminMaster(masterPub, trusted) ? trusted : null;
  }

  function revokedOfficialAccountFor(
    contact: Contact,
  ): TrustedOfficialAccountDocument | null {
    const trusted = officialAccountTrustRef.current;
    return isRevokedOfficialAdminContact(contact, trusted) ? trusted : null;
  }

  function officialAccountNameLocked(contact: Contact): boolean {
    return !!(
      trustedOfficialAccountFor(contact) ||
      revokedOfficialAccountFor(contact)
    );
  }

  function assertNormalSendAllowed(contact: Contact): void {
    if (!revokedOfficialAccountFor(contact)) return;
    throw new OfficialAccountError(
      'revoked',
      t('Senden blockiert: Dieser frühere Admin-Schlüssel wurde widerrufen. Verbinde dich über SKYTALE-SUPPORT neu.'),
    );
  }

  function groupHasRevokedOfficialMember(group: Group): boolean {
    return group.members.some((member) =>
      !!revokedOfficialAccountForMaster(memberMasterPub(member)),
    );
  }

  function displayName(contact: Contact): string {
    return officialAccountNameLocked(contact)
      ? OFFICIAL_ACCOUNT_DISPLAY_NAME
      : ordinaryDisplayName(contact);
  }

  function installOfficialAccountTrust(
    trusted: TrustedOfficialAccountDocument,
  ): void {
    officialAccountTrustRef.current = trusted;
    scheduleOfficialTrustExpiryRerender(trusted);
    const active = contactsRef.current.find(
      (contact) => contact.roomId === activeRoomRef.current,
    );
    if (active && officialAccountNameLocked(active)) {
      setRenaming(false);
    }
    // A valid revoked document deliberately removes the badge immediately.
    bump();
  }

  /** Expiry is part of badge authorization, not merely cache freshness. Wake the
   * UI at the skew-adjusted boundary even if a long-running unlocked tab has no
   * successful network refresh or unrelated React state update. */
  function scheduleOfficialTrustExpiryRerender(
    trusted: TrustedOfficialAccountDocument,
  ): void {
    if (officialTrustExpiryTimerRef.current !== null) {
      clearTimeout(officialTrustExpiryTimerRef.current);
      officialTrustExpiryTimerRef.current = null;
    }
    if (trusted.current !== true || trusted.manifest.status !== 'active') return;
    const expiresAt =
      trusted.manifest.notAfter + OFFICIAL_ACCOUNT_CLOCK_SKEW_MS;
    const check = () => {
      if (
        !lifecycleActiveRef.current ||
        officialAccountTrustRef.current !== trusted
      ) {
        return;
      }
      const remaining = expiresAt - Date.now();
      if (remaining <= 0) {
        officialTrustExpiryTimerRef.current = null;
        bump();
        return;
      }
      officialTrustExpiryTimerRef.current = setTimeout(
        check,
        Math.min(remaining, OFFICIAL_TRUST_TIMER_STEP_MS),
      );
    };
    check();
  }

  const [fingerprint, setFingerprint] = useState('');
  const [shareBundleToken, setShareBundleToken] = useState('');
  const [qrDataUrl, setQrDataUrl] = useState('');
  const [contactCode, setContactCode] = useState('');
  const [contactCodeExpiresAt, setContactCodeExpiresAt] = useState(0);
  const [contactCodeStatus, setContactCodeStatus] = useState<
    'idle' | 'publishing' | 'ready' | 'failed'
  >('idle');
  const [view, setView] = useState<View>('list');
  const [conversationQuery, setConversationQuery] = useState('');
  const [activeRoom, setActiveRoom] = useState<string | null>(null);
  const [messages, setMessages] = useState<Record<string, ChatMessage[]>>({});
  const [statuses, setStatuses] = useState<Record<string, RelayStatus>>({});
  const [addInput, setAddInput] = useState('');
  // The composer input is UNCONTROLLED (its value lives in the DOM via this ref) and
  // we only track a `hasText` boolean that flips on the empty↔non-empty transition.
  // So typing no longer re-renders the whole message list on every keystroke — the
  // main source of the lag in long/group chats. Read/clear go through the ref.
  const msgInputRef = useRef<HTMLTextAreaElement>(null);
  const [hasText, setHasText] = useState(false);
  // Grow the composer with its content (like WhatsApp) up to a few lines, then
  // scroll inside it — so a long message stays readable instead of running off.
  function autoGrowComposer(el: HTMLTextAreaElement): void {
    el.style.height = 'auto';
    el.style.height = `${Math.min(el.scrollHeight, COMPOSER_MAX_HEIGHT)}px`;
  }
  const clearComposer = () => {
    if (msgInputRef.current) {
      msgInputRef.current.value = '';
      autoGrowComposer(msgInputRef.current);
    }
    setHasText(false);
  };
  // Message windowing: render only the most recent MSG_WINDOW messages so opening a
  // long/group chat isn't 3–4 s of rendering the ENTIRE history. Scrolling to the top
  // loads an older page (windowNRef/loadMoreRef drive the scroll effect below).
  const [windowN, setWindowN] = useState(MSG_WINDOW);
  const windowNRef = useRef(MSG_WINDOW);
  windowNRef.current = windowN;
  const loadMoreRef = useRef(false);
  const prevHeightRef = useRef(0);
  const [error, setError] = useState('');
  const [copied, setCopied] = useState(false);
  const [shared, setShared] = useState(false); // feedback for the share button's copy fallback
  const [renaming, setRenaming] = useState(false);
  const [renameInput, setRenameInput] = useState('');
  const [scanning, setScanning] = useState(false);
  const [chatMenu, setChatMenu] = useState(false);
  const [msgMenu, setMsgMenu] = useState<{ roomId: string; m: ChatMessage; x: number; y: number } | null>(null); // long-press popover, anchored at (x,y)
  const [forwardMsg, setForwardMsg] = useState<ChatMessage | null>(null); // message being forwarded → pick a contact
  // Setter forces UI refreshes when ownListRef changes.
  const [, setMultiDevice] = useState(false);
  const [recording, setRecording] = useState(false);
  const [recSeconds, setRecSeconds] = useState(0);
  const [myAvatarB64, setMyAvatarB64] = useState('');
  const [myName, setMyName] = useState('');
  const [profileName, setProfileName] = useState('');
  const [activeGroup, setActiveGroup] = useState<string | null>(null);
  const [groupNameInput, setGroupNameInput] = useState('');
  const [groupRenameInput, setGroupRenameInput] = useState('');
  const [groupSel, setGroupSel] = useState<Set<string>>(new Set());
  const [safetyNumber, setSafetyNumber] = useState('');
  const [safetyQr, setSafetyQr] = useState('');
  const [zoomImg, setZoomImg] = useState<Blob | null>(null); // full-screen image viewer (its own object URL)
  // A just-picked photo/video awaiting the send-preview sheet (where "view once" is chosen).
  // `data` = in-memory bytes (images, small); `file` = the raw File (videos, streamed to R2
  // without ever buffering the whole thing). Exactly one is set.
  const [pendingMedia, setPendingMedia] = useState<{ file: File | null; data: Uint8Array<ArrayBuffer> | null; size: number; name: string; mime: string; url: string; isVideo: boolean } | null>(null);
  const [pendingVO, setPendingVO] = useState(false); // the preview's "einmal ansehen" toggle
  const [r2Upload, setR2Upload] = useState<number | null>(null); // 0..1 while a large file uploads to R2, else null
  const [transcoding, setTranscoding] = useState<number | null>(null); // 0..1 while a video is transcoded to 720p, else null
  const [viewOnce, setViewOnce] = useState<{ blob: Blob; mime: string } | null>(null); // the currently-open view-once media (already wiped from storage)
  const [notifOn, setNotifOn] = useState(false);
  const [notifBusy, setNotifBusy] = useState(false);
  const [qrFull, setQrFull] = useState(false); // own QR blown up full-screen for scanning
  const [cropFile, setCropFile] = useState<File | null>(null); // avatar being cropped
  const [stickerFile, setStickerFile] = useState<File | null>(null); // image becoming a sticker
  const [stickers, setStickers] = useState<Sticker[]>([]);
  const [stickerPanel, setStickerPanel] = useState(false);
  // A sticker tapped in a chat, shown big with the option to keep it.
  const [stickerZoom, setStickerZoom] = useState<{ mime: string; dataB64: string } | null>(null);
  const [replyTo, setReplyTo] = useState<Quote | null>(null); // message being answered
  const swipeReplyRef = useRef<{
    mid: string;
    x: number;
    y: number;
    el: HTMLElement;
    lock: 'h' | 'v' | null; // committed drag axis; decided once, then never re-checked
    dx: number; // last horizontal travel, so a cancelled-but-far-enough drag still fires
  } | null>(null);
  const longPressRef = useRef<number | null>(null); // hold-to-recall timer on own bubbles
  const [backupMode, setBackupMode] = useState<'export' | 'import' | null>(null);
  const [bioSupported, setBioSupported] = useState(false); // platform authenticator present
  const [bioOn, setBioOn] = useState(false); // biometric unlock enrolled for this vault
  const [bioEnroll, setBioEnroll] = useState(false); // enrollment modal open
  const [duressOn, setDuressOn] = useState(false); // a duress password is set for this vault
  const [duressModal, setDuressModal] = useState<'set' | 'remove' | null>(null); // duress setup modal
  const [populatePrompt, setPopulatePrompt] = useState(false); // "fill the decoy" passphrase prompt
  const [populatePass, setPopulatePass] = useState('');
  const [populateErr, setPopulateErr] = useState('');
  const [populateBusy, setPopulateBusy] = useState(false);
  // Switch into the decoy account to populate it: verify the duress passphrase (no wipe — populate
  // is the non-destructive path), then hand App the decoy DEK so it repoints the active DB.
  async function doPopulate() {
    if (populateBusy || !populatePass) return;
    setPopulateBusy(true);
    setPopulateErr('');
    try {
      await runTrackedRuntimeOperation(async (signal, trackedOperation) => {
        const decoyDek = await openDecoyForPopulate(populatePass);
        // Argon2/WebCrypto cannot be interrupted mid-call. A lock may nevertheless
        // have aborted this operation while it was suspended, so reject its late
        // result before it can hide the prompt or start an account transition.
        if (signal.aborted) throw new MessengerInactiveError();
        assertMessengerActive();
        setPopulatePrompt(false);
        setPopulatePass('');
        // Drain the REAL account's inbox before App repoints the active DB, so no
        // in-flight receive persists real-DEK ciphertext into the decoy database.
        // Excluding this operation prevents a self-join deadlock; an EXTERNAL lock
        // calls quiesce without the exemption and therefore still aborts + joins it.
        await quiesceForUnmount(trackedOperation);
        if (signal.aborted) throw new MessengerInactiveError();
        setPopulateBusy(false);
        onEnterDecoy?.(decoyDek);
      });
    } catch (e) {
      if (e instanceof MessengerInactiveError || !lifecycleActiveRef.current) return;
      setPopulateErr(e instanceof WrongPassphraseError ? t('Falsches Duress-Passwort.') : t('Wechsel fehlgeschlagen.'));
      setPopulateBusy(false);
    }
  }

  /** Quiesce every relay and drain already-queued inbox handlers. Used before a restore installs its
   * cross-tab write fence AND before an in-app account switch (real ↔ decoy): closing the relays
   * stops new tasks, and awaiting the queue lets any in-flight onInbox finish, so no ciphertext
   * sealed under the OUTGOING account's DEK is persisted/ACKed into the incoming account's database
   * (which would corrupt the decoy / desync the real ratchet). */
  async function quiesceInbox(): Promise<void> {
    for (const relay of relaysRef.current.values()) relay.close();
    relaysRef.current.clear();
    sendRoomRef.current.clear();
    inboxClientRef.current = null;
    // Drain ALL writer queues to one joint fixed point. Draining them one after
    // another is insufficient: a finishing recall/group/storage task can append
    // a message or inbox task after that earlier queue was already observed idle.
    // Account switches and restore may repoint/replace the DB only once the whole
    // graph is stable in the same observation.
    for (;;) {
      const inboxTail = inboxQueueRef.current;
      const recallTail = recallMutationQueueRef.current;
      const groupTail = groupMutationQueueRef.current;
      const storageTail = storageGateRef.current;
      const groupRetry = groupMutationRetryRef.current;
      await Promise.all([
        inboxTail.catch(() => undefined),
        messageMutationQueueRef.current.drain(),
        recallTail.catch(() => undefined),
        groupTail.catch(() => undefined),
        storageTail.catch(() => undefined),
        groupRetry?.catch(() => undefined) ?? Promise.resolve(),
      ]);
      if (
        inboxQueueRef.current === inboxTail &&
        recallMutationQueueRef.current === recallTail &&
        groupMutationQueueRef.current === groupTail &&
        storageGateRef.current === storageTail &&
        groupMutationRetryRef.current === groupRetry &&
        messageMutationQueueRef.current.pending() === 0
      ) {
        break;
      }
    }
  }

  /** Reversible, fail-closed fence for a restore. This runs before the import
   * operation registers itself, so it can abort and join every older UI/KDF/
   * storage writer without self-joining. A failed import explicitly lifts it. */
  async function suspendForRestore(): Promise<void> {
    assertMessengerActive();
    if (runtimeSuspendedRef.current) return;
    runtimeSuspendedRef.current = true;
    for (const operation of runtimeOperationsRef.current) {
      operation.controller.abort();
    }
    await quiesceInbox();
    for (;;) {
      const pendingOperations = [...runtimeOperationsRef.current];
      if (pendingOperations.length === 0) break;
      await Promise.all(
        pendingOperations.map((operation) =>
          operation.settled.catch(() => undefined),
        ),
      );
    }
    // Boot performs identity/prekey reads and possible initialization before it
    // enters inboxQueueRef. Join that prefix as well; its later relay connects
    // are suppressed by runtimeSuspendedRef.
    await bootTaskRef.current?.catch(() => undefined);
    assertMessengerActive();
  }

  /** Permanently invalidate this Messenger generation and wait for every known
   * writer before App releases the origin-wide Web Lock. */
  async function quiesceForUnmount(
    exemptOperation?: TrackedRuntimeOperation,
  ): Promise<void> {
    lifecycleActiveRef.current = false;
    if (officialTrustExpiryTimerRef.current !== null) {
      clearTimeout(officialTrustExpiryTimerRef.current);
      officialTrustExpiryTimerRef.current = null;
    }
    // A locked/unmounted messenger must never leave a live microphone behind.
    // Detach recorder callbacks before stop so `onstop` cannot launch a late
    // finishRecording writer after this generation has been invalidated.
    sendOnStopRef.current = false;
    const recorder = mediaRecorderRef.current;
    if (recorder && recorder.state !== 'inactive') {
      recorder.ondataavailable = null;
      recorder.onstop = null;
      try {
        recorder.stop();
      } catch {
        // It may have transitioned to inactive between the state read and stop.
      }
    }
    recChunksRef.current = [];
    cleanupRecording();
    for (const operation of runtimeOperationsRef.current) {
      if (operation === exemptOperation) continue;
      operation.controller.abort();
    }
    await quiesceInbox();
    // The active bit prevents new registrations. Drain to a fixed point anyway
    // so a finishing operation cannot escape via a continuation registered just
    // before invalidation.
    for (;;) {
      const pendingOperations = [...runtimeOperationsRef.current].filter(
        (operation) => operation !== exemptOperation,
      );
      if (pendingOperations.length === 0) break;
      await Promise.all(
        pendingOperations.map((operation) =>
          operation.settled.catch(() => undefined),
        ),
      );
    }
    await bootTaskRef.current?.catch(() => undefined);
  }

  /** Leave the decoy populate session back to the real account: drain the decoy inbox FIRST (so no
   *  in-flight decoy receive persists into the real 'scytale' DB), then hand control back to App. */
  async function handleExitDecoy(
    exemptOperation?: TrackedRuntimeOperation,
  ): Promise<void> {
    await quiesceForUnmount(exemptOperation);
    onExitDecoy?.();
  }

  /** A failed import leaves the old generation intact and removes the fence.
   * Rebuild the closed relay clients so queued server rows can drain normally. */
  async function resumeAfterFailedRestore(): Promise<void> {
    if (!lifecycleActiveRef.current) return;
    runtimeSuspendedRef.current = false;
    const id = identityRef.current;
    if (!id) return;
    for (const contact of contactsRef.current) await connectSend(contact);
    connectInbox(await inboxRoom(id.sign.publicKey));
    void requestBootstrap().catch(() => undefined);
    void schedulePendingGroupMutationRetry().catch(() => undefined);
  }

  const [langSheet, setLangSheet] = useState(false); // language picker open
  const [bugOpen, setBugOpen] = useState(false); // bug-report modal open
  const [deleteOpen, setDeleteOpen] = useState(false); // account-delete confirmation open
  const [wiping, setWiping] = useState(false); // account wipe in progress
  const [deviceNames, setDeviceNames] = useState<DeviceNames>({}); // b64(signPub) → local name
  const [removeDev, setRemoveDev] = useState<Uint8Array<ArrayBuffer> | null>(null); // device pending remove-confirm

  /** Publish only a monotonically newer durable own-device authority. Multiple
   * CAS writers may finish their network continuations out of order; a stale
   * continuation must never roll RAM back and gossip a still-valid older list. */
  function publishOwnDeviceList(candidate: DeviceList): DeviceList {
    const current = ownListRef.current;
    if (!current || compareDeviceList(candidate, current) > 0) {
      ownListRef.current = candidate;
      setMultiDevice(candidate.devices.length > 1);
      return candidate;
    }
    return current;
  }

  /** Re-read the CAS-protected record after a commit and publish the maximum of
   * that durable snapshot and any newer durable result already seen in RAM. */
  async function reconcileOwnDeviceList(
    committed?: DeviceList,
  ): Promise<DeviceList> {
    if (committed) publishOwnDeviceList(committed);
    const id = identityRef.current;
    const pre = prekeysRef.current;
    if (!id || !pre) {
      throw new MessengerInactiveError();
    }
    const durable = await loadOrCreateOwnDeviceList(
      dek,
      id,
      ownSpkPublic(pre),
    );
    if (!durable) {
      throw new Error(t('Aktuelle Geräteliste nicht verfügbar.'));
    }
    return publishOwnDeviceList(durable);
  }

  // Rename one of my devices (local-only name store; never gossiped).
  async function renameDevice(signPub: Uint8Array<ArrayBuffer>, current: string) {
    const name = window.prompt(t('Gerätename'), current);
    if (name === null) return;
    setDeviceNames(await setDeviceName(dek, signPub, name));
  }
  // Master removes a device: revoke (re-sign the list without it) + gossip. The removed
  // device self-wipes when the newer list reaches it.
  async function removeDeviceAction(signPub: Uint8Array<ArrayBuffer>) {
    setRemoveDev(null);
    const id = identityRef.current;
    const cur = ownListRef.current;
    if (!id || !cur) return;
    // Grab the self-contact WHILE it still holds a session + list entry for the target — the
    // subsequent gossip prunes it, so this is our one chance to reach that device directly.
    const self = await ensureSelfContact();
    const next = await revokeDevice(dek, id, cur, signPub);
    if (!next) return;
    const authoritative = await reconcileOwnDeviceList(next);
    // Deliver the new, revoking list DIRECTLY to the removed device BEFORE it's pruned from
    // the fan-out set — otherwise it never learns it's gone and its self-wipe never fires
    // (audit H4). `only: signPub` targets exactly that device; it verifies my master + newer
    // list, sees it's omitted, and self-wipes.
    if (self) {
      try {
        const { deliveries } = await enqueueInbox(async () => {
          const current = requireCurrentContact(self);
          const r = await fanoutFromThisDevice(id, current, { kind: 'devlist', list: authoritative }, randomMid(), undefined, signPub);
          await saveContact(dek, current);
          return r;
        });
        for (const d of deliveries) {
          const room = await inboxRoom(d.deviceSignPub);
          connectDeviceInbox(room);
          relaysRef.current.get(room)?.send(d.sealed, randomMid(), true); // silent
        }
      } catch {
        /* best effort — the device also learns it via normal gossip if it reconnects */
      }
    }
    await gossipDeviceList(authoritative);
    bump();
  }
  // This (linked) device unlinks itself → same as an account wipe (which already tells the
  // primary when we're a linked device). Kept as its own action for the manage view.
  async function unlinkSelfAction() {
    setRemoveDev(null);
    await doWipeAccount();
  }

  // Irreversibly wipe this device's crypto container, then reload into onboarding. On a
  // LINKED device, first ask the primary to revoke us (so the master + contacts stop
  // fanning out to this now-dead device and it drops out of the device list). Best-effort,
  // sent BEFORE the wipe so the mailbox holds it even if the primary is offline; we wipe
  // regardless of whether the notice got through. The primary has no one to notify.
  async function doWipeAccount(): Promise<void> {
    return runTrackedRuntimeOperation((signal, trackedOperation) =>
      doWipeAccountWithinRuntime(signal, trackedOperation),
    );
  }

  async function doWipeAccountWithinRuntime(
    signal: AbortSignal,
    trackedOperation: TrackedRuntimeOperation,
  ): Promise<void> {
    if (populatingDecoy) {
      // wipeAccount is deliberately device-global and would delete BOTH vault
      // databases. A reset/revocation encountered while merely populating the
      // decoy must therefore never destroy the mounted-but-hidden real account.
      setError(t('Decoy-Reset während der Befüllung blockiert — zurück im echten Konto kannst du den Decoy neu einrichten.'));
      await handleExitDecoy(trackedOperation);
      return;
    }
    setWiping(true);
    try {
      if (signal.aborted) throw new MessengerInactiveError();
      const id = identityRef.current;
      if (id && !isPrimaryDevice(id)) {
        const self = await ensureSelfContact().catch(() => null);
        if (self) await fanoutSend(self, { kind: 'unlinkreq' }, randomMid(), 4).catch(() => undefined);
      }
      // Remove the server-side endpoint while the authenticated owner socket and
      // local subscription still exist. Relay acknowledgement is bounded/best-effort:
      // an unreachable server must never make a local cryptographic wipe impossible.
      const subscription = await settleWithin(
        currentSubscription().catch(() => null),
        PUSH_UNSUBSCRIBE_TIMEOUT_MS,
      );
      if (subscription?.endpoint && inboxClientRef.current) {
        await settleWithin(
          Promise.resolve(inboxClientRef.current.unsubscribePush(subscription.endpoint)),
          PUSH_UNSUBSCRIBE_TIMEOUT_MS,
        ).catch(() => undefined);
      }
      // Persist disabled intent and remove the browser endpoint only after the
      // server attempt; wipeAccount then unregisters the worker and clears storage.
      // Start this exactly once. If a browser API stalls, wipeAccount still
      // proceeds after the bound and unregisters the worker; a second concurrent
      // disable attempt could otherwise recreate the control cache after wiping.
      await settleWithin(
        disablePush().catch(() => null),
        PUSH_UNSUBSCRIBE_TIMEOUT_MS,
      );
      await wipeAccount({ pushTeardownStarted: true });
    } finally {
      location.reload();
    }
  }

  // ── Device linking ────────────────────────────────────────────────
  // 'menu'  : choose join-as-new vs add-a-device
  // 'qr'    : N shows its QR, waits for the offer
  // 'scan'  : P scans N's QR
  // 'sas'   : both compare the 7 emoji
  // 'done'  : linked
  const [linkView, setLinkView] = useState<'menu' | 'qr' | 'scan' | 'sas' | 'done' | null>(null);
  const [linkQr, setLinkQr] = useState(''); // N's QR image
  const [linkSas, setLinkSas] = useState<SasResult | null>(null);
  const [linkBusy, setLinkBusy] = useState(false);
  const linkSessionRef = useRef<LinkSession | null>(null);
  // Anonymous sealed Grant rows are held individually. A fake/stale candidate
  // may only retire ITS relay row; it must never ACK a valid candidate queued
  // for the same confirmed transcript.
  const linkPendingGrantsRef = useRef<Map<number, Bytes>>(new Map());
  const linkInstallPromiseRef = useRef<Promise<boolean> | null>(null);
  const linkAbortInProgressRef = useRef(false);
  const linkConfirmedRef = useRef(false); // N confirmed the SAS locally
  const confirmedLinkIntentRef = useRef<ConfirmedNewDeviceLinkIntent | null>(null);
  // Rejection-only sessions reconstructed without confirmLinkSession. They can
  // classify a late credential from an explicitly discarded transcript, but
  // cannot ever pass completeLinkOnN's confirmation capability check.
  const discardedLinkSessionsRef = useRef<LinkSession[]>([]);
  // Set synchronously when N confirms and kept through durable recovery. While
  // true, generic UI reset/close paths may hide the overlay but must not discard
  // the session/intent or ACK held Grant rows.
  const linkRecoveryProtectedRef = useRef(false);
  const [linkAbortBusy, setLinkAbortBusy] = useState(false);
  const [primaryLinkDeliveryPending, setPrimaryLinkDeliveryPending] = useState(false);
  const primaryPendingLinkTargetRef = useRef<Bytes | null>(null);
  const [swipeDx, setSwipeDx] = useState(0); // edge-swipe-back drag distance
  const [swiping, setSwiping] = useState(false);
  const swipeStart = useRef<{ x: number; y: number } | null>(null);
  const ackTimers = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());
  // A relay can answer synchronously/within the same task, before the outbound bubble has been
  // persisted. Keep only receipts for deliveryIds whose timer was registered before send().
  const earlyDeliveryReceiptsRef = useRef<Map<
    string,
    { status: 'sent' | 'failed'; errorMsg?: string }
  >>(new Map());

  useEffect(() => {
    void (async () => {
      const [avail, enrolled, duress] = await Promise.all([biometricAvailable(), biometricEnrolled(), duressEnabled()]);
      setBioSupported(avail);
      setBioOn(enrolled);
      setDuressOn(duress);
    })();
  }, []);
  useEffect(() => {
    activeRoomRef.current = activeRoom;
  }, [activeRoom]);
  useEffect(() => {
    viewRef.current = view;
  }, [view]);
  useEffect(() => {
    if (view !== 'add' || !shareBundleToken) return;
    launchRuntimeOperation((signal) => ensureContactInvite(signal));
    // The bundle changes only after a real identity transition. Publishing is
    // deliberately lazy: merely unlocking SKYTALE reveals no contact metadata
    // to the rendezvous service.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [view, shareBundleToken]);
  useEffect(() => {
    activeGroupRef.current = activeGroup;
  }, [activeGroup]);

  // ── Hardware/gesture Back = go up one level, don't leave the PWA ──────────
  // We keep the browser history depth in step with the view depth: descending a
  // level pushes one guard entry; an in-app back button (which lowers `view`)
  // rewinds it programmatically. A real Back press then pops one guard, and the
  // popstate handler moves the view up a level instead of the PWA exiting (which
  // on Android dropped the DEK and forced a re-unlock). At the list there are no
  // guards left, so Back does its default thing (leave the app).
  const histDepthRef = useRef(0);
  const suppressPopRef = useRef(false);
  useEffect(() => {
    const target = viewDepth(view);
    const cur = histDepthRef.current;
    if (target > cur) {
      for (let i = cur; i < target; i++) history.pushState({ scyDepth: i + 1 }, '');
      histDepthRef.current = target;
    } else if (target < cur) {
      // View rose via an in-app control — consume the surplus guards, but tell the
      // popstate handler to ignore the resulting event (the view is already right).
      suppressPopRef.current = true;
      histDepthRef.current = target;
      history.go(target - cur); // negative → pops (cur - target) entries
    }
  }, [view]);
  useEffect(() => {
    const onPop = () => {
      if (suppressPopRef.current) {
        suppressPopRef.current = false; // our own history.go() rewind — not a user Back
        return;
      }
      const v = viewRef.current;
      if (v === 'list') return; // top level → let the browser handle it (exit)
      histDepthRef.current = Math.max(0, histDepthRef.current - 1);
      setView(parentView(v)); // step up one level; the guard was already popped
    };
    window.addEventListener('popstate', onPop);
    return () => window.removeEventListener('popstate', onPop);
  }, []);

  const commitMessages = () => setMessages({ ...messagesRef.current });

  function withStorageGate<T>(task: () => Promise<T>): Promise<T> {
    if (!lifecycleActiveRef.current || runtimeSuspendedRef.current) {
      return Promise.reject(new MessengerInactiveError());
    }
    const run = storageGateRef.current.catch(() => undefined).then(task);
    storageGateRef.current = run.catch(() => undefined);
    return run;
  }

  async function originCanReserve(requestedBytes: number, smallWrite = false): Promise<boolean> {
    if (!navigator.storage?.estimate) return false;
    let estimate: StorageEstimate | null;
    let markerIds: string[];
    try {
      [estimate, markerIds] = await Promise.all([
        navigator.storage.estimate(),
        allRecvMarkerIds(),
      ]);
    } catch {
      return false;
    }
    const markers = await Promise.all(markerIds.map((id) => getRecvMarker(dek, id).catch(() => null)));
    let volatileReservations = 0;
    for (const bytes of r2ReservationsRef.current.values()) {
      if (volatileReservations > Number.MAX_SAFE_INTEGER - bytes) {
        volatileReservations = Number.MAX_SAFE_INTEGER;
        break;
      }
      volatileReservations += bytes;
    }
    const persistedReservations = remainingRecvReservationBytes(markers);
    const reserved =
      persistedReservations > Number.MAX_SAFE_INTEGER - volatileReservations
        ? Number.MAX_SAFE_INTEGER
        : persistedReservations + volatileReservations;
    return hasOriginStorageHeadroom(estimate, requestedBytes, reserved, smallWrite);
  }

  function markRecvDropped(tid: string): void {
    // Bound attacker-controlled bookkeeping for a long-lived open tab.
    if (droppedRecvRef.current.size >= 1024) {
      const oldest = droppedRecvRef.current.values().next().value as string | undefined;
      if (oldest) droppedRecvRef.current.delete(oldest);
    }
    droppedRecvRef.current.add(tid);
    const changed = downloadingRef.current.delete(tid);
    pullProgressRef.current.delete(tid);
    if (changed) bump();
  }

  /**
   * Turn attachment bytes into a stored FileRef. Non-stickers go to the out-of-band
   * attachment store (so the message log never re-encrypts a whole file on append);
   * stickers stay inline (tiny, and the sticker library dedups on their bytes). The
   * WIRE is unchanged — files still travel as inline bytes; this is local storage.
   */
  async function fileRefFor(name: string, mime: string, data: Uint8Array, viewOnce?: boolean): Promise<FileRef> {
    if (name === STICKER_FILENAME) return { name, mime, dataB64: bytesToB64(data) };
    const attId = newAttachmentId();
    await putAttachment(dek, attId, data, name, mime);
    return { name, mime, attId, size: data.length, ...(viewOnce ? { viewOnce: true } : {}) };
  }

  /** Admission for every peer-controlled inline attachment path (plain file,
   * reply, group and self-sync). Chunk/R2 transfers have their own reservations.
   * A denial becomes an explicit placeholder, not an unbounded IndexedDB write. */
  async function inboundFileRefFor(
    roomId: string,
    name: string,
    mime: string,
    data: Uint8Array,
    viewOnce?: boolean,
  ): Promise<FileRef | null> {
    if (!Number.isSafeInteger(data.length) || data.length < 0 || data.length > MAX_ATTACH) return null;
    if (messagesRef.current[roomId] === undefined) {
      messagesRef.current[roomId] = await loadMessages(dek, roomId);
    }
    return withStorageGate(async () => {
      // The per-contact cap always applies (a peer must not fill the device with
      // small files). A small inline payload is already in RAM, so it only needs a
      // relaxed device-headroom floor instead of the large auto-download reserve —
      // that reserve used to dead-end a ~1 KB file when the device was low on space.
      const smallWrite = data.length <= ALWAYS_RECEIVE_INLINE_BYTES;
      const markerIds = await allRecvMarkerIds();
      const activeMarkers = await Promise.all(
        markerIds.map((id) => getRecvMarker(dek, id).catch(() => null)),
      );
      if (
        !mayAutoReceiveAttachment(
          messagesRef.current[roomId] ?? [],
          data.length,
          AUTO_RECEIVE_CONTACT_CAP_BYTES,
          automaticRecvReservationBytes(activeMarkers, roomId),
        ) ||
        !(await originCanReserve(data.length, smallWrite))
      ) {
        return null;
      }
      try {
        return await fileRefFor(name, mime, data, viewOnce);
      } catch (error) {
        if (isStorageFull(error)) return null;
        throw error;
      }
    });
  }

  /** A self-contained quote of a message, for the reply preview + the sent frame. */
  function quoteFrom(m: ChatMessage): Quote {
    let text = m.text ?? '';
    if (!text && m.file) {
      text = isSticker(m.file)
        ? 'Sticker'
        : m.file.mime.startsWith('image/')
          ? 'Foto'
          : m.file.mime.startsWith('video/')
            ? 'Video'
            : m.file.mime.startsWith('audio/')
              ? 'Sprachnachricht'
              : m.file.name;
    }
    return { mid: m.mid ?? '', text: text.slice(0, 140), sender: m.sender, mine: !!m.mine };
  }

  /** Build the display message for an inbound `reply` frame (quote + inner text/file). */
  async function replyMessage(
    quote: Quote,
    inner: MessageContent,
    mid: string,
    mine: boolean,
    inboundRoomId?: string,
  ): Promise<ChatMessage> {
    const base = { mine, ts: Date.now(), mid, reply: quote };
    if (inner.kind === 'text') return { ...base, text: inner.text };
    if (inner.kind === 'file') {
      const file = inboundRoomId
        ? await inboundFileRefFor(inboundRoomId, inner.name, inner.mime, inner.data)
        : await fileRefFor(inner.name, inner.mime, inner.data);
      return file
        ? { ...base, file }
        : { ...base, text: t('Anhang wegen des automatischen Speicherlimits nicht gespeichert.') };
    }
    return { ...base, text: '' };
  }

  // Swipe a bubble LEFT→RIGHT to reply. Horizontal only (a vertical drag scrolls
  // the chat); the bubble is dragged along with the finger, a reply arrow fades in
  // behind it, and past the trigger it opens the reply. On release it springs back
  // (CSS transition). Transform/CSS var are set on the element directly, so nothing
  // re-renders per frame; --reply-progress drives the arrow's fade + scale.
  function resetSwipe(el: HTMLElement) {
    el.style.transition = ''; // back to the stylesheet spring for the snap-back
    el.style.transform = '';
    el.style.setProperty('--reply-progress', '0');
  }
  function clearLongPress() {
    if (longPressRef.current !== null) {
      clearTimeout(longPressRef.current);
      longPressRef.current = null;
    }
  }
  // Hold a message → the floating action popover (reply / copy / forward / delete),
  // anchored at the press point. Not for a tombstone.
  function openMsgMenu(m: ChatMessage, x: number, y: number) {
    const roomId = activeRoomRef.current;
    if (!roomId || m.recalled) return;
    setMsgMenu({ roomId, m, x, y });
  }
  // Delete from the menu: MY message → recall it for everyone; a received one → remove
  // it just from this device. Both drop any attachment blob (recall does so via
  // retractMessage; local delete does it here).
  async function deleteFromMenu(roomId: string, m: ChatMessage): Promise<void> {
    if (m.mine) {
      await recallMessage(roomId, m);
      return;
    }
    await enqueueMessageMutation(roomId, async () => {
      if (messagesRef.current[roomId] === undefined) {
        messagesRef.current[roomId] = await loadMessages(dek, roomId);
      }
      const arr = messagesRef.current[roomId] ?? [];
      const next = arr.filter((x) =>
        m.mid ? !(x.mid === m.mid && x.mine === m.mine) : x !== m,
      );
      await saveMessages(dek, roomId, next);
      messagesRef.current[roomId] = next;
      commitMessages();
    });
    // Keep the cryptographic erase inside the caller's tracked operation so a
    // vault/account transition cannot release its write fence while this local
    // deletion is still touching the outgoing account's attachment store.
    if (m.file?.attId) await secureWipeAttachment(m.file.attId);
  }
  function onBubblePointerDown(e: React.PointerEvent<HTMLDivElement>, m: ChatMessage) {
    // Desktop mouse: no long-press / swipe. Leave the pointer to native text
    // selection so a portion of a message can be selected and copied; copy and
    // reply come from the right-click menu (onContextMenu) instead.
    if (e.pointerType === 'mouse') return;
    if (!m.mid) return; // nothing to link a reply to
    // Don't touch transition/transform yet — wait until the drag commits to the
    // horizontal axis, so a tap or a vertical scroll leaves the bubble untouched.
    swipeReplyRef.current = { mid: m.mid, x: e.clientX, y: e.clientY, el: e.currentTarget, lock: null, dx: 0 };
    // Press-and-hold → the message action popover (unless it's already a tombstone).
    clearLongPress();
    if (!m.recalled) {
      const px = e.clientX;
      const py = e.clientY;
      longPressRef.current = window.setTimeout(() => openMsgMenu(m, px, py), 500);
    }
  }
  function onBubblePointerMove(e: React.PointerEvent<HTMLDivElement>) {
    const st = swipeReplyRef.current;
    if (!st) return;
    const dx = e.clientX - st.x;
    const dy = e.clientY - st.y;
    const ax = Math.abs(dx);
    const ay = Math.abs(dy);
    if (ax > 6 || ay > 6) clearLongPress(); // any real movement → it's a drag, not a hold
    // Decide the axis ONCE, then never re-check it — so a vertical wobble mid-drag
    // can't abort a horizontal reply gesture. Bias toward horizontal: vertical only
    // wins if it CLEARLY dominates (SWIPE_BIAS×), otherwise a mostly-sideways drag
    // that drifts a little down stays a reply drag instead of being handed to scroll.
    if (st.lock === null) {
      if (ax >= SWIPE_SLOP && ax >= ay) {
        st.lock = 'h';
        st.el.style.transition = 'none'; // now follow the finger 1:1
        try {
          // Capture so move/up keep firing even once the pointer leaves the bubble.
          st.el.setPointerCapture(e.pointerId);
        } catch {
          /* capture is a nicety; the drag still works without it */
        }
      } else if (ay >= SWIPE_SLOP && ay > ax * SWIPE_BIAS) {
        swipeReplyRef.current = null; // clear vertical intent → hand it to native scroll
        return;
      } else {
        return; // still ambiguous — wait for a clearer direction
      }
    }
    if (st.lock !== 'h') return;
    st.dx = dx;
    // 1:1 up to the trigger, then rubber-band with resistance instead of a hard wall.
    let t = Math.max(0, dx);
    if (t > REPLY_TRIGGER) t = REPLY_TRIGGER + (t - REPLY_TRIGGER) * REPLY_DAMP;
    t = Math.min(t, REPLY_MAX);
    st.el.style.transform = `translateX(${t}px)`;
    st.el.style.setProperty('--reply-progress', String(Math.min(1, t / REPLY_TRIGGER)));
  }
  // Shared end for both pointerup and pointercancel. Using the last tracked dx (not
  // the event's coordinates) means a drag the browser CANCELS after it passed the
  // trigger still opens the reply, instead of being silently lost.
  function endBubbleSwipe(m: ChatMessage) {
    clearLongPress(); // finger lifted before the hold fired → it was a tap/swipe
    const st = swipeReplyRef.current;
    if (!st) return;
    const fire = st.lock === 'h' && st.dx > REPLY_TRIGGER;
    if (st.lock === 'h') resetSwipe(st.el); // springs back to rest
    swipeReplyRef.current = null;
    if (fire) setReplyTo(quoteFrom(m));
  }
  // Tapping a reply's quoted preview smooth-scrolls the chat to the original
  // message and flashes it. No-op if the original isn't in the loaded log.
  function scrollToQuoted(mid: string | undefined) {
    if (!mid) return;
    const container = document.getElementById('msgs');
    const target = container?.querySelector<HTMLElement>(`[data-mid="${CSS.escape(mid)}"]`);
    if (!target) return;
    target.scrollIntoView({ behavior: 'smooth', block: 'center' });
    target.classList.remove('quote-flash');
    void target.offsetWidth; // reflow so the animation restarts on repeat taps
    target.classList.add('quote-flash');
    window.setTimeout(() => target.classList.remove('quote-flash'), 1200);
  }
  // Once a reply drag is committed to horizontal, stop the browser from scrolling
  // the chat. Without this the browser can hijack a drag that drifts vertically and
  // fire pointercancel, snapping the bubble back mid-gesture. Must be a NON-passive
  // listener for preventDefault to actually suppress the scroll.
  useEffect(() => {
    const stopScrollWhileDragging = (e: TouchEvent) => {
      if (swipeReplyRef.current?.lock === 'h') e.preventDefault();
    };
    document.addEventListener('touchmove', stopScrollWhileDragging, { passive: false });
    return () => document.removeEventListener('touchmove', stopScrollWhileDragging);
  }, []);

  function consumeEarlyDeliveryReceipts(msg: ChatMessage): ChatMessage {
    if (!msg.deliveries?.length) return msg;
    let changed = false;
    const deliveries = msg.deliveries.map((delivery) => {
      const receipt = earlyDeliveryReceiptsRef.current.get(delivery.deliveryId);
      if (!receipt) return delivery;
      earlyDeliveryReceiptsRef.current.delete(delivery.deliveryId);
      changed = true;
      return { ...delivery, status: receipt.status };
    });
    return changed ? { ...msg, deliveries } : msg;
  }

  async function appendMessage(roomId: string, msg: ChatMessage) {
    return enqueueMessageMutation(roomId, async () => {
      // Hydrate a COLD room from storage before appending. Boot preloads every
      // contact/group room (init effect), so post-boot `undefined` means a room with
      // no card — e.g. a self-sync display room for a peer this device hasn't added
      // yet.
      if (messagesRef.current[roomId] === undefined) {
        messagesRef.current[roomId] = await loadMessages(dek, roomId);
      }
      // Recall that arrived BEFORE its original: tombstone only the exact local
      // (room, direction, mid) stream. If an attachment was already materialized,
      // crypto-wipe it BEFORE the message log can drop its only reference.
      let toAppend = await prepareRecalledMessageForAppend(
        recalledMidsRef.current,
        roomId,
        msg,
        secureWipeAttachment,
      );
      // A receipt can arrive before its bubble enters this queue. Fold it into
      // the only durable generation rather than launching a competing write.
      toAppend = consumeEarlyDeliveryReceipts(toAppend);
      const base = messagesRef.current[roomId] ?? [];
      for (;;) {
        const next = [...base, toAppend];
        await saveMessages(dek, roomId, next);
        const afterWrite = consumeEarlyDeliveryReceipts(toAppend);
        if (afterWrite !== toAppend) {
          toAppend = afterWrite;
          continue;
        }
        messagesRef.current[roomId] = next;
        commitMessages();
        return;
      }
    });
  }

  /** Append a just-materialized inbound inline attachment. If the message-log
   * commit fails, crypto-erase the unattached blob so repeated relay delivery
   * cannot fill storage with unreachable copies. */
  async function appendFreshInboundMessage(roomId: string, msg: ChatMessage): Promise<void> {
    try {
      await appendMessage(roomId, msg);
    } catch (error) {
      if (msg.file?.attId) await secureWipeAttachment(msg.file.attId).catch(() => undefined);
      throw error;
    }
  }

  /** Finish a durable recall intent left by a crash between registry persistence
   * and message tombstoning. Runs before inbox connections and also migrates old
   * flat entries, so no stale plaintext/file reference is published on boot. */
  async function reconcileLoadedRecallRegistry(): Promise<void> {
    for (const roomId of Object.keys(messagesRef.current)) {
      await enqueueMessageMutation(roomId, async () => {
        const messages = messagesRef.current[roomId] ?? [];
        const next: ChatMessage[] = [];
        let changed = false;
        for (const message of messages) {
          const prepared = await prepareRecalledMessageForAppend(
            recalledMidsRef.current,
            roomId,
            message,
            secureWipeAttachment,
          );
          next.push(prepared);
          if (prepared !== message) {
            changed = true;
            // Crash-recovery of the same in-flight-pull crypto-erase as retractMessage: a recall that
            // landed while this transfer was mid-pull (interrupted before completion) still has a
            // recvMarker + partial chunks + per-item key locally. Erase them now, gated on OUR marker
            // for exactly THIS room (targetMid is peer-controlled — no cross-room erase).
            const inflight = message.mid ? await getRecvMarker(dek, message.mid).catch(() => null) : null;
            if (message.mid && inflight && inflight.roomId === roomId) {
              await clearRecvMarker(message.mid).catch(() => undefined);
              await secureWipeAttachment(message.mid).catch(() => undefined);
            }
          }
        }
        if (!changed) return;
        await saveMessages(dek, roomId, next);
        messagesRef.current[roomId] = next;
      });
    }
  }

  // Tombstone a message (by mid + direction) as recalled: drop its text/file/reply and
  // delete any attachment blob. If it isn't here yet (out-of-order recall), remember
  // the scoped key so appendMessage tombstones it on arrival. The registry is the
  // durable intent; boot reconciliation completes a crash interrupted operation.
  async function retractMessage(roomId: string, targetMid: string, mine: boolean): Promise<void> {
    const recalled = await enqueueRecallMutation(async () => {
      const key = recallRegistryKey(roomId, mine, targetMid);
      const next = recalledMidsRef.current.has(key)
        ? recalledMidsRef.current
        : new Set(
            addRecallRegistryEntry(
              recalledMidsRef.current,
              roomId,
              mine,
              targetMid,
            ),
          );
      if (next !== recalledMidsRef.current) {
        await saveRecalledMids(dek, [...next]);
        recalledMidsRef.current = next;
      }
      return next;
    });
    await enqueueMessageMutation(roomId, async () => {
      if (messagesRef.current[roomId] === undefined) {
        messagesRef.current[roomId] = await loadMessages(dek, roomId);
      }
      const arr = messagesRef.current[roomId] ?? [];
      const applied = arr.map((message) =>
        applyRecallRegistry(recalled, roomId, message),
      );
      for (const item of applied) {
        if (item.attachmentIdToWipe) {
          await secureWipeAttachment(item.attachmentIdToWipe);
        }
      }
      // An in-flight PULL that gets recalled has materialized partial chunks + a per-item crypto-erase
      // key locally (a recvMarker for targetMid), but applyRecallRegistry deliberately leaves pull/r2
      // ids alone (an unmaterialized attacker-supplied id could collide). A recvMarker under OUR dek
      // proves WE started receiving THIS exact transfer, so its bytes are ours to erase now.
      const inflight = await getRecvMarker(dek, targetMid).catch(() => null);
      if (inflight && inflight.roomId === roomId) {
        await clearRecvMarker(targetMid).catch(() => undefined);
        await secureWipeAttachment(targetMid).catch(() => undefined);
      }
      const next = applied.map((item) => item.message);
      await saveMessages(dek, roomId, next);
      messagesRef.current[roomId] = next;
      commitMessages();
    });
  }

  // Open a view-once photo. The decrypt happens first (we need the bytes in memory),
  // then the message is consumed IRREVERSIBLY before anything is shown: the stored
  // chunks are securely wiped and attId is cleared, so a crash or reload mid-view can
  // never re-open it. The in-memory blob is displayed by ViewOnceViewer and dropped on
  // close. Cannot re-view — that is the whole point.
  async function openViewOnce(roomId: string, m: ChatMessage) {
    if (!m.mid || !m.file?.attId || m.voSeen) return;
    const attId = m.file.attId;
    const mime = m.file.mime;
    let blob: Blob | null = null;
    try {
      blob = await getAttachmentBlob(dek, attId);
    } catch {
      blob = null;
    }
    // Bail BEFORE consuming: a transient load/decode error must not irreversibly destroy an
    // item that was never shown. The blob is already in memory, so consuming only after this
    // check keeps crash-safety (the single viewing still can't be replayed once it succeeds).
    if (!blob) {
      setError(t('Foto ist nicht mehr verfügbar.'));
      return;
    }
    // Consume + wipe BEFORE display — one viewing, no take-backs. The wipe is
    // awaited inside the same room mutation as the tombstone. A crash can leave
    // an unavailable bubble, but can never leave replayable bytes behind a
    // durable "seen" marker or show them before crypto-erasure completed.
    const consumed = await enqueueMessageMutation(roomId, async () => {
      if (messagesRef.current[roomId] === undefined) {
        messagesRef.current[roomId] = await loadMessages(dek, roomId);
      }
      const arr = messagesRef.current[roomId] ?? [];
      if (
        !arr.some(
          (x) =>
            x.mid === m.mid &&
            x.file?.viewOnce &&
            x.file.attId === attId &&
            !x.voSeen,
        )
      ) {
        return false;
      }
      await secureWipeAttachment(attId);
      const next = arr.map((x) =>
        x.mid === m.mid &&
        x.file?.viewOnce &&
        x.file.attId === attId &&
        !x.voSeen
          ? { ...x, voSeen: true, file: { ...x.file, attId: undefined, dataB64: undefined } }
          : x,
      );
      await saveMessages(dek, roomId, next);
      messagesRef.current[roomId] = next;
      commitMessages();
      return true;
    });
    if (!consumed) return;
    setViewOnce({ blob, mime });
  }

  // Recall ("unsend") one of MY OWN messages: tombstone it locally, then ask the peer's
  // devices to retract their copy and mirror the recall to my own other devices. 1:1
  // only for now (groups are a follow-up). Cooperative — no guarantee (SECURITY.md).
  // Forward a message's content to another 1:1 contact — re-sends it as a fresh
  // message (new mid), so it stands on its own. Text and files (re-read from the
  // attachment store or inline bytes); a tombstone/pure-reply has nothing to forward.
  async function forwardTo(contact: Contact, m: ChatMessage): Promise<void> {
    setForwardMsg(null);
    try {
      if (m.file) {
        const blob = m.file.dataB64
          ? new Blob([b64ToBytes(m.file.dataB64)], { type: m.file.mime })
          : m.file.attId
            ? await getAttachmentBlob(dek, m.file.attId)
            : null;
        if (!blob) return setError(t('Anhang nicht mehr verfügbar.'));
        const data = new Uint8Array(await blob.arrayBuffer()) as Uint8Array<ArrayBuffer>;
        const { name, mime } = m.file;
        if (data.length > MAX_ATTACH) {
          if (data.length > AUTOPUSH_CAP) return setError(t('Datei zu groß zum Weiterleiten.'));
          await sendChunkedAttachment(contact, data, name, mime);
          return;
        }
        const mid = randomMid();
        const deliveries = await fanoutSend(contact, { kind: 'file', name, mime, data }, mid);
        void syncToOwnDevices(contact.peerMasterPub, 'sent', mid, Date.now(), { kind: 'file', name, mime, data });
        await appendMessage(contact.roomId, { mine: true, ts: Date.now(), mid, file: await fileRefFor(name, mime, data), deliveries });
      } else if (typeof m.text === 'string' && m.text.length > 0) {
        const mid = randomMid();
        const deliveries = await fanoutSend(contact, { kind: 'text', text: m.text }, mid);
        void syncToOwnDevices(contact.peerMasterPub, 'sent', mid, Date.now(), { kind: 'text', text: m.text });
        await appendMessage(contact.roomId, { mine: true, ts: Date.now(), mid, text: m.text, deliveries });
      } else {
        return;
      }
      bump();
    } catch (e) {
      setError(t('Weiterleiten fehlgeschlagen: {msg}', { msg: (e as Error).message }));
    }
  }

  async function recallMessage(roomId: string, m: ChatMessage): Promise<void> {
    if (!m.mid || !m.mine || m.recalled) return;
    const contact = contactsRef.current.find((c) => c.roomId === roomId);
    if (!contact) return; // group message: not supported yet
    if (revokedOfficialAccountFor(contact)) return; // no recall frame to a revoked admin key
    await retractMessage(roomId, m.mid, true);
    await fanoutSend(contact, { kind: 'recall', targetMid: m.mid }, randomMid());
    void syncToOwnDevices(contact.peerMasterPub, 'sent', m.mid, m.ts, { kind: 'recall', targetMid: m.mid });
    bump();
  }

  // Receive one chunk of a large attachment (Stage 7b). A wire chunk is sealed and
  // stored one-to-one as an attachment chunk, so the transfer is persisted as it
  // arrives (crash-safe) and reassembled by getAttachmentBlob. On the last chunk the
  // meta is committed and ONE message (keyed by the content-addressed tid) is
  // appended. Admission/attachment-quota failures return normally so onInbox ACKs
  // and cannot enter an endless redelivery loop. Terminal: a chunk never becomes a
  // text bubble, is never self-synced/fanned. 1:1 only — a hidden (group-member)
  // contact is not supported.
  async function receiveChunk(contact: Contact, c: Extract<MessageContent, { kind: 'chunk' }>): Promise<void> {
    if (contact.hidden) return; // groups excluded (W7) — drop (and ack)
    if (droppedRecvRef.current.has(c.tid)) return;
    // The tid is attacker-controlled and lands in storage keys — accept only the
    // newAttachmentId charset so it can't break key parsing or collide via ':'.
    if (!/^[A-Za-z0-9]{1,40}$/.test(c.tid)) return;
    // Validate BEFORE touching storage. A malformed/oversized descriptor is dropped.
    if (!Number.isSafeInteger(c.total) || c.total < 1 || c.total > RECV_MAX_CHUNKS) return;
    if (!Number.isSafeInteger(c.idx) || c.idx < 0 || c.idx >= c.total) return;
    if (!Number.isSafeInteger(c.size) || c.size < 0 || c.size > RECV_MAX_BYTES) return;
    if (c.data.length > RECV_MAX_CHUNK_BYTES) return;
    // A non-empty transfer cannot contain empty records or claim more records
    // than bytes. The one canonical empty file is exactly one empty chunk.
    if (
      c.size === 0
        ? c.total !== 1 || c.data.length !== 0
        : c.total > c.size || c.data.length === 0
    ) {
      return;
    }
    // Load this room's messages up front so the anti-aliasing guard runs BEFORE any destructive
    // storage step — including the recall-wipe below. Reject a c.tid that aliases one of MY OWN
    // outbound attachments (a mine=true message with the same attId): an authenticated peer learns
    // my tid from the wire and could otherwise either seal chunks under my shared att:<tid>:key, OR
    // send `recall(tid)` first and then a chunk so the recall-wipe crypto-erases my sent copy. Every
    // legitimate inbound transfer is mine=false, so this never blocks a real receive or a genuine
    // inbound recall-wipe (those match mine=false ids only).
    let roomMessages = messagesRef.current[contact.roomId];
    if (roomMessages === undefined) {
      roomMessages = await loadMessages(dek, contact.roomId);
      messagesRef.current[contact.roomId] = roomMessages;
    }
    const aliasesExistingAttachment = Object.entries(messagesRef.current).some(
      ([roomId, messages]) =>
        messages.some(
          (message) =>
            message.file?.attId === c.tid &&
            (roomId !== contact.roomId || message.mine),
        ),
    );
    if (aliasesExistingAttachment) return;
    // A recall may precede the first or any later chunk. Do not keep filling a
    // protected receive marker for a message that can only become a tombstone;
    // also erase chunks that arrived before the recall.
    if (recallRegistryHas(recalledMidsRef.current, contact.roomId, false, c.tid)) {
      await secureWipeAttachment(c.tid);
      return;
    }
    // Already fully received (re-delivery after completion) → nothing to do. A pending
    // OFFER PLACEHOLDER (mid=tid, mine=false, file.pull set) is NOT "received" — the
    // pull's chunks must flow through, so skip only a COMPLETED (non-pull) message.
    const prior = roomMessages.find((x) => x.mid === c.tid && !x.mine);
    if (prior && !prior.file?.pull) return;
    const explicitlyPulled = !!prior?.file?.pull && explicitPullRef.current.has(c.tid);

    // First chunk of this transfer: register it (bounds concurrency, protects it from
    // the orphan GC, enables resume). Admission is serialized with R2 downloads so
    // every accepted transfer has a real storage reservation. Automatic transfers
    // additionally share a hard 32 MiB stored-byte budget per contact. Later chunks
    // trust the FIRST descriptor, so a peer can't change total/name mid-transfer.
    let marker = await getRecvMarker(dek, c.tid);
    if (!marker) {
      // A completed/orphan attachment under this global storage id belongs to a
      // different local object. Never reuse its per-file key or overwrite it.
      if (await getAttachmentMeta(dek, c.tid)) return;
      const reservedBytes = attachmentRecvReservationBytes(c.size, c.total);
      if (reservedBytes === Number.MAX_SAFE_INTEGER) return;
      const candidate = {
        total: c.total,
        name: c.name,
        mime: c.mime,
        size: c.size,
        ts: Date.now(),
        receivedIdx: [],
        receivedBytes: 0,
        reservedBytes,
        roomId: contact.roomId,
        automatic: !explicitlyPulled,
        viewOnce: c.viewOnce,
      };
      const admission = await withStorageGate(async (): Promise<'ok' | 'contact' | 'storage' | 'concurrency'> => {
        const markerIds = await allRecvMarkerIds();
        if (markerIds.length >= MAX_CONCURRENT_RECV) return 'concurrency';
        const activeMarkers = await Promise.all(
          markerIds.map((id) => getRecvMarker(dek, id).catch(() => null)),
        );
        if (
          !explicitlyPulled &&
          !mayAutoReceiveAttachment(
            roomMessages,
            reservedBytes,
            AUTO_RECEIVE_CONTACT_CAP_BYTES,
            automaticRecvReservationBytes(activeMarkers, contact.roomId),
          )
        ) {
          return 'contact';
        }
        if (!(await originCanReserve(reservedBytes))) return 'storage';
        try {
          await putRecvMarker(dek, c.tid, candidate);
        } catch (error) {
          if (isStorageFull(error)) return 'storage';
          throw error;
        }
        return 'ok';
      });
      if (admission !== 'ok') {
        markRecvDropped(c.tid); // return normally → onInbox acks and ends redelivery
        if (explicitlyPulled && admission === 'storage') {
          setError(t('Nicht genug freier Gerätespeicher für diesen Download.'));
        }
        return;
      }
      marker = candidate;
    } else if (
      marker.roomId !== contact.roomId ||
      typeof marker.automatic !== 'boolean' ||
      c.total !== marker.total ||
      c.size !== marker.size ||
      c.name !== marker.name ||
      c.mime !== marker.mime ||
      !!c.viewOnce !== !!marker.viewOnce
    ) {
      return; // inconsistent with the first chunk — drop
    }

    // Store each index once, and never store more than the CLAIMED size — otherwise
    // total × max-chunk (800 × 256 KB) could store far more than `size` claimed (M2).
    if (!marker.receivedIdx.includes(c.idx)) {
      if (marker.receivedBytes + c.data.length > marker.size) return; // over-claim → drop
      try {
        await sealAndPutChunk(dek, c.tid, c.idx, c.data);
        marker.receivedIdx.push(c.idx);
        marker.receivedBytes += c.data.length;
        await putRecvMarker(dek, c.tid, marker); // progress persisted (crash-safe/idempotent)
      } catch (error) {
        if (!isStorageFull(error)) throw error;
        // The estimate is advisory and browsers may still reject an IndexedDB write.
        // Abandon the whole transfer and ACK this/rest frames instead of creating an
        // infinite redelivery loop that also blocks ratchet-state persistence.
        await clearRecvMarker(c.tid).catch(() => undefined);
        await secureWipeAttachment(c.tid).catch(() => undefined);
        markRecvDropped(c.tid);
        if (explicitlyPulled) setError(t('Nicht genug freier Gerätespeicher für diesen Download.'));
        return;
      }
      // Surface download progress on the pull chip. Re-render only when the whole
      // percent changes (not on every one of hundreds of chunks).
      const pct = Math.floor((marker.receivedIdx.length / marker.total) * 100);
      if (pct !== pullProgressRef.current.get(c.tid)) {
        pullProgressRef.current.set(c.tid, pct);
        if (downloadingRef.current.has(c.tid)) bump();
      }
    }

    if (marker.receivedIdx.length >= marker.total) {
      // Count equality alone is insufficient: a peer could fill every index
      // with undersized chunks and publish corrupt/truncated bytes.
      if (marker.receivedBytes !== marker.size) {
        await clearRecvMarker(c.tid).catch(() => undefined);
        await secureWipeAttachment(c.tid).catch(() => undefined);
        markRecvDropped(c.tid);
        return;
      }
      const storageBytes =
        marker.reservedBytes ??
        attachmentRecvReservationBytes(marker.size, marker.total);
      await finalizeAttachment(dek, c.tid, {
        name: marker.name,
        mime: marker.mime,
        size: marker.size,
        chunks: marker.total,
      });
      // Persist the MESSAGE before clearing the marker (B1): a crash in this window then
      // leaves either the marker (GC protects the chunks) or the persisted, referenced
      // message — never a complete-but-unprotected attachment the orphan sweep deletes.
      let appended = false;
      await enqueueMessageMutation(contact.roomId, async () => {
        const arr = messagesRef.current[contact.roomId] ?? [];
        const placeholder = arr.find((x) => x.mid === c.tid && !x.mine);
        let next: ChatMessage[];
        if (placeholder) {
          // A pulled offer: the placeholder is now downloaded. Reconcile its descriptor
          // to the RECEIVED bytes' meta (the offer's name/mime/size were only a claim),
          // and drop the pull marker so it renders as a normal attachment.
          next = arr.map((x) =>
            x === placeholder
              ? { ...x, file: { name: marker.name, mime: marker.mime, size: marker.size, storageBytes, attId: c.tid, viewOnce: marker.viewOnce || placeholder.file?.viewOnce || undefined } }
              : x,
          );
        } else {
          const message = await prepareRecalledMessageForAppend(
            recalledMidsRef.current,
            contact.roomId,
            {
              mine: false,
              ts: Date.now(),
              mid: c.tid,
              file: { name: marker.name, mime: marker.mime, attId: c.tid, size: marker.size, storageBytes, viewOnce: marker.viewOnce || undefined },
            },
            secureWipeAttachment,
          );
          next = [...arr, message];
          appended = true;
        }
        await saveMessages(dek, contact.roomId, next);
        messagesRef.current[contact.roomId] = next;
        commitMessages();
      });
      if (
        appended &&
        !(viewRef.current === 'chat' && activeRoomRef.current === contact.roomId)
      ) {
        unreadRef.current[contact.roomId] =
          (unreadRef.current[contact.roomId] ?? 0) + 1;
      }
      downloadingRef.current.delete(c.tid);
      pullProgressRef.current.delete(c.tid);
      explicitPullRef.current.delete(c.tid);
      droppedRecvRef.current.delete(c.tid);
      await clearRecvMarker(c.tid);
    }
  }

  // Serialize every inbox task (each queued/live message, and the boot migration
  // seeded as the chain's head) through ONE promise chain. Two decrypts on the
  // same ratchet can therefore never interleave at an await: a relay that replays
  // one ciphertext under two ack-ids no longer has both executions clone the same
  // uncommitted ratchet state and decrypt it twice — the second runs on the
  // committed state and is rejected as an ordinary replay. Also strictly orders
  // every message after the boot migration, closing the onInbox-vs-migration race.
  // A task's rejection is isolated so it can't break the chain for the next task.
  function enqueueInbox<T>(task: () => Promise<T>): Promise<T> {
    if (!lifecycleActiveRef.current || runtimeSuspendedRef.current) {
      return Promise.reject(new MessengerInactiveError());
    }
    // Pin the task to the account it is enqueued under, so an account switch (real ↔ decoy) that
    // lands while it runs makes its every DB op fail closed (StaleAccountGenerationError) instead of
    // persisting the outgoing account's DEK-sealed data into the incoming database. onInbox's catch
    // treats that as "retain the relay row for redelivery". All ratchet-mutating work (onInbox +
    // sends + gossip/self-sync tails) funnels through here, so this one choke point covers them all.
    const origin = currentDbName();
    const run = inboxQueueRef.current.catch(() => undefined).then(async () => {
      assertMessengerActive();
      pinTaskAccount(origin);
      try {
        const result = await task();
        assertMessengerActive();
        return result;
      } finally {
        clearTaskAccount();
      }
    });
    inboxQueueRef.current = run.catch(() => undefined);
    return run;
  }

  /** Adopt an official manifest's public directory only through the normal
   * master-signature/retired-master/rollback gate. A newer gossiped list already
   * on the Contact always wins over the directory snapshot. */
  async function adoptOfficialDeviceList(
    trusted: TrustedOfficialAccountDocument,
    contact: Contact,
  ): Promise<boolean> {
    const list = trusted.deviceList;
    if (
      trusted.manifest.status !== 'active' ||
      !list ||
      !isOfficialAdminContact(contact, trusted) ||
      (contact.peerDeviceList &&
        !isNewerDeviceList(list, contact.peerDeviceList))
    ) {
      return false;
    }
    return applyDeviceListUpdate(contact, list, retiredMastersRef.current);
  }

  /** Refresh is deliberately best-effort and silent. Only a fully verified,
   * durably stored document reaches the UI; network/format failures retain the
   * last good cache. A valid newer revocation is stored and removes the badge. */
  async function refreshOfficialAccountTrust(signal: AbortSignal): Promise<void> {
    if (
      !officialAccountConfigured() ||
      officialTrustRefreshRunningRef.current
    ) return;
    officialTrustRefreshRunningRef.current = true;
    try {
      const current = officialAccountTrustRef.current;
      const candidate = await resolveOfficialAccount(OFFICIAL_ACCOUNT_ALIAS, {
        signal,
        floor: current
          ? { sequence: current.sequence, digest: current.digest }
          : null,
      });
      if (signal.aborted) throw new MessengerInactiveError();
      await enqueueInbox(async () => {
        const trusted = await saveOfficialAccountTrust(dek, candidate);
        installOfficialAccountTrust(trusted);
        if (trusted.manifest.status !== 'active') return;
        const contact = contactsRef.current.find((entry) =>
          isOfficialAdminContact(entry, trusted),
        );
        if (
          contact &&
          (await adoptOfficialDeviceList(trusted, contact))
        ) {
          await saveContact(dek, contact);
        }
      });
    } catch {
      if (signal.aborted) throw new MessengerInactiveError();
      // Keep the last root-verified cache. Background availability must not
      // turn a trusted local identity marker into a flickering network badge.
    } finally {
      officialTrustRefreshRunningRef.current = false;
    }
  }

  /** Resolve a Contact again only after a queued task owns the mutation barrier.
   * Receive processing works on an isolated clone and deletion/re-key can run
   * ahead of an already-scheduled UI send; persisting a captured stale object
   * would otherwise roll the ratchet back or resurrect an erased contact. */
  function requireCurrentContact(captured: Contact): Contact {
    const current =
      contactsRef.current.find((contact) => contact === captured) ??
      contactsRef.current.find(
        (contact) =>
          contact.roomId === captured.roomId &&
          bytesEqual(contact.peerMasterPub, captured.peerMasterPub),
      );
    if (!current) {
      throw new Error('Kontaktzustand ist nicht mehr aktuell.');
    }
    return current;
  }

  /** Publish a durably committed receive candidate without replacing the
   * canonical object. Already-queued send callbacks may hold that object; an
   * in-place publication makes them observe the committed ratchet generation. */
  function publishContactCandidate(
    live: Contact,
    candidate: Contact,
  ): Contact {
    Object.assign(live, candidate);
    return live;
  }

  function enqueueMessageMutation<T>(
    roomId: string,
    task: () => Promise<T>,
  ): Promise<T> {
    return enqueueMessageMutations([roomId], task);
  }

  function enqueueMessageMutations<T>(
    roomIds: readonly string[],
    task: () => Promise<T>,
  ): Promise<T> {
    if (!lifecycleActiveRef.current || runtimeSuspendedRef.current) {
      return Promise.reject(new MessengerInactiveError());
    }
    return messageMutationQueueRef.current.runMany(roomIds, task);
  }

  function enqueueRecallMutation<T>(task: () => Promise<T>): Promise<T> {
    if (!lifecycleActiveRef.current || runtimeSuspendedRef.current) {
      return Promise.reject(new MessengerInactiveError());
    }
    const run = recallMutationQueueRef.current
      .catch(() => undefined)
      .then(task);
    recallMutationQueueRef.current = run.catch(() => undefined);
    return run;
  }

  function enqueueGroupMutation<T>(task: () => Promise<T>): Promise<T> {
    if (!lifecycleActiveRef.current || runtimeSuspendedRef.current) {
      return Promise.reject(new MessengerInactiveError());
    }
    const run = groupMutationQueueRef.current
      .catch(() => undefined)
      .then(task);
    groupMutationQueueRef.current = run.catch(() => undefined);
    return run;
  }

  /** Every fresh X3DH initiation carries our current master-signed DeviceList.
   * This is essential after a safe backup restore replaces the source device:
   * a peer that still has list V can authenticate the fresh device from V+1
   * before applying its ordinary per-device authorization gate. */
  function fanoutFromThisDevice(
    me: IdentityKeys,
    contact: Contact,
    content: MessageContent,
    mid: string,
    exclude?: Bytes,
    only?: Bytes,
    minPv = 0,
  ) {
    return fanoutDeliveries(
      me,
      contact,
      content,
      mid,
      exclude,
      only,
      minPv,
      ownListRef.current ?? undefined,
    );
  }

  // Listen on our own inbox and authenticate as its owner (Ed25519 sig over the
  // DO's challenge) so the relay hands us our queued + live messages.
  function connectInbox(room: string) {
    const id = identityRef.current;
    if (
      !lifecycleActiveRef.current ||
      runtimeSuspendedRef.current ||
      !id
    ) return;
    // The owner role always wins its own inbox. During boot the hidden
    // self-contact used to create a sender-only client for this exact room;
    // the generic has(room) guard then prevented owner authentication, so the
    // relay durably queued messages that this device never drained.
    if (!prepareOwnerRelaySlot(
      room,
      relaysRef.current,
      sendRoomRef.current,
      inboxClientRef.current,
    )) return;
    const client = new RelayClient(room, {
      onCipher: (bytes, ackId) => {
        if (!lifecycleActiveRef.current || runtimeSuspendedRef.current) return;
        void enqueueInbox(() => onInbox(bytes, ackId)).catch(() => undefined);
      },
      auth: {
        signPub: id.sign.publicKey,
        sign: (nonce) => sign(nonce, id.sign.privateKey),
      },
    });
    if (!lifecycleActiveRef.current || runtimeSuspendedRef.current) {
      client.close();
      return;
    }
    relaysRef.current.set(room, client);
    inboxClientRef.current = client;
    client.connect();
  }

  // A send channel to a contact's inbox. Status = reachability dot for them.
  async function connectSend(contact: Contact) {
    const id = identityRef.current;
    if (
      !lifecycleActiveRef.current ||
      runtimeSuspendedRef.current ||
      !id ||
      contact.localOnly
    ) return;
    // The hidden self-contact is a fan-out model for OTHER own devices, not a
    // reason to open an unauthenticated sender socket to this device's inbox.
    // Compare the device key (not `hidden` or the master): hidden group contacts
    // remain sendable, and even a hostile foreign-master bundle cannot reserve
    // our owner-inbox slot by reusing our public signing key.
    if (bytesEqual(contact.peerSignPub, id.sign.publicKey)) {
      sendRoomRef.current.delete(contact.roomId);
      return;
    }
    const room = await inboxRoom(contact.peerSignPub);
    if (!lifecycleActiveRef.current || runtimeSuspendedRef.current) return;
    sendRoomRef.current.set(contact.roomId, room);
    if (relaysRef.current.has(room)) return;
    const client = new RelayClient(room, {
      onStatus: (s) => {
        if (!lifecycleActiveRef.current || runtimeSuspendedRef.current) return;
        setStatuses((prev) => ({ ...prev, [contact.roomId]: s }));
        // Coming back online is the strongest moment to re-offer my device list:
        // a peer that was offline when I linked a device learns it here.
        if (s === 'open') {
          void ensureListGossiped(contact);
          void schedulePendingGroupMutationRetry();
        }
      },
      onAck: (mid) => {
        if (lifecycleActiveRef.current && !runtimeSuspendedRef.current) {
          markStatus(mid, 'sent');
        }
      },
      onNack: (mid, reason) => {
        if (lifecycleActiveRef.current && !runtimeSuspendedRef.current) {
          markStatus(mid, 'failed', reason === 'full'
            ? t('Nicht zugestellt — das Postfach des Empfängers ist voll.')
            : t('Keine Bestätigung vom Relay — noch nicht zugestellt (evtl. offline).'));
        }
      },
    });
    if (!lifecycleActiveRef.current || runtimeSuspendedRef.current) {
      client.close();
      return;
    }
    relaysRef.current.set(room, client);
    client.connect();
  }

  // Send raw sealed bytes to an arbitrary inbox (derived from a device's sign
  // key). Used by the linking flow, whose recipient is our own other device and
  // has no Contact/roomId. Reuses an open relay for that room if one exists.
  async function sendToInbox(recipientSignPub: Bytes, sealed: Bytes): Promise<void> {
    assertRuntimeAvailable();
    const room = await inboxRoom(recipientSignPub);
    assertRuntimeAvailable();
    let client = relaysRef.current.get(room);
    if (!client) {
      client = new RelayClient(room, {});
      assertRuntimeAvailable();
      relaysRef.current.set(room, client);
      client.connect();
    }
    // `completeLinkOnP` keeps a sealed retry intent until this resolves. A
    // socket write alone is not delivery: only the relay's `sent` receipt proves
    // that the grant is durably queued.
    await client.sendConfirmed(sealed, true);
    assertRuntimeAvailable();
  }

  async function retryPendingLinkGrant(
    beforeSend?: () => Promise<void>,
  ): Promise<boolean> {
    const recovered = await recoverPendingLinkGrantAtBoot(dek);
    if (recovered.discardedCorrupt) {
      primaryPendingLinkTargetRef.current = null;
      return true;
    }
    const pending = recovered.pending;
    if (!pending) {
      primaryPendingLinkTargetRef.current = null;
      return false;
    }
    const pendingRecord = recovered.record;
    if (!pendingRecord) throw new Error(t('Pending-Kopplungs-Snapshot fehlt.'));
    primaryPendingLinkTargetRef.current = pending.recipientSignPub;
    await beforeSend?.();
    await sendToInbox(pending.recipientSignPub, pending.sealedPayload);
    const cleanup = await clearPendingLinkGrantAndRecover(dek, pendingRecord);
    if (cleanup.status !== 'cleared') {
      if (cleanup.status === 'discarded-corrupt') {
        primaryPendingLinkTargetRef.current = null;
        return true;
      }
      if (cleanup.status === 'replaced') {
        primaryPendingLinkTargetRef.current = cleanup.pending.recipientSignPub;
        throw new Error(t('Eine neuere ausstehende Kopplung bleibt gespeichert und muss separat zugestellt oder widerrufen werden.'));
      }
      // A was removed/cancelled and no successor exists. Its late receipt must
      // neither recreate pending UI nor clear unrelated state.
      primaryPendingLinkTargetRef.current = null;
      return false;
    }
    primaryPendingLinkTargetRef.current = null;
    return false;
  }

  async function synchronizeCommittedPrimaryLinkList(list: DeviceList): Promise<void> {
    // Publish the durable CAS result immediately. In particular, the hidden
    // self-contact must authorize N before the Grant can reach it and trigger a
    // bootreq back to this primary.
    const authoritative = await reconcileOwnDeviceList(list);
    const self = await ensureSelfContact();
    const durable = ownListRef.current;
    if (
      !self ||
      !durable ||
      !self.peerDeviceList ||
      compareDeviceList(durable, list) < 0 ||
      compareDeviceList(authoritative, list) < 0 ||
      compareDeviceList(self.peerDeviceList, list) < 0
    ) {
      throw new Error(t('Durable Geräteliste konnte nicht in den Selbstkontakt übernommen werden.'));
    }
    bump();
  }

  async function retryPrimaryLinkGrantDeliveryNow() {
    if (linkBusy) return;
    setLinkBusy(true);
    try {
      // Rebuild RAM/self-contact from the already committed DeviceList before
      // re-exposing the pending credential to N.
      const discardedCorruptGrant = await retryPendingLinkGrant(async () => {
        const self = await ensureSelfContact();
        if (!self) throw new Error(t('Selbstkontakt nicht verfügbar.'));
      });
      setPrimaryLinkDeliveryPending(false);
      if (discardedCorruptGrant) {
        setError(t('Beschädigter Kopplungs-Retry wurde entfernt. Prüfe jetzt unter Profil → Geräte die Liste und widerrufe jedes unbekannte oder noch nicht bestätigte Gerät; der ursprüngliche Nachweis könnte bereits zugestellt worden sein.'));
      } else {
        setError(t('Ausstehender Kopplungs-Nachweis wurde bestätigt zugestellt.'));
      }
    } catch (e) {
      setPrimaryLinkDeliveryPending(true);
      setError(t('Ausstehende Gerätekopplung noch nicht zugestellt: {msg}', {
        msg: (e as Error).message,
      }));
    } finally {
      setLinkBusy(false);
    }
  }

  async function cancelPrimaryPendingLinkGrant() {
    if (linkBusy) return;
    const id = identityRef.current;
    if (!id || !isPrimaryDevice(id)) return;
    if (!window.confirm(t(
      'Ausstehende Kopplung abbrechen und das neue Gerät widerrufen? Eine eventuell bereits zugestellte ältere Autorisierung wird durch eine neuere signierte Geräteliste ungültig. Dieser Schritt lässt sich nicht rückgängig machen.',
    ))) {
      return;
    }
    setLinkBusy(true);
    try {
      // Snapshot the self-contact while it still contains the target. After the
      // atomic revoke it is pruned, so this is the last direct notification path.
      const self = await ensureSelfContact();
      const cancelled = await cancelPendingLinkGrantAndRevokeDevice(
        dek,
        id,
        primaryPendingLinkTargetRef.current ?? undefined,
      );
      if (!cancelled) {
        setPrimaryLinkDeliveryPending(false);
        primaryPendingLinkTargetRef.current = null;
        setError(t('Es gibt keine ausstehende Kopplungs-Zustellung mehr.'));
        return;
      }
      setPrimaryLinkDeliveryPending(false);
      primaryPendingLinkTargetRef.current = null;
      const authoritative = await reconcileOwnDeviceList(cancelled.newList);
      if (self) {
        try {
          const { deliveries } = await enqueueInbox(async () => {
            const current = requireCurrentContact(self);
            const result = await fanoutFromThisDevice(
              id,
              current,
              { kind: 'devlist', list: authoritative },
              randomMid(),
              undefined,
              cancelled.targetSignPub,
            );
            await saveContact(dek, current);
            return result;
          });
          for (const delivery of deliveries) {
            const room = await inboxRoom(delivery.deviceSignPub);
            connectDeviceInbox(room);
            relaysRef.current.get(room)?.send(delivery.sealed, randomMid(), true);
          }
        } catch {
          // Best effort: the newer master-signed list is already authoritative
          // and is also gossiped to every reachable peer below.
        }
      }
      await gossipDeviceList(authoritative);
      bump();
      setError(t('Ausstehende Kopplung abgebrochen und das Gerät mit einer neueren Geräteliste widerrufen.'));
    } catch (e) {
      setPrimaryLinkDeliveryPending(true);
      setError(t('Ausstehende Kopplung konnte nicht sicher widerrufen werden: {msg}', {
        msg: (e as Error).message,
      }));
    } finally {
      setLinkBusy(false);
    }
  }

  // Delivery tracking. A 1:1 message is 'pending' until the relay acks the insert
  // ('sent'); a nack or an ack timeout flips it to 'failed'. So the checkmark
  // never claims delivery the relay didn't confirm.
  function clearAckTimer(mid: string) {
    const t = ackTimers.current.get(mid);
    if (t) {
      clearTimeout(t);
      ackTimers.current.delete(mid);
    }
  }
  function startAckTimer(mid: string) {
    if (!lifecycleActiveRef.current) return;
    clearAckTimer(mid);
    ackTimers.current.set(
      mid,
      setTimeout(() => {
        if (runtimeSuspendedRef.current) {
          // A reversible restore fence may outlive the original timeout. Keep
          // the delivery pending and restart its deadline after another window
          // instead of mutating the old message store during the import.
          ackTimers.current.delete(mid);
          startAckTimer(mid);
          return;
        }
        markStatus(mid, 'failed', t('Keine Bestätigung vom Relay — noch nicht zugestellt (evtl. offline).'));
      }, 10_000),
    );
  }
  function markStatus(id: string | null, status: 'sent' | 'failed', errorMsg?: string) {
    if (!lifecycleActiveRef.current || runtimeSuspendedRef.current) return;
    if (!id) {
      if (status === 'failed' && errorMsg) setError(errorMsg);
      return;
    }
    const expectedEarlyReceipt = ackTimers.current.has(id);
    clearAckTimer(id);
    // The global error banner (setError) fires ONLY when a delivery ACTUALLY
    // transitions to failed — never for a terminal (sent/stale) row. Otherwise a
    // late ack-timeout on a delivery we already swept to 'stale' (a revoked device)
    // would pop "not delivered" while the bubble shows delivered (Review-2 fund).
    for (const roomId of Object.keys(messagesRef.current)) {
      const arr = messagesRef.current[roomId];
      // Stage 3d fan-out: `id` is a per-DEVICE deliveryId. Update just that delivery
      // (per-delivery "once sent always sent"), then the bubble re-derives its
      // aggregate at render (aggregateDelivery). A failure of ONE device never
      // rolls back the others.
      const fi = arr.findIndex((m) => m.deliveries?.some((d) => d.deliveryId === id));
      if (fi >= 0) {
        const dels = arr[fi].deliveries!;
        const d = dels.find((x) => x.deliveryId === id)!;
        if (d.status === 'sent' || d.status === 'stale') return; // terminal per delivery — no change, no banner
        void enqueueMessageMutation(roomId, async () => {
          const live = messagesRef.current[roomId] ?? [];
          const liveIndex = live.findIndex((message) =>
            message.deliveries?.some((delivery) => delivery.deliveryId === id),
          );
          if (liveIndex < 0) return;
          const liveDeliveries = live[liveIndex].deliveries!;
          const liveDelivery = liveDeliveries.find(
            (delivery) => delivery.deliveryId === id,
          );
          if (
            !liveDelivery ||
            liveDelivery.status === 'sent' ||
            liveDelivery.status === 'stale'
          ) {
            return;
          }
          const next = [...live];
          next[liveIndex] = {
            ...live[liveIndex],
            deliveries: liveDeliveries.map((delivery) =>
              delivery.deliveryId === id
                ? { ...delivery, status }
                : delivery,
            ),
          };
          await saveMessages(dek, roomId, next);
          messagesRef.current[roomId] = next;
          // Global error banner ONLY when the message reached NO device at all.
          if (
            status === 'failed' &&
            errorMsg &&
            aggregateDelivery(next[liveIndex].deliveries!).label === 'failed'
          ) {
            setError(errorMsg);
          }
          commitMessages();
          bump();
        }).catch(() => undefined);
        return;
      }
      // Legacy single-status (groups / pre-3d records).
      const idx = arr.findIndex((m) => m.mid === id);
      if (idx >= 0) {
        const cur = arr[idx].status;
        if (cur === status) return;
        // INVARIANT: once 'sent' (relay durably has it), always 'sent'. A late
        // nack/timeout must never downgrade a confirmed delivery.
        if (cur === 'sent') return;
        void enqueueMessageMutation(roomId, async () => {
          const live = messagesRef.current[roomId] ?? [];
          const liveIndex = live.findIndex((message) => message.mid === id);
          if (liveIndex < 0) return;
          const liveStatus = live[liveIndex].status;
          if (liveStatus === status || liveStatus === 'sent') return;
          const next = [...live];
          next[liveIndex] = { ...live[liveIndex], status };
          await saveMessages(dek, roomId, next);
          messagesRef.current[roomId] = next;
          if (status === 'failed' && errorMsg) setError(errorMsg);
          commitMessages();
          bump();
        }).catch(() => undefined);
        return;
      }
    }
    if (expectedEarlyReceipt) {
      const previous = earlyDeliveryReceiptsRef.current.get(id);
      // A durable `sent` receipt is terminal and wins over a racing timeout/nack.
      if (!previous || previous.status !== 'sent' || status === 'sent') {
        earlyDeliveryReceiptsRef.current.set(id, { status, errorMsg });
      }
    }
  }

  // A relay to ONE peer device's inbox (Stage 3d fan-out). Ack/nack carry the
  // per-delivery id, so markStatus finds the right per-device entry.
  function connectDeviceInbox(room: string) {
    if (
      !lifecycleActiveRef.current ||
      runtimeSuspendedRef.current ||
      relaysRef.current.has(room)
    ) return;
    const client = new RelayClient(room, {
      onAck: (id) => {
        if (lifecycleActiveRef.current && !runtimeSuspendedRef.current) {
          markStatus(id, 'sent');
        }
      },
      onNack: (id, reason) => {
        if (lifecycleActiveRef.current && !runtimeSuspendedRef.current) {
          markStatus(id, 'failed', reason === 'full'
            ? t('An ein Gerät nicht zugestellt — Postfach voll.')
            : t('Keine Bestätigung vom Relay — noch nicht zugestellt (evtl. offline).'));
        }
      },
    });
    if (!lifecycleActiveRef.current || runtimeSuspendedRef.current) {
      client.close();
      return;
    }
    relaysRef.current.set(room, client);
    client.connect();
  }

  // Encrypt `content` for EVERY authorised peer device and send each copy to its
  // own inbox, all sharing one `mid`. The advanced per-device sessions are persisted
  // BEFORE anything hits the wire, on the send serialization chain (Invariant I/II
  // per session). Returns the per-device delivery rows for the local bubble.
  async function fanoutSend(contact: Contact, content: MessageContent, mid: string, minPv = 0): Promise<DeviceDelivery[]> {
    // A revoked former-admin key must receive NOTHING new — content, replies,
    // recalls, attachment requests or offers all route through here. This is the
    // outbound choke point for every content kind, not just "normal" messages.
    assertNormalSendAllowed(contact);
    const id = identityRef.current;
    if (!id) return [];
    const { deliveries, unreachable } = await enqueueInbox(async () => {
      const current = requireCurrentContact(contact);
      const r = await fanoutFromThisDevice(id, current, content, mid, undefined, undefined, minPv);
      await saveContact(dek, current); // persist advanced sessions before the wire
      return r;
    });
    const silent = isSilentFrame(content.kind); // recall/attreq don't push; text/file/reply/attoffer do
    const rows: DeviceDelivery[] = [];
    for (const d of deliveries) {
      const deliveryId = randomMid();
      const room = await inboxRoom(d.deviceSignPub);
      connectDeviceInbox(room);
      // Register BEFORE send(): a test relay, a loopback, or a fast socket can emit `sent`
      // synchronously before fanoutSend returns and before the bubble is appended.
      startAckTimer(deliveryId);
      relaysRef.current.get(room)?.send(d.sealed, deliveryId, silent);
      rows.push({ device: bytesToB64(d.deviceSignPub), deliveryId, status: 'pending' });
    }
    // A device we can't initiate to yet (authorised, but no signed prekey learned)
    // is out of the reachable set — 'stale' drops it from the denominator, never a
    // permanent failure. It becomes reachable once its list SPK is gossiped.
    for (const u of unreachable) rows.push({ device: bytesToB64(u), deliveryId: '', status: 'stale' });
    return rows;
  }

  /** Control-frame fan-out without user-visible delivery rows or wake-up push. */
  async function silentFanout(
    contact: Contact,
    content: MessageContent,
    only?: Bytes,
  ): Promise<void> {
    const id = identityRef.current;
    // Silent gossip (device lists, acks) must not leak to a revoked admin key.
    if (!id || revokedOfficialAccountFor(contact)) return;
    const { deliveries, unreachable } = await enqueueInbox(async () => {
      const current = requireCurrentContact(contact);
      const result = await fanoutFromThisDevice(
        id,
        current,
        content,
        randomMid(),
        undefined,
        only,
      );
      await saveContact(dek, current);
      return result;
    });
    if (deliveries.length === 0 || unreachable.length > 0) {
      throw new Error('Kontrollnachricht konnte nicht an jedes Zielgerät zugestellt werden.');
    }
    for (const delivery of deliveries) {
      const room = await inboxRoom(delivery.deviceSignPub);
      connectDeviceInbox(room);
      relaysRef.current.get(room)?.send(delivery.sealed, randomMid(), true);
    }
  }

  // Auto-push a large attachment as chunk frames straight to the peer's mailbox (1:1
  // only). Encrypts the whole stream, persists the advanced ratchet BEFORE any frame
  // hits the wire (Invariant II), then dispatches per capable device. Returns false
  // if NO device could receive it (peer too old) so the caller can report it.
  async function sendChunkedAttachment(
    contact: Contact,
    data: Uint8Array<ArrayBuffer>,
    name: string,
    mime: string,
    viewOnce = false,
  ): Promise<boolean> {
    assertNormalSendAllowed(contact);
    const id = identityRef.current;
    if (!id) return false;
    // One 128-bit id is both the transfer/storage id and the visible message
    // MID. Recall addresses MIDs; using a second random bubble id made completed
    // chunked attachments impossible to retract on the recipient.
    const tid = randomMid();
    const total = Math.max(1, Math.ceil(data.length / CHUNK_BYTES));
    // Store locally under the SAME id the peer will use, so the sender sees it too.
    await putAttachment(dek, tid, data, name, mime);
    const out = await enqueueInbox(async () => {
      const current = requireCurrentContact(contact);
      // Only the RECIPIENT's chunks are flagged view-once; the sender keeps a normal copy.
      // View-once chunks carry `vo` in the header, which only a pv>=4 receiver reads — a
      // pv 2/3 receiver would reassemble a permanent copy. Gate view-once on pv>=4 so such a
      // device is `incapable` (not silently downgraded); normal chunks stay pv>=2.
      const r = await fanoutChunks(
        id,
        current,
        { tid, total, size: data.length, name, mime, viewOnce },
        data,
        CHUNK_BYTES,
        viewOnce ? 4 : 2,
        ownListRef.current ?? undefined,
      );
      await saveContact(dek, current); // persist ratchet advances BEFORE the wire (Invariant II)
      return r;
    });
    if (out.perDevice.length === 0) {
      await secureWipeAttachment(tid); // nothing sent — don't leak the local copy
      return false;
    }
    // RelayClient buffers, so a burst is fine within the relay's mailbox byte-cap
    // (AUTOPUSH_CAP << the relay's per-inbox limit).
    for (const dev of out.perDevice) {
      const room = await inboxRoom(dev.deviceSignPub);
      connectDeviceInbox(room);
      const relay = relaysRef.current.get(room);
      for (const sealed of dev.sealed) relay?.send(sealed, randomMid());
    }
    // Chunks carry no per-device delivery rows (W5) — one 'sent' once dispatched.
    // (Per-chunk ack tracking + progress is a later refinement.)
    await appendMessage(contact.roomId, {
      mine: true,
      ts: Date.now(),
      mid: tid,
      file: { name, mime, attId: tid, size: data.length },
      status: 'sent',
    });
    bump();
    return true;
  }

  // Offer a large (> auto-push cap) attachment for pull. Stores it locally (so I can
  // serve pulls and see it myself) and sends a tiny 'attoffer' descriptor to the peer;
  // the recipient shows a download affordance and pulls it on demand. Returns false if
  // the peer's primary device can't handle offers (too old).
  async function sendOfferedAttachment(
    contact: Contact,
    data: Uint8Array<ArrayBuffer>,
    name: string,
    mime: string,
  ): Promise<boolean> {
    assertNormalSendAllowed(contact);
    const id = identityRef.current;
    if (!id) return false;
    // Capable if ANY authorised device handles offers (not just the primary), and the
    // offer is sent ONLY to those (pv>=3) — a below-version device is never handed the
    // byte-16 frame it would throw on and lose.
    const devs = contact.peerDeviceList?.devices.map((d) => d.signPub) ?? [contact.peerSignPub];
    if (!devs.some((sp) => deviceProtocolVersion(contact, sp) >= 3)) return false;
    // Keep transfer id == message MID, matching the recipient's placeholder.
    // This makes a later recall refer to the same authenticated identifier on
    // both sides without changing the wire format.
    const tid = randomMid();
    const total = Math.max(1, Math.ceil(data.length / CHUNK_BYTES));
    await putAttachment(dek, tid, data, name, mime); // keep locally to serve pulls + show to me
    await fanoutSend(contact, { kind: 'attoffer', tid, name, mime, size: data.length, total }, randomMid(), 3);
    await appendMessage(contact.roomId, {
      mine: true,
      ts: Date.now(),
      mid: tid,
      file: { name, mime, attId: tid, size: data.length },
      status: 'sent',
    });
    bump();
    return true;
  }

  // Serve a pull: stream an offered attachment's chunks to the requesting contact.
  // GUARD (amplification): only serve a tid I actually offered to THIS contact (a
  // mine=true message in their room references it) and still hold.
  async function serveAttachment(contact: Contact, tid: string): Promise<void> {
    // The account this serve belongs to. serveAttachment now runs DETACHED (void) from onInbox and
    // its prep reads are NOT covered by quiesceInbox, so if an account switch (decoy exit) lands
    // mid-prep we must bail before the fan-out enqueue — otherwise the inner enqueueInbox would
    // capture the post-switch account as its pin and seal this contact's ratchet advance into the
    // WRONG database.
    const servedOrigin = currentDbName();
    const id = identityRef.current;
    if (!id || !/^[A-Za-z0-9]{1,40}$/.test(tid)) return;
    if (revokedOfficialAccountFor(contact)) return; // no chunk streaming to a revoked admin key
    const arr = messagesRef.current[contact.roomId] ?? (await loadMessages(dek, contact.roomId));
    if (!arr.some((m) => m.mine && m.file?.attId === tid)) return; // not something I offered here
    // Anti-amplification: a ~30 B attreq triggers up to a 25 MB stream, so rate-limit
    // repeated pulls of the SAME tid from the SAME contact (a legit re-pull still works
    // after the cooldown; a spam-replay can't make me re-upload on every request).
    const key = contact.roomId + ':' + tid;
    if (Date.now() - (servedRef.current.get(key) ?? 0) < SERVE_COOLDOWN_MS) return;
    servedRef.current.set(key, Date.now());
    const meta = await getAttachmentMeta(dek, tid);
    const blob = meta ? await getAttachmentBlob(dek, tid) : null;
    if (!meta || !blob) return;
    const data = new Uint8Array(await blob.arrayBuffer()) as Uint8Array<ArrayBuffer>;
    const total = Math.max(1, Math.ceil(data.length / CHUNK_BYTES));
    if (currentDbName() !== servedOrigin) return; // account switched during prep — don't write cross-account
    const out = await enqueueInbox(async () => {
      const current = requireCurrentContact(contact);
      const r = await fanoutChunks(
        id,
        current,
        { tid, total, size: data.length, name: meta.name, mime: meta.mime },
        data,
        CHUNK_BYTES,
        2,
        ownListRef.current ?? undefined,
      );
      await saveContact(dek, current); // persist ratchet advances BEFORE the wire (Invariant II)
      return r;
    });
    for (const dev of out.perDevice) {
      const room = await inboxRoom(dev.deviceSignPub);
      connectDeviceInbox(room);
      const relay = relaysRef.current.get(room);
      // Serving a pull the peer explicitly requested — they already saw the offer and
      // are downloading, so the chunks must not fire a fresh push.
      for (const sealed of dev.sealed) relay?.send(sealed, randomMid(), true);
    }
  }

  // Request an offered attachment (recipient side). Fans the request out to the
  // contact; only the offering device (which holds the file) serves it.
  async function pullAttachment(roomId: string, m: ChatMessage, initiatedByUser = true): Promise<void> {
    if (!m.file?.pull || !m.file.attId || !m.mid) return;
    const tid = m.file.attId;
    if (initiatedByUser) {
      explicitPullRef.current.add(tid);
      droppedRecvRef.current.delete(tid); // a deliberate retry gets a fresh quota decision
    }
    if (downloadingRef.current.has(tid)) return; // already pulling (also guards a double-tap)
    const contact = contactsRef.current.find((c) => c.roomId === roomId);
    if (!contact) return;
    if (revokedOfficialAccountFor(contact)) return; // no attreq to a revoked admin key
    downloadingRef.current.add(tid);
    bump();

    // The pulled attachment has fully arrived once its placeholder no longer carries a
    // `pull` marker (receiveChunk reconciles it on completion).
    const done = () => !(messagesRef.current[roomId] ?? []).some((x) => x.mid === tid && x.file?.pull);

    // Re-request on stall: a stalled transfer (a dropped/nacked chunk, or the sender
    // only just came online) is refilled by re-serving — receiveChunk stores each index
    // once, so re-serving fills only the gaps. Bounded so it can't loop forever.
    let attempts = 0;
    const attempt = async () => {
      attempts++;
      await fanoutSend(contact, { kind: 'attreq', tid }, randomMid());
      window.setTimeout(() => {
        if (done() || !downloadingRef.current.has(tid)) {
          downloadingRef.current.delete(tid);
          return;
        }
        if (attempts >= MAX_PULL_ATTEMPTS) {
          if (downloadingRef.current.delete(tid)) bump(); // give up → chip tappable again
          return;
        }
        void attempt();
      }, PULL_RETRY_MS);
    };
    await attempt();
  }

  /** Download a large R2 attachment on tap: stream-download + decrypt into the local store,
   *  then reconcile the placeholder to a normal attachment (and the R2 object self-deletes). */
  async function downloadR2Message(roomId: string, m: ChatMessage): Promise<void> {
    if (!m.file?.r2 || m.file.attId || !m.mid) return;
    const mid = m.mid;
    if (downloadingRef.current.has(mid)) return;
    const r2 = m.file.r2;
    const name = m.file.name;
    const mime = m.file.mime;
    const valid = tryValidateR2Descriptor(
      { key: r2.key, keyB64: r2.keyB64, size: m.file.size ?? Number.NaN, chunk: r2.chunk },
      CLIENT_MAX_BLOB,
    );
    if (!valid) {
      setError(t('Download fehlgeschlagen: {msg}', { msg: 'Ungültiger Dateideskriptor.' }));
      return;
    }
    const admission = await withStorageGate(async (): Promise<'ok' | 'busy' | 'storage'> => {
      if (downloadingRef.current.has(mid) || r2ReservationsRef.current.has(mid)) return 'busy';
      if (!(await originCanReserve(valid.size))) return 'storage';
      r2ReservationsRef.current.set(mid, valid.size);
      return 'ok';
    });
    if (admission === 'busy') return;
    if (admission === 'storage') {
      setError(t('Nicht genug freier Gerätespeicher für diesen Download.'));
      return;
    }
    downloadingRef.current.add(mid);
    bump();
    const attId = newAttachmentId();
    try {
      await downloadR2ToStore(dek, attId, valid, name, mime, (f) => {
        const pct = Math.floor(f * 100);
        if (pct !== pullProgressRef.current.get(mid)) {
          pullProgressRef.current.set(mid, pct);
          bump();
        }
      });
      // Reconcile the placeholder → a downloaded attachment. Keep view-once so it opens in
      // the self-destruct viewer (not inline) and gets crypto-erased after the single view.
      const vo = m.file.viewOnce;
      await enqueueMessageMutation(roomId, async () => {
        if (messagesRef.current[roomId] === undefined) {
          messagesRef.current[roomId] = await loadMessages(dek, roomId);
        }
        const arr = messagesRef.current[roomId] ?? [];
        const next = arr.map((x) =>
          x.mid === mid
            ? { ...x, file: { name, mime, size: valid.size, attId, viewOnce: vo || undefined } }
            : x,
        );
        await saveMessages(dek, roomId, next);
        messagesRef.current[roomId] = next;
        commitMessages();
      });
    } catch (e) {
      await secureWipeAttachment(attId).catch(() => undefined);
      setError(t('Download fehlgeschlagen: {msg}', { msg: (e as Error).message }));
    } finally {
      downloadingRef.current.delete(mid);
      pullProgressRef.current.delete(mid);
      await withStorageGate(async () => {
        r2ReservationsRef.current.delete(mid);
      });
      bump();
    }
  }

  /** Auto-download an offer the moment it arrives (no manual tap) — the common case
   *  where a peer just sent a video. Once per tid; a failed auto-pull still leaves the
   *  chip for a manual retry. */
  function autoPull(roomId: string, tid: string, total: number) {
    if (autoPulledRef.current.has(tid) || downloadingRef.current.has(tid)) return;
    autoPulledRef.current.add(tid);
    void pullAttachment(
      roomId,
      { mid: tid, mine: false, ts: Date.now(), file: { name: '', mime: '', attId: tid, pull: { total } } },
      false,
    );
  }

  // The hidden "self" contact: peerMaster == MY master, peerDeviceList == my own
  // device list, so I can fan out to my OTHER devices (self-sync). Its sessions are
  // to my devices; it never shows in the UI. Refreshed to my current device list so
  // a revoked own device is pruned (applyDeviceListUpdate also drops its session).
  /** Contact/session mutation for callers that already hold the inbox barrier. */
  async function ensureSelfContactWithinInbox(): Promise<Contact | null> {
    const id = identityRef.current;
    const pre = prekeysRef.current;
    if (!id || !pre) return null;
    const myMaster = asMasterPub(id.master.publicKey);
    const roomId = await computeMasterRoomId(myMaster, myMaster);
    let c = contactsRef.current.find((x) => x.roomId === roomId);
    if (!c) {
      c = {
        roomId,
        peerMasterPub: id.master.publicKey,
        peerEpoch: id.epoch,
        peerSignPub: id.sign.publicKey,
        peerDhPub: id.dh.publicKey,
        peerFingerprint: '',
        ownMasterPub: myMaster,
        regime: 'master',
        verified: true,
        hidden: true,
        sessions: new Map(),
      };
      contactsRef.current = [...contactsRef.current, c];
    }
    const ownList = await loadOrCreateOwnDeviceList(dek, id, ownSpkPublic(pre));
    if (ownList) {
      const authoritative = publishOwnDeviceList(ownList);
      await applyDeviceListUpdate(c, authoritative, retiredMastersRef.current);
    }
    setMultiDevice((ownListRef.current?.devices.length ?? 1) > 1);
    await saveContact(dek, c);
    return c;
  }

  /** Public self-contact entry point. The Contact includes live ratchet state, so
   * creating/updating and serializing it must share the receive/send barrier. */
  async function ensureSelfContact(): Promise<Contact | null> {
    return enqueueInbox(ensureSelfContactWithinInbox);
  }

  // Mirror a message I sent to my OWN other devices (Stage 3d self-sync). The copy
  // carries the TARGET peer's master so the receiving device files it under the
  // right conversation room, plus the original mid so it dedups against the peer's
  // own fan-out copy. Excludes my current device. Fire-and-forget; no status UI.
  async function syncToOwnDevices(targetPeerMaster: Bytes, origin: 'sent' | 'recv', innerMid: string, ts: number, inner: MessageContent) {
    const id = identityRef.current;
    if (!id) return;
    const self = await ensureSelfContact();
    if (!self || !self.peerDeviceList || self.peerDeviceList.devices.length < 2) return; // no other device
    const content: MessageContent = { kind: 'sync', targetPeerMaster, origin, innerMid, ts, inner };
    const { deliveries } = await enqueueInbox(async () => {
      const current = requireCurrentContact(self);
      const r = await fanoutFromThisDevice(id, current, content, randomMid(), id.sign.publicKey);
      await saveContact(dek, current);
      return r;
    });
    for (const d of deliveries) {
      const room = await inboxRoom(d.deviceSignPub);
      connectDeviceInbox(room);
      relaysRef.current.get(room)?.send(d.sealed, randomMid(), true); // self-sync: never notify yourself
    }
  }

  // ── Erst-Sync: the snapshot that makes a linked device a real 1:1 ─────────
  // Sizing: an avatar is capped at AVATAR_IMPORT_CAP and the roster at ROSTER_MAX
  // metadata entries (~250 B each), so the profile/roster frame stays well under
  // MAX_ATTACH. Bounded text history is sent separately in deterministic chunks.

  /** Send every delivery of a fan-out to its device inbox. Only ever used for the
   *  link snapshot / bootstrap frames — all silent, so none arms a phantom push. */
  async function dispatchDeliveries(deliveries: { deviceSignPub: Bytes; sealed: Bytes }[]) {
    for (const d of deliveries) {
      const room = await inboxRoom(d.deviceSignPub);
      connectDeviceInbox(room);
      relaysRef.current.get(room)?.send(d.sealed, randomMid(), true);
    }
  }

  /** Bootstrap is a recovery stream, not best-effort gossip. Each frame must
   * resolve only after the relay confirms a durable INSERT, and the `only`
   * selector above must have produced exactly the intended device. */
  async function dispatchConfirmedBootstrapDelivery(
    targetSignPub: Bytes,
    deliveries: { deviceSignPub: Bytes; sealed: Bytes }[],
  ): Promise<void> {
    const delivery = requireExactBootstrapDelivery(targetSignPub, deliveries);
    const room = await inboxRoom(delivery.deviceSignPub);
    connectDeviceInbox(room);
    const client = relaysRef.current.get(room);
    if (!client) throw new Error('Bootstrap-Relay konnte nicht initialisiert werden.');
    await client.sendConfirmed(delivery.sealed, true);
  }

  /**
   * P side: answer a linked device's PULL with the account bootstrap stream over
   * the SELF contact, authenticated as my own master and fanned to exactly ONE
   * device. It carries profile/roster, bounded optional signed DeviceLists and
   * chunked text history, but no ratchet/session, bundle, room id or attachment.
   */
  /** Fan ONE bootstrap frame to exactly one of my devices. */
  async function sendBootstrapFrame(targetSignPub: Bytes, bid: string, parts: BootstrapPart[]) {
    const id = identityRef.current;
    if (!id) throw new Error('Bootstrap ohne lokale Identität abgebrochen.');
    const self = await ensureSelfContact();
    if (!self) throw new Error('Bootstrap-Selbstkontakt nicht verfügbar.');
    const content: MessageContent = { kind: 'bootstrap', bid, parts };
    const { deliveries, unreachable } = await enqueueInbox(async () => {
      const current = requireCurrentContact(self);
      const r = await fanoutFromThisDevice(id, current, content, randomMid(), id.sign.publicKey, targetSignPub);
      await saveContact(dek, current);
      return r;
    });
    if (unreachable.length > 0) {
      throw new Error('Bootstrap-Ziel ist kryptographisch nicht erreichbar.');
    }
    await dispatchConfirmedBootstrapDelivery(targetSignPub, deliveries);
  }

  /**
   * P side: send past messages to a freshly linked device, ONE CHUNK PER FRAME.
   * Every chunk carries its OWN bid — the applied-marker skips a whole frame, so a
   * shared id would silently drop every chunk after the first.
   *
   * TEXT ONLY for now: a stored attachment is base64 (~4/3 of its 600 KB cap), so a
   * single one already exceeds one frame. Attachments follow with chunked transfer
   * (issue #9).
   */
  async function sendHistoryTo(targetSignPub: Bytes, baseBid: string) {
    const id = identityRef.current;
    if (!id || !isPrimaryDevice(id)) return;
    const guard = bytesToB64(targetSignPub);
    if (historySendingRef.current.has(guard)) return; // a run is already streaming
    historySendingRef.current.add(guard);
    let skipped = 0;
    try {
      for (const c of contactsRef.current) {
        if (c.hidden || c.staleIdentity || bytesEqual(c.peerMasterPub, id.master.publicKey)) continue;
        const all = messagesRef.current[c.roomId] ?? [];
        const msgs: HistoryMessage[] = [];
        for (const m of all) {
          if (m.mid && typeof m.text === 'string' && m.text.length > 0) {
            msgs.push({ mine: !!m.mine, ts: m.ts, mid: m.mid, text: m.text, sender: m.sender });
          } else {
            skipped++; // attachment, or a pre-mid record we cannot dedup safely
          }
        }
        if (!msgs.length) continue;
        // Budget in UTF-8 BYTES: String.length counts UTF-16 units, so CJK text
        // would silently produce ~3x the intended frame size.
        const enc = new TextEncoder();
        const chunks: HistoryMessage[][] = [];
        let batch: HistoryMessage[] = [];
        let bytes = 0;
        for (const m of msgs) {
          const size = enc.encode(m.text).length + (m.sender ? enc.encode(m.sender).length : 0) + 80;
          if (batch.length && bytes + size > HISTORY_CHUNK_BYTES) {
            chunks.push(batch);
            batch = [];
            bytes = 0;
          }
          batch.push(m);
          bytes += size;
        }
        if (batch.length) chunks.push(batch);
        // Chunk ids are DETERMINISTIC and per contact: a retry re-sends the same id
        // with the same content, so applied chunks are skipped and only the gaps
        // land. A global counter would shift the boundaries between attempts and
        // hide new content behind an already-applied id.
        const room = bytesToB64(c.peerMasterPub);
        for (let i = 0; i < chunks.length; i++) {
          await sendBootstrapFrame(targetSignPub, `${baseBid}-h-${room}-${i}`, [
            { t: 'history', pm: c.peerMasterPub, idx: i, total: chunks.length, msgs: chunks[i] },
          ]);
        }
      }
      for (const group of groupsRef.current) {
        const all = messagesRef.current[group.id] ?? [];
        const msgs: HistoryMessage[] = [];
        for (const message of all) {
          if (
            message.mid &&
            typeof message.text === 'string' &&
            message.text.length > 0
          ) {
            msgs.push({
              mine: !!message.mine,
              ts: message.ts,
              mid: message.mid,
              text: message.text,
              sender: message.sender,
            });
          } else {
            skipped++;
          }
        }
        if (!msgs.length) continue;
        const enc = new TextEncoder();
        const chunks: HistoryMessage[][] = [];
        let batch: HistoryMessage[] = [];
        let bytes = 0;
        for (const message of msgs) {
          const size =
            enc.encode(message.text).length +
            (message.sender ? enc.encode(message.sender).length : 0) +
            80;
          if (batch.length && bytes + size > HISTORY_CHUNK_BYTES) {
            chunks.push(batch);
            batch = [];
            bytes = 0;
          }
          batch.push(message);
          bytes += size;
        }
        if (batch.length) chunks.push(batch);
        for (let index = 0; index < chunks.length; index++) {
          await sendBootstrapFrame(
            targetSignPub,
            `${baseBid}-gh-${group.id}-${index}`,
            [
              {
                t: 'ghistory',
                groupId: group.id,
                idx: index,
                total: chunks.length,
                msgs: chunks[index],
              },
            ],
          );
        }
      }
      // Only this frame stops the receiver from re-pulling.
      await sendBootstrapFrame(targetSignPub, `${baseBid}-done`, [{ t: 'done', skipped }]);
    } finally {
      historySendingRef.current.delete(guard);
    }
  }

  async function sendBootstrapTo(targetSignPub: Bytes, bid: string) {
    const id = identityRef.current;
    if (!id || !isPrimaryDevice(id)) return; // only the primary answers a pull
    if ((await loadPendingGroupMutationSnapshots(dek)).length > 0) {
      throw new Error(
        'Bootstrap wartet auf die bestätigte Zustellung einer Gruppenänderung.',
      );
    }
    const self = await ensureSelfContact();
    if (!self) return;
    const prof = myProfileRef.current;
    const avatar = prof.avatarB64 && prof.avatarB64.length <= AVATAR_IMPORT_CAP ? prof.avatarB64 : undefined;
    // Byte-budget the attached device lists: profile+roster ride in ONE unchunked frame that
    // must stay under the relay's per-message cap (~1.2 M b64). Include `dl` (which lets the
    // linked device initiate X3DH) up to a safe budget; any contact past it is sent without a
    // dl (send-blocked until it re-gossips) rather than risking a too-large, silently-dropped
    // frame that would break the whole Erst-Sync (audit L3).
    const DL_BUDGET = 500 * 1024;
    let dlUsed = 0;
    const contacts: RosterEntry[] = [];
    for (const c of contactsRef.current
      .filter((c) => !c.hidden && !c.staleIdentity && !bytesEqual(c.peerMasterPub, id.master.publicKey))
      .slice(0, ROSTER_MAX)) {
      let dl: Uint8Array<ArrayBuffer> | null = null;
      if (c.peerDeviceList) {
        const enc = await encodeDeviceList(c.peerDeviceList);
        if (dlUsed + enc.length <= DL_BUDGET) {
          dl = enc;
          dlUsed += enc.length;
        }
      }
      contacts.push({
        pm: c.peerMasterPub,
        pe: c.peerEpoch,
        psp: c.peerSignPub,
        pdp: c.peerDhPub,
        nick: c.nickname ?? null,
        pn: c.peerName ?? null,
        vf: c.verified === true, // a SUGGESTION on the far side, never adopted blindly
        dl,
      });
    }
    const parts: BootstrapPart[] = [
      { t: 'profile', name: prof.name, avatar },
      { t: 'roster', contacts },
    ];
    await sendBootstrapFrame(targetSignPub, bid, parts);
    // Replay barriers precede all live group states. A newly linked device must
    // never accept an old retained invitation in the gap before it learns that
    // this account had already been removed or had left.
    const tombstones = (await loadGroupRemovalTombstones(dek))
      .slice(0, 4096)
      .map((snapshot) => snapshot.tombstone);
    for (let index = 0; index < tombstones.length; index += 64) {
      await sendBootstrapFrame(
        targetSignPub,
        `${bid}-gt-${index / 64}`,
        [
          {
            t: 'gtombstones',
            tombstones: tombstones.slice(index, index + 64),
          },
        ],
      );
    }
    // Group state travels before group history, one bounded frame per group.
    for (const group of groupsRef.current) {
      await sendBootstrapFrame(
        targetSignPub,
        `${bid}-g-${group.id}`,
        [{ t: 'groups', groups: [await toInvite(group)] }],
      );
    }
    // Then the past messages, chunked, each frame independently applicable.
    await sendHistoryTo(targetSignPub, bid);
  }

  /**
   * N side: ask my primary for the snapshot. PULL rather than an eager push at
   * link time, because a push would arrive before this device has installed its
   * identity — it would be acked and lost. Safe to repeat: the requestId doubles
   * as the snapshot's idempotency key.
   */
  async function requestBootstrap() {
    const id = identityRef.current;
    if (!id || isPrimaryDevice(id)) return; // only a linked device pulls
    const req = bootstrapRequestRef.current;
    if (!req || !req.pending) return;
    const self = await ensureSelfContact();
    if (!self || !self.peerDeviceList || self.peerDeviceList.devices.length < 2) return;
    const content: MessageContent = { kind: 'bootreq', requestId: req.requestId };
    const { deliveries } = await enqueueInbox(async () => {
      const current = requireCurrentContact(self);
      const r = await fanoutFromThisDevice(id, current, content, randomMid(), id.sign.publicKey);
      await saveContact(dek, current);
      return r;
    });
    await dispatchDeliveries(deliveries);
  }

  /**
   * Acknowledge a peer's device list so they stop re-offering it.
   *
   * ⚠️ NEVER await this from inside an onInbox/queued task: encryptAndPersist
   * enqueues on the SAME chain, so awaiting it from within a queued task chains a
   * task behind the one that is waiting for it — the inbox would deadlock and stop
   * processing messages entirely. Call it as `void sendListAckTo(...)`.
   */
  async function sendListAckTo(contact: Contact, epoch: number, version: number, toDevice?: Bytes) {
    const id = identityRef.current;
    if (!id) return;
    try {
      if (toDevice) {
        // Address the DEVICE that offered the list. sendContent would go to the
        // peer's pinned PRIMARY, but the watermark is kept per device — a list
        // offered by their secondary would never see an ack and that device would
        // re-offer forever, filling the mailbox.
        const { deliveries } = await enqueueInbox(async () => {
          const current = requireCurrentContact(contact);
          const r = await fanoutFromThisDevice(id, current, { kind: 'listack', epoch, version }, randomMid(), undefined, toDevice);
          await saveContact(dek, current);
          return r;
        });
        await dispatchDeliveries(deliveries);
      } else {
        await sendEnvelopeTo(
          contact,
          await encryptAndPersist(contact, (current) =>
            sendListAck(id, current, epoch, version),
          ),
          undefined,
          true,
        );
      }
    } catch {
      /* best effort — they re-offer and we ack again */
    }
  }

  /**
   * Offer MY current device list to one peer — but only while their acknowledged
   * (epoch, version) is behind it. This is what actually makes a newly linked
   * device reachable: the one-shot gossip at link time misses every peer that was
   * offline, and those peers would then keep sending to the primary only, forever.
   * Throttled per contact so a chatty conversation can't turn into a gossip storm.
   *
   * ⚠️ Same rule as sendListAckTo: never await this from inside a queued task.
   */
  function peerAckForDevice(
    contact: Contact,
    deviceSignPub: Bytes,
  ): { epoch: number; version: number } | undefined {
    const perDevice =
      contact.peerAckedListByDevice?.[bytesToB64(deviceSignPub)];
    if (perDevice) return perDevice;
    // Backward compatibility: the old person-wide watermark can only safely
    // stand for the pinned primary. It must never silence retries to siblings.
    return bytesEqual(deviceSignPub, contact.peerSignPub)
      ? contact.peerAckedListEV
      : undefined;
  }

  function peerHasAckedListOnEveryDevice(
    contact: Contact,
    list: DeviceList,
  ): boolean {
    const targets =
      contact.peerDeviceList?.devices.map((device) => device.signPub) ??
      [contact.peerSignPub];
    return targets.every((target) => {
      const acked = peerAckForDevice(contact, target);
      return (
        !!acked &&
        !isNewerDeviceList(
          { epoch: list.epoch, version: list.version },
          acked,
        )
      );
    });
  }

  async function ensureListGossiped(contact: Contact) {
    const id = identityRef.current;
    const list = ownListRef.current;
    if (!id || !list) return;
    if (contact.localOnly || contact.staleIdentity) return;
    // Never gossip our device list (topology) to a revoked former-admin key.
    if (revokedOfficialAccountFor(contact)) return;
    const targets =
      contact.peerDeviceList?.devices.map((device) => device.signPub) ??
      [contact.peerSignPub];
    for (const target of targets) {
      const acked = peerAckForDevice(contact, target);
      if (
        acked &&
        !isNewerDeviceList(
          { epoch: list.epoch, version: list.version },
          acked,
        )
      ) {
        continue;
      }
      const attemptKey = `${contact.roomId}:${bytesToB64(target)}`;
      const last = listGossipAttemptRef.current.get(attemptKey);
      const sameList =
        last && last.epoch === list.epoch && last.version === list.version;
      // Exponential, per-device retry. An ack from B1 cannot suppress B2.
      const tries = sameList ? last.tries : 0;
      const wait = Math.min(
        GOSSIP_COOLDOWN_MS * 2 ** tries,
        GOSSIP_MAX_BACKOFF_MS,
      );
      if (sameList && Date.now() - last.at < wait) continue;
      listGossipAttemptRef.current.set(attemptKey, {
        epoch: list.epoch,
        version: list.version,
        at: Date.now(),
        tries: sameList ? tries + 1 : 0,
      });
      try {
        // fanoutDeliveries can establish X3DH from the target's signed SPK, so
        // hidden group contacts do not need a pre-existing session.
        await silentFanout(contact, { kind: 'devlist', list }, target);
      } catch {
        /* unreachable right now — the next trigger retries this device */
      }
    }
  }

  /** Stop the periodic bootstrap pull (idempotent). */
  async function clearBootstrapPending() {
    const req = bootstrapRequestRef.current;
    if (!req?.pending) return;
    bootstrapRequestRef.current = { ...req, pending: false };
    await saveBootstrapRequest(dek, bootstrapRequestRef.current);
  }

  /**
   * N side: apply a snapshot from my primary. Idempotent via `bid`. Every merge
   * only FILLS GAPS — anything this device already pinned or verified wins, and
   * `verified` is never adopted from the wire (only suggested).
   */
  async function applyBootstrapIfNew(
    bid: string,
    parts: BootstrapPart[],
    source: Contact,
  ) {
    const id = identityRef.current;
    if (!id) return;
    const isDone = parts.some((p) => p.t === 'done');
    if (bootstrapAppliedRef.current.has(bid)) {
      // Already imported. Only the completion frame may stop the pull — otherwise a
      // re-delivered first chunk would end a sync that is still missing chunks.
      if (isDone) await clearBootstrapPending();
      return;
    }
    const myMaster = asMasterPub(id.master.publicKey);
    for (const p of parts) {
      if (p.t === 'profile') {
        // Gap-fill: never overwrite a name/avatar this device already has.
        const cur = myProfileRef.current;
        const avatar = p.avatar && p.avatar.length <= AVATAR_IMPORT_CAP ? p.avatar : undefined;
        const next: MyProfile = { name: cur.name ?? p.name, avatarB64: cur.avatarB64 ?? avatar };
        if (next.name !== cur.name || next.avatarB64 !== cur.avatarB64) {
          // Persistence FIRST. A transient IndexedDB abort must leave RAM unchanged so the same
          // bootstrap ciphertext retries the write instead of seeing a phantom "already filled"
          // profile and then durably marking the bootstrap applied.
          await saveProfile(dek, next);
          myProfileRef.current = next;
          setProfileName(next.name ?? '');
          setMyAvatarB64(next.avatarB64 ?? '');
          setMyName(next.name ?? '');
        }
      } else if (p.t === 'groups') {
        for (const invite of p.groups) {
          await applyGroupInvite(invite, source, true);
        }
      } else if (p.t === 'gtombstones') {
        for (const tombstone of p.tombstones) {
          const installed = await saveGroupRemovalTombstone(dek, tombstone);
          const current = groupsRef.current.find(
            (group) => group.id === installed.tombstone.groupId,
          );
          if (!current) continue;
          const sameOwner =
            !!current.ownerMasterPub &&
            bytesEqual(
              current.ownerMasterPub,
              installed.tombstone.ownerMasterPub,
            );
          if (
            !sameOwner ||
            installed.tombstone.blockReadd ||
            current.revision <= installed.tombstone.revision
          ) {
            await deleteGroupActionWithinInbox(
              installed.tombstone.groupId,
              installed.tombstone,
            );
          } else {
            await clearGroupRemovalTombstone(installed);
          }
        }
      } else if (p.t === 'ghistory') {
        if (
          !/^grp_[0-9a-f]{32}$/.test(p.groupId) ||
          !groupsRef.current.some((group) => group.id === p.groupId)
        ) {
          continue;
        }
        await enqueueMessageMutation(p.groupId, async () => {
          if (messagesRef.current[p.groupId] === undefined) {
            messagesRef.current[p.groupId] = await loadMessages(dek, p.groupId);
          }
          const base = messagesRef.current[p.groupId] ?? [];
          const next = [...base];
          let added = 0;
          for (const history of p.msgs) {
            if (hasMessage(next, history.mid, history.mine)) continue;
            next.push({
              mine: history.mine,
              ts: history.ts,
              mid: history.mid,
              text: history.text,
              sender: history.sender,
            });
            added++;
          }
          if (!added) return;
          next.sort((a, b) => a.ts - b.ts);
          await saveMessages(dek, p.groupId, next);
          messagesRef.current[p.groupId] = next;
        });
      } else if (p.t === 'history') {
        // DISPLAY ROOM derived locally from (my master, pm) — never from the wire,
        // exactly like a roster entry. Missing messages are appended and the log
        // re-sorted by timestamp; dedup by (mid, direction) so a message this device
        // already holds from the live path is not duplicated.
        const room = await computeMasterRoomId(myMaster, asMasterPub(p.pm));
        await enqueueMessageMutation(room, async () => {
          if (messagesRef.current[room] === undefined) {
            messagesRef.current[room] = await loadMessages(dek, room);
          }
          const base = messagesRef.current[room] ?? [];
          const next = [...base];
          let added = 0;
          for (const h of p.msgs) {
            if (hasMessage(next, h.mid, h.mine)) continue;
            next.push({ mine: h.mine, ts: h.ts, mid: h.mid, text: h.text, sender: h.sender });
            added++;
          }
          if (!added) return;
          next.sort((a, b) => a.ts - b.ts);
          // Never publish the merged snapshot until it is durable.
          await saveMessages(dek, room, next);
          messagesRef.current[room] = next;
        });
      } else if (p.t === 'done') {
        if (p.skipped > 0) console.info(`[erst-sync] ${p.skipped} Nachrichten nicht übertragen (Anhänge / ohne mid).`);
      } else if (p.t === 'roster') {
        for (const entry of p.contacts) {
          const merged = await mergeRosterEntry(contactsRef.current, entry, myMaster, retiredMastersRef.current);
          if (!merged) continue; // self / denylisted / room collision
          // By roomId, not object identity: addBundle can insert the same peer
          // during an await here and would otherwise get a second, send-blocked
          // record that overwrites the real one under the same storage key.
          const known = contactsRef.current.some((c) => c.roomId === merged.roomId);
          if (!known) contactsRef.current = [...contactsRef.current, merged];
          else if (!contactsRef.current.includes(merged)) continue;
          await saveContact(dek, merged);
        }
      }
    }
    // Marker LAST: a crash before this just replays the (idempotent) merge.
    bootstrapAppliedRef.current.add(bid);
    await saveBootstrapApplied(dek, bootstrapAppliedRef.current);
    if (isDone) await clearBootstrapPending(); // every chunk arrived
    commitMessages();
    bump();
  }

  // When a peer device is revoked, sweep this conversation's still-open delivery
  // rows for that device to 'stale' — so the aggregate drops it from the CURRENT
  // device set (Review fund 6): a message the person actually received on their
  // other devices stops showing a permanent partial-failure. A 'sent' row stays
  // (once delivered, always delivered).
  async function sweepRevokedDeliveries(contact: Contact): Promise<void> {
    const list = contact.peerDeviceList;
    if (!list) return;
    const live = new Set(list.devices.map((d) => bytesToB64(d.signPub)));
    await enqueueMessageMutation(contact.roomId, async () => {
      const arr = messagesRef.current[contact.roomId];
      if (!arr) return;
      let changed = false;
      const next = arr.map((message) => {
        const deliveries = message.deliveries;
        if (!deliveries) return message;
        let messageChanged = false;
        const updated = deliveries.map((delivery) => {
          if (
            delivery.status !== 'stale' &&
            delivery.status !== 'sent' &&
            !live.has(delivery.device)
          ) {
            // The device is gone from the list — its ack will never come.
            clearAckTimer(delivery.deliveryId);
            changed = true;
            messageChanged = true;
            return { ...delivery, status: 'stale' as const };
          }
          return delivery;
        });
        return messageChanged
          ? { ...message, deliveries: updated }
          : message;
      });
      if (!changed) return;
      await saveMessages(dek, contact.roomId, next);
      messagesRef.current[contact.roomId] = next;
      commitMessages();
      bump();
    });
  }

  // ── roomId migration (device-DH → master) ──────────────────────────
  // Move one contact's storage AND its in-memory maps from oldRoomId to its
  // already-set contact.roomId. The single crash-safe routine every mutation
  // site funnels through (boot migration, acceptRotation, acceptMasterChange) —
  // so no site can orphan history or leave a dead map key. The caller sets the
  // new contact.roomId first (migrate for boot; the door functions themselves).
  async function reKeyContactInMemory(oldRoomId: string, contact: Contact): Promise<void> {
    const newRoomId = contact.roomId;
    if (oldRoomId === newRoomId) return;
    // Lock BOTH aliases as one queue entry. Waiting only on the old id lets an
    // ACK/append under the already-derived master id race moveContactStorage;
    // locking them independently in caller order can deadlock two inverse moves.
    await enqueueMessageMutations([oldRoomId, newRoomId], async () => {
      // Stage BOTH scoped recall namespaces before moving the contact/history.
      // A crash on either side of moveContactStorage then retains a key matching
      // the surviving room generation; the old aliases are removed afterwards.
      const stagedRecalls = moveRecallRegistryRoom(
        recalledMidsRef.current,
        oldRoomId,
        newRoomId,
        true,
      );
      if (
        stagedRecalls.length !== recalledMidsRef.current.size ||
        stagedRecalls.some((value) => !recalledMidsRef.current.has(value))
      ) {
        await saveRecalledMids(dek, stagedRecalls);
        recalledMidsRef.current = new Set(stagedRecalls);
      }
      await moveContactStorage(dek, oldRoomId, contact); // re-seal storage old → new
      const movedRecalls = moveRecallRegistryRoom(
        recalledMidsRef.current,
        oldRoomId,
        newRoomId,
      );
      if (
        movedRecalls.length !== recalledMidsRef.current.size ||
        movedRecalls.some((value) => !recalledMidsRef.current.has(value))
      ) {
        await saveRecalledMids(dek, movedRecalls);
        recalledMidsRef.current = new Set(movedRecalls);
      }
      if (messagesRef.current[oldRoomId] !== undefined) {
        messagesRef.current[newRoomId] = messagesRef.current[oldRoomId];
        delete messagesRef.current[oldRoomId];
      }
      if (unreadRef.current[oldRoomId] !== undefined) {
        unreadRef.current[newRoomId] = unreadRef.current[oldRoomId];
        delete unreadRef.current[oldRoomId];
      }
      const room = sendRoomRef.current.get(oldRoomId);
      if (room !== undefined) {
        sendRoomRef.current.set(newRoomId, room);
        sendRoomRef.current.delete(oldRoomId);
      }
      if (profileSentRef.current.has(oldRoomId)) {
        profileSentRef.current.delete(oldRoomId);
        profileSentRef.current.add(newRoomId);
      }
      setStatuses((prev) => {
        if (prev[oldRoomId] === undefined) return prev;
        const n = { ...prev };
        n[newRoomId] = n[oldRoomId];
        delete n[oldRoomId];
        return n;
      });
    });
  }

  // One-time boot migration of the whole vault to the master regime. Pulls each
  // contact's per-contact retiredMasters into the GLOBAL denylist, sets
  // ownMasterPub where missing, and re-keys every device-regime contact —
  // collapsing crash-interrupted duplicates (two records for one peer) by
  // keeping the one with a live ratchet / more messages, never blind-overwriting.
  async function migrateContactsToMaster() {
    const id = identityRef.current;
    if (!id) return;
    const myMaster = asMasterPub(id.master.publicKey);

    // Move per-contact retiredMasters into the global denylist (one-time).
    const retired = retiredMastersRef.current;
    for (const c of contactsRef.current) {
      if (c.retiredMasters?.length) {
        for (const rm of c.retiredMasters) if (!retired.has(rm)) await addRetiredMaster(dek, rm);
        c.retiredMasters = undefined;
      }
    }

    // Give un-migrated contacts an ownMasterPub. A staleIdentity contact without
    // one lost its pre-link master (pre-v0.18.7) → cannot derive the peer-
    // symmetric room; leave it device-regime, the user must reconnect.
    for (const c of contactsRef.current) {
      if (c.regime === 'master') continue;
      if (!c.ownMasterPub && !c.staleIdentity) c.ownMasterPub = myMaster;
    }

    // Group by the TARGET master-roomId to detect crash-interrupted duplicates.
    const score = (c: Contact) => (hasSession(c) ? 1_000_000 : 0) + (messagesRef.current[c.roomId]?.length ?? 0);
    const byTarget = new Map<string, Contact[]>();
    for (const c of contactsRef.current) {
      if (c.regime !== 'master' && !c.ownMasterPub) continue; // hard case, skip
      const target =
        c.regime === 'master'
          ? c.roomId
          : await computeMasterRoomId(asMasterPub(c.ownMasterPub!), asMasterPub(c.peerMasterPub));
      (byTarget.get(target) ?? byTarget.set(target, []).get(target)!).push(c);
    }

    const losers: Contact[] = [];
    const survivorIds = new Set<string>(); // final roomIds a winner occupies — never delete
    for (const group of byTarget.values()) {
      // Winner: highest score. On a TIE prefer the record ALREADY in the master
      // regime (already at the target roomId), so we never migrate a device copy
      // ONTO a live master record's key and then delete that same key as a
      // "loser" — the silent, permanent data loss a crash-interrupted duplicate
      // produced (the winner's freshly re-sealed contact+history would be wiped).
      let winner = group[0];
      for (const c of group) {
        const s = score(c);
        const w = score(winner);
        if (s > w || (s === w && winner.regime !== 'master' && c.regime === 'master')) winner = c;
      }
      for (const c of group) if (c !== winner) losers.push(c);
      if (winner.regime !== 'master') {
        try {
          const oldRoomId = winner.roomId;
          await migrateContactRoomId(winner); // sets winner.roomId + regime='master'
          await reKeyContactInMemory(oldRoomId, winner); // moves storage + maps
        } catch (e) {
          console.error('[migrate] Kontakt nicht migrierbar (bleibt device):', (e as Error).message);
        }
      }
      survivorIds.add(winner.roomId); // post-migration roomId
    }
    for (const l of losers) {
      // Never delete a storage key a migrated winner now owns: if a device winner
      // was re-keyed INTO a master loser's roomId, moveContactStorage already
      // re-sealed contact+messages there and reKeyContactInMemory moved the live
      // messages under that key — removeContact/delete would nuke the survivor.
      if (survivorIds.has(l.roomId)) continue;
      await removeContact(dek, l.roomId);
      delete messagesRef.current[l.roomId];
    }
    if (losers.length) contactsRef.current = contactsRef.current.filter((c) => !losers.includes(c));
  }

  // ── Device linking ──────────────────────────────────────────────────
  function acknowledgeLinkGrantRow(ackId: number) {
    linkPendingGrantsRef.current.delete(ackId);
    seenIdsRef.current.add(ackId);
    inboxClientRef.current?.ack(ackId);
  }

  function acknowledgePendingLinkGrantRows() {
    for (const ackId of [...linkPendingGrantsRef.current.keys()]) acknowledgeLinkGrantRow(ackId);
  }

  // Before SAS confirmation this is a total abort. Once N has confirmed, the
  // encrypted recovery intent is a durable protocol transition: generic close,
  // navigation and retry paths may no longer discard it or ACK held Grants.
  function resetLink(): boolean {
    if (linkRecoveryProtectedRef.current) {
      setLinkBusy(true);
      return false;
    }
    acknowledgePendingLinkGrantRows();
    linkSessionRef.current = null;
    linkPendingGrantsRef.current.clear();
    linkInstallPromiseRef.current = null;
    linkConfirmedRef.current = false;
    confirmedLinkIntentRef.current = null;
    setLinkSas(null);
    setLinkQr('');
    setLinkBusy(false);
    return true;
  }

  async function discardConfirmedNewDeviceRecovery() {
    const id = identityRef.current;
    const session = linkSessionRef.current;
    if (
      !id ||
      !session ||
      session.role !== 'new' ||
      !linkRecoveryProtectedRef.current ||
      !linkConfirmedRef.current
    ) {
      return;
    }
    if (linkAbortInProgressRef.current || linkInstallPromiseRef.current) {
      setError(t('Der Kopplungs-Nachweis wird gerade geprüft. Warte kurz und versuche den Abbruch erneut.'));
      return;
    }
    if (
      id.previousMasterPub &&
      session.offer &&
      bytesEqual(id.master.publicKey, session.offer.masterPub) &&
      id.epoch === session.offer.epoch
    ) {
      setError(t('Diese Kopplung ist lokal bereits installiert und kann nicht mehr als wartender Versuch verworfen werden. Schließe die Recovery ab und widerrufe das Gerät anschließend am Hauptgerät.'));
      return;
    }
    const confirmed = window.confirm(t(
      'Kopplung endgültig verwerfen? Dies löscht nur die lokale Recovery. Das Hauptgerät kann dieses Gerät bereits autorisiert haben. Prüfe dort danach unter „Geräte verwalten“ die Liste und widerrufe dieses Gerät ausdrücklich.',
    ));
    if (!confirmed) return;

    // Close the install race synchronously before the first await. A Grant that
    // arrives during the durable discard is retained, but cannot start install.
    linkAbortInProgressRef.current = true;
    setLinkAbortBusy(true);
    try {
      const intent =
        confirmedLinkIntentRef.current ??
        await loadConfirmedNewDeviceLinkIntent(dek);
      if (!intent) throw new Error(t('Bestätigter Recovery-Intent fehlt.'));
      const rejectionSession = await restoreDiscardedNewDeviceLinkSession(intent, id);
      const ownGrantRows = await confirmedLinkGrantRows(
        id,
        session,
        linkPendingGrantsRef.current,
      );
      // The explicit user decision becomes durable before any relay row is
      // retired. The atomic transition retains a rejection-only transcript
      // without TTL, so even a Grant arriving after reload stays attributable.
      await discardConfirmedNewDeviceLinkIntent(dek, intent);
      discardedLinkSessionsRef.current = [
        ...discardedLinkSessionsRef.current,
        rejectionSession,
      ];
      confirmedLinkIntentRef.current = null;
      linkRecoveryProtectedRef.current = false;
      linkConfirmedRef.current = false;
      // ACK only credentials proven to belong to the discarded transcript.
      // Anonymous malformed/foreign sibling rows are removed from local RAM
      // without consuming their independent relay entries.
      for (const ackId of ownGrantRows) {
        if (linkPendingGrantsRef.current.has(ackId)) acknowledgeLinkGrantRow(ackId);
      }
      linkPendingGrantsRef.current.clear();
      linkSessionRef.current = null;
      linkInstallPromiseRef.current = null;
      setLinkSas(null);
      setLinkQr('');
      setLinkBusy(false);
      setLinkView('menu');
      setError(t('Lokale Kopplungs-Recovery endgültig verworfen. Prüfe jetzt am Hauptgerät die Geräteliste und widerrufe dieses Gerät, falls es dort bereits auftaucht.'));
    } catch (e) {
      setError(t('Kopplungs-Recovery konnte nicht sicher verworfen werden: {msg}', {
        msg: (e as Error).message,
      }));
      setLinkBusy(false);
    } finally {
      linkAbortInProgressRef.current = false;
      setLinkAbortBusy(false);
      if (
        linkRecoveryProtectedRef.current &&
        linkConfirmedRef.current &&
        linkPendingGrantsRef.current.size > 0
      ) {
        void installGrant().catch(() => undefined);
      }
    }
  }

  // N starts: show our QR, then wait for P's offer on our inbox.
  async function startJoinAsNewDevice() {
    const id = identityRef.current;
    const pre = prekeysRef.current;
    if (!id || !pre || linkRecoveryProtectedRef.current) return;
    setError('');
    const { session, qrToken } = await startLinkOnN(id, ownSpkPublic(pre));
    linkSessionRef.current = session;
    linkConfirmedRef.current = false;
    confirmedLinkIntentRef.current = null;
    linkPendingGrantsRef.current.clear();
    setLinkQr(await makeQr(qrToken).catch(() => ''));
    setLinkView('qr');
  }

  // N received P's offer → derive and show the emoji.
  async function onLinkOffer(payload: Bytes) {
    const session = linkSessionRef.current;
    if (!session || session.role !== 'new' || linkRecoveryProtectedRef.current) {
      return; // not linking, wrong role, or an already-confirmed transcript
    }
    try {
      const sas = await offerReceivedOnN(session, payload);
      setLinkSas(sas);
      setLinkView('sas');
    } catch (e) {
      setError('Kopplung fehlgeschlagen: ' + (e as Error).message);
      resetLink();
      setLinkView(null);
    }
  }

  // N received P's grant. Held until the user confirms the emoji here too — an
  // unconfirmed grant is never installed.
  async function onLinkGrant(payload: Bytes, ackId: number) {
    const session = linkSessionRef.current;
    if (!session || session.role !== 'new') return;
    linkPendingGrantsRef.current.set(ackId, payload);
    if (linkConfirmedRef.current && !linkAbortInProgressRef.current) {
      void installGrant().catch(() => undefined);
    }
  }

  async function matchesDiscardedLinkGrant(payload: Bytes): Promise<boolean> {
    const id = identityRef.current;
    if (!id || discardedLinkSessionsRef.current.length === 0) return false;
    let grant;
    try {
      grant = await decodeLinkGrant(payload);
    } catch {
      return false;
    }
    for (const session of discardedLinkSessionsRef.current) {
      try {
        if (await verifyDiscardedNewDeviceLinkGrant(id, session, grant)) return true;
      } catch {
        // A different/corrupt anonymous candidate is not attributable to this
        // tombstone and therefore cannot be ACKed on its behalf.
      }
    }
    return false;
  }

  // N confirmed the emoji. Persist the exact transcript BEFORE making the
  // confirmation active for Grant installation; boot reconstructs and
  // cryptographically revalidates this capability after any crash/reload.
  async function onNConfirmSas() {
    const id = identityRef.current;
    const pre = prekeysRef.current;
    const session = linkSessionRef.current;
    if (!id || !pre || !session || session.role !== 'new') return;
    if (linkRecoveryProtectedRef.current && linkConfirmedRef.current) {
      // Retry an already-durable confirmation without rewriting its pre-link
      // identity witness (the identity may have committed before a later write
      // failed). The held authenticated candidate remains attempt-specific.
      setLinkBusy(true);
      if (linkPendingGrantsRef.current.size > 0) await installGrant();
      return;
    }
    // Protect synchronously: navigation while the durable write is pending must
    // not reset the transcript or ACK an early Grant.
    linkRecoveryProtectedRef.current = true;
    setLinkBusy(true);
    try {
      confirmLinkSession(session);
      const intent = await createConfirmedNewDeviceLinkIntent(
        session,
        id,
        ownSpkPublic(pre),
      );
      await saveConfirmedNewDeviceLinkIntent(dek, intent);
      confirmedLinkIntentRef.current = intent;
      linkConfirmedRef.current = true;
      if (linkPendingGrantsRef.current.size > 0) await installGrant();
      // Otherwise remain busy while waiting for P's confirmed Grant.
    } catch (e) {
      setError('Kopplung konnte nicht sicher bestätigt werden: ' + (e as Error).message);
      // Keep protection/session/rows. The same confirmation can be retried; no
      // row is lost because IndexedDB was temporarily unavailable.
      setLinkBusy(false);
    }
  }

  function installGrant(): Promise<boolean> {
    if (linkInstallPromiseRef.current) return linkInstallPromiseRef.current;
    if (linkAbortInProgressRef.current) return Promise.resolve(false);
    const run = runRuntimeOperation(async (signal) => {
      if (signal.aborted) throw new MessengerInactiveError();
      const installed = await drainPendingLinkGrants();
      if (signal.aborted) throw new MessengerInactiveError();
      return installed;
    }).finally(() => {
      if (linkInstallPromiseRef.current === run) linkInstallPromiseRef.current = null;
    });
    linkInstallPromiseRef.current = run;
    return run;
  }

  async function drainPendingLinkGrants(): Promise<boolean> {
    if (!linkConfirmedRef.current) return false;
    return drainLinkGrantCandidates(
      linkPendingGrantsRef.current,
      performInstallGrant,
      // Anonymous outer sealing authenticates only the recipient. A malformed,
      // stale or forged candidate retires ITS row and cannot consume the
      // confirmed session or ACK another candidate waiting behind it.
      acknowledgeLinkGrantRow,
    );
  }

  async function performInstallGrant(
    ackId: number,
    payload: Bytes,
  ): Promise<'installed' | 'invalid' | 'retry'> {
    const id = identityRef.current;
    const session = linkSessionRef.current;
    if (
      !id ||
      !session ||
      session.role !== 'new' ||
      !linkConfirmedRef.current ||
      linkPendingGrantsRef.current.get(ackId) !== payload
    ) {
      return 'retry';
    }
    setLinkBusy(true);
    let identityCommitted = false;
    let grantValidated = false;
    try {
      const grant = await decodeLinkGrant(payload);
      if (!(await verifyConfirmedNewDeviceLinkGrant(id, session, grant))) {
        setError(t('Ungültiger oder veralteter Kopplungs-Nachweis wurde verworfen.'));
        setLinkBusy(false);
        return 'invalid';
      }
      grantValidated = true;
      // Farewell BEFORE the identity swap: our contacts still pin the OLD master,
      // and once we install, sending is blocked (staleIdentity). So the goodbye
      // must ride out over the still-valid old session, or never.
      const farewell = async () => {
        for (const c of contactsRef.current) {
          try {
            await sendEnvelopeTo(
              c,
              await encryptAndPersist(c, (current) =>
                sendMessage(id, current, t('🔗 Ich habe ein neues Gerät gekoppelt — meine Identität ändert sich. Bitte bestätige die neue Identität, wenn du gefragt wirst.')),
              ),
            );
          } catch {
            /* one unreachable contact must not block the link */
          }
        }
      };
      // Snapshot the PRE-SWAP master. A retry after the atomic identity/list
      // commit uses previousMasterPub and must not overwrite that witness.
      const preSwapMaster = asMasterPub(id.previousMasterPub ?? id.master.publicKey);
      const alreadyInstalled = await confirmedLinkGrantAlreadyInstalled(id, session, grant);
      // Farewell uses encryptAndPersist, which enters the inbox queue itself.
      // Finish those courtesy sends first; the security-critical identity swap,
      // every stale-contact barrier and its bootstrap witness then commit as ONE
      // inbox task. No live receive/UI writer can land a stale full Contact after
      // the swap or observe the new identity with old send permissions.
      if (!alreadyInstalled) await farewell();
      const linked = await enqueueInbox(async () => {
        const installed = alreadyInstalled
          ? id
          : await completeLinkOnN(dek, id, session, grant);
        identityCommitted = true; // newly committed, or proven by durable witness
        for (const c of contactsRef.current) {
          c.staleIdentity = true;
          if (!c.ownMasterPub) c.ownMasterPub = preSwapMaster;
        }
        identityRef.current = installed;
        for (const c of contactsRef.current) await saveContact(dek, c);
        // Preserve an already-created request id across a post-commit retry, but
        // always repeat the durable write. Publishing a RAM ref before a failed
        // IndexedDB write must not let the next retry skip this barrier.
        const bootstrapRequest =
          bootstrapRequestRef.current ?? {
            requestId: randomMid(),
            pending: true,
          };
        await saveBootstrapRequest(dek, bootstrapRequest);
        bootstrapRequestRef.current = bootstrapRequest;
        return installed;
      });
      // Identity/list, every contact barrier and the bootstrap request are now
      // durable. Only then retire the recovery capability and held relay rows.
      await clearConfirmedNewDeviceLinkIntent(dek);
      confirmedLinkIntentRef.current = null;
      linkRecoveryProtectedRef.current = false;
      acknowledgePendingLinkGrantRows();
      resetLink();
      setLinkView('done');
      bump();
      void requestBootstrap();
      // UI-only refreshes cannot turn a completed protocol into a poison row.
      void fingerprintOf(linked).then(setFingerprint).catch(() => undefined);
      const pre = prekeysRef.current;
      if (pre) {
        void encodeBundle(currentBundle(linked, pre))
          .then((token) => {
            return makeQr(updateShareBundle(token));
          })
          .then(setQrDataUrl)
          .catch(() => undefined);
      }
      return 'installed';
    } catch (e) {
      setError('Kopplung fehlgeschlagen: ' + (e as Error).message);
      if (
        grantValidated ||
        identityCommitted ||
        isStorageFull(e) ||
        isTransientStorageFailure(e) ||
        e instanceof StaleAccountGenerationError
      ) {
        // Once authenticated against the confirmed transcript, any failure may
        // straddle a crash/storage boundary. Retain this exact row + intent.
        setLinkBusy(false);
        return 'retry';
      }
      // Decode/shape failure before authentication: retire only this anonymous
      // candidate. Never reset the confirmed session or ACK sibling rows.
      setLinkBusy(false);
      return 'invalid';
    }
  }

  // P scanned N's QR → send the inert offer and show the emoji.
  async function onScanNewDevice(qrToken: string) {
    const id = identityRef.current;
    if (!id) return;
    setError('');
    setLinkBusy(true);
    try {
      const { session, sas } = await beginLinkOnP(id, qrToken, sendToInbox);
      linkSessionRef.current = session;
      setLinkSas(sas);
      setLinkView('sas');
    } catch (e) {
      setError('Kopplung fehlgeschlagen: ' + (e as Error).message);
      resetLink();
      setLinkView('menu');
    } finally {
      setLinkBusy(false);
    }
  }

  // P confirmed the emoji → atomically persist list + retry intent, publish the
  // committed list to RAM/self-contact, and only then expose the Grant to N.
  // Gossip our updated device list to every contact with an established session,
  // including hidden group-member contacts. This is the revocation transport
  // that keeps group fan-out on the same authoritative target set as 1:1.
  async function gossipDeviceList(list: DeviceList) {
    const id = identityRef.current;
    if (!id) return;
    // A caller may finish after another CAS writer. Reconcile first and use one
    // monotonic authority for peer gossip and the explicit self-device fanout.
    const authoritative = await reconcileOwnDeviceList(list);
    for (const c of contactsRef.current) {
      if (
        c.localOnly ||
        c.staleIdentity ||
        bytesEqual(c.peerMasterPub, id.master.publicKey)
      ) {
        continue;
      }
      try {
        await ensureListGossiped(c);
      } catch {
        /* unreachable contact — best effort, they learn it next time */
      }
    }
    // Also deliver my updated list to my OWN other devices (via the self-contact), so
    // a device linked earlier learns about a sibling linked later and self-syncs to
    // it too (Review fund 4). The recipient adopts it into its stored own list.
    const self = await ensureSelfContact();
    if (self && self.peerDeviceList && self.peerDeviceList.devices.length >= 2) {
      try {
        const { deliveries } = await enqueueInbox(async () => {
          const current = requireCurrentContact(self);
          const r = await fanoutFromThisDevice(id, current, { kind: 'devlist', list: authoritative }, randomMid(), id.sign.publicKey);
          await saveContact(dek, current);
          return r;
        });
        for (const d of deliveries) {
          const room = await inboxRoom(d.deviceSignPub);
          connectDeviceInbox(room);
          relaysRef.current.get(room)?.send(d.sealed, randomMid(), true); // devlist gossip to own devices — silent
        }
      } catch {
        /* best effort */
      }
    }
  }

  async function onPConfirmSas() {
    const id = identityRef.current;
    const pre = prekeysRef.current;
    const session = linkSessionRef.current;
    if (!id || !pre || !session) return;
    confirmLinkSession(session);
    setLinkBusy(true);
    try {
      const currentList = await loadOrCreateOwnDeviceList(dek, id, ownSpkPublic(pre));
      if (!currentList) throw new Error(t('Geräteliste nicht verfügbar.'));
      const newList = await completeLinkOnP(
        dek,
        id,
        session,
        sendToInbox,
        synchronizeCommittedPrimaryLinkList,
      );
      setPrimaryLinkDeliveryPending(false);
      primaryPendingLinkTargetRef.current = null;
      // Gossip the updated list so contacts learn the new device (and, later,
      // stop accepting a removed one). Best-effort: revocation takes effect for
      // a contact once it has seen this newer, master-signed list.
      await gossipDeviceList(newList);
      resetLink();
      setLinkView('done');
    } catch (e) {
      if (e instanceof LinkGrantDeliveryPendingError) {
        // DeviceList + exact retry payload are already durable. Keep that
        // distinction visible: retrying the same payload is safe; starting a
        // second link/revoke remains blocked until delivery is resolved.
        await synchronizeCommittedPrimaryLinkList(e.committedList).catch(() => undefined);
        setPrimaryLinkDeliveryPending(true);
        primaryPendingLinkTargetRef.current = e.pendingTarget;
        setError(t('Das neue Gerät ist bereits dauerhaft autorisiert, aber der Kopplungs-Nachweis wurde vom Relay noch nicht bestätigt. Du kannst dieselbe Zustellung wiederholen oder die ausstehende Autorisierung atomar abbrechen und widerrufen.'));
        resetLink();
        setLinkView('menu');
        return;
      }
      if (e instanceof LinkGrantDeliveryCancelledError) {
        await synchronizeCommittedPrimaryLinkList(e.currentList).catch(() => undefined);
        await gossipDeviceList(e.currentList).catch(() => undefined);
        setPrimaryLinkDeliveryPending(false);
        primaryPendingLinkTargetRef.current = null;
        setError(e.discardedCorruptReplacement
          ? t('Eine parallel ersetzte Kopplungs-Recovery war beschädigt und wurde entfernt. Prüfe die aktuelle Geräteliste und widerrufe unbekannte Geräte.')
          : t('Die ausstehende Kopplung wurde parallel beendet oder widerrufen; die aktuelle Geräteliste wurde übernommen.'));
        resetLink();
        setLinkView('menu');
        return;
      }
      setError('Kopplung fehlgeschlagen: ' + (e as Error).message);
      resetLink();
      setLinkView(null);
    }
  }

  async function onInbox(bytes: Bytes, ackId: number) {
    const id = identityRef.current;
    const lookup = lookupRef.current;
    if (!id || !lookup) return; // not ready — leave queued (no ack), retry on reconnect

    if (seenIdsRef.current.has(ackId)) {
      inboxClientRef.current?.ack(ackId);
      return;
    }

    let retainRelayRow = false;
    try {
      let env;
      try {
        // Sealed Sender: open the anonymous outer box, then dispatch on the
        // payload tag — an inbox also receives non-envelope payloads (a device
        // linking grant, which has no ratchet session behind it).
        const opened = await openPayload(id, bytes);
        if (!opened) return; // not sealed for us
        // Device-linking payloads (N side): the offer carries P's SAS ephemeral
        // + master so N can show the emoji; the grant arrives after P confirms.
        if (opened.type === SEALED_LINK_OFFER) {
          await onLinkOffer(opened.payload);
          return;
        }
        if (opened.type === SEALED_LINK_GRANT) {
          const session = linkSessionRef.current;
          const disposition = await classifyLinkGrantRelayRow(
            opened.payload,
            session?.role === 'new',
            matchesDiscardedLinkGrant,
          );
          if (disposition === 'discarded') {
            // Exact late credential of a consciously discarded transcript:
            // reject and ACK this row, without resurrecting install capability.
            return;
          }
          if (disposition === 'active' && session?.role === 'new') {
            // Keep this exact row until it is either proven invalid itself or
            // the credential + stale-contact/bootstrap barrier are durable.
            retainRelayRow = true;
            await onLinkGrant(opened.payload, ackId);
          }
          // With no active attempt, an unmatched candidate is generically
          // stale/invalid and only this exact outer relay row is ACKed below.
          return;
        }
        if (opened.type !== SEALED_ENVELOPE) return; // unknown tag — drop
        env = await decodeEnvelope(opened.payload);
      } catch {
        return; // handled in finally (ack + drop)
      }

      // RESOLVE (regime-robust): may use the legacy device-derivation for a
      // not-yet-migrated contact. Resolution only — authorisation happens in
      // receiveEnvelope against the master.
      const myMaster = asMasterPub(id.master.publicKey);
      let contact = await resolveContactByConv(contactsRef.current, env.conv, id.dh.publicKey, myMaster);
      if (!contact && env.type === 'prekey' && bytesEqual(env.x3dh.masterPub, id.master.publicKey)) {
        // A prekey under MY OWN master is one of my other devices (self-sync). Route
        // it to the hidden self-contact, never auto-create a visible "contact for me".
        contact = (await ensureSelfContactWithinInbox()) ?? undefined;
      }
      if (!contact) {
        if (env.type !== 'prekey') return;
        // AUTO-CREATE only on a MASTER-based conv that matches the sender's own
        // claimed master. A device-based unknown conv is not a valid reason to
        // mint a contact post-flip (Stage 3c): resolution may use the legacy
        // derivation, creation may not — else the weaker path becomes a trust
        // decision (the openInbound-fallback shape).
        const masterConv = await computeMasterRoomId(myMaster, asMasterPub(env.x3dh.masterPub));
        if (env.conv !== masterConv) return;
        // DENYLIST before creation: a prekey under an abandoned master must not
        // mint a fresh contact (the retired-master replay the global denylist
        // exists to stop — under master-roomId it lands as a NEW conversation,
        // so the check must sit here, not only on the old contact).
        if (retiredMastersRef.current.has(await masterKeyB64(env.x3dh.masterPub))) {
          console.warn('[recv] Auto-Create unter verlassenem Master abgelehnt.');
          return;
        }
        // MERGE AFFORDANCE (unproven): the prekey carries a previousMaster hint,
        // and we still have a contact pinned to THAT master → the person may have
        // changed identity. Offer a merge (record pendingMaster on the origin) —
        // it PROVES nothing, so it only prompts; the user must compare the safety
        // number, and acceptMasterChange (verified=false) is the confirm.
        const prev = env.x3dh.previousMaster;
        if (prev) {
          // A retired master claimed as origin is an attack, not a merge.
          if (retiredMastersRef.current.has(await masterKeyB64(prev))) {
            console.warn('[recv] Herkunfts-Hinweis nennt verlassenen Master — abgelehnt.');
            return;
          }
          const origin = contactsRef.current.find((c) => bytesEqual(c.peerMasterPub, prev));
          if (origin && !bytesEqual(origin.peerMasterPub, env.x3dh.masterPub)) {
            // Fire the merge affordance AT MOST ONCE per origin, until the user
            // acts (accept via acceptMasterChange, or dismiss). previousMaster is
            // unsigned and attacker-chosen; gating the dedup on the exact claimed
            // master let a FRESH master per message defeat it and repeatedly
            // overwrite the pending claim + re-raise the alert — an unauthenticated
            // pendingMaster-overwrite + warning-fatigue lever (Review D). Once a
            // claim is pending we surface the FIRST one and ignore later hints;
            // the user must compare the safety number out-of-band regardless.
            const consistent =
              !origin.pendingMaster &&
              (await verifyDeviceCert(
                env.x3dh.masterPub, env.x3dh.epoch, env.x3dh.identitySignPub, env.x3dh.identityDhPub, env.x3dh.deviceCert,
              ));
            if (consistent) {
              origin.pendingMaster = {
                masterPub: env.x3dh.masterPub, epoch: env.x3dh.epoch,
                signPub: env.x3dh.identitySignPub, dhPub: env.x3dh.identityDhPub,
              };
              await saveContact(dek, origin);
              setError(t('⚠ {name} meldet sich mit einer neuen Identität (unbelegt). Prüfe sie in der Kontaktansicht und vergleiche die Sicherheitsnummer.', { name: displayName(origin) }));
              bump();
            }
            return; // the merge affordance is the path — do NOT auto-create a stranger
          }
        }
        contact = await makeContactFromHeader(myMaster, env.x3dh);
        contactsRef.current = [...contactsRef.current, contact];
        messagesRef.current[contact.roomId] = [];
        await connectSend(contact);
        await saveContact(dek, contact);
      }

      // Decrypt against an isolated candidate. Application persistence happens
      // first; only then is the advanced ratchet/OPK committed and published in
      // memory. A quota/corruption failure can therefore leave the relay row
      // unacked and safely decrypt it again after recovery.
      const liveContact = contact;
      contact = await deserializeContact(await serializeContact(liveContact));
      let authenticatedOneTimePreKeyId: number | undefined;
      let receiveStateCommitted = false;
      const commitReceiveState = async () => {
        if (receiveStateCommitted) return;
        if (authenticatedOneTimePreKeyId !== undefined) {
          const prekeys = prekeysRef.current;
          if (!prekeys) throw new Error('Prekey-Zustand nicht geladen.');
          await saveContactAndConsumeOneTimePreKey(
            dek,
            contact!,
            prekeys,
            authenticatedOneTimePreKeyId,
          );
        } else {
          await saveContact(dek, contact!);
        }
        contact = publishContactCandidate(liveContact, contact!);
        receiveStateCommitted = true;
      };

      let content!: MessageContent;
      let mid = '';
      try {
        const r = await receiveEnvelope(id, contact, env, lookup);
        authenticatedOneTimePreKeyId = r.authenticatedOneTimePreKeyId;
        if (r.outcome !== 'message') {
          // Authenticated, but the plaintext frame was invalid or an unauthorised
          // self-frame (F-06/F-20/F-22 hardening). There is no content to process;
          // There are no application side effects to coordinate, so commit the
          // authenticated drop immediately and ACK it.
          await commitReceiveState();
          console.warn(`[recv] authenticated-drop (${r.reason}) — verworfen.`);
          return;
        }
        content = r.content;
        mid = r.mid;
      } catch (e) {
        if (e instanceof MasterChangedError) {
          // Persist the pending claim; the message itself is dropped. `verified`
          // stays as it was — the pin has NOT moved, and only a user-confirmed
          // accept moves it. Alert only on a NEW claim (see firstOccurrence):
          // the same claim can be replayed at will by anyone who can reach our
          // inbox, and a warning per copy would blunt the user against it.
          await saveContact(dek, contact);
          contact = publishContactCandidate(liveContact, contact);
          if (e.firstOccurrence) {
            setError(t('⚠ Sicherheit: Für {name} wird eine neue Identität behauptet — nicht übernommen. Prüfe sie in der Kontaktansicht, bevor du sie akzeptierst.', { name: displayName(contact) }));
          }
          bump();
        } else if (e instanceof RetiredIdentityError) {
          // Persist the attempt flag, but alert ONLY on the first one. Whoever
          // holds the abandoned key can replay endlessly; a toast per message
          // would be a harassment lever and would blunt the user against real
          // warnings. The state stays visible in the contact view.
          await saveContact(dek, contact);
          contact = publishContactCandidate(liveContact, contact);
          if (e.firstOccurrence) {
            setError(t('⚠ Sicherheit: Jemand hat sich als {name} mit einer bereits ersetzten Identität gemeldet — abgelehnt.', { name: displayName(contact) }));
          }
          bump();
        } else if (e instanceof RevokedDeviceError) {
          // Dropped silently (no toast): a revoked device can replay forever, so
          // per-message alerts would be the same fatigue lever as the retired
          // case. Logged for diagnosis. Full "delivered to a no-longer-valid
          // device" surfacing is the send-side status work (3d).
          console.warn('[recv] Prekey von widerrufenem Gerät verworfen.');
        }
        throw e; // drop the message (don't process the unpinned master)
      }
      // Apply and persist idempotent application effects first. The cloned,
      // advanced receive state is committed only after this dispatch succeeds.
      // A crash between the two leaves the relay row unacknowledged; on retry the
      // old ratchet can decrypt again and the message-level ids deduplicate an
      // application effect that had already reached disk.
      const hiddenDirectContent =
        contact.hidden &&
        !bytesEqual(contact.peerMasterPub, id.master.publicKey) &&
        (content.kind === 'text' ||
          content.kind === 'file' ||
          content.kind === 'reply' ||
          content.kind === 'chunk' ||
          content.kind === 'recall' ||
          content.kind === 'attoffer' ||
          content.kind === 'attreq' ||
          content.kind === 'r2');
      if (hiddenDirectContent) {
        // A group-introduced hidden contact is authorised only as a transport
        // peer for group/control frames. Letting ordinary 1:1 content fall
        // through would create an invisible, undeletable storage channel.
        console.warn('[group] Direkter Inhalt eines versteckten Mitgliedskontakts verworfen.');
      } else if (content.kind === 'profile') {
        contact.peerName = content.name;
        contact.peerAvatarB64 = content.avatar ? bytesToB64(content.avatar) : undefined;
      } else if (content.kind === 'ginvite') {
        await applyGroupInvite(
          content.group,
          contact,
          bytesEqual(contact.peerMasterPub, id.master.publicKey),
        );
      } else if (content.kind === 'group') {
        await applyGroupMessage(
          content.groupId,
          content.revision,
          content.stateHash,
          content.senderName,
          content.inner,
          contact,
          mid,
          ackId,
        );
      } else if (content.kind === 'groupsync') {
        await applyGroupSync(content, contact);
      } else if (content.kind === 'gremove') {
        await applyGroupRemove(content.state, contact);
      } else if (content.kind === 'gremoveLegacy') {
        const legacy = groupsRef.current.find(
          (group) => group.id === content.groupId,
        );
        if (
          legacy &&
          !legacy.ownerMasterPub &&
          legacy.revision === 0 &&
          isGroupMember(legacy, contact.peerMasterPub)
        ) {
          await deleteGroupActionWithinInbox(legacy.id);
        }
      } else if (content.kind === 'gleave') {
        await applyGroupLeave(
          content.groupId,
          content.revision,
          content.stateHash,
          contact,
        );
      } else if (content.kind === 'devlist') {
        // Learn the peer's newer device list (revocation gossip). Verified +
        // rollback-checked + denylist-guarded inside applyDeviceListUpdate; on
        // success the final receive-state commit persists it together with the
        // advanced ratchet.
        if (await applyDeviceListUpdate(contact, content.list, retiredMastersRef.current)) {
          let acceptedList = content.list;
          const ownUpdate = bytesEqual(
            contact.peerMasterPub,
            id.master.publicKey,
          );
          if (ownUpdate) {
            const durableBefore = await reconcileOwnDeviceList();
            if (compareDeviceList(content.list, durableBefore) > 0) {
              // A genuinely newer, master-authenticated list that omits this
              // linked device is a revocation. An older delayed continuation is
              // not: durable authority wins, avoiding a stale-list self-wipe.
              if (!deviceInList(content.list, id.sign.publicKey)) {
                void doWipeAccount().catch(() => undefined);
                return;
              }
              await adoptDeviceList(dek, id, content.list);
            }
            acceptedList = await reconcileOwnDeviceList(content.list);
            // The self-contact may just have accepted a list older than our
            // durable CAS record. Restore it monotonically before persistence.
            await applyDeviceListUpdate(
              contact,
              acceptedList,
              retiredMastersRef.current,
            );
          }
          await sweepRevokedDeliveries(contact); // fund 6: drop revoked devices from open bubbles
          // The same independently signed directory is cached in every group
          // roster containing this master. Merge by its own (epoch, version)
          // clock; an owner roster revision is never allowed to roll it back.
          const nextGroups: Group[] = [];
          for (const group of groupsRef.current) {
            const result = await applyGroupMemberDeviceList(group, acceptedList);
            nextGroups.push(result.group);
            if (result.applied) await saveGroup(dek, result.group);
          }
          groupsRef.current = nextGroups;
          // If this is MY OWN list (delivered from my primary to the self-contact),
          // adopt it as my stored own list too, so a secondary device's self-sync
          // targets a later-linked sibling as well (Review fund 4).
          if (ownUpdate) publishOwnDeviceList(acceptedList);
        }
        // ACK UNCONDITIONALLY — also when the list was NOT newer and applyDevice-
        // ListUpdate returned false. The sender re-offers until our ack catches up;
        // staying silent on an already-known list would keep it offering forever.
        // The ack names the version we actually hold now.
        if (!bytesEqual(contact.peerMasterPub, id.master.publicKey)) {
          const held = contact.peerDeviceList ?? content.list;
          const from = env.type === 'prekey' ? env.x3dh.identitySignPub : env.dev;
          void sendListAckTo(contact, held.epoch, held.version, from); // fire-and-forget: see the helper
        }
      } else if (content.kind === 'listack') {
        // A peer tells me which (epoch, version) of MY list they hold. Deliberately
        // NOT self-gated: an ack about my own list is legitimate from anyone I sent
        // it to, and it carries no state beyond moving a watermark FORWARD.
        // TERMINAL: never rendered, never re-dispatched.
        const mine = ownListRef.current;
        const claimed = { epoch: content.epoch, version: content.version };
        if (mine && !isNewerDeviceList(claimed, { epoch: mine.epoch, version: mine.version })) {
          // Ignore an ack from the FUTURE (a version I never published) — it could
          // otherwise silence the gossip for a list the peer does not actually have.
          const from =
            env.type === 'prekey'
              ? env.x3dh.identitySignPub
              : (env.dev ?? contact.peerSignPub);
          const key = bytesToB64(from);
          const previous = contact.peerAckedListByDevice?.[key];
          if (!previous || isNewerDeviceList(claimed, previous)) {
            contact.peerAckedListByDevice = {
              ...(contact.peerAckedListByDevice ?? {}),
              [key]: claimed,
            };
            if (bytesEqual(from, contact.peerSignPub)) {
              contact.peerAckedListEV = claimed;
            }
          }
        }
      } else if (content.kind === 'unlinkreq') {
        // A linked device of MINE asks to be unlinked. Revoke it (re-sign the list without
        // it) and gossip. Gated: only my own self-contact, only the primary can re-sign.
        // The sender device is read off the AUTHENTICATED envelope, so it can't name
        // another device to revoke. The device wipes itself on its side regardless.
        if (bytesEqual(contact.peerMasterPub, id.master.publicKey) && isPrimaryDevice(id) && ownListRef.current) {
          const from = env.type === 'prekey' ? env.x3dh.identitySignPub : env.dev;
          const next = from ? await revokeDevice(dek, id, ownListRef.current, from) : null;
          if (next) {
            const authoritative = await reconcileOwnDeviceList(next);
            // Gossip encrypts through enqueueInbox. Detach it from this already
            // held receive task or it would await its own queue tail forever.
            void gossipDeviceList(authoritative).catch(() => undefined);
          }
        }
      } else if (content.kind === 'rotation') {
        // A dual-signed rotation PROVES the peer's master continuity → acceptRotation
        // re-pins to the new master and re-keys, KEEPING `verified` (unlike the
        // unproven previousMaster path, which clears it). Denylist-first and
        // reject-before-any-state-touch live inside acceptRotation; a forged or
        // rolled-back chain throws and changes nothing.
        try {
          if (authenticatedOneTimePreKeyId !== undefined) {
            // A room migration and OPK consumption cannot currently share one
            // transaction. Keep the authenticated session but defer this dormant
            // rotation frame; a normal-session retry can carry it safely.
            console.warn('[recv] Rotation als erste Prekey-Nachricht zurückgestellt.');
          } else if (masterReferencedByLiveGroup(contact.peerMasterPub)) {
            // A contact-only master re-pin would leave signed group rosters on
            // the old identity and either strand delivery or silently recreate a
            // hidden old-master contact. Until an owner-authored roster
            // migration exists, fail closed before touching the Contact.
            throw new Error(
              'Identitätswechsel ist blockiert, solange der Kontakt Mitglied einer Gruppe ist.',
            );
          } else {
            const r = await acceptRotation(contact, content.statement, retiredMastersRef.current);
            await reKeyContactInMemory(r.oldRoomId, contact); // persists contact + moves storage
            contact = publishContactCandidate(liveContact, contact);
            receiveStateCommitted = true;
            if (activeRoomRef.current === r.oldRoomId) setActiveRoom(r.newRoomId);
          }
        } catch (e) {
          console.warn('[recv] Rotation abgelehnt:', (e as Error).message);
        }
      } else if (content.kind === 'sync' && bytesEqual(contact.peerMasterPub, id.master.publicKey)) {
        // Self-sync: a copy of a message from ANOTHER of my devices. GATED to the
        // self-contact (peerMaster == my master) — a 'sync' from any other session is
        // an injection attempt and is already rejected in receiveEnvelope; this is
        // defence in depth. It authenticated under my hidden self-contact, but
        // belongs in the conversation with
        // content.targetPeerMaster — DECRYPT-ROOM ≠ DISPLAY-ROOM. TERMINAL: only
        // appended, never re-fanned/re-synced/re-dispatched. Deduped by the ORIGINAL
        // mid against the peer's own fan-out copy that may also reach this device.
        const displayRoom = await computeMasterRoomId(myMaster, asMasterPub(content.targetPeerMaster));
        const inner = content.inner;
        if (inner.kind === 'recall') {
          // My own recall, mirrored from another of my devices → tombstone my copy here.
          await retractMessage(displayRoom, inner.targetMid, content.origin === 'sent');
        } else {
        // Dedup within the SAME direction only (mid, mine). A self-synced SENT copy
        // (mine=true) must not be suppressed by a peer message that REFLECTS its mid,
        // and vice versa — the peer knows this mid (it decrypted its own fan-out copy),
        // so a mid-only namespace would let it silently drop my own message here.
        const already = hasMessage(messagesRef.current[displayRoom] ?? [], content.innerMid, content.origin === 'sent');
        if (!already && (inner.kind === 'text' || inner.kind === 'file' || inner.kind === 'reply')) {
          let synced: ChatMessage;
          if (inner.kind === 'file') {
            const file = await inboundFileRefFor(
              displayRoom,
              inner.name,
              inner.mime,
              inner.data,
              inner.viewOnce,
            );
            synced = file
              ? { mine: content.origin === 'sent', ts: content.ts, mid: content.innerMid, file }
              : {
                  mine: content.origin === 'sent',
                  ts: content.ts,
                  mid: content.innerMid,
                  text: t('Anhang wegen des automatischen Speicherlimits nicht gespeichert.'),
                };
          } else if (inner.kind === 'reply') {
            synced = await replyMessage(
              inner.quote,
              inner.inner,
              content.innerMid,
              content.origin === 'sent',
              displayRoom,
            );
          } else {
            synced = {
              mine: content.origin === 'sent',
              ts: content.ts,
              mid: content.innerMid,
              text: inner.text,
            };
          }
          await appendFreshInboundMessage(displayRoom, synced);
          if (content.origin !== 'sent' && !(viewRef.current === 'chat' && activeRoomRef.current === displayRoom)) {
            unreadRef.current[displayRoom] = (unreadRef.current[displayRoom] ?? 0) + 1;
          }
        }
        }
      } else if (content.kind === 'bootreq') {
        // A linked device of MINE pulls the account snapshot. receiveEnvelope already
        // refuses this frame from a non-self contact; re-checking here is defence in
        // depth. Only the PRIMARY answers, so sibling devices don't all reply to one
        // request. TERMINAL: never appended to a conversation.
        if (!bytesEqual(contact.peerMasterPub, id.master.publicKey)) {
          console.warn('[recv] bootreq von einem Nicht-Selbst-Kontakt — verworfen.');
        } else if (isPrimaryDevice(id)) {
          // `dev` is a resolution hint only; for a prekey the device is authenticated
          // in the header. Either way the reply is sealed to that device's key.
          const requester = env.type === 'prekey' ? env.x3dh.identitySignPub : (env.dev ?? contact.peerSignPub);
          void sendBootstrapTo(requester, content.requestId).catch((e) => {
            // No synthetic "done": N keeps its durable pull pending and retries.
            console.warn('[bootstrap] Versand nicht dauerhaft bestätigt:', (e as Error).message);
          });
        }
      } else if (content.kind === 'bootstrap') {
        // The account snapshot from my primary: profile + roster. Self-gated,
        // TERMINAL (never rendered as a message, never re-fanned), and idempotent
        // via `bid` so a re-delivery imports nothing twice.
        if (!bytesEqual(contact.peerMasterPub, id.master.publicKey)) {
          console.warn('[recv] bootstrap von einem Nicht-Selbst-Kontakt — verworfen.');
        } else {
          await applyBootstrapIfNew(content.bid, content.parts, contact);
        }
      } else if (content.kind === 'chunk') {
        // A piece of a large attachment: store it, and on the last chunk append the
        // reassembled attachment. Terminal — never a bubble, never self-synced.
        await receiveChunk(contact, content);
      } else if (content.kind === 'recall') {
        // The peer recalls one of THEIR messages → tombstone their copy (mine=false).
        await retractMessage(contact.roomId, content.targetMid, false);
      } else if (content.kind === 'attoffer') {
        // A large attachment offered for pull → append a download-affordance placeholder.
        if (
          !contact.hidden &&
          /^[A-Za-z0-9]{1,40}$/.test(content.tid) &&
          content.total >= 1 &&
          content.total <= RECV_MAX_CHUNKS &&
          content.size >= 0 &&
          content.size <= RECV_MAX_BYTES &&
          !hasMessage(messagesRef.current[contact.roomId] ?? [], content.tid, false)
        ) {
          await appendMessage(contact.roomId, {
            mine: false,
            ts: Date.now(),
            mid: content.tid,
            file: { name: content.name, mime: content.mime, size: content.size, attId: content.tid, pull: { total: content.total } },
          });
          if (!(viewRef.current === 'chat' && activeRoomRef.current === contact.roomId)) {
            unreadRef.current[contact.roomId] = (unreadRef.current[contact.roomId] ?? 0) + 1;
          }
          // Start downloading straight away — no manual tap needed.
          autoPull(contact.roomId, content.tid, content.total);
        }
      } else if (content.kind === 'attreq') {
        // The peer pulls an attachment I offered → stream its chunks (guarded). Fire-and-forget:
        // serveAttachment nests its own enqueueInbox for the fan-out, and AWAITING it from inside
        // this (already-queued) onInbox task would be a circular wait on the same queue — a self-
        // deadlock. void-ing it lets that inner task chain AFTER this one, preserving Invariant-II
        // serialization. Its own errors are contained; the peer re-requests via the pull retry.
        void serveAttachment(contact, content.tid).catch(() => undefined);
      } else if (content.kind === 'r2') {
        // A large attachment stored in R2 → a tap-to-download placeholder (not auto-pulled;
        // could be up to ~1 GB). The E2E per-file key rides in the descriptor.
        const r2 = tryValidateR2Descriptor(
          { key: content.key, keyB64: content.keyB64, size: content.size, chunk: content.chunk },
          CLIENT_MAX_BLOB,
        );
        if (
          !contact.hidden &&
          mid &&
          r2 &&
          !hasMessage(messagesRef.current[contact.roomId] ?? [], mid, false)
        ) {
          await appendMessage(contact.roomId, {
            mine: false,
            ts: Date.now(),
            mid,
            file: {
              name: content.name,
              mime: content.mime,
              size: r2.size,
              viewOnce: content.viewOnce || undefined,
              r2: { key: r2.key, keyB64: r2.keyB64, chunk: r2.chunk },
            },
          });
          if (!(viewRef.current === 'chat' && activeRoomRef.current === contact.roomId)) {
            unreadRef.current[contact.roomId] = (unreadRef.current[contact.roomId] ?? 0) + 1;
          }
        }
      } else if (mid && hasMessage(messagesRef.current[contact.roomId] ?? [], mid, false)) {
        // DEDUP on the E2E mid, WITHIN the received direction (mine=false): one peer
        // message can reach this device via direct fan-out AND (with receive-sync) a
        // copy from another of my devices AND a re-delivery — all mine=false, same mid.
        // Scoping to mine=false is the fix for the mid-reflection suppression: a peer
        // that reflects the mid of my OWN sent message can no longer collide with it
        // (my sent copy is mine=true). The mid is authenticated in the AEAD, so it
        // can't be forged to suppress a real future message of the SAME direction.
        // Already have it — skip (the ackId is still recorded in `finally`).
      } else {
        let inMsg: ChatMessage;
        if (content.kind === 'file') {
          const file = await inboundFileRefFor(
            contact.roomId,
            content.name,
            content.mime,
            content.data,
            content.viewOnce,
          );
          inMsg = file
            ? { mine: false, ts: Date.now(), mid, file }
            : {
                mine: false,
                ts: Date.now(),
                mid,
                text: t('Anhang wegen des automatischen Speicherlimits nicht gespeichert.'),
              };
        } else if (content.kind === 'reply') {
          inMsg = await replyMessage(content.quote, content.inner, mid, false, contact.roomId);
        } else {
          inMsg = incomingMessage(content, mid);
        }
        await appendFreshInboundMessage(contact.roomId, inMsg);
        if (!(viewRef.current === 'chat' && activeRoomRef.current === contact.roomId)) {
          unreadRef.current[contact.roomId] = (unreadRef.current[contact.roomId] ?? 0) + 1;
        }
        // Stopgap while this peer has not yet learned my other devices: mirror what
        // I RECEIVE to them, so a freshly linked device doesn't miss incoming
        // messages during the propagation window. Gated on the peer being BEHIND my
        // current list — once they ack it they fan out to my devices themselves, and
        // this stops (no permanent doubling of inbound traffic). Dedup by
        // (mid, received) keeps it from showing twice next to their own copy.
        const myList = ownListRef.current;
        const peerBehind =
          !!myList &&
          !peerHasAckedListOnEveryDevice(contact, myList);
        if (
          peerBehind &&
          mid &&
          !bytesEqual(contact.peerMasterPub, id.master.publicKey) &&
          (content.kind === 'text' || content.kind === 'file')
        ) {
          void syncToOwnDevices(contact.peerMasterPub, 'recv', mid, Date.now(), content);
        }
      }
      await commitReceiveState();
      void ensureProfileSent(contact);
      void ensureListGossiped(contact); // keep peers current on MY devices
      bump();
    } catch (e) {
      if (e instanceof DeferredGroupTransitionError) {
        // Bounded transition only: keep this exact ciphertext in the relay and
        // discard the cloned ratchet advance. Once the owner state lands, the
        // row re-decrypts and commits normally; a crash cannot lose it.
        retainRelayRow = true;
      } else if (e instanceof DuplicateGroupTransitionRowError) {
        // ACK this additional relay row but deliberately do NOT commit its
        // cloned ratchet. The original stable ackId remains retained as the
        // crash-recovery copy until the signed owner state arrives.
      } else if (isStorageFull(e)) {
        // Do NOT ack: the relay keeps the message and re-delivers it once there is
        // room again. Acking a message we could not store would delete it for good.
        setError('Speicher voll — Nachricht nicht gespeichert. Gib Speicher frei; sie wird erneut zugestellt.');
        retainRelayRow = true;
      } else if (e instanceof StaleAccountGenerationError) {
        // A restore/account switch fenced this generation. Never ACK against
        // stale state: the replacement account (or a reload after a failed
        // restore) must be allowed to drain the still-durable relay row.
        setError(t('Kontostand wird ersetzt — Nachricht bleibt zur erneuten Zustellung im Relay.'));
        retainRelayRow = true;
      } else if (e instanceof MessageCorruptionError) {
        // Fail closed and retain the ciphertext. Boot normally catches this
        // before connecting; this branch covers a runtime corruption signal.
        setError(t('Nachrichtenverlauf beschädigt — neue Nachricht wurde nicht bestätigt.'));
        retainRelayRow = true;
      } else if (isTransientStorageFailure(e)) {
        // IndexedDB can abort transiently without reporting a quota condition.
        // Treat it like any other uncommitted application write.
        setError(t('Lokaler Speicher vorübergehend nicht verfügbar — Nachricht bleibt im Relay.'));
        retainRelayRow = true;
      }
      // else: a permanent drop (decrypt failure, duplicate, unknown frame) — swallow
      // and ack below so the relay stops re-delivering it.
    } finally {
      if (!retainRelayRow) {
        seenIdsRef.current.add(ackId);
        inboxClientRef.current?.ack(ackId);
      }
    }
  }

  async function addBundle(rawInput: string, signal?: AbortSignal) {
    setError('');
    const id = identityRef.current;
    if (!id) return;
    if (rawInput.length > MAX_CONTACT_INPUT_CHARS) {
      setError(t('Kontaktcode, Alias oder Link ist zu lang.'));
      return;
    }
    try {
      // The permanent, root-signed support alias is deliberately recognised
      // before ordinary SK1 rendezvous codes or raw bundles. Scanner, clipboard
      // and manual input all call this one function and therefore get identical
      // verification and rollback behaviour.
      const officialAlias = extractOfficialAccountAlias(rawInput);
      const resolvedOfficial = officialAlias
        ? await resolveOfficialAccount(officialAlias, {
            signal,
            floor: officialAccountTrustRef.current
              ? {
                  sequence: officialAccountTrustRef.current.sequence,
                  digest: officialAccountTrustRef.current.digest,
                }
              : null,
          })
        : null;
      const trustedOfficial = resolvedOfficial
        ? await enqueueInbox(async () => {
            const stored = await saveOfficialAccountTrust(
              dek,
              resolvedOfficial,
            );
            installOfficialAccountTrust(stored);
            return stored;
          })
        : null;
      if (
        trustedOfficial &&
        trustedOfficial.manifest.status !== 'active'
      ) {
        throw new OfficialAccountError(
          'revoked',
          'Der offizielle Admin-Account wurde widerrufen.',
        );
      }
      // saveOfficialAccountTrust is a monotone cross-tab CAS and may return a
      // newer existing winner instead of the just-fetched candidate. Never let
      // an expired winner authorise Contact/session mutation merely because it
      // still carries a once-valid public bundle.
      if (
        trustedOfficial &&
        (!trustedOfficial.bundle ||
          !isOfficialAdminMaster(
            trustedOfficial.masterPub,
            trustedOfficial,
          ))
      ) {
        throw new OfficialAccountError(
          'not-current',
          'Die gespeicherte Admin-Beschreibung ist abgelaufen. Bitte später erneut versuchen.',
        );
      }

      const shortCode = officialAlias ? null : extractContactCode(rawInput);
      const token = shortCode
        ? (await resolveContactInvite(shortCode, signal)).bundle
        : officialAlias
          ? ''
          : extractToken(rawInput);
      if (!trustedOfficial && !token) return;
      const decodeOrdinaryBundle = async () => {
        const bundle = await decodeBundle(token);
        return bundle;
      };
      const bundle = trustedOfficial?.bundle ?? (await decodeOrdinaryBundle());
      // Adding your OWN code would pass every check and silently create a "chat
      // with yourself". Compare MASTERS, not device keys: under master-based
      // rooms an own SECOND device (same master, different dh) must also be
      // caught, and it would slip a dhPub-only guard.
      if (bytesEqual(bundle.masterPub, id.master.publicKey)) {
        setError(t('Das ist dein eigener Verbindungscode.'));
        return;
      }
      const contact = await enqueueInbox(async () => {
        const candidate = await makeContact(
          asMasterPub(id.master.publicKey),
          bundle,
        );
        const existing = contactsRef.current.find(
          (entry) => entry.roomId === candidate.roomId,
        );
        if (existing) {
          if (trustedOfficial) {
            if (!bytesEqual(existing.peerMasterPub, bundle.masterPub)) {
              throw new OfficialAccountError(
                'signature',
                'Der offizielle Alias passt nicht zum gepinnten Kontakt.',
              );
            }
            existing.hidden = undefined;
            // A peer-gossiped directory may be ahead of the root manifest. Keep
            // it and its sessions; adopt the bootstrap bundle only if it is not
            // behind that local cryptographic state.
            const list = existing.peerDeviceList;
            const bundleMayAdvance =
              bundle.epoch >= existing.peerEpoch &&
              (!list ||
                bundle.epoch > list.epoch ||
                (bundle.epoch === list.epoch &&
                  deviceInList(list, bundle.identitySignPub)));
            if (bundleMayAdvance) {
              existing.bundle = bundle;
              existing.peerEpoch = Math.max(existing.peerEpoch, bundle.epoch);
              existing.peerSignPub = bundle.identitySignPub;
              existing.peerDhPub = bundle.identityDhPub;
              if (list && bundle.epoch > list.epoch) {
                existing.peerDeviceList = undefined;
                existing.sessions = new Map();
              }
            }
            await adoptOfficialDeviceList(
              trustedOfficial,
              existing,
            );
            await saveContact(dek, existing);
            return existing;
          }
          if (
            !bytesEqual(existing.peerMasterPub, bundle.masterPub) ||
            bundle.epoch < existing.peerEpoch
          ) {
            throw new Error('Der Verbindungscode passt nicht zum bereits gepinnten Kontaktstand.');
          }
          if (
            existing.peerDeviceList &&
            bundle.epoch === existing.peerDeviceList.epoch &&
            !deviceInList(existing.peerDeviceList, bundle.identitySignPub)
          ) {
            throw new Error('Der Verbindungscode gehört zu einem widerrufenen Gerät.');
          }
          // A member first learned through a group becomes a normal visible
          // contact when its code is scanned. Keep newer DeviceLists/sessions and
          // local verification, but adopt the freshly verified initiator bundle.
          existing.hidden = undefined;
          existing.bundle = bundle;
          existing.peerEpoch = Math.max(existing.peerEpoch, bundle.epoch);
          existing.peerSignPub = bundle.identitySignPub;
          existing.peerDhPub = bundle.identityDhPub;
          if (
            existing.peerDeviceList &&
            bundle.epoch > existing.peerDeviceList.epoch
          ) {
            existing.peerDeviceList = undefined;
            existing.sessions = new Map();
          }
          await saveContact(dek, existing);
          return existing;
        }
        if (
          trustedOfficial?.deviceList &&
          !(await adoptOfficialDeviceList(
            trustedOfficial,
            candidate,
          ))
        ) {
          throw new OfficialAccountError(
            'signature',
            'Die offizielle Geräteliste konnte nicht sicher übernommen werden.',
          );
        }
        contactsRef.current = [...contactsRef.current, candidate];
        // Do NOT clobber an existing log: under master-based rooms my other
        // device may already have self-synced history into this exact room.
        // The inbox barrier makes this load-and-publish one ordered operation.
        const persistedLog = await loadMessages(dek, candidate.roomId);
        messagesRef.current[candidate.roomId] =
          messagesRef.current[candidate.roomId] ?? persistedLog;
        commitMessages();
        await saveContact(dek, candidate);
        return candidate;
      });
      await connectSend(contact);
      setAddInput('');
      openChat(contact.roomId);
      bump();
    } catch (e) {
      if (signal?.aborted) throw new MessengerInactiveError();
      if (e instanceof ContactCodeError || e instanceof OfficialAccountError) {
        setError(t(e.message));
      } else {
        setError(t('Ungültiges Bundle: {msg}', { msg: (e as Error).message }));
      }
    }
  }

  useEffect(
    () => {
      const unregister = registerVaultRuntimeQuiescer(quiesceForUnmount);
      return () => {
        // Keep the bridge registered until this unawaitable React cleanup has at
        // least started and joined the same quiescence path. App teardown can
        // therefore still obtain the promise instead of releasing its Web Lock
        // merely because child-effect cleanup happened first.
        void quiesceForUnmount()
          .catch(() => undefined)
          .finally(unregister);
      };
    },
    // The mounted Messenger owns one stable account generation. Re-registering
    // on renders would let a late disposer clear a newer callback.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [],
  );

  useEffect(() => {
    if (initedRef.current) return;
    initedRef.current = true;
    const bootTask = (async () => {
      const id = await loadOrCreateIdentity(dek);
      assertMessengerActive();
      const pre = await loadOrCreatePreKeys(dek, id);
      assertMessengerActive();
      identityRef.current = id;
      prekeysRef.current = pre;
      lookupRef.current = {
        signedPreKey: (i) => findSignedPreKey(pre, i)?.keyPair,
        oneTimePreKey: (i) => findOneTimePreKey(pre, i)?.keyPair.privateKey,
      };
      // A human-confirmed N-side transcript is a durable protocol transition.
      // Recover it before loading/connecting the inbox so a queued Grant can
      // neither be treated as stale nor ACKed without cryptographic validation.
      // The loader authenticates the DEK-sealed record; linkflow then binds the
      // canonical transcript to current Identity/SPK, proves the ephemeral
      // keypair and recomputes SAS rather than trusting stored display/flags.
      const discardedLinkIntents = await loadDiscardedNewDeviceLinkIntents(dek);
      assertMessengerActive();
      discardedLinkSessionsRef.current = await Promise.all(
        discardedLinkIntents.map((intent) =>
          restoreDiscardedNewDeviceLinkSession(intent, id)),
      );
      assertMessengerActive();
      const confirmedLinkIntent = await loadConfirmedNewDeviceLinkIntent(dek);
      assertMessengerActive();
      if (confirmedLinkIntent) {
        const recovered = await restoreConfirmedNewDeviceLinkSession(
          confirmedLinkIntent,
          id,
          ownSpkPublic(pre),
        );
        assertMessengerActive();
        confirmedLinkIntentRef.current = confirmedLinkIntent;
        linkSessionRef.current = recovered;
        linkConfirmedRef.current = true;
        linkRecoveryProtectedRef.current = true;
        setLinkSas(recovered.sas ?? null);
        setLinkBusy(true);
        setLinkView('sas');
      }
      const fingerprint = await fingerprintOf(id);
      assertMessengerActive();
      setFingerprint(fingerprint);

      const prof = await loadProfile(dek);
      assertMessengerActive();
      myProfileRef.current = prof;
      const [deviceNames, storedStickers] = await Promise.all([
        loadDeviceNames(dek),
        loadStickers(dek),
      ]);
      assertMessengerActive();
      setDeviceNames(deviceNames);
      setStickers(storedStickers);
      setMyAvatarB64(prof.avatarB64 ?? '');
      setMyName(prof.name ?? '');
      setProfileName(prof.name ?? '');

      const token = await encodeBundle(currentBundle(id, pre));
      assertMessengerActive();
      makeQr(updateShareBundle(token))
        .then((qr) => {
          if (lifecycleActiveRef.current && !runtimeSuspendedRef.current) {
            setQrDataUrl(qr);
          }
        })
        .catch(() => undefined);

      retiredMastersRef.current = await loadRetiredMasters(dek);
      assertMessengerActive();
      // Re-open and fully verify the signed cache on every boot. An unconfigured
      // release stays silent and fail-closed; it never attempts a directory fetch
      // merely because an old local record happens to exist.
      if (officialAccountConfigured()) {
        try {
          const cachedOfficial = await loadOfficialAccountTrust(dek);
          assertMessengerActive();
          if (cachedOfficial) installOfficialAccountTrust(cachedOfficial);
        } catch {
          officialAccountTrustRef.current = null;
          // A corrupt or no-longer-release-valid cache never renders. A valid
          // record below the release floor is exposed as null and can be replaced
          // by the current signed directory stand during the refresh below.
        }
      }
      // Erst-Sync state: which snapshots this device already imported, and whether
      // it is still waiting for one (a linked device keeps asking across reloads).
      bootstrapAppliedRef.current = await loadBootstrapApplied(dek);
      assertMessengerActive();
      bootstrapRequestRef.current = await loadBootstrapRequest(dek);
      assertMessengerActive();
      // Crash recovery for the narrow post-identity-commit window in linking:
      // if the grant was installed but the first bootstrap request record did
      // not make it to disk, reconstruct it from the linked-identity witness.
      if (
        id.previousMasterPub &&
        !isPrimaryDevice(id) &&
        !bootstrapRequestRef.current &&
        bootstrapAppliedRef.current.size === 0
      ) {
        bootstrapRequestRef.current = { requestId: randomMid(), pending: true };
        await saveBootstrapRequest(dek, bootstrapRequestRef.current);
        assertMessengerActive();
      }
      contactsRef.current = await loadContacts(dek);
      assertMessengerActive();
      const cachedOfficial = officialAccountTrustRef.current;
      if (cachedOfficial?.manifest.status === 'active') {
        const officialContact = contactsRef.current.find((contact) =>
          isOfficialAdminContact(contact, cachedOfficial),
        );
        if (
          officialContact &&
          (await adoptOfficialDeviceList(
            cachedOfficial,
            officialContact,
          ))
        ) {
          await saveContact(dek, officialContact);
          assertMessengerActive();
        }
      }
      // Crash reconciliation for device linking: installLinkedIdentity commits
      // the new identity/list atomically before the old contacts can be marked.
      // previousMasterPub is the durable witness that this identity swap happened.
      // Any contact not already reconnected under the current master must regain
      // the stale send barrier before a socket is opened.
      if (id.previousMasterPub) {
        const currentMaster = asMasterPub(id.master.publicKey);
        const previousMaster = asMasterPub(id.previousMasterPub);
        for (const c of contactsRef.current) {
          assertMessengerActive();
          if (c.ownMasterPub && bytesEqual(c.ownMasterPub, currentMaster)) continue;
          c.staleIdentity = true;
          if (!c.ownMasterPub) c.ownMasterPub = previousMaster;
          await saveContact(dek, c);
          assertMessengerActive();
        }
      }
      // A primary may have crashed after atomically authorising a new device but
      // before receiving the relay's durable INSERT receipt. Re-offer that exact
      // sealed grant before any further own-list mutation. A corrupt P-only
      // delivery intent is atomically discarded because its authoritative list
      // already committed; warn about a possible delivered-but-unconfirmed
      // device so the user can explicitly revoke it.
      try {
        const discardedCorruptGrant = await retryPendingLinkGrant(async () => {
          // The durable list must reach RAM + hidden self-contact before the
          // retried Grant can let N send an immediately valid bootreq.
          const self = await ensureSelfContact();
          assertMessengerActive();
          if (!self) throw new Error(t('Selbstkontakt nicht verfügbar.'));
        });
        assertMessengerActive();
        setPrimaryLinkDeliveryPending(false);
        if (discardedCorruptGrant) {
          setError(t('Beschädigter Kopplungs-Retry wurde entfernt. Prüfe jetzt unter Profil → Geräte die Liste und widerrufe jedes unbekannte oder noch nicht bestätigte Gerät; der ursprüngliche Nachweis könnte bereits zugestellt worden sein.'));
        }
      } catch (e) {
        if (e instanceof MessengerInactiveError) throw e;
        setPrimaryLinkDeliveryPending(true);
        setError(t('Ausstehende Gerätekopplung noch nicht zugestellt: {msg}', { msg: (e as Error).message }));
      }
      // Seed the inbox queue with the whole vault load + one-time master migration,
      // so every queued/live message the relay delivers on connect is processed
      // strictly AFTER it (no onInbox-vs-migration race). Messages load FIRST, keyed
      // by the current roomIds, so the duplicate-collapse tiebreak compares real
      // history counts (not an empty map); reKeyContactInMemory relocates them.
      const bootLoad = enqueueInbox(async () => {
        for (const c of contactsRef.current) {
          assertMessengerActive();
          messagesRef.current[c.roomId] = await loadMessages(dek, c.roomId);
          assertMessengerActive();
        }
        await migrateContactsToMaster();
        assertMessengerActive();
        await ensureSelfContactWithinInbox(); // hidden self-contact for self-sync; refresh my device list
        assertMessengerActive();
        for (const c of contactsRef.current) {
          assertMessengerActive();
          await connectSend(c);
          assertMessengerActive();
        }
        let gs = await loadGroups(dek);
        assertMessengerActive();
        for (const snapshot of await loadGroupRemovalTombstones(dek)) {
          assertMessengerActive();
          const stored = gs.find(
            (group) => group.id === snapshot.tombstone.groupId,
          );
          if (!stored) continue;
          const sameOwner =
            !!stored.ownerMasterPub &&
            bytesEqual(
              stored.ownerMasterPub,
              snapshot.tombstone.ownerMasterPub,
            );
          if (
            !sameOwner ||
            snapshot.tombstone.blockReadd ||
            stored.revision <= snapshot.tombstone.revision
          ) {
            // Tombstone-first deletion may have crashed before erasing the live
            // group. Finish it before any relay is connected.
            await removeGroup(dek, stored.id);
            assertMessengerActive();
            gs = gs.filter((group) => group.id !== stored.id);
          } else {
            // A strictly newer accepted re-add was saved before its exact
            // tombstone clear completed.
            await clearGroupRemovalTombstone(snapshot);
            assertMessengerActive();
          }
        }
        groupsRef.current = gs;
        for (const g of gs) {
          assertMessengerActive();
          messagesRef.current[g.id] = await loadMessages(dek, g.id);
          assertMessengerActive();
          for (const member of g.members) {
            await ensureMemberContactWithinInbox(member);
            assertMessengerActive();
          }
        }
        groupsBootReadyRef.current = true;
        // Include cardless/self-sync histories when reconstructing the scope of
        // legacy flat recall entries. Ambiguous legacy values are discarded.
        for (const roomId of await allMessageRoomIds()) {
          assertMessengerActive();
          if (messagesRef.current[roomId] === undefined) {
            messagesRef.current[roomId] = await loadMessages(dek, roomId);
            assertMessengerActive();
          }
        }
        const storedRecalls = await loadRecalledMids(dek);
        assertMessengerActive();
        const scopedRecalls = migrateLegacyRecalledMids(storedRecalls, messagesRef.current);
        if (
          scopedRecalls.length !== storedRecalls.length ||
          scopedRecalls.some((value, index) => value !== storedRecalls[index])
        ) {
          await saveRecalledMids(dek, scopedRecalls);
          assertMessengerActive();
        }
        recalledMidsRef.current = new Set(scopedRecalls);
        await reconcileLoadedRecallRegistry();
        assertMessengerActive();
        commitMessages();
        bump();
        await sweepOrphanAttachments(); // race-free: still inside the boot task
        assertMessengerActive();
      });
      // AFTER the boot task (never inside it — both of these enqueue on the same
      // chain, so awaiting them from within it would deadlock the inbox):
      // re-ask for the account snapshot if this device is still waiting, and offer
      // my device list to every peer whose acknowledgement is behind.
      void bootLoad
        .then(async () => {
          assertMessengerActive();
          await requestBootstrap();
          assertMessengerActive();
          await schedulePendingGroupMutationRetry();
          assertMessengerActive();
          for (const c of contactsRef.current) {
            await ensureListGossiped(c);
            assertMessengerActive();
          }
        })
        .catch(() => undefined);

      await bootLoad; // contacts are on their final master roomIds; messages loaded
      assertMessengerActive();

      // Only connect after every persisted history authenticated successfully.
      // Otherwise a corrupt room could fail boot while live ciphertexts are
      // already decrypted, ACKed and permanently removed from the relay.
      const ownInbox = await inboxRoom(id.sign.publicKey);
      assertMessengerActive();
      connectInbox(ownInbox);
      // Restore an existing push subscription so the DO keeps waking this device.
      if (pushSupported()) {
        currentSubscription()
          .then((sub) => {
            if (
              sub &&
              lifecycleActiveRef.current &&
              !runtimeSuspendedRef.current
            ) {
              inboxClientRef.current?.setPush(sub);
              setNotifOn(true);
            }
          })
          .catch(() => undefined);
      }

      const hashMatch = location.hash.match(/[#&]add=([^&]+)/);
      if (hashMatch) {
        assertMessengerActive();
        history.replaceState(null, '', location.pathname + location.search);
        await addBundle(decodeURIComponent(hashMatch[1]));
        assertMessengerActive();
      }
      if (officialAccountConfigured()) {
        launchRuntimeOperation((signal) =>
          refreshOfficialAccountTrust(signal),
        );
      }
    })();
    bootTaskRef.current = bootTask;
    void bootTask.catch((e) => {
      if (e instanceof MessengerInactiveError || !lifecycleActiveRef.current) return;
      for (const relay of relaysRef.current.values()) relay.close();
      relaysRef.current.clear();
      inboxClientRef.current = null;
      setError(t('Tresor konnte nicht sicher geladen werden: {msg}', { msg: (e as Error).message }));
    });
    void bootTask.then(
      () => {
        if (bootTaskRef.current === bootTask) bootTaskRef.current = null;
      },
      () => {
        if (bootTaskRef.current === bootTask) bootTaskRef.current = null;
      },
    );

    // iOS freezes PWAs in the background and silently kills their sockets. When
    // we come back to the foreground, force every relay to reconnect so the
    // inbox re-drains — otherwise the app looks "connected" but receives nothing.
    const onForeground = () => {
      if (
        lifecycleActiveRef.current &&
        !runtimeSuspendedRef.current &&
        document.visibilityState === 'visible'
      ) {
        const officialTrust = officialAccountTrustRef.current;
        if (officialTrust) scheduleOfficialTrustExpiryRerender(officialTrust);
        if (officialAccountConfigured()) {
          launchRuntimeOperation((signal) =>
            refreshOfficialAccountTrust(signal),
          );
        }
        for (const r of relaysRef.current.values()) r.reconnect();
        void schedulePendingGroupMutationRetry();
      }
    };
    document.addEventListener('visibilitychange', onForeground);
    window.addEventListener('pageshow', onForeground);
    // Revocations and device rotations must reach an already-open PWA without a
    // manual reload. Foreground transitions refresh immediately; this bounded
    // poll covers a tab that remains continuously visible. Calls coalesce above.
    const officialTrustRefreshInterval = window.setInterval(() => {
      if (
        officialAccountConfigured() &&
        lifecycleActiveRef.current &&
        !runtimeSuspendedRef.current &&
        document.visibilityState === 'visible'
      ) {
        launchRuntimeOperation((signal) =>
          refreshOfficialAccountTrust(signal),
        );
      }
    }, OFFICIAL_TRUST_REFRESH_INTERVAL_MS);

    return () => {
      // Invalidate first: a promise that resumes while sockets are being closed
      // cannot enqueue work, update state, or create a replacement relay.
      lifecycleActiveRef.current = false;
      if (officialTrustExpiryTimerRef.current !== null) {
        clearTimeout(officialTrustExpiryTimerRef.current);
        officialTrustExpiryTimerRef.current = null;
      }
      document.removeEventListener('visibilitychange', onForeground);
      window.removeEventListener('pageshow', onForeground);
      window.clearInterval(officialTrustRefreshInterval);
      officialTrustRefreshRunningRef.current = false;
      groupsBootReadyRef.current = false;
      for (const r of relaysRef.current.values()) r.close();
      relaysRef.current.clear();
      sendRoomRef.current.clear();
      inboxClientRef.current = null;
      for (const t of ackTimers.current.values()) clearTimeout(t);
      ackTimers.current.clear();
      earlyDeliveryReceiptsRef.current.clear();
      // Drop the component's last strong references to long-lived secret/session
      // material. Suspended operations fail at their next lifecycle checkpoint.
      identityRef.current = null;
      prekeysRef.current = null;
      lookupRef.current = null;
      ownListRef.current = null;
      officialAccountTrustRef.current = null;
      contactsRef.current = [];
      groupsRef.current = [];
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Pin the message list to the bottom (newest message) on open and on new messages.
  // A single scroll-to-bottom isn't enough: attachments decrypt ASYNCHRONOUSLY and
  // swap a placeholder for an <img>/<video> only later, growing the list after the
  // scroll and stranding a freshly-opened chat in the middle. A ResizeObserver on the
  // rows catches every height change whenever and however it happens; we keep re-
  // pinning to the bottom until the user deliberately scrolls up. useLayoutEffect
  // does the first scroll before paint, so there's no visible jump.
  useLayoutEffect(() => {
    if (view !== 'chat') return;
    const el = document.getElementById('msgs');
    if (!el) return;
    const toBottom = () => {
      el.scrollTop = el.scrollHeight;
    };
    const atBottom = () => el.scrollHeight - el.scrollTop - el.clientHeight < 80;
    let pin = true; // stay glued to the bottom until the user scrolls away from it
    toBottom();
    const onScroll = () => {
      pin = atBottom();
      // Near the top → reveal an older page of messages (windowing). Remember the
      // height first so the viewport stays put after the prepend (restore effect).
      if (el.scrollTop < 260 && !loadMoreRef.current) {
        const roomKey = activeGroupRef.current ?? activeRoomRef.current;
        const total = roomKey ? messagesRef.current[roomKey]?.length ?? 0 : 0;
        if (windowNRef.current < total) {
          prevHeightRef.current = el.scrollHeight;
          loadMoreRef.current = true;
          setWindowN((n) => n + MSG_WINDOW);
        }
      }
    };
    el.addEventListener('scroll', onScroll, { passive: true });
    // Observe ONLY the content wrapper's height — one target, cheap even with hundreds
    // of messages — instead of every bubble. Fires whenever content grows (a lazily
    // decrypted image swaps in, a video sizes up, the keyboard opens), so we can re-pin.
    const inner = el.querySelector('.msgs-inner') ?? el;
    const ro = new ResizeObserver(() => {
      if (pin) toBottom();
    });
    ro.observe(inner);
    const raf = requestAnimationFrame(toBottom);
    return () => {
      el.removeEventListener('scroll', onScroll);
      ro.disconnect();
      cancelAnimationFrame(raf);
    };
  }, [messages, activeRoom, activeGroup, view]);

  useEffect(() => {
    setRenaming(false);
    setChatMenu(false);
  }, [activeRoom, activeGroup]);

  // App-icon badge: the running app is the source of truth for the total unread
  // count. unreadRef changes are always followed by a re-render (bump/commit), so
  // this recomputes and repaints the badge whenever it actually changes.
  const totalUnread = Object.values(unreadRef.current).reduce((s, n) => s + (n || 0), 0);
  useEffect(() => {
    launchRuntimeOperation(() => applyBadge(totalUnread));
    // launchRuntimeOperation reads stable lifetime refs; depending on its render
    // identity would repeat the badge write on every render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [totalUnread]);

  // After an older page is prepended, keep the viewport on the same message instead
  // of jumping (the newly added rows above would otherwise push everything down).
  useLayoutEffect(() => {
    if (!loadMoreRef.current) return;
    loadMoreRef.current = false;
    const el = document.getElementById('msgs');
    if (el) el.scrollTop += el.scrollHeight - prevHeightRef.current;
  }, [windowN]);

  /** Delete the out-of-band attachments referenced by a room's messages, so
   *  removing a chat does not leak its videos in the vault. */
  /** Delete attachment blobs no message references any more — orphans from an
   *  interrupted store, or from a message that never got persisted. Runs once at
   *  boot INSIDE the inbox task, before any delivery, so it can never race a
   *  concurrent store and delete a live attachment. */
  async function sweepOrphanAttachments() {
    const referenced = new Set<string>();
    for (const roomId of await allMessageRoomIds()) {
      assertMessengerActive();
      for (const m of await loadMessages(dek, roomId)) {
        if (m.file?.attId) referenced.add(m.file.attId);
      }
      assertMessengerActive();
    }
    // An in-progress INCOMING transfer is in-use, not an orphan — protect it. A stale
    // one (sender vanished mid-transfer, marker older than the TTL) is dropped along
    // with its partial chunks. A marker whose attachment already completed (referenced
    // by a message) is just a leftover → clear it without touching the attachment.
    for (const tid of await allRecvMarkerIds()) {
      assertMessengerActive();
      if (referenced.has(tid)) {
        await clearRecvMarker(tid);
        assertMessengerActive();
        continue;
      }
      const marker = await getRecvMarker(dek, tid);
      assertMessengerActive();
      if (marker && Date.now() - marker.ts > RECV_TTL_MS) {
        await clearRecvMarker(tid);
        assertMessengerActive();
        await secureWipeAttachment(tid);
        assertMessengerActive();
      } else {
        referenced.add(tid); // live transfer — keep its chunks
      }
    }
    for (const id of await allAttachmentIds()) {
      assertMessengerActive();
      if (!referenced.has(id)) {
        await secureWipeAttachment(id);
        assertMessengerActive();
      }
    }
  }

  // Crypto-erase every attachment this room references. Loads from the store if the
  // in-memory list is already gone, so it works whatever order the caller clears state.
  async function gcRoomAttachments(roomId: string) {
    const msgs = messagesRef.current[roomId] ?? (await loadMessages(dek, roomId));
    for (const m of msgs) {
      if (m.file?.attId) await secureWipeAttachment(m.file.attId);
    }
  }

  async function deleteContactAction(roomId: string) {
    setChatMenu(false);
    // The inbox barrier must be OUTER: a receive task may already be decrypting
    // (and therefore not have entered the room queue yet). Let that task finish
    // its append + saveContact before erasing both records, then prevent every
    // later inbox task from overtaking this deletion.
    await enqueueInbox(() =>
      enqueueMessageMutation(roomId, async () => {
        await gcRoomAttachments(roomId); // crypto-erase attachments while the room still exists
        const sendRoom = sendRoomRef.current.get(roomId);
        if (sendRoom) {
          relaysRef.current.get(sendRoom)?.close();
          relaysRef.current.delete(sendRoom);
          sendRoomRef.current.delete(roomId);
        }
        contactsRef.current = contactsRef.current.filter((c) => c.roomId !== roomId);
        delete messagesRef.current[roomId];
        delete unreadRef.current[roomId];
        profileSentRef.current.delete(roomId);
        await removeContact(dek, roomId);
        if (activeRoom === roomId) {
          setActiveRoom(null);
          setView('list');
        }
        commitMessages();
        bump();
      }),
    );
  }

  async function clearChatAction(roomId: string) {
    setChatMenu(false);
    // See deleteContactAction: room-only ordering misses an older inbox task
    // that is still decrypting/building an attachment before appendMessage().
    await enqueueInbox(() =>
      enqueueMessageMutation(roomId, async () => {
        await gcRoomAttachments(roomId); // crypto-erase this room's attachments first
        messagesRef.current[roomId] = [];
        await clearMessages(roomId); // crypto-erase the per-room key → history unrecoverable
        commitMessages();
        bump();
      }),
    );
  }

  /**
   * Encrypt through the ratchet and persist the advanced state BEFORE the bytes
   * go anywhere. Every outgoing path must go through here.
   *
   * ⚠️ WHY THIS IS NOT OPTIONAL: `ratchetEncrypt` mutates the sending chain in
   * place (`state.CKs = ck; state.Ns += 1`). If the app dies before the contact
   * is written — an iOS PWA freeze, a service-worker reload, a crash — the next
   * load restores the OLD chain key, and the next send derives the SAME message
   * key. The AES-GCM IV is derived from that message key rather than transmitted
   * (see messageKeyMaterial), so an identical key comes with an identical IV:
   * two different plaintexts under one (key, nonce) pair. That is a two-time pad
   * — it leaks the XOR of both plaintexts and lets an attacker recover the GHASH
   * authentication key, i.e. it breaks confidentiality AND lets them forge.
   *
   * ⚠️ DO NOT "OPTIMISE" THE ORDER. Persist-before-send is not a preference,
   * it is the only correct order, and the asymmetry is total:
   *   - persist → send:  if the send fails, the chain has still advanced. The
   *     next message uses a FRESH key and simply leaves a gap, which is exactly
   *     what the recipient's skipped-key mechanism exists to absorb. Cost: at
   *     most one message that never arrives.
   *   - send → persist:  a crash in the gap rolls the chain back to a key that
   *     has ALREADY been used on the wire. Cost: nonce reuse — the original bug,
   *     merely with a narrower window.
   * A lost message is recoverable. A reused (key, nonce) pair is not.
   */
  async function encryptAndPersist(
    contact: Contact,
    produce: (current: Contact) => Promise<Bytes>,
  ): Promise<Bytes> {
    // Serialize the ratchet-mutating send through the SAME chain as onInbox.
    // ratchetEncrypt advances CKs/Ns IN PLACE on contact.ratchet; a CONCURRENT
    // onInbox ratchetDecrypt clones the whole state and commits it back via
    // Object.assign(state, draft) (ratchet.ts:226-228) — which would ROLL BACK
    // that CKs advance if the send landed between the clone and the commit. The
    // next send then re-derives the same message key → (key, nonce) reuse =
    // two-time-pad (leaks plaintext XOR + the GHASH auth key → forgery). The
    // keystone enqueueInbox covered receive-vs-receive only; send-vs-receive on the
    // same contact was still open. No awaited send runs inside an onInbox task
    // (ensureProfileSent is fire-and-forget), so this cannot self-deadlock.
    return enqueueInbox(async () => {
      const current = requireCurrentContact(contact);
      const envelope = await produce(current);
      await saveContact(dek, current);
      return envelope;
    });
  }

  // ── Groups ────────────────────────────────────────────────────────
  // `silent` suppresses the wake-up push for control frames (listack/devlist/roster
  // changes). Defaults to false because this helper ALSO carries real messages
  // (group chat messages, the device-linking notice) that must still push.
  async function sendEnvelopeTo(contact: Contact, envelope: Bytes, mid?: string, silent = false) {
    assertRuntimeAvailable();
    let room = sendRoomRef.current.get(contact.roomId);
    if (!room) {
      await connectSend(contact);
      assertRuntimeAvailable();
      room = sendRoomRef.current.get(contact.roomId);
    }
    assertRuntimeAvailable();
    (room ? relaysRef.current.get(room) : undefined)?.send(envelope, mid, silent);
  }

  function groupMemberFromContact(contact: Contact): GroupMember {
    return {
      masterPub: contact.peerMasterPub,
      epoch: contact.peerEpoch,
      signPub: contact.peerSignPub,
      dhPub: contact.peerDhPub,
      bundle: contact.bundle ? groupBroadcastBundle(contact.bundle) : undefined,
      deviceList: contact.peerDeviceList,
      // A local nickname is private metadata and must never leak through a roster.
      name: contact.peerName,
    };
  }

  function reconcileMemberWithContact(
    member: GroupMember,
    contact: Contact,
  ): GroupMember {
    const current = groupMemberFromContact(contact);
    return {
      ...member,
      ...current,
      bundle: current.bundle ?? member.bundle,
      deviceList: current.deviceList ?? member.deviceList,
      name: member.name ?? current.name,
    };
  }

  function ownGroupMember(): GroupMember | null {
    const id = identityRef.current;
    const pre = prekeysRef.current;
    if (!id || !pre) return null;
    return {
      masterPub: id.master.publicKey,
      epoch: id.epoch,
      signPub: id.sign.publicKey,
      dhPub: id.dh.publicKey,
      bundle: groupBroadcastBundle(currentBundle(id, pre)),
      deviceList: ownListRef.current ?? undefined,
      name: myProfileRef.current.name,
    };
  }

  function refreshGroupDirectories(group: Group): Group {
    return {
      ...group,
      members: group.members.map((member) => {
        const contact = contactsRef.current.find((candidate) =>
          bytesEqual(candidate.peerMasterPub, memberMasterPub(member)),
        );
        if (!contact) return member;
        return reconcileMemberWithContact(member, contact);
      }),
    };
  }

  // Upsert the hidden pairwise contact that backs one group member. DeviceLists
  // are re-verified through the normal Contact path, so group-originated keys do
  // not get a weaker revocation or rollback rule.
  /** Contact/session mutation for group flows already running as an inbox task. */
  async function ensureMemberContactWithinInbox(
    m: GroupMember,
  ): Promise<Contact | null> {
    const id = identityRef.current;
    if (!id) return null;
    const master = memberMasterPub(m);
    if (bytesEqual(master, id.master.publicKey)) return null;
    if (retiredMastersRef.current.has(await masterKeyB64(master))) {
      console.warn('[group] Mitglied unter verlassenem Master abgelehnt.');
      return null;
    }
    const myMaster = asMasterPub(id.master.publicKey);
    let contact = contactsRef.current.find((candidate) =>
      bytesEqual(candidate.peerMasterPub, master),
    );
    if (contact) {
      if (m.deviceList) {
        await applyDeviceListUpdate(contact, m.deviceList, retiredMastersRef.current);
      }
      if (
        !contact.bundle &&
        m.bundle &&
        bytesEqual(m.bundle.masterPub, contact.peerMasterPub)
      ) {
        contact.bundle = groupBroadcastBundle(m.bundle);
      }
      if (!contact.peerName && m.name) contact.peerName = m.name;
      await saveContact(dek, contact);
      await connectSend(contact);
      return contact;
    }

    const bundle = m.bundle ? groupBroadcastBundle(m.bundle) : undefined;
    if (!bundle || !bytesEqual(bundle.masterPub, master)) {
      console.warn('[group] Mitglied ohne verifiziertes, initiierbares Prekey-Bundle abgelehnt.');
      return null;
    }
    try {
      contact = await makeContact(myMaster, bundle);
      contact.hidden = true;
      contact.peerName = m.name;
      if (
        m.deviceList &&
        !(await applyDeviceListUpdate(contact, m.deviceList, retiredMastersRef.current))
      ) {
        console.warn('[group] Geräteliste des Mitglieds konnte nicht übernommen werden.');
        return null;
      }
      contactsRef.current = [...contactsRef.current, contact];
      await saveContact(dek, contact);
      await connectSend(contact);
      return contact;
    } catch {
      console.warn('[group] Versteckter Mitgliedskontakt abgelehnt.');
      return null;
    }
  }

  /** Public group-directory entry point. Device-list reconciliation may prune
   * ratchet sessions, so the mutation and full Contact write are inbox-serial. */
  async function ensureMemberContact(
    m: GroupMember,
  ): Promise<Contact | null> {
    return enqueueInbox(() => ensureMemberContactWithinInbox(m));
  }

  async function confirmedFanout(
    contact: Contact,
    content: MessageContent,
    minPv = 0,
  ): Promise<void> {
    const id = identityRef.current;
    if (!id) throw new Error('Keine lokale Identität.');
    const { deliveries, unreachable } = await enqueueInbox(async () => {
      const current = requireCurrentContact(contact);
      const result = await fanoutFromThisDevice(
        id,
        current,
        content,
        randomMid(),
        undefined,
        undefined,
        minPv,
      );
      await saveContact(dek, current);
      return result;
    });
    if (deliveries.length === 0) {
      throw new Error(
        `Gruppenstand konnte ${unreachable.length || 1} Gerät(en) nicht kryptographisch zugestellt werden.`,
      );
    }
    await Promise.all(
      deliveries.map(async (delivery) => {
        const room = await inboxRoom(delivery.deviceSignPub);
        connectDeviceInbox(room);
        const relay = relaysRef.current.get(room);
        if (!relay) throw new Error('Relay für Gruppenstand nicht verfügbar.');
        await relay.sendConfirmed(delivery.sealed, isSilentFrame(content.kind));
      }),
    );
    if (unreachable.length > 0) {
      throw new Error(
        `Gruppenstand wartet noch auf ${unreachable.length} autorisierte(s) Gerät(e).`,
      );
    }
  }

  async function syncGroupStateToOwnDevices(group: Group): Promise<void> {
    const id = identityRef.current;
    const self = await ensureSelfContact();
    if (
      !id ||
      !self ||
      !self.peerDeviceList ||
      self.peerDeviceList.devices.length < 2
    ) {
      return;
    }
    const invite = await toInvite(group);
    const { deliveries, unreachable } = await enqueueInbox(async () => {
      const current = requireCurrentContact(self);
      const result = await fanoutFromThisDevice(
        id,
        current,
        { kind: 'ginvite', group: invite },
        randomMid(),
        id.sign.publicKey,
        undefined,
        6,
      );
      await saveContact(dek, current);
      return result;
    });
    await Promise.all(
      deliveries.map(async (delivery) => {
        const room = await inboxRoom(delivery.deviceSignPub);
        connectDeviceInbox(room);
        const relay = relaysRef.current.get(room);
        if (!relay) throw new Error('Eigenes Geräte-Relay nicht verfügbar.');
        await relay.sendConfirmed(delivery.sealed, true);
      }),
    );
    if (unreachable.length > 0) {
      throw new Error('Gruppenstand wartet noch auf mindestens ein eigenes Gerät.');
    }
  }

  async function sendGroupInvites(input: Group): Promise<Group> {
    const id = identityRef.current;
    const me = ownGroupMember();
    if (!id || !me) throw new Error('Gruppenschlüssel nicht geladen.');
    if (
      input.ownerMasterPub &&
      !bytesEqual(input.ownerMasterPub, id.master.publicKey)
    ) {
      throw new Error('Nur der Gruppen-Owner darf den Gruppenstand verteilen.');
    }
    const group = refreshGroupDirectories(input);
    const targets: Array<{ contact: Contact; invite: GroupInvite }> = [];
    for (const member of group.members) {
      const contact = await ensureMemberContact(member);
      if (!contact) {
        throw new Error(`${member.name || 'Mitglied'} ist kryptographisch nicht erreichbar.`);
      }
      const targetMaster = memberMasterPub(member);
      const roster = [
        me,
        ...group.members.filter(
          (candidate) =>
            !bytesEqual(memberMasterPub(candidate), targetMaster),
        ),
      ];
      const invite = await toInvite({ ...group, members: roster });
      targets.push({ contact, invite });
    }
    // Resolve and validate the complete target set before publishing the first
    // owner state. A durable mutation marker covers partial relay failures.
    for (const target of targets) {
      await confirmedFanout(target.contact, {
        kind: 'ginvite',
        group: target.invite,
      }, 6);
    }
    await syncGroupStateToOwnDevices(group);
    confirmedGroupStateRef.current.set(
      group.id,
      group.stateHash
        ? bytesToB64(group.stateHash)
        : `legacy:${group.revision}`,
    );
    return group;
  }

  function assertGroupContactReady(
    contact: Contact,
    label: string,
  ): void {
    const devices = contact.peerDeviceList?.devices ?? [
      {
        signPub: contact.peerSignPub,
        signedPreKey: contact.bundle?.signedPreKey,
      },
    ];
    if (devices.length === 0) {
      throw new Error(`${label} hat keine autorisierten Geräte.`);
    }
    for (const device of devices) {
      if (deviceProtocolVersion(contact, device.signPub) < 6) {
        throw new Error(
          `${label} verwendet auf mindestens einem autorisierten Gerät noch kein Gruppenprotokoll v4.`,
        );
      }
      const established =
        !!contact.sessions.get(bytesToB64(device.signPub))?.ratchet;
      const initiable =
        !!device.signedPreKey ||
        (bytesEqual(device.signPub, contact.peerSignPub) &&
          !!contact.bundle?.signedPreKey);
      if (!established && !initiable) {
        throw new Error(
          `${label} ist auf mindestens einem autorisierten Gerät nicht kryptographisch erreichbar.`,
        );
      }
    }
  }

  /**
   * Fail before the atomic group/outbox CAS if even one authorised target
   * device cannot receive v4. A partial commit would otherwise strand the
   * owner on a roster revision that some member devices can never parse.
   */
  async function preflightGroupMutationWithinInbox(
    group: Group,
  ): Promise<void> {
    const checked = new Set<string>();
    for (const member of group.members) {
      const master = memberMasterPub(member);
      const key = bytesToB64(master);
      if (checked.has(key)) continue;
      const contact = await ensureMemberContactWithinInbox(member);
      if (!contact) {
        throw new Error(`${member.name || 'Mitglied'} ist nicht erreichbar.`);
      }
      assertGroupContactReady(contact, member.name || 'Ein Gruppenmitglied');
      checked.add(key);
    }

    const id = identityRef.current;
    const self = await ensureSelfContactWithinInbox();
    if (!id || !self || !self.peerDeviceList) {
      throw new Error('Eigene signierte Geräteliste ist nicht verfügbar.');
    }
    for (const device of self.peerDeviceList.devices) {
      if (bytesEqual(device.signPub, id.sign.publicKey)) continue;
      if (deviceProtocolVersion(self, device.signPub) < 6) {
        throw new Error(
          'Mindestens ein eigenes verknüpftes Gerät unterstützt Gruppenprotokoll v4 noch nicht.',
        );
      }
      const established =
        !!self.sessions.get(bytesToB64(device.signPub))?.ratchet;
      if (!established && !device.signedPreKey) {
        throw new Error(
          'Mindestens ein eigenes verknüpftes Gerät ist für den Gruppenstand nicht erreichbar.',
        );
      }
    }
  }

  async function gcUnreferencedHiddenContactsWithinInbox(): Promise<void> {
    const id = identityRef.current;
    if (!id) return;
    const referenced = new Set<string>();
    for (const group of groupsRef.current) {
      for (const member of group.members) {
        referenced.add(bytesToB64(memberMasterPub(member)));
      }
    }
    // A removed member is intentionally absent from the current roster but its
    // hidden transport contact is still required until every terminal gremove
    // has a confirmed relay insert. Durable outbox targets therefore pin it.
    for (const snapshot of await loadPendingGroupMutationSnapshots(dek)) {
      for (const master of snapshot.mutation.removedMasters) {
        referenced.add(bytesToB64(master));
      }
    }
    const removable = contactsRef.current.filter(
      (contact) =>
        contact.hidden === true &&
        !contact.localOnly &&
        !bytesEqual(contact.peerMasterPub, id.master.publicKey) &&
        !referenced.has(bytesToB64(contact.peerMasterPub)),
    );
    if (removable.length === 0) return;
    const rooms = new Set(removable.map((contact) => contact.roomId));
    contactsRef.current = contactsRef.current.filter(
      (contact) => !rooms.has(contact.roomId),
    );
    for (const contact of removable) {
      sendRoomRef.current.delete(contact.roomId);
      delete messagesRef.current[contact.roomId];
      delete unreadRef.current[contact.roomId];
      await gcRoomAttachments(contact.roomId);
      await removeContact(dek, contact.roomId);
    }
    commitMessages();
  }

  async function gcUnreferencedHiddenContacts(): Promise<void> {
    return enqueueInbox(gcUnreferencedHiddenContactsWithinInbox);
  }

  async function dispatchPendingGroupMutationWithinRuntime(
    requested: PendingGroupMutationSnapshot,
  ): Promise<void> {
    const id = identityRef.current;
    let snapshot = requested;
    let mutation = snapshot.mutation;
    let group = groupsRef.current.find(
      (candidate) => candidate.id === mutation.groupId,
    );
    if (!group) {
      await clearPendingGroupMutation(snapshot);
      return;
    }
    // Always operate on the newest durable slot. A late completion for revision
    // N must neither delete nor overwrite a successor N+1 marker.
    const durable = (await loadPendingGroupMutationSnapshots(dek)).find(
      (candidate) => candidate.mutation.groupId === mutation.groupId,
    );
    if (!durable) return;
    snapshot = durable;
    mutation = snapshot.mutation;
    group = groupsRef.current.find(
      (candidate) => candidate.id === mutation.groupId,
    );
    if (!group) {
      await clearPendingGroupMutation(snapshot);
      return;
    }
    if (group.revision > mutation.revision) {
      // Recover a pre-v3/beta crash shape (newer group record, older outbox)
      // without losing its removed targets: promote the marker to the current
      // state atomically, then deliver that exact state.
      snapshot = await enqueueGroupMutation(async () => {
        const current = groupsRef.current.find(
          (candidate) => candidate.id === mutation.groupId,
        );
        const latest = (await loadPendingGroupMutationSnapshots(dek)).find(
          (candidate) => candidate.mutation.groupId === mutation.groupId,
        );
        if (!current || !latest) throw new Error('Gruppen-Mutations-Retry fehlt.');
        if (latest.mutation.revision >= current.revision) return latest;
        return replacePendingGroupMutation(
          dek,
          current,
          latest.mutation.removedMasters,
          latest.record,
          latest.mutation.deleteLocalAfterDispatch,
        );
      });
      mutation = snapshot.mutation;
      group = groupsRef.current.find(
        (candidate) => candidate.id === mutation.groupId,
      );
    }
    if (
      !id ||
      !group ||
      group.revision !== mutation.revision ||
      !group.stateHash ||
      !bytesEqual(group.stateHash, mutation.stateHash) ||
      !group.ownerMasterPub ||
      !isGroupOwner(group, id.master.publicKey)
    ) {
      throw new Error('Ausstehender Gruppenstand passt nicht zum lokalen Owner-Stand.');
    }
    await sendGroupInvites(group);
    for (const master of mutation.removedMasters) {
      const contact = contactsRef.current.find((candidate) =>
        bytesEqual(candidate.peerMasterPub, master),
      );
      if (!contact) continue;
      try {
        await confirmedFanout(contact, {
          kind: 'gremove',
          state: await toGroupStateProof(group),
        }, 6);
      } catch {
        // The signed removal proof is a courtesy/cleanup notification, never an
        // authorization veto. A malicious member controls its own DeviceList
        // and could otherwise add an unreachable/old device to make itself
        // permanently unremovable. Remaining members already received the new
        // owner-signed roster above; all subsequent fan-out excludes this
        // master and stale group frames from it are rejected.
        console.warn('[group] Entfernungsnachweis konnte nicht an alle entfernten Geräte zugestellt werden.');
      }
    }
    if (mutation.deleteLocalAfterDispatch) {
      const barrier: GroupRemovalTombstone = {
        groupId: group.id,
        ownerMasterPub: group.ownerMasterPub,
        revision: group.revision,
        stateHash: group.stateHash,
        blockReadd: true,
      };
      // Finalize in recoverable order: replay barrier, live-state erase, then
      // exact marker clear. Every crash prefix is completed safely at boot.
      await saveGroupRemovalTombstone(dek, barrier);
      await deleteGroupAction(group.id, barrier, true);
      await clearPendingGroupMutation(snapshot);
      await gcUnreferencedHiddenContacts();
    } else if (await clearPendingGroupMutation(snapshot)) {
        await gcUnreferencedHiddenContacts();
    }
  }

  async function dispatchPendingGroupMutation(
    requested: PendingGroupMutationSnapshot,
  ): Promise<void> {
    return runRuntimeOperation(async (signal) => {
      if (signal.aborted) throw new MessengerInactiveError();
      await dispatchPendingGroupMutationWithinRuntime(requested);
      if (signal.aborted) throw new MessengerInactiveError();
    });
  }

  /** Atomic owner-state commit for callers that already hold the inbox barrier.
   * Lock order is always inbox -> group; reversing it deadlocks an inbound leave
   * against a simultaneous local group mutation. */
  async function commitDurableGroupMutationWithinInbox(
    group: Group,
    removedMasters: Bytes[] = [],
    deleteLocalAfterDispatch = false,
  ): Promise<{ group: Group; snapshot: PendingGroupMutationSnapshot }> {
    if (!group.ownerMasterPub) {
      throw new Error('Legacy-Gruppen haben keinen dauerhaften Owner-Mutationspfad.');
    }
    return enqueueGroupMutation(async () => {
      await preflightGroupMutationWithinInbox(group);
      const previous = (await loadPendingGroupMutationSnapshots(dek)).find(
        (candidate) => candidate.mutation.groupId === group.id,
      );
      if (previous) {
        throw new Error(
          'Der vorherige Gruppenstand wartet noch auf bestätigte Zustellung.',
        );
      }
      const current = groupsRef.current.find(
        (candidate) => candidate.id === group.id,
      );
      if (
        current?.ownerMasterPub &&
        group.revision !== nextGroupRevision(current)
      ) {
        throw new Error('Gruppenstand wurde parallel geändert; bitte erneut versuchen.');
      }
      const refreshed = refreshGroupDirectories(group);
      const snapshot = await commitGroupMutation(
        dek,
        refreshed,
        removedMasters,
        deleteLocalAfterDispatch,
      );
      groupsRef.current = [
        refreshed,
        ...groupsRef.current.filter((candidate) => candidate.id !== refreshed.id),
      ];
      confirmedGroupStateRef.current.delete(refreshed.id);
      return { group: refreshed, snapshot };
    });
  }

  async function commitDurableGroupMutation(
    group: Group,
    removedMasters: Bytes[] = [],
    deleteLocalAfterDispatch = false,
  ): Promise<{ group: Group; snapshot: PendingGroupMutationSnapshot }> {
    return enqueueInbox(() =>
      commitDurableGroupMutationWithinInbox(
        group,
        removedMasters,
        deleteLocalAfterDispatch,
      ),
    );
  }

  async function persistAndDispatchGroupMutation(
    group: Group,
    removedMasters: Bytes[] = [],
    deleteLocalAfterDispatch = false,
  ): Promise<Group> {
    if (!group.ownerMasterPub) {
      const refreshed = refreshGroupDirectories(group);
      await saveGroup(dek, refreshed);
      groupsRef.current = [
        refreshed,
        ...groupsRef.current.filter((candidate) => candidate.id !== refreshed.id),
      ];
      confirmedGroupStateRef.current.delete(refreshed.id);
      return sendGroupInvites(refreshed);
    }
    const committed = await commitDurableGroupMutation(
      group,
      removedMasters,
      deleteLocalAfterDispatch,
    );
    await dispatchPendingGroupMutation(committed.snapshot);
    return committed.group;
  }

  async function resumePendingGroupMutations(): Promise<void> {
    for (const snapshot of await loadPendingGroupMutationSnapshots(dek)) {
      try {
        await dispatchPendingGroupMutation(snapshot);
      } catch (error) {
        setError(
          `Ausstehender Gruppenstand wird später erneut zugestellt: ${(error as Error).message}`,
        );
      }
    }
  }

  function schedulePendingGroupMutationRetry(): Promise<void> {
    if (!groupsBootReadyRef.current) return Promise.resolve();
    if (groupMutationRetryRef.current) return groupMutationRetryRef.current;
    const retry = resumePendingGroupMutations().finally(() => {
      if (groupMutationRetryRef.current === retry) {
        groupMutationRetryRef.current = null;
      }
    });
    groupMutationRetryRef.current = retry;
    return retry;
  }

  async function createGroup() {
    const id = identityRef.current;
    if (!id) return;
    if (!isPrimaryDevice(id)) {
      setError(t('Nur das primäre Gerät kann eine Gruppe erstellen.'));
      return;
    }
    const members: GroupMember[] = [];
    for (const contact of contactsRef.current) {
      if (!groupSel.has(contact.roomId)) continue;
      if (revokedOfficialAccountFor(contact)) {
        setError(
          t('Der widerrufene frühere Admin kann keiner Gruppe hinzugefügt werden. Verbinde dich über SKYTALE-SUPPORT neu.'),
        );
        return;
      }
      const hasReachableList = contact.peerDeviceList?.devices.some(
        (device) => !!device.signedPreKey,
      );
      if (!contact.bundle && !hasReachableList) continue;
      members.push(groupMemberFromContact(contact));
    }
    if (members.length === 0) {
      setError(t('Wähle mindestens einen erreichbaren Kontakt.'));
      return;
    }
    let group: Group = {
      id: randomGroupId(),
      name: groupNameInput.trim() || 'Gruppe',
      members,
      createdAt: Date.now(),
      revision: 1,
      ownerMasterPub: id.master.publicKey,
      roster: [
        id.master.publicKey,
        ...members.map(memberMasterPub),
      ],
    };
    try {
      group = await signGroupState(group, id);
      await toInvite(group);
    } catch (error) {
      setError(`Gruppe ist zu groß oder enthält einen ungültigen Stand: ${(error as Error).message}`);
      return;
    }
    messagesRef.current[group.id] = [];
    try {
      await persistAndDispatchGroupMutation(group);
    } catch (error) {
      if (!groupsRef.current.some((candidate) => candidate.id === group.id)) {
        delete messagesRef.current[group.id];
        setError(`Gruppe konnte nicht gespeichert werden: ${(error as Error).message}`);
        return;
      }
      setError(`Gruppe gespeichert, aber der Schlüsselstand ist noch nicht vollständig zugestellt: ${(error as Error).message}`);
    }
    setGroupSel(new Set());
    setGroupNameInput('');
    openGroup(group.id);
  }

  function openGroup(gid: string) {
    setError('');
    setActiveGroup(gid);
    setActiveRoom(null);
    activeRoomRef.current = null;
    unreadRef.current[gid] = 0;
    setWindowN(MSG_WINDOW); // render only the most recent page → instant open
    setView('chat');
    bump();
  }

  async function groupSend(inner: MessageContent, localMsg: ChatMessage) {
    const id = identityRef.current;
    let group = groupsRef.current.find((candidate) => candidate.id === activeGroup);
    if (!id || !group) return;
    if (groupHasRevokedOfficialMember(group)) {
      setError(
        t('Gruppennachricht blockiert: Entferne den widerrufenen früheren Admin oder verbinde dich über SKYTALE-SUPPORT neu.'),
      );
      return;
    }
    const logicalMid = localMsg.mid ?? randomMid();
    try {
      // State-before-content is an owner responsibility. A non-owner may resume
      // from a durably stored owner state after reload, but must never
      // re-authorise that state under their own pairwise identity.
      if (
        (!group.ownerMasterPub ||
          bytesEqual(group.ownerMasterPub, id.master.publicKey)) &&
        confirmedGroupStateRef.current.get(group.id) !==
          (group.stateHash
            ? bytesToB64(group.stateHash)
            : `legacy:${group.revision}`)
      ) {
        group = await sendGroupInvites(group);
      }
      const contacts: Contact[] = [];
      for (const member of group.members) {
        const contact = await ensureMemberContact(member);
        if (!contact) {
          throw new Error(`${member.name || 'Mitglied'} ist nicht erreichbar.`);
        }
        contacts.push(contact);
      }
      // Directory clocks are independent from the owner roster revision. Use
      // the newest verified Contact directories both for target selection and
      // for the multiplicative attachment budget.
      group = refreshGroupDirectories(group);
      groupsRef.current = groupsRef.current.map((candidate) =>
        candidate.id === group!.id ? group! : candidate,
      );
      await saveGroup(dek, group);
      if (inner.kind === 'file') {
        const policy = boundedGroupAttachmentPolicy(
          group,
          inner.data.length,
          ownListRef.current?.devices.length ?? 1,
        );
        if (!policy.allowed) {
          throw new Error('Anhang überschreitet das sichere Gruppen-Fanout-Budget.');
        }
      }
      const { deliveries, unreachable } = await enqueueInbox(async () => {
        const currentContacts = contacts.map(requireCurrentContact);
        const result = await groupFanoutToDevices(
          id,
          currentContacts,
          group!.id,
          group!.revision,
          group!.stateHash,
          myProfileRef.current.name,
          inner,
          logicalMid,
          group!.ownerMasterPub
            ? { senderDeviceList: ownListRef.current ?? undefined }
            : {
                legacyGroup: group!,
                senderDeviceList: ownListRef.current ?? undefined,
              },
        );
        // All advanced member ratchets cross the durability boundary before the
        // first ciphertext is allowed onto any relay.
        await Promise.all(
          currentContacts.map((contact) => saveContact(dek, contact)),
        );
        return result;
      });
      const rows: DeviceDelivery[] = [];
      for (const delivery of deliveries) {
        const deliveryId = randomMid();
        const room = await inboxRoom(delivery.deviceSignPub);
        connectDeviceInbox(room);
        startAckTimer(deliveryId);
        relaysRef.current.get(room)?.send(delivery.sealed, deliveryId, false);
        rows.push({
          device: bytesToB64(delivery.deviceSignPub),
          deliveryId,
          status: 'pending',
        });
      }
      for (const missing of unreachable) {
        rows.push({
          device: bytesToB64(missing.deviceSignPub),
          deliveryId: '',
          status: 'stale',
        });
      }
      let ownSyncError: Error | null = null;
      try {
        await syncGroupMessageToOwnDevices(
          group,
          inner,
          logicalMid,
          localMsg.ts,
        );
      } catch (error) {
        ownSyncError = error as Error;
      }
      await appendMessage(group.id, {
        ...localMsg,
        mid: logicalMid,
        deliveries: rows,
      });
      if (unreachable.length > 0 || ownSyncError) {
        const peerWarning =
          unreachable.length > 0
            ? `${unreachable.length} autorisierte(s) Empfängergerät(e) waren nicht erreichbar.`
            : '';
        const ownWarning = ownSyncError
          ? ` Eigene Gerätesynchronisierung unvollständig: ${ownSyncError.message}`
          : '';
        setError(`${peerWarning}${ownWarning}`.trim());
      }
    } catch (error) {
      setError(`Gruppennachricht nicht gesendet: ${(error as Error).message}`);
      return;
    }
    bump();
  }

  async function syncGroupMessageToOwnDevices(
    group: Group,
    inner: MessageContent,
    innerMid: string,
    ts: number,
  ): Promise<void> {
    const id = identityRef.current;
    const self = await ensureSelfContact();
    if (
      !id ||
      !self ||
      !self.peerDeviceList ||
      self.peerDeviceList.devices.length < 2
    ) {
      return;
    }
    const content: MessageContent = {
      kind: 'groupsync',
      group: await toInvite(group),
      innerMid,
      ts,
      inner,
    };
    const { deliveries, unreachable } = await enqueueInbox(async () => {
      const current = requireCurrentContact(self);
      const result = await fanoutFromThisDevice(
        id,
        current,
        content,
        randomMid(),
        id.sign.publicKey,
        undefined,
        6,
      );
      await saveContact(dek, current);
      return result;
    });
    if (unreachable.length > 0) {
      throw new Error(
        `${unreachable.length} eigenes Gerät(e) unterstützen den Gruppenstand nicht oder sind kryptographisch nicht erreichbar.`,
      );
    }
    await Promise.all(
      deliveries.map(async (delivery) => {
        const room = await inboxRoom(delivery.deviceSignPub);
        connectDeviceInbox(room);
        const relay = relaysRef.current.get(room);
        if (!relay) throw new Error('Eigenes Geräte-Relay nicht verfügbar.');
        await relay.sendConfirmed(delivery.sealed, true);
      }),
    );
  }

  /** Internal group erase for call sites that already execute as an inbox task.
   * Calling enqueueInbox again from those paths would await our own tail forever. */
  async function deleteGroupActionWithinInbox(
    gid: string,
    removal?: GroupRemovalTombstone,
    preserveMutation = false,
  ) {
    setChatMenu(false);
    await enqueueMessageMutation(gid, async () => {
      const existing = groupsRef.current.find((group) => group.id === gid);
      const barrier =
        removal ??
        (existing?.ownerMasterPub && existing.stateHash
          ? {
              groupId: existing.id,
              ownerMasterPub: existing.ownerMasterPub,
              revision: existing.revision,
              stateHash: existing.stateHash,
              blockReadd: true,
            }
          : undefined);
      if (barrier) {
        // Persist replay protection before erasing the live state. Boot recovery
        // completes a crash between these two writes.
        await saveGroupRemovalTombstone(dek, barrier);
      }
      groupsRef.current = groupsRef.current.filter((g) => g.id !== gid);
      delete messagesRef.current[gid];
      delete unreadRef.current[gid];
      await gcRoomAttachments(gid);
      await removeGroup(dek, gid);
      // Delete state first. If the app crashes before this explicit discard, boot
      // recovery sees no group and compare-clears only the stale exact marker.
      if (!preserveMutation) await discardPendingGroupMutation(gid);
      await gcUnreferencedHiddenContactsWithinInbox();
      if (activeGroup === gid) {
        setActiveGroup(null);
        setView('list');
      }
      commitMessages();
      bump();
    });
  }

  /** External/UI group erase. The outer inbox barrier covers receive work that
   * started before the click but has not reached appendMessage's room queue yet. */
  async function deleteGroupAction(
    gid: string,
    removal?: GroupRemovalTombstone,
    preserveMutation = false,
  ) {
    await enqueueInbox(() =>
      deleteGroupActionWithinInbox(gid, removal, preserveMutation),
    );
  }

  function groupTransitionContentBytes(
    content: MessageContent,
    depth = 0,
  ): number {
    if (depth > 1) return Number.POSITIVE_INFINITY;
    if (content.kind === 'text') {
      return new TextEncoder().encode(content.text).length + 96;
    }
    if (content.kind === 'file') {
      return (
        content.data.length +
        new TextEncoder().encode(content.name + content.mime).length +
        192
      );
    }
    if (content.kind === 'reply') {
      return 256 + groupTransitionContentBytes(content.inner, depth + 1);
    }
    return Number.POSITIVE_INFINITY;
  }

  function queueGroupTransitionFrame(
    groupId: string,
    revision: number | undefined,
    stateHash: Bytes | undefined,
    sender: Contact,
    inner: MessageContent,
    mid: string,
    ackId: number,
  ): 'queued' | 'retained' | 'duplicate' | 'reject' {
    if (
      !Number.isSafeInteger(revision) ||
      (revision as number) < 1 ||
      !stateHash ||
      stateHash.length !== 32 ||
      !mid
    ) {
      return 'reject';
    }
    const now = Date.now();
    let totalBytes = 0;
    for (const [id, frames] of pendingGroupFramesRef.current) {
      const fresh = frames.filter(
        (frame) => now - frame.queuedAt <= GROUP_TRANSITION_TTL_MS,
      );
      if (fresh.length > 0) {
        pendingGroupFramesRef.current.set(id, fresh);
        totalBytes += fresh.reduce((sum, frame) => sum + frame.bytes, 0);
      } else {
        pendingGroupFramesRef.current.delete(id);
        expiredGroupTransitionsRef.current.set(id, now);
        while (
          expiredGroupTransitionsRef.current.size >
          GROUP_TRANSITION_MAX_IDS * 2
        ) {
          const oldest = expiredGroupTransitionsRef.current.keys().next().value;
          if (oldest === undefined) break;
          expiredGroupTransitionsRef.current.delete(oldest);
        }
      }
    }
    pendingGroupBytesRef.current = totalBytes;
    // Check the tombstone only AFTER pruning. The redelivery that discovers an
    // expired frame must be ACKed, not immediately re-enqueued for another TTL.
    const expiredAt = expiredGroupTransitionsRef.current.get(groupId);
    if (expiredAt && now - expiredAt <= GROUP_TRANSITION_TTL_MS) {
      return 'reject';
    }
    if (expiredAt) expiredGroupTransitionsRef.current.delete(groupId);

    const bytes = groupTransitionContentBytes(inner);
    if (!Number.isSafeInteger(bytes) || bytes > GROUP_TRANSITION_MAX_BYTES) {
      return 'reject';
    }
    const senderKey = bytesToB64(sender.peerMasterPub);
    const existing = pendingGroupFramesRef.current.get(groupId) ?? [];
    const duplicate = existing.find(
      (frame) => frame.mid === mid && frame.senderKey === senderKey,
    );
    if (duplicate) {
      // Re-delivery of the one crash-safety row must stay retained. A distinct
      // relay row with the same authenticated E2E identity is ACKed without
      // committing its cloned ratchet state (see Duplicate...Error).
      return duplicate.ackId === ackId ? 'retained' : 'duplicate';
    }
    if (
      existing.length >= GROUP_TRANSITION_MAX_PER_GROUP ||
      pendingGroupBytesRef.current + bytes > GROUP_TRANSITION_MAX_BYTES ||
      (!pendingGroupFramesRef.current.has(groupId) &&
        pendingGroupFramesRef.current.size >= GROUP_TRANSITION_MAX_IDS)
    ) {
      return 'reject';
    }
    pendingGroupFramesRef.current.set(groupId, [
      ...existing,
      {
        revision: revision as number,
        stateHash,
        ackId,
        sender,
        senderKey,
        inner,
        mid,
        bytes,
        queuedAt: now,
      },
    ]);
    pendingGroupBytesRef.current += bytes;
    return 'queued';
  }

  async function flushGroupTransitionFrames(group: Group): Promise<void> {
    const frames = pendingGroupFramesRef.current.get(group.id);
    if (!frames?.length) return;
    for (const frame of frames) {
      if (frame.revision > group.revision) continue;
      await applyGroupMessage(
        group.id,
        frame.revision,
        frame.stateHash,
        undefined,
        frame.inner,
        frame.sender,
        frame.mid,
        frame.ackId,
      );
    }
    const remaining = frames.filter(
      (frame) => frame.revision > group.revision,
    );
    pendingGroupBytesRef.current -= frames
      .filter((frame) => frame.revision <= group.revision)
      .reduce((sum, frame) => sum + frame.bytes, 0);
    if (remaining.length > 0) {
      pendingGroupFramesRef.current.set(group.id, remaining);
    } else {
      pendingGroupFramesRef.current.delete(group.id);
    }
  }

  async function applyGroupMessage(
    groupId: string,
    revision: number | undefined,
    stateHash: Bytes | undefined,
    _senderName: string | undefined, // intentionally unused — never trust it
    inner: MessageContent,
    contact: Contact,
    wireMid: string,
    ackId: number,
  ) {
    if (!/^grp_[0-9a-f]{32}$/.test(groupId)) return;
    // Bind deduplication to the authenticated PERSON. Copies from two authorised
    // devices of that person share a logical MID and collapse; another member
    // cannot suppress it by reflecting the same MID.
    const messageId = `g:${bytesToB64(contact.peerMasterPub)}:${wireMid}`;
    const buildMsg = async (
      payload: MessageContent,
      sender: string,
      mid: string,
    ): Promise<ChatMessage | null> => {
      if (payload.kind === 'text') {
        return { mine: false, ts: Date.now(), mid, sender, text: payload.text };
      }
      if (payload.kind === 'reply') {
        return {
          ...(await replyMessage(payload.quote, payload.inner, mid, false, groupId)),
          sender,
        };
      }
      if (payload.kind === 'file') {
        const file = await inboundFileRefFor(
          groupId,
          payload.name,
          payload.mime,
          payload.data,
          payload.viewOnce,
        );
        return file
          ? { mine: false, ts: Date.now(), mid, sender, file }
          : {
              mine: false,
              ts: Date.now(),
              mid,
              sender,
              text: t('Anhang wegen des automatischen Speicherlimits nicht gespeichert.'),
            };
      }
      return null;
    };
    const g = groupsRef.current.find((x) => x.id === groupId);
    if (!g) {
      const queued = queueGroupTransitionFrame(
          groupId,
          revision,
          stateHash,
          contact,
          inner,
          wireMid,
          ackId,
        );
      if (queued === 'queued' || queued === 'retained') {
        console.warn('[group] Nachricht wartet begrenzt auf den Owner-Gruppenstand.');
        throw new DeferredGroupTransitionError();
      }
      if (queued === 'duplicate') {
        throw new DuplicateGroupTransitionRowError();
      } else {
        console.warn('[group] Nachricht für unbekannte Gruppe verworfen.');
      }
      return;
    }
    const framePolicy = classifyGroupFrame(
      g,
      contact.peerMasterPub,
      revision,
      stateHash,
    );
    if (framePolicy === 'defer') {
      const queued = queueGroupTransitionFrame(
          groupId,
          revision,
          stateHash,
          contact,
          inner,
          wireMid,
          ackId,
        );
      if (queued === 'queued' || queued === 'retained') {
        console.warn('[group] Nachricht wartet begrenzt auf den nächsten Rosterstand.');
        throw new DeferredGroupTransitionError();
      }
      if (queued === 'duplicate') {
        throw new DuplicateGroupTransitionRowError();
      } else {
        console.warn('[group] Übergangsnachricht konnte nicht sicher gepuffert werden.');
      }
      return;
    }
    if (framePolicy === 'reject') {
      console.warn('[group] Nachricht unter unzulässigem Rosterstand verworfen.');
      return;
    }
    const member = g.members.find((candidate) =>
      bytesEqual(memberMasterPub(candidate), contact.peerMasterPub),
    )!;
    if (hasMessage(messagesRef.current[g.id] ?? [], messageId, false)) return;
    const message = await buildMsg(
      inner,
      contact.peerName || member.name || shortFp(contact.peerFingerprint),
      messageId,
    );
    if (!message) return;
    await appendFreshInboundMessage(g.id, message);
    if (!(viewRef.current === 'chat' && activeGroupRef.current === g.id)) {
      unreadRef.current[g.id] = (unreadRef.current[g.id] ?? 0) + 1;
    }
  }

  async function applyGroupSync(
    content: Extract<MessageContent, { kind: 'groupsync' }>,
    sender: Contact,
  ) {
    const id = identityRef.current;
    if (!id || !bytesEqual(sender.peerMasterPub, id.master.publicKey)) return;
    let group: Group | null = null;
    try {
      const incoming = await fromInvite(content.group);
      const current = groupsRef.current.find(
        (candidate) => candidate.id === incoming.id,
      );
      const safeOlderOwnHistory =
        !!current &&
        !!current.ownerMasterPub &&
        !!incoming.ownerMasterPub &&
        incoming.revision < current.revision &&
        bytesEqual(current.ownerMasterPub, incoming.ownerMasterPub) &&
        current.dissolved !== true &&
        incoming.dissolved !== true &&
        !!current.roster?.some((master) =>
          bytesEqual(master, id.master.publicKey),
        ) &&
        !!incoming.roster?.some((master) =>
          bytesEqual(master, id.master.publicKey),
        );
      // Own-device history may legitimately arrive after this device has
      // already installed later owner revisions. The signed older checkpoint
      // authenticates where the message was sent; keep the newer authority
      // state and append only the deduplicated local history item.
      group = safeOlderOwnHistory
        ? current
        : await applyGroupInvite(content.group, sender, true);
    } catch {
      console.warn('[group] Ungültiger eigener Gruppen-Sync verworfen.');
      return;
    }
    if (
      !group ||
      !content.innerMid ||
      !Number.isSafeInteger(content.ts) ||
      content.ts <= 0 ||
      hasMessage(messagesRef.current[group.id] ?? [], content.innerMid, true)
    ) {
      return;
    }
    let message: ChatMessage | null = null;
    if (content.inner.kind === 'text') {
      message = {
        mine: true,
        ts: content.ts,
        mid: content.innerMid,
        text: content.inner.text,
      };
    } else if (content.inner.kind === 'reply') {
      message = await replyMessage(
        content.inner.quote,
        content.inner.inner,
        content.innerMid,
        true,
        group.id,
      );
      message.ts = content.ts;
    } else if (content.inner.kind === 'file') {
      const file = await inboundFileRefFor(
        group.id,
        content.inner.name,
        content.inner.mime,
        content.inner.data,
        content.inner.viewOnce,
      );
      message = file
        ? {
            mine: true,
            ts: content.ts,
            mid: content.innerMid,
            file,
          }
        : {
            mine: true,
            ts: content.ts,
            mid: content.innerMid,
            text: t('Anhang wegen des automatischen Speicherlimits nicht gespeichert.'),
          };
    }
    if (message) await appendFreshInboundMessage(group.id, message);
  }

  function masterReferencedByLiveGroup(master: Bytes): boolean {
    return groupsRef.current.some(
      (group) =>
        (!!group.ownerMasterPub &&
          bytesEqual(group.ownerMasterPub, master)) ||
        !!group.roster?.some((candidate) => bytesEqual(candidate, master)) ||
        group.members.some((member) =>
          bytesEqual(memberMasterPub(member), master),
        ),
    );
  }

  // AUTHORIZATION (audit F-02): a group roster is applied ONLY from an authorized
  // sender. For an existing group the authenticated `sender` must be a CURRENT
  // local member — otherwise a removed member (who still holds a pairwise session
  // and knows the group id) could resurrect themselves, or a stranger could
  // overwrite/rename the roster. A brand-new group is trust-on-first-invite. The
  // decision — and the merge that preserves local-only state — lives in the pure,
  // unit-tested decideInvite().
  async function applyGroupInvite(
    invite: GroupInvite,
    sender: Contact,
    fromOwnDevice = false,
  ): Promise<Group | null> {
    let incoming: Group;
    try {
      incoming = await fromInvite(invite);
    } catch {
      console.warn('[group] Ungültige Einladung verworfen.');
      return null;
    }
    if (contactsRef.current.some((contact) => contact.roomId === incoming.id)) {
      console.warn('[group] Gruppen-ID kollidiert mit einem 1:1-Raum.');
      return null;
    }
    const id = identityRef.current;
    if (!id) return null;
    if (
      incoming.ownerMasterPub &&
      (!incoming.roster?.some((master) =>
        bytesEqual(master, id.master.publicKey),
      ) ||
        incoming.members.some((member) =>
          bytesEqual(memberMasterPub(member), id.master.publicKey),
        ))
    ) {
      console.warn('[group] Falsch personalisiertes globales Roster verworfen.');
      return null;
    }
    if (
      !fromOwnDevice &&
      incoming.ownerMasterPub &&
      !incoming.roster?.some((master) =>
        bytesEqual(master, incoming.ownerMasterPub!),
      )
    ) {
      console.warn('[group] Gruppen-Owner fehlt im personalisierten Roster.');
      return null;
    }
    if (
      !fromOwnDevice &&
      !incoming.ownerMasterPub &&
      !incoming.members.some((member) =>
        bytesEqual(memberMasterPub(member), sender.peerMasterPub),
      )
    ) {
      console.warn('[group] Legacy-Einladung ohne authentifizierten Absender im Roster verworfen.');
      return null;
    }
    const removalBarrier = await loadGroupRemovalTombstone(dek, incoming.id);
    if (
      removalBarrier &&
      !permitsGroupReadd(
        removalBarrier.tombstone,
        incoming,
        id.master.publicKey,
      )
    ) {
      console.warn('[group] Einladung durch lokalen Removal-Tombstone verworfen.');
      return null;
    }
    const existing = groupsRef.current.find((x) => x.id === incoming.id);
    const decision = decideInvite(
      existing,
      incoming,
      sender.peerMasterPub,
      fromOwnDevice,
    );
    if (decision.verdict === 'reject') {
      console.warn('[group] ginvite verworfen —', decision.reason);
      return null;
    }
    const g = decision.group;
    if (
      g.dissolved === true &&
      g.ownerMasterPub &&
      g.stateHash
    ) {
      const barrier: GroupRemovalTombstone = {
        groupId: g.id,
        ownerMasterPub: g.ownerMasterPub,
        revision: g.revision,
        stateHash: g.stateHash,
        blockReadd: true,
      };
      await saveGroupRemovalTombstone(dek, barrier);
      if (existing) await deleteGroupActionWithinInbox(g.id, barrier);
      return null;
    }
    for (const member of g.members) {
      if (bytesEqual(memberMasterPub(member), sender.peerMasterPub)) {
        if (member.deviceList) {
          await applyDeviceListUpdate(
            sender,
            member.deviceList,
            retiredMastersRef.current,
          );
        }
        continue;
      }
      if (!(await ensureMemberContactWithinInbox(member))) {
        console.warn('[group] Einladung enthält ein nicht erreichbares Mitglied.');
        return null;
      }
    }
    // Reconcile against already-held, independently newer signed DeviceLists
    // before persisting/bootstrap-forwarding this owner state. The authenticated
    // sender is a cloned receive candidate and therefore merged explicitly.
    let installed = refreshGroupDirectories(g);
    installed = {
      ...installed,
      members: installed.members.map((member) =>
        bytesEqual(memberMasterPub(member), sender.peerMasterPub)
          ? reconcileMemberWithContact(member, sender)
          : member,
      ),
    };
    const had = messagesRef.current[installed.id];
    groupsRef.current = [
      installed,
      ...groupsRef.current.filter((x) => x.id !== installed.id),
    ];
    messagesRef.current[installed.id] = had ?? [];
    await saveGroup(dek, installed);
    if (removalBarrier) {
      await clearGroupRemovalTombstone(removalBarrier);
    }
    await flushGroupTransitionFrames(installed);
    await gcUnreferencedHiddenContactsWithinInbox();
    bump();
    return installed;
  }

  // A `gremove` ("you were removed") deletes the whole group locally — so it must
  // be authorized just like a roster change: only a CURRENT member may remove you.
  // An unknown group, or a sender who is not a member (a stranger who learned the
  // group id, or an already-removed member), is ignored — otherwise anyone could
  // wipe a victim's group, history and attachments (audit F-02).
  async function applyGroupRemove(
    proof: Extract<MessageContent, { kind: 'gremove' }>['state'],
    sender: Contact,
  ) {
    let removedState: Group;
    try {
      removedState = await fromGroupStateProof(proof);
    } catch {
      console.warn('[group] Ungültiger Entfernungsnachweis verworfen.');
      return;
    }
    const id = identityRef.current;
    if (
      !id ||
      !removedState.ownerMasterPub ||
      !removedState.stateHash ||
      !removedState.previousStateHash ||
      !bytesEqual(sender.peerMasterPub, removedState.ownerMasterPub) ||
      removedState.roster?.some((master) =>
        bytesEqual(master, id.master.publicKey),
      )
    ) {
      console.warn('[group] Nicht autorisierter Entfernungsnachweis verworfen.');
      return;
    }
    const g = groupsRef.current.find((group) => group.id === removedState.id);
    const priorTombstone = await loadGroupRemovalTombstone(dek, removedState.id);
    if (!g && !priorTombstone) {
      console.warn('[group] Entfernungsnachweis für unbekannte Gruppe verworfen.');
      return;
    }
    if (
      g &&
      (!g.ownerMasterPub ||
        !g.stateHash ||
        !bytesEqual(g.ownerMasterPub, removedState.ownerMasterPub) ||
        removedState.revision !== g.revision + 1 ||
        !bytesEqual(removedState.previousStateHash, g.stateHash))
    ) {
      console.warn('[group] Entfernungsnachweis schließt nicht an lokalen Stand an.');
      return;
    }
    if (
      priorTombstone &&
      (!bytesEqual(
        priorTombstone.tombstone.ownerMasterPub,
        removedState.ownerMasterPub,
      ) ||
        removedState.revision <= priorTombstone.tombstone.revision)
    ) {
      return;
    }
    const barrier: GroupRemovalTombstone = {
      groupId: removedState.id,
      ownerMasterPub: removedState.ownerMasterPub,
      revision: removedState.revision,
      stateHash: removedState.stateHash,
      // A signed terminal state has no legitimate successor. Ordinary removal
      // checkpoints remain re-addable by a later owner-signed state that
      // contains us, even if we were intentionally offline for intermediate
      // revisions and therefore cannot verify a contiguous hash chain.
      blockReadd: removedState.dissolved === true,
    };
    await saveGroupRemovalTombstone(dek, barrier);
    if (g) await deleteGroupActionWithinInbox(removedState.id, barrier);
  }

  async function updateGroup(
    candidate: Group,
    sync: boolean,
    removedMasters: Bytes[] = [],
  ) {
    const id = identityRef.current;
    const current = groupsRef.current.find((group) => group.id === candidate.id);
    if (!id || !current) return;
    if (!candidate.ownerMasterPub || !current.ownerMasterPub) {
      setError(t('Legacy-Gruppen können nicht sicher verändert werden; erstelle eine neue Gruppe.'));
      return;
    }
    if (
      !isPrimaryDevice(id) ||
      !isGroupOwner(current, id.master.publicKey) ||
      !current.stateHash
    ) {
      setError(t('Nur das primäre Owner-Gerät kann die Gruppe verwalten.'));
      return;
    }
    let group: Group;
    try {
      group = await signGroupState(
        {
          ...candidate,
          previousStateHash: current.stateHash,
          stateHash: undefined,
          stateSignature: undefined,
        },
        id,
      );
      await toInvite(group);
    } catch (error) {
      setError(`Gruppenänderung abgelehnt: ${(error as Error).message}`);
      return;
    }
    if (sync) {
      try {
        await persistAndDispatchGroupMutation(group, removedMasters);
      } catch (error) {
        setError(
          `Gruppenstand lokal gespeichert; dauerhafte Zustellung wird wiederholt: ${(error as Error).message}`,
        );
      }
    } else {
      groupsRef.current = groupsRef.current.map((x) =>
        x.id === group.id ? group : x,
      );
      await saveGroup(dek, group);
      confirmedGroupStateRef.current.delete(group.id);
    }
    bump();
  }

  async function addMembersToGroup(group: Group, roomIds: string[]) {
    const id = identityRef.current;
    if (
      !id ||
      !group.ownerMasterPub ||
      !isPrimaryDevice(id) ||
      !isGroupOwner(group, id.master.publicKey)
    ) {
      setError(t('Nur das primäre Owner-Gerät kann Mitglieder hinzufügen.'));
      return;
    }
    const additions: GroupMember[] = [];
    for (const c of contactsRef.current) {
      if (!roomIds.includes(c.roomId)) continue;
      if (revokedOfficialAccountFor(c)) {
        setError(
          t('Der widerrufene frühere Admin kann keiner Gruppe hinzugefügt werden. Verbinde dich über SKYTALE-SUPPORT neu.'),
        );
        return;
      }
      if (
        !c.bundle &&
        !c.peerDeviceList?.devices.some((device) => !!device.signedPreKey)
      ) {
        continue;
      }
      if (
        group.members.some((member) =>
          bytesEqual(memberMasterPub(member), c.peerMasterPub),
        )
      ) {
        continue;
      }
      additions.push(groupMemberFromContact(c));
    }
    if (additions.length === 0) return;
    await updateGroup(
      {
        ...group,
        members: [...group.members, ...additions],
        roster: [
          ...(group.roster ?? []),
          ...additions.map(memberMasterPub),
        ],
        revision: nextGroupRevision(group),
      },
      true,
    );
  }

  async function removeMemberFromGroup(group: Group, member: GroupMember) {
    const id = identityRef.current;
    if (!id) return;
    if (
      !group.ownerMasterPub ||
      !isPrimaryDevice(id) ||
      !isGroupOwner(group, id.master.publicKey)
    ) {
      setError(t('Nur das primäre Owner-Gerät kann Mitglieder entfernen.'));
      return;
    }
    const newGroup = {
      ...group,
      members: group.members.filter(
        (candidate) =>
          !bytesEqual(memberMasterPub(candidate), memberMasterPub(member)),
      ),
      roster: group.roster?.filter(
        (master) => !bytesEqual(master, memberMasterPub(member)),
      ),
      revision: nextGroupRevision(group),
    };
    // Keep the removed hidden contact until both the new owner state and the
    // terminal remove frame are durably inserted. The sealed mutation marker
    // resumes this exact sequence after reload.
    await updateGroup(newGroup, true, [memberMasterPub(member)]);
  }

  async function leaveGroup(group: Group) {
    const id = identityRef.current;
    if (!id) return;
    if (group.ownerMasterPub && isGroupOwner(group, id.master.publicKey)) {
      if (!isPrimaryDevice(id) || !group.stateHash) {
        setError(t('Nur das primäre Owner-Gerät kann die Gruppe auflösen.'));
        return;
      }
      const removed = group.members.map(memberMasterPub);
      const finalState = await signGroupState(
        {
          ...group,
          members: [],
          roster: [id.master.publicKey],
          dissolved: true,
          revision: nextGroupRevision(group),
          previousStateHash: group.stateHash,
          stateHash: undefined,
          stateSignature: undefined,
        },
        id,
      );
      try {
        await persistAndDispatchGroupMutation(finalState, removed, true);
      } catch (error) {
        setError(
          `Auflösung gespeichert; Zustellung wird wiederholt: ${(error as Error).message}`,
        );
      }
      bump();
      return;
    } else if (group.ownerMasterPub) {
      const owner = group.members.find((member) =>
        bytesEqual(memberMasterPub(member), group.ownerMasterPub!),
      );
      const contact = owner ? await ensureMemberContact(owner) : null;
      if (!contact) {
        setError(t('Der Gruppen-Owner ist nicht erreichbar; Austritt nicht gesendet.'));
        return;
      }
      await confirmedFanout(contact, {
        kind: 'gleave',
        groupId: group.id,
        revision: group.revision,
        stateHash: group.stateHash,
      }, 6);
    } else {
      setError(t('Legacy-Gruppe wird lokal archiviert; sichere Mitgliederänderungen benötigen eine neue v4-Gruppe.'));
    }
    await deleteGroupAction(group.id);
  }

  async function renameGroup(group: Group, name: string) {
    const n = name.trim();
    if (!n || n === group.name) return;
    const id = identityRef.current;
    if (!id || (group.ownerMasterPub && !isGroupOwner(group, id.master.publicKey))) {
      setError(t('Nur das primäre Owner-Gerät kann die Gruppe umbenennen.'));
      return;
    }
    if (!group.ownerMasterPub || !isPrimaryDevice(id)) {
      setError(t('Nur das primäre Owner-Gerät kann die Gruppe umbenennen.'));
      return;
    }
    await updateGroup(
      {
        ...group,
        name: n,
        revision: nextGroupRevision(group),
      },
      true,
    );
  }

  async function applyGroupLeave(
    groupId: string,
    revision: number | undefined,
    stateHash: Bytes | undefined,
    contact: Contact,
  ) {
    const g = groupsRef.current.find((x) => x.id === groupId);
    if (!g) return;
    if (!g.ownerMasterPub) {
      console.warn('[group] Legacy-Austritt ohne eindeutigen Owner verworfen.');
      return;
    }
    const id = identityRef.current;
    if (
      (!id ||
        !isPrimaryDevice(id) ||
        !isGroupOwner(g, id.master.publicKey) ||
        revision !== g.revision ||
        !stateHash ||
        !g.stateHash ||
        !bytesEqual(stateHash, g.stateHash) ||
        !isGroupMemberMaster(g, contact.peerMasterPub))
    ) {
      console.warn('[group] Ungültige Austrittsanfrage verworfen.');
      return;
    }
    const newGroup = await signGroupState(
      {
        ...g,
        members: g.members.filter(
          (member) =>
            !bytesEqual(memberMasterPub(member), contact.peerMasterPub),
        ),
        roster: g.roster?.filter(
          (master) => !bytesEqual(master, contact.peerMasterPub),
        ),
        revision: nextGroupRevision(g),
        previousStateHash: g.stateHash,
        stateHash: undefined,
        stateSignature: undefined,
      },
      id,
    );
    const committed = await commitDurableGroupMutationWithinInbox(
      newGroup,
      [contact.peerMasterPub],
    );
    // We are inside the serialized inbox task; enqueueing and awaiting a send
    // here would self-deadlock. Schedule delivery behind this task. The atomic
    // state+marker commit above makes an intervening crash recoverable.
    void dispatchPendingGroupMutation(committed.snapshot).catch((error) =>
      setError(`Austritt gespeichert, Roster-Sync ausstehend: ${(error as Error).message}`),
    );
    bump();
  }

  function openManage(g: Group) {
    setChatMenu(false);
    setGroupRenameInput(g.name);
    setGroupSel(new Set());
    setView('gmanage');
  }

  function openChat(roomId: string) {
    setError('');
    setActiveGroup(null);
    setActiveRoom(roomId);
    activeRoomRef.current = roomId;
    unreadRef.current[roomId] = 0;
    setWindowN(MSG_WINDOW); // render only the most recent page → instant open
    setView('chat');
    bump();
  }

  // Edge-swipe back: drag from the left screen edge toward the middle to leave a
  // chat (iOS-style). Live-follows the finger; past a threshold it goes to the list.
  function onSwipeDown(e: React.PointerEvent) {
    if (e.pointerType === 'mouse' || e.clientX > 30) return; // touch/pen, from the edge
    swipeStart.current = { x: e.clientX, y: e.clientY };
  }
  function onSwipeMove(e: React.PointerEvent) {
    const s = swipeStart.current;
    if (!s) return;
    const dx = e.clientX - s.x;
    const dy = e.clientY - s.y;
    if (dx <= 0) {
      setSwipeDx(0);
      return;
    }
    if (Math.abs(dy) > Math.abs(dx) && Math.abs(dy) > 14) {
      swipeStart.current = null; // vertical intent → let the chat scroll
      setSwipeDx(0);
      return;
    }
    setSwiping(true);
    setSwipeDx(Math.min(dx, window.innerWidth));
  }
  function onSwipeUp() {
    const triggered = !!swipeStart.current && swipeDx > 90;
    swipeStart.current = null;
    setSwiping(false);
    setSwipeDx(0);
    if (triggered) setView('list');
  }

  function startRename() {
    const c = contactsRef.current.find((x) => x.roomId === activeRoom);
    if (!c || officialAccountNameLocked(c)) return;
    setRenameInput(c?.nickname ?? '');
    setRenaming(true);
  }

  async function saveNickname() {
    const roomId = activeRoom;
    if (!roomId) return;
    const name = renameInput.trim();
    setRenaming(false);
    await enqueueInbox(async () => {
      const c = contactsRef.current.find((x) => x.roomId === roomId);
      if (!c || officialAccountNameLocked(c)) return;
      c.nickname = name || undefined;
      await saveContact(dek, c);
    });
    bump();
  }

  /** Support flow: resolve/add the official SKYTALE-SUPPORT account and open its
   * chat, then open the report dialog over it. addBundle surfaces its own error if
   * support is unavailable (e.g. not yet activated), in which case we don't open. */
  async function startBugReport(signal?: AbortSignal): Promise<void> {
    await addBundle(OFFICIAL_ACCOUNT_ALIAS, signal);
    const support = contactsRef.current.find((c) =>
      isOfficialAdminContact(c, officialAccountTrustRef.current),
    );
    if (support) setBugOpen(true);
  }

  /** Send the assembled report as a normal E2E message to SKYTALE-SUPPORT (targeted
   * at the support contact, never merely the active chat), so the admin gets a
   * categorised ticket and can reply in the same conversation. */
  async function submitBugReport(message: string): Promise<void> {
    const support = contactsRef.current.find((c) =>
      isOfficialAdminContact(c, officialAccountTrustRef.current),
    );
    if (!support) throw new Error('Support nicht verfügbar');
    const mid = randomMid();
    const ts = Date.now();
    const content: MessageContent = { kind: 'text', text: message };
    const deliveries = await fanoutSend(support, content, mid);
    void syncToOwnDevices(support.peerMasterPub, 'sent', mid, ts, content);
    await appendMessage(support.roomId, { mine: true, text: message, ts, mid, deliveries });
    void ensureProfileSent(support);
    bump();
  }

  async function onSend() {
    setError('');
    const text = (msgInputRef.current?.value ?? '').trim();
    const id = identityRef.current;
    if (!text || !id) return;
    if (activeGroup) {
      const q = replyTo;
      clearComposer();
      setReplyTo(null);
      const content: MessageContent = q ? { kind: 'reply', quote: q, inner: { kind: 'text', text } } : { kind: 'text', text };
      await groupSend(content, { mine: true, text, ts: Date.now(), reply: q ?? undefined });
      return;
    }
    if (!activeRoom) return;
    const contact = contactsRef.current.find((c) => c.roomId === activeRoom);
    if (!contact) return;
    // Provisioned local simulation contact: append a plausible local echo but
    // never create a relay channel. Do not infer this from missing sessions or
    // bundles — legitimate linked-device roster contacts can temporarily be
    // send-blocked in exactly that way.
    if (contact.localOnly) {
      const q = replyTo;
      clearComposer();
      setReplyTo(null);
      await appendMessage(activeRoom, {
        mine: true,
        text,
        ts: Date.now(),
        mid: randomMid(),
        status: 'sent',
        reply: q ?? undefined,
      });
      bump();
      return;
    }
    try {
      // ONE E2E mid: stamped into the AEAD frame, reused for the local echo and
      // shared across every fan-out (+ self-sync) copy so they dedup. fanoutSend
      // encrypts per authorised device, persists the advanced sessions before the
      // wire, and returns per-device delivery rows for the aggregate bubble.
      const mid = randomMid();
      const ts = Date.now();
      const q = replyTo;
      const content: MessageContent = q ? { kind: 'reply', quote: q, inner: { kind: 'text', text } } : { kind: 'text', text };
      const deliveries = await fanoutSend(contact, content, mid);
      // Mirror to my own other devices so they show it in this conversation.
      void syncToOwnDevices(contact.peerMasterPub, 'sent', mid, ts, content);
      await appendMessage(activeRoom, { mine: true, text, ts, mid, deliveries, reply: q ?? undefined });
      clearComposer();
      setReplyTo(null);
      void ensureProfileSent(contact);
      bump();
    } catch (e) {
      setError('Senden fehlgeschlagen: ' + (e as Error).message);
    }
  }

  async function onPickFile(e: ChangeEvent<HTMLInputElement>) {
    const input = e.target;
    const file = input.files?.[0];
    input.value = '';
    const id = identityRef.current;
    if (!file || !id || (!activeRoom && !activeGroup)) return;
    setError('');
    // iCloud probe: an offloaded photo/video (iOS "Optimise Storage") reads as 0 bytes or
    // fails until iOS fetches it from iCloud. Verify readability up front so we give a clear
    // hint instead of silently failing deep in the transcode/upload.
    if (!file.size) {
      setError(t('Datei konnte nicht geladen werden — evtl. noch in iCloud. Öffne sie kurz in der Fotos-App und versuch es dann erneut.'));
      return;
    }
    try {
      await readSliceRetry(file, 0, Math.min(file.size, 65536));
    } catch {
      setError(t('Datei konnte nicht geladen werden — evtl. noch in iCloud. Öffne sie kurz in der Fotos-App und versuch es dann erneut.'));
      return;
    }
    try {
      let data: Uint8Array<ArrayBuffer> | null = null;
      let mime = file.type || 'application/octet-stream';
      let name = file.name || 'datei';
      let theFile = file;
      const isImage = mime.startsWith('image/');
      const isVideo = mime.startsWith('video/');
      if (isImage) {
        const c = await compressImage(file, MAX_ATTACH);
        data = c.data as Uint8Array<ArrayBuffer>;
        mime = c.mime;
        name = name.replace(/\.[^.]+$/, '') + '.jpg';
      } else if (isVideo) {
        // Optimise to 720p before anything else (best-effort; original on any failure).
        setTranscoding(0);
        try {
          const smaller = await transcodeVideoTo720p(file, (f) => setTranscoding(f));
          if (smaller && smaller.size < file.size) {
            theFile = new File([smaller], name.replace(/\.[^.]+$/, '') + '.mp4', { type: 'video/mp4' });
            mime = 'video/mp4';
            name = theFile.name;
          }
        } finally {
          setTranscoding(null);
        }
      }
      // Non-images are NOT buffered here — a large video/file must stream (a 1 GB read
      // would OOM). The raw File is carried through and sliced during upload.
      if (name === STICKER_FILENAME) name = 'datei';
      const size = data ? data.length : theFile.size;
      const src = { file: data ? null : theFile, data, size };
      // Photos/videos in a 1:1 chat go through a preview sheet that carries the
      // "view once" option — so it lives INSIDE the send flow, not in a side menu.
      if ((isImage || isVideo) && activeRoom && !activeGroup) {
        setPendingVO(false);
        const url = data ? URL.createObjectURL(new Blob([data], { type: mime })) : URL.createObjectURL(theFile);
        setPendingMedia({ ...src, name, mime, url, isVideo });
        return;
      }
      // Everything else (non-media, or a group) is sent straight away — no view-once.
      await sendMedia(src, name, mime, false);
    } catch (err) {
      setError('Anhang fehlgeschlagen: ' + (err as Error).message);
    }
  }

  /** Actually send a picked photo/video/file. `viewOnce` (1:1 only) flags the recipient's
   *  copy as self-destructing; the sender always keeps a normal copy. Routes by size so
   *  EVERY attachment is retrievable while the sender is offline: inline (≤600 KB, in the
   *  relay message), auto-push chunks (≤2 MB, to the mailbox), or R2 (larger, up to ~1 GB).
   *  The old sender-streamed offer/pull tier (needed the sender online) is no longer used. */
  async function sendMedia(src: { file: File | null; data: Uint8Array<ArrayBuffer> | null; size: number }, name: string, mime: string, viewOnce: boolean): Promise<void> {
    try {
      const size = src.size;
      // Large files (videos up to ~1 GB) → encrypted straight to R2, streamed so the whole
      // file is never in memory. Needs the raw File; only the mailbox path uses byte arrays.
      // For VIEW-ONCE, the threshold drops to the auto-push cap so a view-once video of any
      // size self-destructs via R2 — whose delete-after-download matches the one-view idea.
      // Every attachment must be retrievable while the sender is offline. Anything
      // above the auto-push mailbox cap therefore goes to R2 (a tiny descriptor rides
      // the relay message; the ciphertext waits in R2 until fetched) instead of the
      // old sender-streamed offer/pull, which required the sender to stay online.
      const r2Threshold = AUTOPUSH_CAP;
      if (size > r2Threshold) {
        if (size > CLIENT_MAX_BLOB) {
          setError(t('Datei zu groß — maximal ~1 GB.'));
          return;
        }
        if (activeGroup) {
          setError(t('Große Dateien gehen nur in Einzelchats.'));
          return;
        }
        const contact = contactsRef.current.find((c) => c.roomId === activeRoom);
        if (!contact) return;
        // R2 streams from a File; wrap raw bytes (e.g. a large compressed image) if
        // that is all we have, so a 1:1 byte payload above the cap still goes offline.
        const file = src.file ?? (src.data ? new File([src.data], name, { type: mime }) : null);
        if (!file) return;
        await sendViaR2(contact, file, name, mime, viewOnce);
        return;
      }
      // Small enough for the relay mailbox — get the bytes (buffer the File only now, small).
      const data = src.data ?? (new Uint8Array(await src.file!.arrayBuffer()) as Uint8Array<ArrayBuffer>);
      if (data.length > MAX_ATTACH) {
        const target = activeGroup ? null : contactsRef.current.find((c) => c.roomId === activeRoom);
        // Auto-push chunked: a 1:1 contact, above the inline cap and within AUTOPUSH_CAP.
        if (target && data.length <= AUTOPUSH_CAP) {
          const sent = await sendChunkedAttachment(target, data, name, mime, viewOnce);
          if (!sent) setError(t('Konnte gerade nicht gesendet werden — Empfänger nicht erreichbar oder App veraltet. Bitte erneut versuchen.'));
          return;
        }
        if (target && data.length <= MAX_BIG_ATTACH) {
          const offered = await sendOfferedAttachment(target, data, name, mime);
          if (!offered) setError(t('Konnte gerade nicht gesendet werden — Empfänger nicht erreichbar oder App veraltet. Bitte erneut versuchen.'));
          return;
        }
        setError(activeGroup ? `In Gruppen gehen aktuell nur Anhänge bis ~${Math.round(MAX_ATTACH / 1024)} KB.` : t('Datei zu groß — maximal ~1 GB.'));
        return;
      }
      const mid = randomMid();
      const localMsg: ChatMessage = { mine: true, ts: Date.now(), file: await fileRefFor(name, mime, data), mid };
      if (activeGroup) {
        const group = groupsRef.current.find((candidate) => candidate.id === activeGroup);
        if (!group) return;
        const policy = boundedGroupAttachmentPolicy(
          group,
          data.length,
          ownListRef.current?.devices.length ?? 1,
        );
        if (!policy.allowed) {
          setError(
            t('Anhang für diese Gruppen-/Geräteanzahl zu groß — bitte kleiner senden.'),
          );
          return;
        }
        await groupSend({ kind: 'file', name, mime, data }, localMsg);
        return;
      }
      const contact = contactsRef.current.find((c) => c.roomId === activeRoom);
      if (!contact) return;
      // Only the RECIPIENT's copy is view-once (byte 18). The sender keeps a normal,
      // re-viewable copy, and self-sync mirrors that normal copy to my own devices —
      // "view once" is a property of what the other side received, not of my own photo.
      // A view-once file is a byte-18 frame → gate on pv>=4 so a below-4 device isn't sent
      // a frame it would throw-and-drop (and never receives a normal, permanent copy either).
      const deliveries = await fanoutSend(contact, { kind: 'file', name, mime, data, viewOnce: viewOnce || undefined }, mid, viewOnce ? 4 : 0);
      void syncToOwnDevices(contact.peerMasterPub, 'sent', mid, localMsg.ts, { kind: 'file', name, mime, data });
      await appendMessage(contact.roomId, { ...localMsg, deliveries });
      bump();
    } catch (err) {
      setError('Anhang fehlgeschlagen: ' + (err as Error).message);
    }
  }

  /** Send a large file via R2: stream-encrypt + upload (also storing the sender's local
   *  copy in the same pass), then hand the recipient a tiny E2E descriptor (key + R2 id).
   *  Not self-synced to my own devices in v1 (would race the delete-after-download). */
  async function sendViaR2(contact: Contact, file: File, name: string, mime: string, viewOnce = false): Promise<void> {
    assertNormalSendAllowed(contact);
    // The R2 descriptor is a byte-19 frame a pv<4 device can't parse. Check up front that
    // some device can receive it, so we don't waste a (possibly ~1 GB) upload on an
    // undeliverable send — and the ciphertext never lingers orphaned in R2.
    const devs = contact.peerDeviceList?.devices.map((d) => d.signPub) ?? [contact.peerSignPub];
    if (!devs.some((sp) => deviceProtocolVersion(contact, sp) >= 4)) {
      setError(t('Konnte gerade nicht gesendet werden — Empfänger nicht erreichbar oder App veraltet. Bitte erneut versuchen.'));
      return;
    }
    const attId = newAttachmentId();
    const mid = randomMid();
    setR2Upload(0);
    try {
      const ref = await uploadFileToR2(file, (f) => setR2Upload(f), { dek, attId, name, mime });
      // The sender keeps a normal, re-viewable copy; only the recipient's descriptor is flagged.
      const localMsg: ChatMessage = { mine: true, ts: Date.now(), mid, file: { name, mime, attId, size: ref.size } };
      const deliveries = await fanoutSend(
        contact,
        { kind: 'r2', key: ref.key, keyB64: ref.keyB64, name, mime, size: ref.size, chunk: ref.chunk, viewOnce: viewOnce || undefined },
        mid,
        4,
      );
      await appendMessage(contact.roomId, { ...localMsg, deliveries });
      bump();
    } catch (e) {
      await secureWipeAttachment(attId).catch(() => undefined);
      if (e instanceof StorageFullError) setError(t('Speicher gerade voll — bitte in ein paar Minuten erneut senden.'));
      else if (e instanceof FileReadError)
        setError(t('Datei konnte nicht geladen werden — evtl. noch in iCloud. Öffne sie kurz in der Fotos-App und versuch es dann erneut.'));
      else setError(t('Senden fehlgeschlagen: {msg}', { msg: (e as Error).message }));
    } finally {
      setR2Upload(null);
    }
  }

  /** Confirm the media preview: send with the chosen view-once flag, then tear it down. */
  async function confirmPendingMedia() {
    const p = pendingMedia;
    if (!p) return;
    setPendingMedia(null);
    try {
      await sendMedia({ file: p.file, data: p.data, size: p.size }, p.name, p.mime, pendingVO);
    } finally {
      URL.revokeObjectURL(p.url);
    }
  }
  function cancelPendingMedia() {
    if (pendingMedia) URL.revokeObjectURL(pendingMedia.url);
    setPendingMedia(null);
  }

  /** Turn a cropped square into a stored, reusable sticker. */
  async function onStickerCropped(bytes: Uint8Array, mime: string) {
    setStickerFile(null);
    if (stickers.length >= MAX_STICKERS) {
      setError(t('Sticker-Grenze erreicht ({n}) — lösche erst einen.', { n: MAX_STICKERS }));
      return;
    }
    const next: Sticker[] = [
      { id: crypto.randomUUID(), dataB64: bytesToB64(bytes), mime, ts: Date.now() },
      ...stickers,
    ];
    setStickers(next);
    await saveStickers(dek, next);
  }

  /**
   * Keep a sticker someone sent me: copy it into my own set. Dedup is by payload,
   * not by id — the sender's id means nothing here, and the same image arriving
   * twice must not fill the (capped) set with duplicates.
   */
  async function addStickerToLibrary(s: { mime: string; dataB64: string }) {
    if (stickers.some((x) => x.dataB64 === s.dataB64)) return; // already mine
    if (stickers.length >= MAX_STICKERS) {
      setStickerZoom(null);
      setError(t('Sticker-Grenze erreicht ({n}) — lösche erst einen.', { n: MAX_STICKERS }));
      return;
    }
    const next: Sticker[] = [
      { id: crypto.randomUUID(), dataB64: s.dataB64, mime: s.mime, ts: Date.now() },
      ...stickers,
    ];
    setStickers(next);
    await saveStickers(dek, next);
    setStickerZoom(null);
  }

  async function deleteSticker(id: string) {
    const next = stickers.filter((s) => s.id !== id);
    setStickers(next);
    await saveStickers(dek, next);
  }

  /**
   * Send a stored sticker. It goes out as an ordinary image attachment named
   * STICKER_FILENAME — see lib/stickers.ts for why a new frame type would make
   * stickers disappear on not-yet-updated devices instead of degrading.
   */
  async function sendSticker(st: Sticker) {
    const id = identityRef.current;
    if (!id || (!activeRoom && !activeGroup)) return;
    setStickerPanel(false);
    setError('');
    try {
      const data = b64ToBytes(st.dataB64);
      const mid = randomMid();
      const localMsg: ChatMessage = {
        mine: true,
        ts: Date.now(),
        file: await fileRefFor(STICKER_FILENAME, st.mime, data),
        mid,
      };
      if (activeGroup) {
        await groupSend({ kind: 'file', name: STICKER_FILENAME, mime: st.mime, data }, localMsg);
        return;
      }
      const contact = contactsRef.current.find((c) => c.roomId === activeRoom);
      if (!contact) return;
      const deliveries = await fanoutSend(contact, { kind: 'file', name: STICKER_FILENAME, mime: st.mime, data }, mid);
      void syncToOwnDevices(contact.peerMasterPub, 'sent', mid, localMsg.ts, { kind: 'file', name: STICKER_FILENAME, mime: st.mime, data });
      await appendMessage(contact.roomId, { ...localMsg, deliveries });
      bump();
    } catch (err) {
      setError('Sticker fehlgeschlagen: ' + (err as Error).message);
    }
  }

  function cleanupRecording() {
    if (recTimerRef.current) {
      clearInterval(recTimerRef.current);
      recTimerRef.current = null;
    }
    recStreamRef.current?.getTracks().forEach((t) => t.stop());
    recStreamRef.current = null;
    mediaRecorderRef.current = null;
    setRecording(false);
    setRecSeconds(0);
  }

  async function startRecording(signal?: AbortSignal) {
    if (!activeRoom) return;
    setError('');
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      // Permission prompts can outlive a vault lock. If the user grants access
      // after quiescence already ran, stop the just-created stream immediately
      // instead of installing a microphone the cleanup could never have seen.
      if (
        signal?.aborted ||
        !lifecycleActiveRef.current ||
        runtimeSuspendedRef.current
      ) {
        stream.getTracks().forEach((track) => track.stop());
        throw new MessengerInactiveError();
      }
      recStreamRef.current = stream;
      const mime = pickAudioMime();
      const rec = new MediaRecorder(stream, {
        ...(mime ? { mimeType: mime } : {}),
        audioBitsPerSecond: VOICE_BITS_PER_SECOND,
      });
      recChunksRef.current = [];
      sendOnStopRef.current = true;
      rec.ondataavailable = (e) => {
        if (e.data.size) recChunksRef.current.push(e.data);
      };
      rec.onstop = () =>
        launchRuntimeOperation(() =>
          finishRecording(rec.mimeType || mime || 'audio/webm'),
        );
      mediaRecorderRef.current = rec;
      rec.start();
      setRecording(true);
      setRecSeconds(0);
      recTimerRef.current = window.setInterval(() => {
        setRecSeconds((s) => {
          if (s + 1 >= MAX_REC_SECONDS) stopAndSend();
          return s + 1;
        });
      }, 1000);
    } catch (e) {
      if (e instanceof MessengerInactiveError || !lifecycleActiveRef.current) {
        return;
      }
      setError(t('Mikrofon nicht verfügbar: {msg}', { msg: (e as Error).message }));
      cleanupRecording();
    }
  }

  function stopAndSend() {
    sendOnStopRef.current = true;
    mediaRecorderRef.current?.stop();
  }

  function cancelRecording() {
    sendOnStopRef.current = false;
    mediaRecorderRef.current?.stop();
  }

  async function finishRecording(rawMime: string) {
    const chunks = recChunksRef.current;
    const send = sendOnStopRef.current;
    cleanupRecording();
    if (!send || chunks.length === 0) return;
    const id = identityRef.current;
    if (!id || (!activeRoom && !activeGroup)) return;

    const mime = rawMime.startsWith('audio/') ? rawMime.split(';')[0] : 'audio/webm';
    const ext = mime.includes('mp4') ? 'm4a' : mime.includes('ogg') ? 'ogg' : 'webm';
    const data = new Uint8Array(await new Blob(chunks, { type: mime }).arrayBuffer());
    if (data.length > MAX_ATTACH) {
      setError(t('Aufnahme zu groß ({kb} KB).', { kb: Math.round(data.length / 1024) }));
      return;
    }
    const name = `sprachnachricht.${ext}`;
    const mid = randomMid();
    try {
      // Inside the try: storing the attachment can fail (quota), and that must
      // surface as an error, not an unhandled rejection that silently drops it.
      const localMsg: ChatMessage = { mine: true, ts: Date.now(), file: await fileRefFor(name, mime, data), mid };
      if (activeGroup) {
        await groupSend({ kind: 'file', name, mime, data }, localMsg);
        return;
      }
      const contact = contactsRef.current.find((c) => c.roomId === activeRoom);
      if (!contact) return;
      const deliveries = await fanoutSend(contact, { kind: 'file', name, mime, data }, mid);
      void syncToOwnDevices(contact.peerMasterPub, 'sent', mid, localMsg.ts, { kind: 'file', name, mime, data });
      await appendMessage(contact.roomId, { ...localMsg, deliveries });
      bump();
    } catch (e) {
      setError('Senden fehlgeschlagen: ' + (e as Error).message);
    }
  }

  async function ensureProfileSent(contact: Contact) {
    const id = identityRef.current;
    const p = myProfileRef.current;
    if (
      !id ||
      !hasSession(contact) ||
      profileSentRef.current.has(contact.roomId) ||
      // Never push our profile (name + avatar) to a revoked former-admin key.
      revokedOfficialAccountFor(contact)
    ) return;
    if (!p.name && !p.avatarB64) return;
    try {
      const envelope = await encryptAndPersist(contact, (current) =>
        sendProfile(id, current, p.name, p.avatarB64 ? b64ToBytes(p.avatarB64) : undefined),
      );
      let room = sendRoomRef.current.get(contact.roomId);
      if (!room) {
        await connectSend(contact);
        room = sendRoomRef.current.get(contact.roomId);
      }
      (room ? relaysRef.current.get(room) : undefined)?.send(envelope, undefined, true); // profile refresh — silent
      profileSentRef.current.add(contact.roomId);
    } catch {
      /* retry next session */
    }
  }

  async function broadcastProfile() {
    profileSentRef.current.clear();
    for (const c of contactsRef.current) if (hasSession(c)) await ensureProfileSent(c);
  }

  async function togglePush() {
    if (notifBusy) return;
    setNotifBusy(true);
    setError('');
    try {
      if (notifOn) {
        const endpoint = await disablePush();
        if (endpoint) inboxClientRef.current?.unsubscribePush(endpoint);
        setNotifOn(false);
      } else {
        const sub = await enablePush(); // throws a user-facing reason on failure
        inboxClientRef.current?.setPush(sub);
        setNotifOn(true);
      }
    } catch (e) {
      setError('Benachrichtigungen fehlgeschlagen: ' + (e as Error).message);
    } finally {
      setNotifBusy(false);
    }
  }

  function onPickAvatar(e: ChangeEvent<HTMLInputElement>) {
    const input = e.target;
    const file = input.files?.[0];
    input.value = '';
    if (!file) return;
    setError('');
    setCropFile(file); // open the cropper; saving happens in onCropDone
  }

  async function onCropDone(bytes: Uint8Array) {
    try {
      const b64 = bytesToB64(bytes as Uint8Array<ArrayBuffer>);
      myProfileRef.current = { ...myProfileRef.current, avatarB64: b64 };
      setMyAvatarB64(b64);
      setCropFile(null);
      await saveProfile(dek, myProfileRef.current);
      await broadcastProfile();
      bump();
    } catch (err) {
      setError('Avatar fehlgeschlagen: ' + (err as Error).message);
      setCropFile(null);
    }
  }

  async function saveProfileMeta() {
    myProfileRef.current = { ...myProfileRef.current, name: profileName.trim() || undefined };
    setMyName(profileName.trim());
    await saveProfile(dek, myProfileRef.current);
    await broadcastProfile();
    setView('list');
  }

  /** Public activation input for the offline root-signing ceremony. This action is
   * rendered only when the currently loaded own master is already the root-signed
   * ADMIN identity. It exports no private key and currentBundle carries no OPK. */
  async function exportOfficialAdminDescriptor(
    signal?: AbortSignal,
  ): Promise<void> {
    const identity = identityRef.current;
    const prekeys = prekeysRef.current;
    const deviceList = ownListRef.current;
    const trusted = officialAccountTrustRef.current;
    if (
      !identity ||
      !prekeys ||
      !deviceList ||
      !isOfficialAdminMaster(identity.master.publicKey, trusted)
    ) {
      throw new OfficialAccountError(
        'configuration',
        'Der öffentliche Admin-Deskriptor ist für dieses Konto nicht verfügbar.',
      );
    }
    const descriptor = {
      v: 1,
      bundle: await encodeBundle(currentBundle(identity, prekeys)),
      deviceList: base64urlEncode(await encodeDeviceList(deviceList)),
    } as const;
    if (
      signal?.aborted ||
      !lifecycleActiveRef.current ||
      runtimeSuspendedRef.current
    ) {
      throw new MessengerInactiveError();
    }
    const url = URL.createObjectURL(
      new Blob([JSON.stringify(descriptor, null, 2) + '\n'], {
        type: 'application/json',
      }),
    );
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = 'skytale-admin-descriptor.json';
    anchor.rel = 'noopener';
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 0);
  }

  /** Install a new self-contained bundle for QR/backcompat and invalidate only
   * the in-memory remote invite. Already shared remote codes keep their fixed
   * 24-hour server TTL, but can never be mistaken for the new identity. */
  function updateShareBundle(token: string): string {
    const link = `${location.origin}/#add=${token}`;
    shareBundleTokenRef.current = token;
    contactInviteRef.current = null;
    contactInvitePublishRef.current = null;
    setShareBundleToken(token);
    setContactCode('');
    setContactCodeExpiresAt(0);
    setContactCodeStatus('idle');
    return link;
  }

  async function ensureContactInvite(signal?: AbortSignal): Promise<void> {
    const bundle = shareBundleTokenRef.current;
    if (!bundle) {
      throw new ContactCodeError('unavailable', 'Kurzcode ist noch nicht verfügbar.');
    }
    let cached = contactInviteRef.current;
    if (cached?.bundle === bundle && cached.draft.expiresAt <= Date.now()) {
      contactInviteRef.current = null;
      cached = null;
    }
    if (
      cached?.bundle === bundle &&
      cached.expiresAt !== undefined &&
      cached.expiresAt > Date.now()
    ) {
      setContactCode(cached.draft.code);
      setContactCodeExpiresAt(cached.expiresAt);
      setContactCodeStatus('ready');
      setError('');
      return;
    }
    if (cached?.bundle === bundle && cached.expiresAt !== undefined) {
      // Expired means a genuinely fresh salt/code, not a silent extension of a
      // previously shared capability.
      contactInviteRef.current = null;
    }

    const alreadyPublishing = contactInvitePublishRef.current;
    if (alreadyPublishing) {
      const result = await alreadyPublishing;
      if (result.bundle !== shareBundleTokenRef.current) throw new MessengerInactiveError();
      setContactCode(result.draft.code);
      setContactCodeExpiresAt(result.expiresAt);
      setContactCodeStatus('ready');
      setError('');
      return;
    }

    setContactCodeStatus('publishing');
    let pending!: Promise<{
      bundle: string;
      draft: ContactInviteDraft;
      expiresAt: number;
    }>;
    pending = (async () => {
      let draft =
        contactInviteRef.current?.bundle === bundle
          ? contactInviteRef.current.draft
          : undefined;
      if (!draft) draft = await createContactInvite(bundle);
      if (signal?.aborted || shareBundleTokenRef.current !== bundle) {
        throw new MessengerInactiveError();
      }
      contactInviteRef.current = { bundle, draft };
      const expiresAt = await publishContactInvite(draft, signal);
      return { bundle, draft, expiresAt };
    })();
    contactInvitePublishRef.current = pending;
    try {
      const result = await pending;
      if (shareBundleTokenRef.current !== bundle) throw new MessengerInactiveError();
      contactInviteRef.current = result;
      setContactCode(result.draft.code);
      setContactCodeExpiresAt(result.expiresAt);
      setContactCodeStatus('ready');
      setError('');
    } catch (error) {
      if (shareBundleTokenRef.current === bundle && lifecycleActiveRef.current) {
        setContactCode('');
        setContactCodeExpiresAt(0);
        setContactCodeStatus('failed');
      }
      throw error;
    } finally {
      if (contactInvitePublishRef.current === pending) {
        contactInvitePublishRef.current = null;
      }
    }
  }

  async function copyContactCode() {
    if (contactCodeStatus !== 'ready' || !contactCode) return;
    try {
      await navigator.clipboard.writeText(contactCode);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard may be blocked; the box is selectable anyway */
    }
  }

  // Deliberately NO URL: external HTTPS links often open a browser instead of an
  // installed PWA (especially on iOS). The complete message can be pasted into
  // SKYTALE; extractContactCode finds and validates the embedded SK1 code.
  function contactShareText(): string {
    return (
      t('Verbinde dich mit mir auf SKYTALE 🔐') +
      '\n\n' +
      contactCode +
      '\n\n' +
      `SKYTALE → ${t('Verbinden')} → ${t('Aus Zwischenablage verbinden')}`
    );
  }

  // Sender affordance. navigator.share is the native sheet (works outgoing on
  // iOS standalone PWAs); where it's absent (most desktops) fall back to copying
  // the same text. A cancelled share sheet throws AbortError — swallowed, it is
  // not an error the user needs to see.
  async function shareContactCode() {
    if (contactCodeStatus !== 'ready' || !contactCode) return;
    const text = contactShareText();
    try {
      if (typeof navigator !== 'undefined' && navigator.share) {
        await navigator.share({ text }); // the native sheet is its own feedback
      } else {
        // No share sheet (most desktops): we copied instead — acknowledge on THIS
        // button, not the separate 'Kopieren' one the user didn't click.
        await navigator.clipboard.writeText(text);
        setShared(true);
        window.setTimeout(() => setShared(false), 1500);
      }
    } catch {
      /* share sheet cancelled, or share/clipboard unavailable — nothing to do */
    }
  }

  // Receiver affordance. Reading the clipboard needs a user gesture (this is one)
  // and may prompt on iOS — both fine. addBundle runs the SAME cert-verifying
  // path as the QR scan and the manual box, so pasting is not a weaker channel;
  // the bundle is public keys and the MitM backstop is the safety-number compare.
  async function pasteAndAdd(signal?: AbortSignal) {
    setError('');
    try {
      if (!navigator.clipboard?.readText) {
        setError(t('Zwischenablage nicht verfügbar — füge den Code unten ins Feld ein.'));
        return;
      }
      const text = await navigator.clipboard.readText();
      if (!text.trim()) {
        setError(t('Zwischenablage ist leer — kopiere zuerst den Verbindungscode deines Kontakts.'));
        return;
      }
      await addBundle(text, signal);
    } catch {
      if (signal?.aborted) throw new MessengerInactiveError();
      setError(t('Zugriff auf die Zwischenablage nicht möglich — füge den Code stattdessen unten ins Feld ein.'));
    }
  }

  function openContact() {
    setChatMenu(false);
    setRenaming(false);
    setView('contact');
  }

  async function openVerify() {
    const c = contactsRef.current.find((x) => x.roomId === activeRoom);
    const id = identityRef.current;
    setView('verify');
    if (!c || !id) return;
    const sn = await masterSafetyNumber(id.master.publicKey, c.peerMasterPub);
    setSafetyNumber(sn);
    makeQr('SCYTALE-SN:' + sn.replace(/ /g, '')).then(setSafetyQr).catch(() => undefined);
  }

  async function markVerified() {
    const roomId = activeRoom;
    if (!roomId) return;
    await enqueueInbox(async () => {
      const c = contactsRef.current.find((x) => x.roomId === roomId);
      if (!c) return;
      c.verified = true;
      c.verifiedSuggestion = undefined; // acted on — the hint has served its purpose
      await saveContact(dek, c);
    });
    bump();
  }

  /** Hide the "verified on your other device" hint for good. Only the hint — it
   *  never granted trust, so dismissing it changes nothing about `verified`. */
  async function dismissVerifiedSuggestion() {
    const roomId = activeRoom;
    if (!roomId) return;
    await enqueueInbox(async () => {
      const c = contactsRef.current.find((x) => x.roomId === roomId);
      if (!c) return;
      c.verifiedSuggestion = undefined;
      c.verifiedSuggestionDismissed = true; // survives a re-delivered snapshot
      await saveContact(dek, c);
    });
    bump();
  }

  /** Acknowledge the retired-identity notice. Clears only the *notice*, never
   *  the denylist itself — the rejection stays permanent, the banner does not. */
  async function dismissRetiredNotice() {
    const roomId = activeRoom;
    if (!roomId) return;
    await enqueueInbox(async () => {
      const c = contactsRef.current.find((x) => x.roomId === roomId);
      if (!c) return;
      c.retiredAttempt = undefined;
      await saveContact(dek, c);
    });
    bump();
  }

  // ── The door, peer side ─────────────────────────────────────────────
  // This contact presented a new master (pendingMaster) and the user chose to
  // accept it. Re-pins to the new identity, drops the session, forces a fresh
  // safety-number comparison. Deliberate user action only.
  async function acceptNewIdentity() {
    const roomId = activeRoom;
    const current = contactsRef.current.find((x) => x.roomId === roomId);
    if (!roomId || !current?.pendingMaster) return;
    if (revokedOfficialAccountFor(current)) {
      setError(
        t('Diese Identität darf nicht manuell ersetzt werden. Verbinde dich ausschließlich über SKYTALE-SUPPORT neu.'),
      );
      return;
    }
    if (masterReferencedByLiveGroup(current.peerMasterPub)) {
      setError(
        t('Entferne den Kontakt zuerst aus allen Gruppen; erst danach kann seine neue Identität übernommen werden.'),
      );
      return;
    }
    if (!confirm(t('Neue Identität dieses Kontakts übernehmen? Danach musst du die Sicherheitsnummer erneut vergleichen.')))
      return;
    const r = await enqueueInbox(async () => {
      const c = contactsRef.current.find((entry) => entry.roomId === roomId);
      if (!c?.pendingMaster) return null;
      if (revokedOfficialAccountFor(c)) {
        setError(
          t('Diese Identität darf nicht manuell ersetzt werden. Verbinde dich ausschließlich über SKYTALE-SUPPORT neu.'),
        );
        return null;
      }
      // The roster may have changed while the confirmation dialog was open.
      if (masterReferencedByLiveGroup(c.peerMasterPub)) {
        setError(
          t('Entferne den Kontakt zuerst aus allen Gruppen; erst danach kann seine neue Identität übernommen werden.'),
        );
        return null;
      }
      const changed = await acceptMasterChange(c); // sets new roomId + verified=false
      if (!changed) return null;
      // Commit the contact re-key BEFORE persisting the denylist entry (Review E):
      // a crash between the two leaves the milder, self-correcting state — the
      // contact is on the NEW master and the old master is not yet retired.
      await reKeyContactInMemory(changed.oldRoomId, c);
      retiredMastersRef.current = await addRetiredMaster(
        dek,
        changed.retiredMaster,
      );
      return changed;
    });
    if (!r) return;
    if (activeRoomRef.current === r.oldRoomId) setActiveRoom(r.newRoomId);
    setError('');
    bump();
  }

  // ── The door, our side ──────────────────────────────────────────────
  // We linked a device, so this contact still pins our old master and sending
  // is blocked. Reconnecting resets the session; the next message runs a fresh
  // X3DH under our current identity, which the peer then has to accept.
  async function reconnectStaleContact() {
    const roomId = activeRoom;
    const id = identityRef.current;
    if (!roomId || !id) return;
    const current = contactsRef.current.find((entry) => entry.roomId === roomId);
    if (current && revokedOfficialAccountFor(current)) {
      setError(
        t('Diese Identität darf nicht manuell ersetzt werden. Verbinde dich ausschließlich über SKYTALE-SUPPORT neu.'),
      );
      return;
    }
    const r = await enqueueInbox(async () => {
      const c = contactsRef.current.find((entry) => entry.roomId === roomId);
      if (!c) return null;
      if (revokedOfficialAccountFor(c)) {
        setError(
          t('Diese Identität darf nicht manuell ersetzt werden. Verbinde dich ausschließlich über SKYTALE-SUPPORT neu.'),
        );
        return null;
      }
      const changed = await reconnectContact(
        c,
        asMasterPub(id.master.publicKey),
      ); // sets new roomId
      await reKeyContactInMemory(changed.oldRoomId, c);
      return changed;
    });
    if (!r) return;
    if (activeRoomRef.current === r.oldRoomId) setActiveRoom(r.newRoomId);
    setError('');
    bump();
  }

  // Periodic safety net: re-offer my device list to peers still behind, and re-ask
  // for the account snapshot while this device is still waiting for one. Both are
  // no-ops once everyone is current. Paused while the tab is hidden — a background
  // tab should not spend battery on gossip nobody is waiting for.
  useEffect(() => {
    const t = window.setInterval(() => {
      if (document.hidden || runtimeSuspendedRef.current) return;
      void requestBootstrap();
      void schedulePendingGroupMutationRetry();
      for (const c of contactsRef.current) void ensureListGossiped(c);
    }, 60_000);
    return () => window.clearInterval(t);
    // Reads everything through refs, so it never goes stale.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Full-screen image viewer (avatars, later chat images). Tap anywhere closes.
  const lightbox = zoomImg ? <LightboxImg blob={zoomImg} onClose={() => setZoomImg(null)} /> : null;
  const viewOnceEl = viewOnce ? <ViewOnceViewer blob={viewOnce.blob} mime={viewOnce.mime} onClose={() => setViewOnce(null)} /> : null;
  const r2UploadEl =
    r2Upload !== null ? (
      <div className="r2-upload" role="status">
        <div className="r2-upload-row">
          <IconArchive />
          <span>{t('Video wird hochgeladen…')}</span>
          <span className="r2-upload-pct">{Math.round(r2Upload * 100)} %</span>
        </div>
        <div className="r2-upload-bar">
          <div className="r2-upload-fill" style={{ width: `${Math.round(r2Upload * 100)}%` }} />
        </div>
      </div>
    ) : null;
  const transcodeEl =
    transcoding !== null ? (
      <div className="r2-upload" role="status">
        <div className="r2-upload-row">
          <IconArchive />
          <span>{t('Video wird optimiert…')}</span>
          <span className="r2-upload-pct">{Math.round(transcoding * 100)} %</span>
        </div>
        <div className="r2-upload-bar">
          <div className="r2-upload-fill" style={{ width: `${Math.round(transcoding * 100)}%` }} />
        </div>
      </div>
    ) : null;
  const canVO = !!pendingMedia && pendingMedia.size <= CLIENT_MAX_BLOB; // any size: ≤2 MB self-destructs via mailbox, larger via R2
  const mediaPreviewEl = pendingMedia ? (
    <div className="crop-modal vo-preview" role="dialog" aria-label={t('Senden')}>
      <div className="crop-head">{pendingMedia.isVideo ? t('Video senden') : t('Foto senden')}</div>
      <div className="vo-preview-stage">
        {pendingMedia.isVideo ? (
          <video className="vo-preview-media" src={pendingMedia.url} controls playsInline />
        ) : (
          <img className="vo-preview-media" src={pendingMedia.url} alt="" />
        )}
      </div>
      <div className="vo-preview-foot">
        {/* View-once is only offered when the media fits the self-destruct path (≤ ~2 MB).
            A full-width "arm" pill — no checkbox — that fills with the accent + glows when
            armed; the bomb signals self-destruct. */}
        {canVO && (
          <button
            type="button"
            className={`vo-arm${pendingVO ? ' on' : ''}`}
            onClick={() => setPendingVO((v) => !v)}
            aria-pressed={pendingVO}
          >
            <IconBomb size={21} />
            <span>{t('Einmal ansehen')}</span>
          </button>
        )}
        {canVO && (
          <div className={`vo-armhint${pendingVO ? ' on' : ''}`}>
            {t('Zerstört sich nach dem einmaligen Ansehen selbst — für immer und unwiederbringlich vernichtet.')}
          </div>
        )}
        <div className="crop-actions">
          <button className="btn btn-outline" onClick={cancelPendingMedia}>
            {t('Abbrechen')}
          </button>
          <button
            className="btn btn-primary"
            onClick={() =>
              launchRuntimeOperation(() => confirmPendingMedia())
            }
          >
            {t('Senden')}
          </button>
        </div>
      </div>
    </div>
  ) : null;

  // Long-press action popover, floating next to the pressed message.
  const msgMenuEl = msgMenu
    ? (() => {
        const m = msgMenu.m;
        const isText = !!m.text && !m.file;
        const hasContent = !!(m.text || m.file);
        const rows = 1 + (isText ? 1 : 0) + (hasContent ? 1 : 0) + 1;
        const W = 210;
        const H = rows * 44 + 10;
        const vw = window.innerWidth;
        const vh = window.innerHeight;
        const left = Math.min(Math.max(8, msgMenu.x - W / 2), vw - W - 8);
        const top = msgMenu.y + 8 + H < vh ? msgMenu.y + 8 : Math.max(8, msgMenu.y - H - 8);
        const close = () => setMsgMenu(null);
        return (
          <div className="msg-scrim" onClick={close} onContextMenu={(e) => e.preventDefault()}>
            <div className="msg-pop" style={{ left, top, width: W }} onClick={(e) => e.stopPropagation()}>
              <button className="msg-pop-row" onClick={() => { setReplyTo(quoteFrom(m)); close(); }}>
                <IconReply />
                <span>{t('Antworten')}</span>
              </button>
              {isText && (
                <button
                  className="msg-pop-row"
                  onClick={() => {
                    void navigator.clipboard?.writeText(m.text ?? '');
                    close();
                  }}
                >
                  <IconCopy />
                  <span>{t('Kopieren')}</span>
                </button>
              )}
              {hasContent && (
                <button className="msg-pop-row" onClick={() => { setForwardMsg(m); close(); }}>
                  <IconForward />
                  <span>{t('Weiterleiten')}</span>
                </button>
              )}
              <button
                className="msg-pop-row danger"
                onClick={() => {
                  const mm = msgMenu;
                  close();
                  launchRuntimeOperation(() =>
                    deleteFromMenu(mm.roomId, mm.m),
                  );
                }}
              >
                <IconTrash />
                <span>{t('Löschen')}</span>
              </button>
            </div>
          </div>
        );
      })()
    : null;

  // Forward picker: choose a 1:1 contact (avatar/identicon + name) to forward to.
  const forwardEl = forwardMsg ? (
    <div className="sheet-scrim" onClick={() => setForwardMsg(null)}>
      <div className="fwd-sheet" onClick={(e) => e.stopPropagation()}>
        <div className="fwd-head">{t('Weiterleiten an')}</div>
        <div className="fwd-list">
          {contactsRef.current
            .filter((c) => !c.hidden && !c.staleIdentity)
            .map((c) => {
              const officialAdmin = !!trustedOfficialAccountFor(c);
              const revokedOfficialAdmin = !!revokedOfficialAccountFor(c);
              return (
                <button
                  key={c.roomId}
                  className="fwd-row"
                  disabled={revokedOfficialAdmin}
                  onClick={() =>
                    launchRuntimeOperation(() => forwardTo(c, forwardMsg))
                  }
                >
                  <div className="avatar-wrap">
                    {c.peerAvatarB64 ? (
                      <img className="avatar-img" src={avatarSrc(c.peerAvatarB64)} alt="" />
                    ) : (
                      <div className="avatar">
                        <Identicon seed={c.roomId} />
                      </div>
                    )}
                  </div>
                  <span className="fwd-name">{displayName(c)}</span>
                  {officialAdmin && <OfficialAdminBadge />}
                  {revokedOfficialAdmin && <RevokedOfficialAdminBadge />}
                </button>
              );
            })}
        </div>
      </div>
    </div>
  ) : null;

  // Tapping a sticker in a chat opens it large, with the option to keep it. The
  // action button must stop propagation — the backdrop closes on click.
  const stickerViewEl = stickerZoom ? (
    <div className="sticker-view" onClick={() => setStickerZoom(null)} role="dialog" aria-label={t('Sticker')}>
      <img src={`data:${stickerZoom.mime};base64,${stickerZoom.dataB64}`} alt={t('Sticker')} />
      {stickers.some((s) => s.dataB64 === stickerZoom.dataB64) ? (
        <p className="sticker-view-note">{t('Ist schon in deinen Stickern.')}</p>
      ) : (
        <button
          className="btn btn-primary"
          onClick={(e) => {
            e.stopPropagation();
            launchRuntimeOperation(() => addStickerToLibrary(stickerZoom));
          }}
        >
          {t('Zu meinen Stickern hinzufügen')}
        </button>
      )}
      <button className="lightbox-close" onClick={() => setStickerZoom(null)} aria-label={t('Schließen')}>
        ×
      </button>
    </div>
  ) : null;

  const closeLink = () => {
    // A confirmed recovery remains protected even when the overlay closes. This
    // keeps the rest of the app usable while P/relay is offline; Settings can
    // reopen the reconstructed SAS without discarding/ACKing protocol state.
    resetLink();
    setLinkView(null);
  };
  const linkRole = linkSessionRef.current?.role;
  const linkOverlay = linkView === 'scan' ? (
    // Standalone full-screen scanner — deliberately NOT inside .link-card. That
    // card runs a transform animation, and a transformed ancestor becomes the
    // containing block for the scanner's position:fixed (especially sticky on
    // iOS via the animation fill-mode), collapsing the camera to a thin strip.
    // Rendered bare, its position:fixed resolves against the viewport as meant.
    <QrScanner
      onResult={(text) => {
        if (linkBusy || linkSessionRef.current) return;
        launchRuntimeOperation(() => onScanNewDevice(text.trim()));
      }}
      onClose={closeLink}
    />
  ) : linkView ? (
    <div className="link-overlay" role="dialog" aria-label={t('Gerät koppeln')}>
      <div className="link-card">
        <button className="link-x" onClick={closeLink} aria-label={t('Schließen')}>
          ×
        </button>

        {linkView === 'menu' && (
          <>
            <div className="link-head">{t('Gerät koppeln')}</div>
            <p className="link-sub">{t('Welche Rolle hat dieses Gerät?')}</p>
            {primaryLinkDeliveryPending && (
              <div role="status">
                <p className="link-sub">
                  {t('Ein neues Gerät ist bereits dauerhaft autorisiert; nur die bestätigte Relay-Zustellung des Kopplungs-Nachweises steht noch aus. Starte keinen zweiten Versuch.')}
                </p>
                <button
                  className="btn btn-outline btn-tall"
                  disabled={linkBusy}
                  onClick={() =>
                    launchRuntimeOperation(() =>
                      retryPrimaryLinkGrantDeliveryNow(),
                    )
                  }
                >
                  {linkBusy ? t('Zustellung läuft…') : t('Ausstehende Zustellung erneut versuchen')}
                </button>
                <button
                  className="btn btn-danger btn-tall"
                  style={{ marginTop: 10 }}
                  disabled={linkBusy}
                  onClick={() =>
                    launchRuntimeOperation(() =>
                      cancelPrimaryPendingLinkGrant(),
                    )
                  }
                >
                  {t('Autorisierung abbrechen und widerrufen')}
                </button>
              </div>
            )}
            <button
              className="btn btn-primary btn-tall"
              disabled={primaryLinkDeliveryPending}
              onClick={() =>
                launchRuntimeOperation(() => startJoinAsNewDevice())
              }
            >
              {t('Dieses Gerät verbinden')}
              <span className="link-btn-note">{t('Zeigt einen QR-Code, den das Hauptgerät scannt')}</span>
            </button>
            <button
              className="btn btn-outline btn-tall"
              style={{ marginTop: 12 }}
              disabled={primaryLinkDeliveryPending}
              onClick={() => {
                const id = identityRef.current;
                if (id && !isPrimaryDevice(id)) {
                  setError(t('Dieses Gerät ist selbst gekoppelt — nur das Hauptgerät kann weitere hinzufügen.'));
                  return;
                }
                setLinkView('scan');
              }}
            >
              {t('Neues Gerät hinzufügen')}
              <span className="link-btn-note">{t('Scannt den QR-Code des neuen Geräts')}</span>
            </button>
          </>
        )}

        {linkView === 'qr' && (
          <>
            <div className="link-head">{t('Auf dem Hauptgerät scannen')}</div>
            <p className="link-sub">
              {tb('Öffne auf deinem Hauptgerät **Profil → Gerät koppeln → Neues Gerät hinzufügen** und scanne diesen Code.')}
            </p>
            <div className="link-qr">{linkQr ? <img src={linkQr} alt={t('Kopplungs-QR')} /> : <span className="ph">…</span>}</div>
            <p className="link-wait">
              <span className="rec-dot" /> {t('Warte auf das Hauptgerät…')}
            </p>
          </>
        )}


        {linkView === 'sas' && linkSas && (
          <>
            <div className="link-head">{t('Stimmen die Emojis überein?')}</div>
            <p className="link-sub">
              {tb('Vergleiche diese sieben Zeichen mit dem **anderen Gerät**. Nur wenn sie exakt gleich sind, ist die Verbindung frei von einem Angreifer in der Mitte.')}
            </p>
            <div className="sas-grid">
              {linkSas.emoji.map((e, i) => (
                <div key={i} className="sas-cell">
                  <span className="sas-emoji">{e.char}</span>
                  <span className="sas-name">{e.name}</span>
                </div>
              ))}
            </div>
            {linkBusy ? (
              <p className="link-wait">
                <span className="rec-dot" /> {t('Warte auf Bestätigung des Hauptgeräts…')}
              </p>
            ) : (
              <div className="link-actions">
                <button className="btn btn-danger" onClick={closeLink}>
                  {t('Stimmt nicht')}
                </button>
                <button
                  className="btn btn-primary"
                  onClick={() =>
                    launchRuntimeOperation(() =>
                      linkRole === 'primary'
                        ? onPConfirmSas()
                        : onNConfirmSas(),
                    )
                  }
                >
                  {t('Stimmt überein')}
                </button>
              </div>
            )}
            {linkRecoveryProtectedRef.current && linkConfirmedRef.current && linkRole === 'new' && (
              <div>
                <p className="link-sub">
                  {t('Diese bestätigte Recovery bleibt auch nach dem Schließen erhalten. Wenn das Hauptgerät nicht mehr erreichbar ist, kannst du sie nach einer zusätzlichen Warnung lokal endgültig verwerfen. Eine dort bereits erteilte Autorisierung musst du am Hauptgerät separat widerrufen.')}
                </p>
                <button
                  className="btn btn-danger btn-tall"
                  disabled={linkAbortBusy}
                  onClick={() =>
                    launchRuntimeOperation(() =>
                      discardConfirmedNewDeviceRecovery(),
                    )
                  }
                >
                  {linkAbortBusy
                    ? t('Recovery wird verworfen…')
                    : t('Kopplungs-Recovery endgültig verwerfen')}
                </button>
              </div>
            )}
          </>
        )}

        {linkView === 'done' && (
          <>
            <div className="link-done-icon">
              <IconShield size={30} filled />
            </div>
            <div className="link-head">{t('Gerät gekoppelt')}</div>
            <p className="link-sub">
              {linkRole === 'primary'
                ? t('Das neue Gerät gehört jetzt zu deiner Identität. Es holt sich gleich dein Profil und deine Kontaktliste.')
                : t('Dieses Gerät nutzt jetzt deine bestehende Identität. Profil und Kontakte werden gerade von deinem Hauptgerät übertragen — das kann einen Moment dauern. Bestehende Kontakte müssen die neue Identität bestätigen; schreibe ihnen, um das auszulösen.')}
            </p>
            <button className="btn btn-primary btn-tall" onClick={() => setLinkView(null)}>
              {t('Fertig')}
            </button>
          </>
        )}
      </div>
    </div>
  ) : null;

  const contacts = contactsRef.current;
  const visibleContacts = contacts.filter((c) => !c.hidden);
  const groups = groupsRef.current;
  const activeContact = contacts.find((c) => c.roomId === activeRoom) ?? null;
  const activeGroupData = groups.find((g) => g.id === activeGroup) ?? null;
  const st = (roomId: string) => statuses[roomId] ?? 'closed';
  const lastPreview = (m?: ChatMessage) =>
    m
      ? m.text ||
        (m.file
          ? isSticker(m.file)
            ? 'Sticker'
            : m.file.mime.startsWith('video/')
              ? '🎬 Video'
              : m.file.mime.startsWith('image/')
                ? '📷 Bild'
                : m.file.mime.startsWith('audio/')
                  ? '🎤 Sprachnachricht'
                  : '📎 Anhang'
          : '')
      : '';

  // The sticker cropper is rendered next to the panel, not in the profile view:
  // the picker is reachable only from a chat, so the modal must live there too.
  const stickerCropEl = stickerFile ? (
    <CropModal
      file={stickerFile}
      shape="square"
      onCancel={() => setStickerFile(null)}
      onDone={(b, mime) =>
        launchRuntimeOperation(() => onStickerCropped(b, mime))
      }
    />
  ) : null;

  const stickerPanelEl = stickerPanel ? (
    <div className="sticker-panel">
      {stickers.length === 0 && (
        <p className="sticker-empty">
          {t('Noch keine Sticker. Mach aus einem Bild einen — er bleibt verschlüsselt auf deinem Gerät.')}
        </p>
      )}
      <div className="sticker-grid">
        {stickers.map((st) => (
          <div key={st.id} className="sticker-cell">
            <button
              className="sticker-btn"
              onClick={() =>
                launchRuntimeOperation(() => sendSticker(st))
              }
              aria-label={t('Sticker senden')}
            >
              <img src={`data:${st.mime};base64,${st.dataB64}`} alt="" />
            </button>
            <button
              className="sticker-del"
              aria-label={t('Sticker löschen')}
              onClick={() =>
                launchRuntimeOperation(() => deleteSticker(st.id))
              }
            >
              ×
            </button>
          </div>
        ))}
        <button
          className="sticker-add"
          onClick={() => stickerInputRef.current?.click()}
          aria-label={t('Sticker hinzufügen')}
        >
          +
        </button>
      </div>
    </div>
  ) : null;

  const composerEl = recording ? (
    <div className="composer recording">
      <button className="attach-btn danger" onClick={cancelRecording} aria-label={t('Abbrechen')}>
        <IconTrash />
      </button>
      <div className="rec-indicator">
        <span className="rec-dot" />
        {t('Aufnahme…')} {fmtRec(recSeconds)}
      </div>
      <button className="send-btn" onClick={stopAndSend} aria-label={t('Senden')}>
        <IconSend />
      </button>
    </div>
  ) : (
    <div className="composer">
      {replyTo && (
        <div className="reply-bar">
          <div className="reply-bar-tx">
            <span className="reply-bar-who">{replyTo.mine ? t('Antwort an dich') : t('Antwort')}</span>
            <span className="reply-bar-text">{replyTo.text || '📎 Anhang'}</span>
          </div>
          <button className="reply-bar-x" onClick={() => setReplyTo(null)} aria-label={t('Antwort verwerfen')}>
            ×
          </button>
        </div>
      )}
      <input
        ref={fileInputRef}
        type="file"
        hidden
        onChange={(e) =>
          launchRuntimeOperation(() => onPickFile(e))
        }
      />
      <input
        ref={stickerInputRef}
        type="file"
        accept="image/*"
        hidden
        onChange={(e) => {
          const f = e.target.files?.[0];
          e.target.value = '';
          if (f) setStickerFile(f);
        }}
      />
      <button className="attach-btn" title={t('Anhang')} onClick={() => fileInputRef.current?.click()}>
        <IconAttach />
      </button>
      <button
        className={`attach-btn${stickerPanel ? ' active' : ''}`}
        title={t('Sticker')}
        aria-expanded={stickerPanel}
        onClick={() => setStickerPanel((v) => !v)}
      >
        <IconSticker />
      </button>
      <div className="composer-pill">
        <textarea
          ref={msgInputRef}
          rows={1}
          defaultValue=""
          placeholder={t('Verschlüsselte Nachricht…')}
          onInput={(e) => {
            const el = e.currentTarget;
            setHasText(el.value.trim().length > 0);
            autoGrowComposer(el);
          }}
          onKeyDown={(e) => {
            // Desktop: Enter sends, Shift+Enter is a newline. On a touch keyboard
            // Enter always inserts a newline so a message can span multiple lines;
            // sending is the button.
            if (
              e.key === 'Enter' &&
              !e.shiftKey &&
              window.matchMedia('(pointer: fine)').matches
            ) {
              e.preventDefault();
              launchRuntimeOperation(() => onSend());
            }
          }}
        />
      </div>
      {hasText ? (
        <button
          className="send-btn"
          onClick={() => launchRuntimeOperation(() => onSend())}
          aria-label={t('Senden')}
        >
          <IconSend />
        </button>
      ) : (
        <button
          className="send-btn mic"
          onClick={() =>
            launchRuntimeOperation((signal) => startRecording(signal))
          }
          aria-label={t('Sprachnachricht')}
        >
          <IconMic />
        </button>
      )}
    </div>
  );

  // WhatsApp-style: groups and contacts in one list, most recent activity on
  // top. Chats without messages (ts 0) sink to the bottom until they get one.
  // The list is rendered once and becomes the persistent master pane on laptops.
  const query = conversationQuery.trim().toLocaleLowerCase();
  const convItems = [
    ...groups.map((g) => {
      const last = messagesRef.current[g.id]?.at(-1);
      return { kind: 'group' as const, group: g, last, unread: unreadRef.current[g.id] ?? 0, ts: last?.ts ?? 0 };
    }),
    ...visibleContacts.map((c) => {
      const last = messagesRef.current[c.roomId]?.at(-1);
      return { kind: 'contact' as const, contact: c, last, unread: unreadRef.current[c.roomId] ?? 0, ts: last?.ts ?? 0 };
    }),
  ]
    .filter((item) => {
      if (!query) return true;
      const name =
        item.kind === 'group'
          ? item.group.name
          : officialAccountNameLocked(item.contact)
            ? `${displayName(item.contact)} ${OFFICIAL_ACCOUNT_ALIAS}`
            : `${displayName(item.contact)} ${item.contact.peerName ?? ''}`;
      const preview = item.last ? lastPreview(item.last) : '';
      return `${name} ${preview}`.toLocaleLowerCase().includes(query);
    })
    .sort((a, b) => b.ts - a.ts);
  const conversationContextOpen =
    view === 'chat' || view === 'contact' || view === 'verify' || view === 'gmanage';

  const conversationListEl = (
    <div className="list">
      <div className="list-top">
        <div className="list-head">
          <button
            className="list-brand"
            onClick={() => setView('profile')}
            title={t('Profil')}
            aria-label={t('Profil öffnen')}
          >
            {myAvatarB64 ? (
              <img className="brand-avatar" src={avatarSrc(myAvatarB64)} alt="" />
            ) : (
              <img src="/scytale-icon.svg" alt="" />
            )}
            <div className="brand-txt">
              <div className="t">
                <span className="brand-name">{myName.trim() || t('Dein Profil')}</span>
                <span className="ver">v{__APP_VERSION__}</span>
              </div>
              <div className="fp">{shortFp(fingerprint)}</div>
            </div>
          </button>
          <div className="icon-btns">
            <button
              className="icon-btn"
              title={t('Neue Gruppe')}
              aria-label={t('Neue Gruppe')}
              onClick={() => {
                setError('');
                setGroupSel(new Set());
                setGroupNameInput('');
                setView('newgroup');
              }}
            >
              <IconGroup />
            </button>
            <button
              className="icon-btn"
              title={t('Teilen / Kontakt')}
              aria-label={t('Teilen / Kontakt')}
              onClick={() => {
                setError('');
                setView('add');
              }}
            >
              <IconPlus />
            </button>
            <button
              className="icon-btn"
              title={t('Sperren')}
              aria-label={t('Sperren')}
              onClick={onLock}
            >
              <IconLock size={15} />
            </button>
          </div>
        </div>
        <label className="search-bar">
          <span className="g" aria-hidden="true">
            <IconSearch />
          </span>
          <input
            type="search"
            value={conversationQuery}
            onChange={(event) => setConversationQuery(event.target.value)}
            placeholder={t('Chats durchsuchen')}
            aria-label={t('Chats durchsuchen')}
          />
        </label>
      </div>

      <div className="enc-line">
        <IconShield size={13} />
        {t('Alle Nachrichten Ende-zu-Ende verschlüsselt')}
      </div>

      <div className="conv-scroll">
        {groups.length === 0 && visibleContacts.length === 0 ? (
          <div className="list-empty">
            {t('Noch keine Chats.')}<br />{tb('Oben: **+** für Kontakte, das Gruppen-Symbol für eine Gruppe.')}
          </div>
        ) : convItems.length === 0 ? (
          <div className="list-empty">{t('Keine passenden Chats gefunden.')}</div>
        ) : (
          convItems.map((item) => {
            if (item.kind === 'group') {
              const selected = conversationContextOpen && activeGroup === item.group.id;
              return (
                <button
                  key={item.group.id}
                  className={`conv-row${selected ? ' active' : ''}`}
                  aria-current={selected ? 'page' : undefined}
                  onClick={() => openGroup(item.group.id)}
                >
                  <div className="avatar-wrap">
                    <div className="avatar group">
                      <IconGroup size={22} />
                    </div>
                  </div>
                  <div className="conv-main">
                    <div className="conv-line1">
                      <span className="conv-name">{item.group.name}</span>
                      <span className="conv-ts">{fmtListTs(item.last?.ts)}</span>
                    </div>
                    <div className="conv-line2">
                      <span className="conv-last">
                        {item.last
                          ? (item.last.mine ? '' : item.last.sender ? `${item.last.sender}: ` : '') +
                            lastPreview(item.last)
                          : `${item.group.members.length + 1} Mitglieder`}
                      </span>
                      {item.unread > 0 && <span className="unread">{item.unread}</span>}
                    </div>
                  </div>
                </button>
              );
            }
            const selected = conversationContextOpen && activeRoom === item.contact.roomId;
            const officialAdmin = !!trustedOfficialAccountFor(item.contact);
            const revokedOfficialAdmin = !!revokedOfficialAccountFor(item.contact);
            return (
              <button
                key={item.contact.roomId}
                className={`conv-row${selected ? ' active' : ''}`}
                aria-current={selected ? 'page' : undefined}
                onClick={() => openChat(item.contact.roomId)}
              >
                <div className="avatar-wrap">
                  {item.contact.peerAvatarB64 ? (
                    <img className="avatar-img" src={avatarSrc(item.contact.peerAvatarB64)} alt="" />
                  ) : (
                    <div className="avatar">
                      <Identicon seed={item.contact.roomId} />
                    </div>
                  )}
                  <span className={`sdot ${st(item.contact.roomId)}`} />
                </div>
                <div className="conv-main">
                  <div className="conv-line1">
                    <span className="conv-name">{displayName(item.contact)}</span>
                    {officialAdmin && <OfficialAdminBadge />}
                    {revokedOfficialAdmin && <RevokedOfficialAdminBadge />}
                    {item.contact.verified && !revokedOfficialAdmin && (
                      <span
                        className="verified-badge"
                        aria-label={t('Safety Number manuell verifiziert')}
                        title={t('Safety Number manuell verifiziert')}
                      >
                        <IconShield size={14} filled />
                      </span>
                    )}
                    <span className="conv-ts">{fmtListTs(item.last?.ts)}</span>
                  </div>
                  <div className="conv-line2">
                    <span className="conv-last">
                      {item.last ? lastPreview(item.last) : hasSession(item.contact) ? t('Verbunden') : t('Neu — sag Hallo')}
                    </span>
                    {item.unread > 0 && <span className="unread">{item.unread}</span>}
                  </div>
                </div>
              </button>
            );
          })
        )}
      </div>
    </div>
  );

  const renderMessengerShell = (detail: ReactNode | null) => (
    <div className={`messenger-shell${detail === null ? ' list-view' : ''}`}>
      <aside className="messenger-sidebar" aria-label={t('Chats')}>
        {conversationListEl}
      </aside>
      <main className="messenger-pane">
        {detail ?? (
          <div className="desktop-empty">
            <img src="/scytale-icon.svg" alt="" />
            <div className="desktop-empty-brand">SKYTALE</div>
            <p>{t('Wähle links einen Chat aus.')}</p>
            <span>
              <IconShield size={13} />
              {t('Alle Nachrichten Ende-zu-Ende verschlüsselt')}
            </span>
          </div>
        )}
      </main>
      {/* Rendered at shell level, not inside any single view: startBugReport opens the
          SKYTALE-SUPPORT chat, so the dialog must survive that navigation and show over
          whichever view is current (chat after opening, or settings if it hasn't yet). */}
      {bugOpen && <BugReport onClose={() => setBugOpen(false)} onSubmit={submitBugReport} />}
    </div>
  );

  // ── Contact list ──────────────────────────────────────────────────
  if (view === 'list') return renderMessengerShell(null);

  // ── Chat ──────────────────────────────────────────────────────────
  if (view === 'chat' && activeContact) {
    const msgs = messages[activeContact.roomId] ?? [];
    const start = Math.max(0, msgs.length - windowN);
    const shown = start > 0 ? msgs.slice(start) : msgs;
    const verified = !!activeContact.verified;
    const officialAdmin = !!trustedOfficialAccountFor(activeContact);
    const revokedOfficialAdmin = !!revokedOfficialAccountFor(activeContact);
    return renderMessengerShell(
      <div
        className="chat"
        onPointerDown={onSwipeDown}
        onPointerMove={onSwipeMove}
        onPointerUp={onSwipeUp}
        onPointerCancel={onSwipeUp}
        style={{
          transform: swipeDx ? `translateX(${swipeDx}px)` : undefined,
          transition: swiping ? 'none' : 'transform 0.22s ease',
        }}
      >
        <div className="chat-top">
          <button className="chat-back" onClick={() => setView('list')} aria-label={t('Zurück')}>
            <IconBack />
          </button>
          <button className="chat-avatar-btn" onClick={openContact} aria-label="Kontaktinfo">
            {activeContact.peerAvatarB64 ? (
              <img className="avatar-img sm" src={avatarSrc(activeContact.peerAvatarB64)} alt="" />
            ) : (
              <div className="avatar sm">
                <Identicon seed={activeContact.roomId} />
              </div>
            )}
          </button>
          {renaming && !officialAdmin && !revokedOfficialAdmin ? (
            <div className="rename-row">
              <input
                autoFocus
                value={renameInput}
                placeholder={t('Name für diesen Kontakt…')}
                onChange={(e) => setRenameInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    launchRuntimeOperation(() => saveNickname());
                  }
                }}
              />
              <button
                className="btn btn-primary"
                onClick={() =>
                  launchRuntimeOperation(() => saveNickname())
                }
              >
                ✓
              </button>
            </div>
          ) : (
            <div className="chat-peer">
              {officialAdmin || revokedOfficialAdmin ? (
                <div className="n static">{displayName(activeContact)}</div>
              ) : (
                <button className="n" onClick={startRename} title={t('Umbenennen')}>
                  {displayName(activeContact)} <span className="pencil">✎</span>
                </button>
              )}
              <div className="chat-trust-row">
                {officialAdmin && <OfficialAdminBadge />}
                {revokedOfficialAdmin && <RevokedOfficialAdminBadge />}
                {!revokedOfficialAdmin && (
                  <button
                    className="verify-line"
                    style={{ color: verified ? 'var(--verified)' : 'var(--muted)' }}
                    onClick={() =>
                      launchRuntimeOperation(() => openVerify())
                    }
                  >
                    <IconLock size={10} />
                    {verified ? t('verifiziert') : t('nicht verifiziert · antippen')}
                  </button>
                )}
              </div>
            </div>
          )}
          {!revokedOfficialAdmin && (
            <span className={`sdot ${st(activeContact.roomId)}`} style={{ position: 'static', border: 0, width: 9, height: 9 }} />
          )}
          <button className="chat-menu-btn" onClick={() => setChatMenu((v) => !v)} aria-label={t('Menü')}>
            <IconDots />
          </button>
          {chatMenu && (
            <div className="chat-menu">
              <button
                onClick={() => {
                  setChatMenu(false);
                  if (confirm(t('Chatverlauf wirklich löschen?'))) {
                    launchRuntimeOperation(() =>
                      clearChatAction(activeContact.roomId),
                    );
                  }
                }}
              >
                {t('Chatverlauf löschen')}
              </button>
              <button
                className="danger"
                onClick={() => {
                  setChatMenu(false);
                  if (confirm(t('Kontakt und Chat wirklich löschen?'))) {
                    launchRuntimeOperation(() =>
                      deleteContactAction(activeContact.roomId),
                    );
                  }
                }}
              >
                {t('Kontakt löschen')}
              </button>
            </div>
          )}
        </div>

        {revokedOfficialAdmin && (
          <OfficialAccountRevokedWarning
            onRecover={() =>
              launchRuntimeOperation((signal) =>
                addBundle(OFFICIAL_ACCOUNT_ALIAS, signal),
              )
            }
          />
        )}

        <div id="msgs" className="msgs">
          <div className="msgs-inner">
          <div className="enc-pill">
            <span className="g">
              <IconLock size={10} />
            </span>
            {t('Verschlüsselt · nur ihr beide lest mit')}
          </div>
          {shown.map((m, i) => (
            <div
              key={m.mid ?? `${m.ts}-${start + i}`}
              data-mid={m.mid}
              className={`bubble ${m.mine ? 'mine' : 'theirs'}${m.file && isSticker(m.file) ? ' is-sticker' : m.file && (m.file.mime.startsWith('image/') || m.file.mime.startsWith('video/')) ? ' has-file' : ''}${(() => { const e = !m.file && !m.recalled ? bigEmojiLevel(m.text) : 0; return e ? ` emoji-${e}${m.reply ? '' : ' emoji-big'}` : ''; })()}`}
              onPointerDown={(e) => onBubblePointerDown(e, m)}
              onPointerMove={onBubblePointerMove}
              onPointerUp={() => endBubbleSwipe(m)}
              onPointerCancel={() => endBubbleSwipe(m)}
              onContextMenu={(e) => {
                e.preventDefault();
                if (m.mid && !m.recalled) openMsgMenu(m, e.clientX, e.clientY);
              }}
            >
              {m.recalled ? (
                <span className="recalled">{t('Nachricht zurückgerufen')}</span>
              ) : (
                <>
                  {m.reply && (
                    <div
                      className="bubble-quote"
                      role="button"
                      title="Zur Nachricht springen"
                      onClick={() => scrollToQuoted(m.reply?.mid)}
                    >
                      {(m.reply.mine || m.reply.sender) && <span className="bq-who">{m.reply.mine ? 'Du' : m.reply.sender}</span>}
                      <span className="bq-text">{m.reply.text || '📎 Anhang'}</span>
                    </div>
                  )}
                  {m.file ? (
                    m.file.r2 && !m.file.attId ? (
                      <button
                        className="pull-chip"
                        disabled={!!(m.mid && downloadingRef.current.has(m.mid))}
                        onClick={() =>
                          launchRuntimeOperation(() =>
                            downloadR2Message(activeContact?.roomId ?? '', m),
                          )
                        }
                      >
                        <IconArchive />
                        <span className="pull-name">{m.file.name || (m.file.mime.startsWith('video/') ? t('Video') : t('Datei'))}</span>
                        <span className="pull-size">
                          {m.mid && downloadingRef.current.has(m.mid)
                            ? `${pullProgressRef.current.get(m.mid) ?? 0} %`
                            : `${Math.round(((m.file.size ?? 0) / (1024 * 1024)) * 10) / 10} MB · ${t('laden')}`}
                        </span>
                      </button>
                    ) : m.file.viewOnce ? (
                      m.voSeen || !m.file.attId ? (
                        <span className="vo-seen">
                          <IconBomb size={14} /> {t('Foto angesehen')}
                        </span>
                      ) : (
                        <button
                          className="vo-open"
                          onClick={() =>
                            launchRuntimeOperation(() =>
                              openViewOnce(activeContact?.roomId ?? '', m),
                            )
                          }
                        >
                          <IconBomb size={16} />
                          <span className="vo-open-tx">
                            <span className="vo-open-title">{t('Einmal ansehen')}</span>
                            <span className="vo-open-sub">{t('Löscht sich nach dem Öffnen')}</span>
                          </span>
                        </button>
                      )
                    ) : m.file.pull ? (
                      <button
                        className="pull-chip"
                        disabled={!!(m.file.attId && downloadingRef.current.has(m.file.attId))}
                        onClick={() =>
                          launchRuntimeOperation(() =>
                            pullAttachment(activeContact?.roomId ?? '', m),
                          )
                        }
                      >
                        <IconArchive />
                        <span className="pull-name">{m.file.name}</span>
                        <span className="pull-size">
                          {m.file.attId && downloadingRef.current.has(m.file.attId)
                            ? `${pullProgressRef.current.get(m.file.attId) ?? 0} %`
                            : `${(Math.round(((m.file.size ?? 0) / (1024 * 1024)) * 10) / 10)} MB · ${t('laden')}`}
                        </span>
                      </button>
                    ) : (
                      <Attachment
                        dek={dek}
                        file={m.file}
                        onImageZoom={(b) => setZoomImg(b)}
                        onStickerZoom={(f) => setStickerZoom({ mime: f.mime, dataB64: f.dataB64 ?? '' })}
                      />
                    )
                  ) : (
                    m.text
                  )}
                </>
              )}
              <span className="meta">
                {fmtClock(m.ts)}
                {m.mine && msgStatusEl(m)}
              </span>
            </div>
          ))}
          </div>
        </div>

        {error && <div className="err-note">{error}</div>}

        {stickerCropEl}
        {stickerPanelEl}
        {!revokedOfficialAdmin && composerEl}
        {msgMenuEl}
        {forwardEl}
        {lightbox}
        {viewOnceEl}
        {mediaPreviewEl}
        {r2UploadEl}
        {transcodeEl}
        {stickerViewEl}
      </div>
    );
  }

  // ── Group chat ────────────────────────────────────────────────────
  if (view === 'chat' && activeGroupData) {
    const msgs = messages[activeGroupData.id] ?? [];
    const start = Math.max(0, msgs.length - windowN);
    const shown = start > 0 ? msgs.slice(start) : msgs;
    const revokedOfficialMember = groupHasRevokedOfficialMember(activeGroupData);
    return renderMessengerShell(
      <div
        className="chat"
        onPointerDown={onSwipeDown}
        onPointerMove={onSwipeMove}
        onPointerUp={onSwipeUp}
        onPointerCancel={onSwipeUp}
        style={{
          transform: swipeDx ? `translateX(${swipeDx}px)` : undefined,
          transition: swiping ? 'none' : 'transform 0.22s ease',
        }}
      >
        <div className="chat-top">
          <button
            className="chat-back"
            onClick={() => {
              setActiveGroup(null);
              setView('list');
            }}
            aria-label={t('Zurück')}
          >
            <IconBack />
          </button>
          <div className="avatar sm group">
            <IconGroup size={18} />
          </div>
          <div className="chat-peer">
            <div className="n">{activeGroupData.name}</div>
            <span className="peer-fp">{t('{n} Mitglieder', { n: activeGroupData.members.length + 1 })}</span>
          </div>
          <button className="chat-menu-btn" onClick={() => setChatMenu((v) => !v)} aria-label={t('Menü')}>
            <IconDots />
          </button>
          {chatMenu && (
            <div className="chat-menu">
              <button onClick={() => openManage(activeGroupData)}>{t('Gruppe verwalten')}</button>
              <button
                onClick={() => {
                  setChatMenu(false);
                  if (confirm(t('Chatverlauf wirklich löschen?'))) {
                    launchRuntimeOperation(() =>
                      clearChatAction(activeGroupData.id),
                    );
                  }
                }}
              >
                {t('Chatverlauf löschen')}
              </button>
              <button
                className="danger"
                onClick={() => {
                  setChatMenu(false);
                  if (confirm(t('Gruppe wirklich verlassen?'))) {
                    launchRuntimeOperation(() =>
                      leaveGroup(activeGroupData),
                    );
                  }
                }}
              >
                {t('Gruppe verlassen')}
              </button>
            </div>
          )}
        </div>
        {revokedOfficialMember && (
          <OfficialAccountRevokedWarning
            group
            onRecover={() =>
              launchRuntimeOperation((signal) =>
                addBundle(OFFICIAL_ACCOUNT_ALIAS, signal),
              )
            }
          />
        )}
        <div id="msgs" className="msgs">
          <div className="msgs-inner">
          <div className="enc-pill">
            <span className="g">
              <IconLock size={10} />
            </span>
            {t('Verschlüsselt · Ende-zu-Ende')}
          </div>
          {shown.map((m, i) => (
            <div
              key={m.mid ?? `${m.ts}-${start + i}`}
              data-mid={m.mid}
              className={`bubble ${m.mine ? 'mine' : 'theirs'}${m.file && isSticker(m.file) ? ' is-sticker' : m.file && (m.file.mime.startsWith('image/') || m.file.mime.startsWith('video/')) ? ' has-file' : ''}${(() => { const e = !m.file && !m.recalled ? bigEmojiLevel(m.text) : 0; return e ? ` emoji-${e}${m.reply ? '' : ' emoji-big'}` : ''; })()}`}
              onPointerDown={(e) => onBubblePointerDown(e, m)}
              onPointerMove={onBubblePointerMove}
              onPointerUp={() => endBubbleSwipe(m)}
              onPointerCancel={() => endBubbleSwipe(m)}
              onContextMenu={(e) => {
                e.preventDefault();
                if (m.mid && !m.recalled) openMsgMenu(m, e.clientX, e.clientY);
              }}
            >
              {!m.mine && m.sender && <div className="bubble-sender">{m.sender}</div>}
              {m.recalled ? (
                <span className="recalled">{t('Nachricht zurückgerufen')}</span>
              ) : (
                <>
                  {m.reply && (
                    <div
                      className="bubble-quote"
                      role="button"
                      title="Zur Nachricht springen"
                      onClick={() => scrollToQuoted(m.reply?.mid)}
                    >
                      {(m.reply.mine || m.reply.sender) && <span className="bq-who">{m.reply.mine ? 'Du' : m.reply.sender}</span>}
                      <span className="bq-text">{m.reply.text || '📎 Anhang'}</span>
                    </div>
                  )}
                  {m.file ? (
                    <Attachment
                      dek={dek}
                      file={m.file}
                      onImageZoom={(b) => setZoomImg(b)}
                      onStickerZoom={(f) => setStickerZoom({ mime: f.mime, dataB64: f.dataB64 ?? '' })}
                    />
                  ) : (
                    m.text
                  )}
                </>
              )}
              <span className="meta">
                {fmtClock(m.ts)}
                {m.mine && msgStatusEl(m)}
              </span>
            </div>
          ))}
          </div>
        </div>
        {error && <div className="err-note">{error}</div>}
        {stickerCropEl}
        {stickerPanelEl}
        {!revokedOfficialMember && composerEl}
        {msgMenuEl}
        {forwardEl}
      </div>
    );
  }

  // ── Share / Add ───────────────────────────────────────────────────
  if (view === 'add') {
    const contactCodeReady = contactCodeStatus === 'ready' && !!contactCode;
    const contactCodeLabel =
      contactCodeStatus === 'publishing' || contactCodeStatus === 'idle'
        ? t('Kurzcode wird erstellt…')
        : contactCodeStatus === 'failed'
          ? t('Kurzcode momentan nicht verfügbar — QR-Code funktioniert weiterhin.')
          : contactCode;
    const contactCodeExpiry =
      contactCodeReady && contactCodeExpiresAt > 0
        ? t('Gültig bis {date}', {
            date: new Intl.DateTimeFormat(getLang(), {
              dateStyle: 'medium',
              timeStyle: 'short',
            }).format(contactCodeExpiresAt),
          })
        : '';
    return renderMessengerShell(
      <div className="subview">
        <div className="subhead">
          <button className="back" onClick={() => setView('list')} aria-label={t('Zurück')}>
            <IconBack />
          </button>
          <div className="h">{t('Verbinden')}</div>
        </div>
        <div className="subbody">
          <div className="sect-lbl">{t('Mich teilen')}</div>
          <div className="card share-card">
            <button
              className="qr-card tappable"
              onClick={() => qrDataUrl && setQrFull(true)}
              aria-label={t('QR-Code groß anzeigen')}
            >
              {qrDataUrl ? <img src={qrDataUrl} alt={t('QR-Code deines Kontakt-Links')} /> : <span className="ph">QR…</span>}
            </button>
            <p className="share-hint">
              {tb('**Persönlich:** Code antippen für Vollbild, der andere scannt ihn.')}
              <br />
              {tb('**Aus der Ferne:** kurzen Code teilen — er öffnet keinen Browser.')}
            </p>
            <div
              className={`link-box contact-code-box${contactCodeReady ? ' ready' : ''}`}
              aria-live="polite"
            >
              {contactCodeLabel}
            </div>
            <div className="contact-code-expiry" aria-hidden={!contactCodeExpiry}>
              {contactCodeExpiry || '\u00a0'}
            </div>
            <div className="share-actions">
              <button
                className="btn btn-primary"
                disabled={contactCodeStatus === 'publishing' || contactCodeStatus === 'idle'}
                onClick={() => {
                  if (contactCodeStatus === 'failed') {
                    launchRuntimeOperation((signal) => ensureContactInvite(signal));
                  } else {
                    void shareContactCode();
                  }
                }}
              >
                {contactCodeStatus === 'failed'
                  ? t('Erneut versuchen')
                  : contactCodeStatus === 'publishing' || contactCodeStatus === 'idle'
                    ? t('Wird erstellt…')
                    : shared
                      ? t('Kopiert ✓')
                      : t('Code teilen')}
              </button>
              <button
                className="btn btn-outline"
                disabled={!contactCodeReady}
                onClick={() => void copyContactCode()}
              >
                {copied ? t('Kopiert ✓') : t('Kopieren')}
              </button>
            </div>
          </div>

          <div className="divider">
            <div className="l" />
            <span>{t('ODER')}</span>
            <div className="l" />
          </div>

          <div className="sect-lbl">{t('Kontakt hinzufügen')}</div>
          <div className="card pad16">
            <button
              className="btn btn-primary"
              onClick={() =>
                launchRuntimeOperation((signal) => pasteAndAdd(signal))
              }
            >
              {t('Aus Zwischenablage verbinden')}
            </button>
            <button className="btn btn-outline scan-btn" style={{ marginTop: 10 }} onClick={() => setScanning(true)}>
              <IconCamera /> {t('QR-Code scannen')}
            </button>
            <div className="or-tiny">{t('oder Code / Alias / Link manuell einfügen')}</div>
            <textarea
              className="paste-box"
              placeholder={t('Kontaktcode, Alias, Link oder Bundle-Token einfügen')}
              value={addInput}
              maxLength={MAX_CONTACT_INPUT_CHARS}
              onChange={(e) => setAddInput(e.target.value)}
            />
            <button
              className="btn btn-ghost"
              onClick={() =>
                launchRuntimeOperation((signal) => addBundle(addInput, signal))
              }
            >
              {t('Hinzufügen')}
            </button>
          </div>

          {error && <div className="err-note">{error}</div>}

          {scanning && (
            <QrScanner
              onResult={(text) => {
                setScanning(false);
                launchRuntimeOperation((signal) => addBundle(text, signal));
              }}
              onClose={() => setScanning(false)}
            />
          )}

          {qrFull && qrDataUrl && (
            <div className="qr-full" onClick={() => setQrFull(false)} role="dialog" aria-label={t('QR-Code Vollbild')}>
              <img src={qrDataUrl} alt={t('QR-Code deines Kontakt-Links')} />
              <p>{t('Halte den Code vor die Kamera des Kontakts · tippen zum Schließen')}</p>
            </div>
          )}

          <div className="info-note">
            <span className="g">
              <IconInfo />
            </span>
            <p>
              {tb('Enthält **nur öffentliche Schlüssel**. Über jeden Kanal teilbar — gegen MITM danach die Safety Number vergleichen.')}
            </p>
          </div>
        </div>
      </div>
    );
  }

  // ── Verify / Safety Number ────────────────────────────────────────
  if (view === 'verify' && activeContact) {
    const verified = !!activeContact.verified;
    const groups = safetyNumber ? safetyNumber.split(' ') : [];
    return renderMessengerShell(
      <div className="subview">
        <div className="subhead">
          <button className="back" onClick={() => setView('chat')} aria-label={t('Zurück')}>
            <IconBack />
          </button>
          <div className="h">{t('Safety Number')}</div>
        </div>
        <div className="verify-body">
          <div className="qr-card sm">
            {safetyQr ? <img src={safetyQr} alt={t('Safety-Number-QR')} /> : <span className="ph">…</span>}
          </div>
          <p className="verify-expl">
            {tb('Vergleicht diese Zahl mit **{name}** — persönlich oder über einen anderen Kanal.', { name: displayName(activeContact) })}
          </p>
          <div className="sn-grid">
            {groups.map((g, i) => (
              <span key={i}>{g}</span>
            ))}
          </div>
          {verified ? (
            <div className="verified-banner">
              <IconShield size={17} />
              {t('Als verifiziert markiert')}
            </div>
          ) : (
            <button
              className="btn btn-primary"
              style={{ height: 50 }}
              onClick={() =>
                launchRuntimeOperation(() => markVerified())
              }
            >
              {t('Als verifiziert markieren')}
            </button>
          )}
          <p className="verify-foot">{t('Stimmen die Zahlen überein, ist die Leitung frei von Man-in-the-Middle.')}</p>
        </div>
      </div>
    );
  }

  // ── Contact detail ────────────────────────────────────────────────
  if (view === 'contact' && activeContact) {
    const c = activeContact;
    const verified = !!c.verified;
    const hasAvatar = !!c.peerAvatarB64;
    const officialAdmin = !!trustedOfficialAccountFor(c);
    const revokedOfficialAdmin = !!revokedOfficialAccountFor(c);
    const officialIdentity = officialAdmin || revokedOfficialAdmin;
    return renderMessengerShell(
      <div className="subview">
        <div className="subhead">
          <button className="back" onClick={() => setView('chat')} aria-label={t('Zurück')}>
            <IconBack />
          </button>
          <div className="h">{t('Kontakt')}</div>
        </div>
        <div className="contact-body">
          <button
            className="contact-avatar"
            onClick={() => hasAvatar && setZoomImg(new Blob([b64ToBytes(c.peerAvatarB64!)], { type: 'image/jpeg' }))}
            aria-label={hasAvatar ? t('Profilbild groß ansehen') : undefined}
          >
            {hasAvatar ? (
              <img src={avatarSrc(c.peerAvatarB64!)} alt={t('Profilbild')} />
            ) : (
              <div className="contact-identicon">
                <Identicon seed={c.roomId} />
              </div>
            )}
          </button>

          <div className="contact-name-row">
            <div className="contact-name">{displayName(c)}</div>
            {officialAdmin && <OfficialAdminBadge />}
            {revokedOfficialAdmin && <RevokedOfficialAdminBadge />}
          </div>
          {revokedOfficialAdmin ? (
            <div className="contact-verify-chip revoked">
              <IconShield size={12} filled />
              {t('Admin-Schlüssel widerrufen')}
            </div>
          ) : (
            <button
              className="contact-verify-chip"
              style={{ color: verified ? 'var(--verified)' : 'var(--muted)' }}
              onClick={() =>
                launchRuntimeOperation(() => openVerify())
              }
            >
              <IconLock size={12} />
              {verified ? t('verifiziert') : t('nicht verifiziert · zum Prüfen antippen')}
            </button>
          )}

          {officialAdmin && (
            <div className="official-account-note">
              <IconShield size={19} filled />
              <div>
                <b>{t('Kryptografisch bestätigter SKYTALE-Administrator')}</b>
                <span>
                  {t('Dieses ADMIN-Kennzeichen wurde mit dem in dieser SKYTALE-Version eingebauten Vertrauensschlüssel geprüft.')}
                </span>
              </div>
            </div>
          )}

          {revokedOfficialAdmin && (
            <OfficialAccountRevokedWarning
              onRecover={() =>
                launchRuntimeOperation((signal) =>
                  addBundle(OFFICIAL_ACCOUNT_ALIAS, signal),
                )
              }
            />
          )}

          {!revokedOfficialAdmin && !verified && c.verifiedSuggestion && !c.verifiedSuggestionDismissed && (
            <div className="contact-warn">
              <div className="cw-text">
                <b>{t('Auf deinem anderen Gerät bestätigt')}</b>
                <span>
                  {t('Beim Übernehmen deiner Kontakte kam die Info mit, dass du diesen Kontakt auf einem anderen Gerät schon verifiziert hast. Das allein zählt hier NICHT als Bestätigung — vergleiche die Sicherheitsnummer auf diesem Gerät selbst.')}
                </span>
              </div>
              <button
                className="btn btn-primary sm"
                onClick={() =>
                  launchRuntimeOperation(() => openVerify())
                }
              >
                {t('Sicherheitsnummer vergleichen')}
              </button>
              <button
                className="btn btn-ghost sm"
                onClick={() =>
                  launchRuntimeOperation(() =>
                    dismissVerifiedSuggestion(),
                  )
                }
              >
                {t('Ausblenden')}
              </button>
            </div>
          )}

          {c.retiredAttempt && (
            <div className="contact-warn">
              <div className="cw-text">
                <b>{t('Abgelehnter Anmeldeversuch')}</b>
                <span>
                  {t('Es kamen Nachrichten unter einer früheren, bereits ersetzten Identität dieses Kontakts an. Sie wurden verworfen. Das ist normal, wenn ein altes Gerät noch läuft — kann aber auch bedeuten, dass jemand einen alten Schlüssel besitzt.')}
                </span>
              </div>
              <button
                className="btn btn-ghost sm"
                onClick={() =>
                  launchRuntimeOperation(() =>
                    dismissRetiredNotice(),
                  )
                }
              >
                {t('Verstanden')}
              </button>
            </div>
          )}

          {!revokedOfficialAdmin && c.pendingMaster && (
            <div className="contact-warn door">
              <div className="cw-text">
                <b>{t('Neue Identität behauptet')}</b>
                <span>
                  {t('Dieser Kontakt meldet sich mit einem neuen Identitätsschlüssel — etwa nach einem Gerätewechsel. Übernimm ihn nur, wenn du sicher bist, dass es wirklich diese Person ist. Danach ist ein neuer Sicherheitsnummer-Vergleich fällig.')}
                </span>
              </div>
              <button
                className="btn btn-primary sm"
                onClick={() =>
                  launchRuntimeOperation(() => acceptNewIdentity())
                }
              >
                {t('Neue Identität akzeptieren')}
              </button>
            </div>
          )}

          {!revokedOfficialAdmin && c.staleIdentity && (
            <div className="contact-warn door">
              <div className="cw-text">
                <b>{t('Verbindung veraltet')}</b>
                <span>
                  {t('Du hast ein Gerät gekoppelt, seitdem hat sich deine Identität geändert. Dieser Kontakt kennt noch die alte. „Neu verbinden“ baut die Sitzung frisch auf — die Gegenseite sieht dann eine Identitätswarnung und muss dich neu bestätigen.')}
                </span>
              </div>
              <button
                className="btn btn-primary sm"
                onClick={() =>
                  launchRuntimeOperation(() =>
                    reconnectStaleContact(),
                  )
                }
              >
                {t('Neu verbinden')}
              </button>
            </div>
          )}

          <div className="contact-fields">
            {officialIdentity ? (
              <>
                <div className="contact-field">
                  <span className="cf-label">{t('Offizielle Adresse')}</span>
                  <span className="cf-value mono">{OFFICIAL_ACCOUNT_ALIAS}</span>
                </div>
                <div className="contact-field">
                  <span className="cf-label">{t('Offizieller Kontoname')}</span>
                  <span className="cf-value">{OFFICIAL_ACCOUNT_DISPLAY_NAME}</span>
                </div>
              </>
            ) : (
              <>
                {renaming ? (
                  <div className="contact-field">
                    <span className="cf-label">{t('Dein Name für den Kontakt')}</span>
                    <div className="rename-row">
                      <input
                        autoFocus
                        value={renameInput}
                        placeholder={t('Nickname…')}
                        onChange={(e) => setRenameInput(e.target.value)}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter') {
                            launchRuntimeOperation(() => saveNickname());
                          }
                        }}
                      />
                      <button
                        className="btn btn-primary"
                        onClick={() =>
                          launchRuntimeOperation(() => saveNickname())
                        }
                      >
                        ✓
                      </button>
                    </div>
                  </div>
                ) : (
                  <button className="contact-field tappable" onClick={startRename}>
                    <span className="cf-label">
                      {t('Dein Name für den Kontakt')} <span className="pencil">✎</span>
                    </span>
                    <span className="cf-value">{c.nickname?.trim() || <em>{t('nicht gesetzt')}</em>}</span>
                  </button>
                )}

                <div className="contact-field">
                  <span className="cf-label">{t('Name, den die Person selbst gesetzt hat')}</span>
                  <span className="cf-value">{c.peerName?.trim() || <em>{t('keiner')}</em>}</span>
                </div>
              </>
            )}

            <div className="contact-field">
              <span className="cf-label">{t('Sicherheitsnummer (Fingerprint)')}</span>
              <span className="cf-value mono">{c.peerFingerprint}</span>
            </div>
          </div>

          <div className="contact-actions">
            <button
              className="btn btn-ghost"
              onClick={() => {
                if (confirm(t('Chatverlauf wirklich löschen?'))) {
                  launchRuntimeOperation(() =>
                    clearChatAction(c.roomId),
                  );
                }
              }}
            >
              {t('Chatverlauf löschen')}
            </button>
            <button
              className="btn btn-danger"
              onClick={() => {
                if (confirm(t('Kontakt und Chat wirklich löschen?'))) {
                  launchRuntimeOperation(() =>
                    deleteContactAction(c.roomId),
                  );
                }
              }}
            >
              {t('Kontakt löschen')}
            </button>
          </div>
        </div>
        {lightbox}
        {viewOnceEl}
        {mediaPreviewEl}
        {r2UploadEl}
        {transcodeEl}
        {stickerViewEl}
      </div>
    );
  }

  // ── Profile ───────────────────────────────────────────────────────
  if (view === 'devices') {
    const idv = identityRef.current;
    const primary = !!(idv && isPrimaryDevice(idv));
    const meSign = idv?.sign.publicKey;
    const devices = ownListRef.current?.devices ?? [];
    const removingSelf = !!removeDev && (!primary || !!(meSign && bytesEqual(removeDev, meSign)));
    return renderMessengerShell(
      <div className="subview">
        <div className="subhead">
          <button className="back" onClick={() => setView('profile')} aria-label={t('Zurück')}>
            <IconBack />
          </button>
          <div className="h">{t('Geräte')}</div>
        </div>
        <div className="subbody">
          <p className="share-hint" style={{ textAlign: 'left' }}>
            {primary
              ? t('Diese Geräte sind mit deiner Identität verknüpft. Entfernst du eins, wird sein Krypto-Container gelöscht.')
              : t('Dieses Gerät ist mit deiner Identität verknüpft.')}
          </p>
          <div className="card pad16">
            {devices.map((d, i) => {
              const b64 = bytesToB64(d.signPub);
              const isMe = !!(meSign && bytesEqual(d.signPub, meSign));
              const name = deviceNames[b64] || (isMe ? t('Dieses Gerät') : t('Gerät {n}', { n: i + 1 }));
              return (
                <div key={b64} className="dev-row">
                  <span className="setting-ic"><IconDevices size={15} /></span>
                  <span className="setting-tx">
                    <span className="setting-title">{name}</span>
                    <span className="setting-sub">{isMe ? t('Dieses Gerät') : t('Verknüpftes Gerät')}</span>
                  </span>
                  {primary && (
                    <button
                      className="dev-act"
                      title={t('Umbenennen')}
                      onClick={() =>
                        launchRuntimeOperation(() =>
                          renameDevice(
                            d.signPub,
                            deviceNames[b64] ?? '',
                          ),
                        )
                      }
                    >
                      ✎
                    </button>
                  )}
                  {primary && !isMe && (
                    <button className="dev-act danger" title={t('Entfernen')} onClick={() => setRemoveDev(d.signPub)}>
                      <IconTrash size={15} />
                    </button>
                  )}
                </div>
              );
            })}
            {devices.length <= 1 && <p className="share-hint">{t('Noch keine weiteren Geräte gekoppelt.')}</p>}
          </div>

          {!primary && !populatingDecoy && (
            <button className="btn btn-danger" style={{ marginTop: 16 }} onClick={() => setRemoveDev(meSign ?? new Uint8Array())}>
              {t('Dieses Gerät entkoppeln')}
            </button>
          )}
        </div>

        {removeDev && (
          <div className="crop-modal" role="dialog" aria-label={t('Gerät entfernen')}>
            <div className="crop-head">{removingSelf ? t('Dieses Gerät entkoppeln') : t('Gerät entfernen')}</div>
            <div className="backup-body">
              <div className="err-note" style={{ textAlign: 'left' }}>
                <p>{tb('Der Krypto-Container dieses Geräts wird **unwiderruflich gelöscht** — Nachrichten, Kontakte und Schlüssel dort sind dann weg.')}</p>
              </div>
            </div>
            <div className="crop-actions">
              <button className="btn btn-outline" onClick={() => setRemoveDev(null)}>
                {t('Abbrechen')}
              </button>
              <button
                className="btn btn-danger"
                onClick={() => {
                  if (removingSelf) {
                    void unlinkSelfAction();
                  } else {
                    launchRuntimeOperation(() =>
                      removeDeviceAction(removeDev),
                    );
                  }
                }}
              >
                {t('Entfernen')}
              </button>
            </div>
          </div>
        )}
      </div>
    );
  }

  if (view === 'learn') {
    return renderMessengerShell(<Explainer onClose={() => setView('profile')} />);
  }

  if (view === 'profile') {
    return renderMessengerShell(
      <div className="subview">
        <div className="subhead">
          <button className="back" onClick={() => setView('list')} aria-label={t('Zurück')}>
            <IconBack />
          </button>
          <div className="h">{t('Profil')}</div>
        </div>
        <div className="profile-body">
          <input ref={avatarInputRef} type="file" accept="image/*" hidden onChange={onPickAvatar} />
          {cropFile && (
            <CropModal
              file={cropFile}
              onCancel={() => setCropFile(null)}
              onDone={(b) =>
                launchRuntimeOperation(() => onCropDone(b))
              }
            />
          )}

          {/* Identity: avatar + name + save, one quiet line on what happens to it. */}
          <div className="profile-id">
            <button className="profile-avatar" onClick={() => avatarInputRef.current?.click()}>
              {myAvatarB64 ? <img src={avatarSrc(myAvatarB64)} alt={t('Dein Avatar')} /> : <span className="ph">＋</span>}
              <span className="edit-badge">
                <IconCamera size={14} />
              </span>
            </button>
            <input
              className="profile-name-input"
              value={profileName}
              placeholder={t('Dein Name')}
              onChange={(e) => setProfileName(e.target.value)}
            />
            <button
              className="btn btn-primary profile-save"
              onClick={() =>
                launchRuntimeOperation(() => saveProfileMeta())
              }
            >
              {t('Speichern & teilen')}
            </button>
            <p className="profile-id-hint">
              <IconLock size={11} /> {t('Bild & Name gehen Ende-zu-Ende verschlüsselt an deine Kontakte.')}
            </p>
          </div>

          {error && <div className="err-note">{error}</div>}

          {/* Grouped into sections so it reads as menus, not one long undifferentiated list. */}
          <div className="settings-list">
            <div className="settings-sec">{t('Sicherheit')}</div>
            {bioSupported && (
              <button
                className="setting-row"
                role="switch"
                aria-checked={bioOn}
                onClick={() => {
                  if (bioOn) {
                    if (confirm(t('Face ID / Touch ID entfernen? Der Tresor bleibt per Passphrase entsperrbar.'))) {
                      launchRuntimeOperation(async () => {
                        await disableBiometricUnlock();
                        setBioOn(false);
                      }); // on failure the header keeps PRF → toggle honestly stays on
                    }
                  } else {
                    setBioEnroll(true);
                  }
                }}
              >
                <span className="setting-ic"><IconLock size={15} /></span>
                <span className="setting-tx">
                  <span className="setting-title">{t('Face ID / Touch ID')}</span>
                  <span className="setting-sub">{t('Entsperren ohne Passphrase — Schlüssel bleibt gleich')}</span>
                </span>
                <span className={`switch${bioOn ? ' on' : ''}`}>
                  <span className="knob" />
                </span>
              </button>
            )}

            {populatingDecoy && onExitDecoy && (
              // Only shown during a deliberate in-app populate session (App state, never persisted),
              // so a coercer who duress-opened the decoy never sees it — no tell that a real
              // account exists.
              <button className="setting-row accent" onClick={() => void handleExitDecoy()}>
                <span className="setting-ic"><IconBack size={15} /></span>
                <span className="setting-tx">
                  <span className="setting-title">{t('Zurück zum echten Konto')}</span>
                  <span className="setting-sub">{t('Du befüllst gerade das Decoy-Konto')}</span>
                </span>
                <span className="setting-go"><IconChevron /></span>
              </button>
            )}

            {!populatingDecoy && (
              // Hidden while populating the decoy: the active DB is then the decoy itself, and
              // arming/removing duress there would delete the live database (service also refuses).
              <button
                className="setting-row"
                role="switch"
                aria-checked={duressOn}
                onClick={() => setDuressModal(duressOn ? 'remove' : 'set')}
              >
                <span className="setting-ic"><IconShield size={15} /></span>
                <span className="setting-tx">
                  <span className="setting-title">{t('Duress-Passwort')}</span>
                  <span className="setting-sub">{t('Notfall-Passwort: löscht beim Entsperren das echte Konto und öffnet ein Schein-Konto')}</span>
                </span>
                <span className={`switch${duressOn ? ' on' : ''}`}>
                  <span className="knob" />
                </span>
              </button>
            )}

            {duressOn && onEnterDecoy && !populatingDecoy && (
              <button
                className="setting-row"
                onClick={() => {
                  setPopulatePass('');
                  setPopulateErr('');
                  setPopulatePrompt(true);
                }}
              >
                <span className="setting-ic"><IconShield size={15} /></span>
                <span className="setting-tx">
                  <span className="setting-title">{t('Decoy-Konto befüllen')}</span>
                  <span className="setting-sub">{t('Ins Schein-Konto wechseln und es glaubwürdig einrichten')}</span>
                </span>
                <span className="setting-go"><IconChevron /></span>
              </button>
            )}

            <div className="settings-sec">{t('Geräte')}</div>
            <button
              className="setting-row"
              onClick={() => {
                if (resetLink()) setLinkView('menu');
                else setLinkView('sas');
              }}
            >
              <span className="setting-ic"><IconDevices /></span>
              <span className="setting-tx">
                <span className="setting-title">{t('Gerät koppeln')}</span>
                <span className="setting-sub">
                  {primaryLinkDeliveryPending
                    ? t('Autorisierung gespeichert — Relay-Zustellung ausstehend')
                    : t('Zweites Gerät per QR + Emoji-Abgleich')}
                </span>
              </span>
              <span className="setting-go"><IconChevron /></span>
            </button>

            <button className="setting-row" onClick={() => setView('devices')}>
              <span className="setting-ic"><IconDevices /></span>
              <span className="setting-tx">
                <span className="setting-title">{t('Geräte verwalten')}</span>
                <span className="setting-sub">{t('Verknüpfte Geräte ansehen, benennen, entfernen')}</span>
              </span>
              <span className="setting-go"><IconChevron /></span>
            </button>

            <div className="settings-sec">{t('Daten & Backup')}</div>
            <button className="setting-row" onClick={() => setBackupMode('export')}>
              <span className="setting-ic"><IconArchive /></span>
              <span className="setting-tx">
                <span className="setting-title">{t('Backup exportieren')}</span>
                <span className="setting-sub">{t('Verschlüsselte Datei, eigene Passphrase')}</span>
              </span>
              <span className="setting-go"><IconChevron /></span>
            </button>

            <button className="setting-row" onClick={() => setBackupMode('import')}>
              <span className="setting-ic"><IconArchive /></span>
              <span className="setting-tx">
                <span className="setting-title">{t('Wiederherstellen')}</span>
                <span className="setting-sub">{t('Konto aus einer Backup-Datei laden')}</span>
              </span>
              <span className="setting-go"><IconChevron /></span>
            </button>

            {identityRef.current &&
              isOfficialAdminMaster(
                identityRef.current.master.publicKey,
                officialAccountTrustRef.current,
              ) && (
                <button
                  className="setting-row"
                  onClick={() =>
                    launchRuntimeOperation((signal) =>
                      exportOfficialAdminDescriptor(signal),
                    )
                  }
                >
                  <span className="setting-ic"><IconShield size={15} filled /></span>
                  <span className="setting-tx">
                    <span className="setting-title">
                      {t('Öffentlichen Admin-Deskriptor exportieren')}
                    </span>
                    <span className="setting-sub">
                      {t('Nur öffentliche Schlüssel für die Offline-Signatur')}
                    </span>
                  </span>
                  <span className="setting-go"><IconChevron /></span>
                </button>
              )}

            <div className="settings-sec">{t('Allgemein')}</div>
            {pushSupported() && (
              <button
                className="setting-row"
                onClick={() => launchRuntimeOperation(() => togglePush())}
                disabled={notifBusy}
              >
                <span className="setting-ic"><IconBell /></span>
                <span className="setting-tx">
                  <span className="setting-title">{t('Benachrichtigungen')}</span>
                  <span className="setting-sub">{t('Inhaltloses Wecksignal — nie Absender oder Text')}</span>
                </span>
                <span className={`switch${notifOn ? ' on' : ''}`}>
                  <span className="knob" />
                </span>
              </button>
            )}

            <button className="setting-row" onClick={() => setLangSheet(true)}>
              <span className="setting-ic"><IconGlobe /></span>
              <span className="setting-tx">
                <span className="setting-title">{t('Sprache')}</span>
                <span className="setting-sub">{LANGS.find((l) => l.code === getLang())?.name ?? getLang()}</span>
              </span>
              <span className="setting-go"><IconChevron /></span>
            </button>

            <button className="setting-row" onClick={() => setView('learn')}>
              <span className="setting-ic"><IconGraduation /></span>
              <span className="setting-tx">
                <span className="setting-title">{t('So funktioniert der Schutz')}</span>
                <span className="setting-sub">{t('In 5 Schritten einfach erklärt')}</span>
              </span>
              <span className="setting-go"><IconChevron /></span>
            </button>

            <button className="setting-row" onClick={() => launchRuntimeOperation((signal) => startBugReport(signal))}>
              <span className="setting-ic"><IconBug /></span>
              <span className="setting-tx">
                <span className="setting-title">{t('Fehler melden')}</span>
                <span className="setting-sub">{t('Etwas klemmt oder du hast eine Idee?')}</span>
              </span>
              <span className="setting-go"><IconChevron /></span>
            </button>

            {!populatingDecoy && (
              <>
                <div className="settings-sec">{t('Konto')}</div>
                <button className="setting-row danger" onClick={() => setDeleteOpen(true)}>
                  <span className="setting-ic"><IconTrash size={15} /></span>
                  <span className="setting-tx">
                    <span className="setting-title">{t('Account löschen / zurücksetzen')}</span>
                    <span className="setting-sub">{t('Alle Daten auf diesem Gerät unwiderruflich entfernen')}</span>
                  </span>
                  <span className="setting-go"><IconChevron /></span>
                </button>
              </>
            )}
          </div>

          {deleteOpen && (
            <div className="crop-modal" role="dialog" aria-label={t('Account löschen')}>
              <div className="crop-head">{t('Account löschen / zurücksetzen')}</div>
              <div className="backup-body">
                <div className="err-note" style={{ textAlign: 'left' }}>
                  <p>
                    {tb(
                      'Das entfernt **unwiderruflich** deine Identität, alle Chats, Kontakte und Schlüssel von **diesem Gerät**. Ohne ein vorher exportiertes Backup gibt es keine Wiederherstellung.',
                    )}
                  </p>
                  <p style={{ opacity: 0.72 }}>{t('Das erreicht weder deine Kontakte noch den Server — dort gibt es kein Konto.')}</p>
                </div>
              </div>
              <div className="crop-actions">
                <button className="btn btn-outline" onClick={() => setDeleteOpen(false)} disabled={wiping}>
                  {t('Abbrechen')}
                </button>
                <button
                  className="btn btn-danger"
                  onClick={() => void doWipeAccount().catch(() => undefined)}
                  disabled={wiping}
                >
                  {wiping ? '…' : t('Endgültig löschen')}
                </button>
              </div>
            </div>
          )}

          {backupMode && (
            <BackupModal
              mode={backupMode}
              dek={dek}
              onClose={() => setBackupMode(null)}
              onBeforeImport={suspendForRestore}
              onImportFailed={resumeAfterFailedRestore}
              runRuntimeOperation={runRuntimeOperation}
            />
          )}
          {bioEnroll && (
            <BiometricEnroll
              runRuntimeOperation={runRuntimeOperation}
              onDone={() => {
                setBioOn(true);
                setBioEnroll(false);
              }}
              onClose={() => setBioEnroll(false)}
            />
          )}
          {duressModal && (
            <DuressSetup
              mode={duressModal}
              runRuntimeOperation={runRuntimeOperation}
              onDone={() => {
                setDuressOn(duressModal === 'set');
                setDuressModal(null);
              }}
              onClose={() => setDuressModal(null)}
            />
          )}
          {populatePrompt && (
            <div className="crop-modal" role="dialog" aria-label={t('Decoy-Konto befüllen')}>
              <div className="crop-head">{t('Decoy-Konto befüllen')}</div>
              <div className="backup-body">
                <p className="backup-warn">
                  {tb('Gib dein **Duress-Passwort** ein, um ins Schein-Konto zu wechseln. Lege dort glaubwürdige Kontakte und Chats an. Dein echtes Konto bleibt unangetastet — tippe „Zurück zum echten Konto", wenn du fertig bist.')}
                </p>
                <label className="backup-field">
                  <span>{t('Duress-Passwort')}</span>
                  <input
                    type="password"
                    value={populatePass}
                    autoComplete="off"
                    autoFocus
                    disabled={populateBusy}
                    onChange={(e) => setPopulatePass(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && void doPopulate()}
                  />
                </label>
                {populateErr && <div className="err-note">{populateErr}</div>}
              </div>
              <div className="crop-actions">
                <button className="btn btn-ghost" onClick={() => setPopulatePrompt(false)} disabled={populateBusy}>
                  {t('Abbrechen')}
                </button>
                <button
                  className="btn btn-primary"
                  disabled={populateBusy || !populatePass}
                  onClick={() => void doPopulate()}
                >
                  {populateBusy ? '…' : t('Wechseln')}
                </button>
              </div>
            </div>
          )}
          {langSheet && (
            <div className="lang-scrim" onClick={() => setLangSheet(false)}>
              <div className="lang-sheet" onClick={(e) => e.stopPropagation()}>
                <div className="lang-sheet-h">{t('Sprache')}</div>
                {LANGS.map((l) => (
                  <button
                    key={l.code}
                    className={`lang-row${l.code === getLang() ? ' on' : ''}`}
                    onClick={() => {
                      setLang(l.code as Lang);
                      setLangSheet(false);
                    }}
                  >
                    <span className="lang-name">{l.name}</span>
                    {l.code === getLang() && <IconDoubleCheck size={14} />}
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
        {linkOverlay}
      </div>
    );
  }

  // ── New group ─────────────────────────────────────────────────────
  if (view === 'newgroup') {
    const selectable = visibleContacts.filter(
      (contact) =>
        !!contact.bundle ||
        !!contact.peerDeviceList?.devices.some((device) => !!device.signedPreKey),
    );
    return renderMessengerShell(
      <div className="subview">
        <div className="subhead">
          <button className="back" onClick={() => setView('list')} aria-label={t('Zurück')}>
            <IconBack />
          </button>
          <div className="h">{t('Neue Gruppe')}</div>
        </div>
        <div className="subbody">
          <div className="field-lbl">{t('Gruppenname')}</div>
          <input
            className="name-input"
            value={groupNameInput}
            placeholder={t('z. B. Redaktion')}
            onChange={(e) => setGroupNameInput(e.target.value)}
          />
          <div className="sect-lbl" style={{ marginTop: 18 }}>
            {t('Mitglieder wählen')}
          </div>
          {selectable.length === 0 ? (
            <p className="share-hint" style={{ textAlign: 'left' }}>
              {t('Du brauchst zuerst Kontakte (über deren Code), um sie in eine Gruppe zu holen.')}
            </p>
          ) : (
            <div className="card pad16">
              {selectable.map((c) => {
                const on = groupSel.has(c.roomId);
                const officialAdmin = !!trustedOfficialAccountFor(c);
                const revokedOfficialAdmin = !!revokedOfficialAccountFor(c);
                return (
                  <button
                    key={c.roomId}
                    className={`member-row${on ? ' on' : ''}`}
                    disabled={revokedOfficialAdmin}
                    onClick={() => {
                      const s = new Set(groupSel);
                      if (on) s.delete(c.roomId);
                      else s.add(c.roomId);
                      setGroupSel(s);
                    }}
                  >
                    {c.peerAvatarB64 ? (
                      <img className="avatar-img sm" src={avatarSrc(c.peerAvatarB64)} alt="" />
                    ) : (
                      <div className="avatar sm">
                        <Identicon seed={c.roomId} />
                      </div>
                    )}
                    <span className="conv-name">{displayName(c)}</span>
                    {officialAdmin && <OfficialAdminBadge />}
                    {revokedOfficialAdmin && <RevokedOfficialAdminBadge />}
                    <span className={`check${on ? ' on' : ''}`}>{on ? '✓' : ''}</span>
                  </button>
                );
              })}
            </div>
          )}
          {error && <div className="err-note">{error}</div>}
          <button
            className="btn btn-primary"
            style={{ marginTop: 18 }}
            disabled={groupSel.size === 0}
            onClick={() => launchRuntimeOperation(() => createGroup())}
          >
            {t('Gruppe erstellen ({n})', { n: groupSel.size })}
          </button>
        </div>
      </div>
    );
  }

  // ── Manage group ──────────────────────────────────────────────────
  if (view === 'gmanage' && activeGroupData) {
    const g = activeGroupData;
    const localIdentity = identityRef.current;
    const canManage =
      !!g.ownerMasterPub &&
      !!(
        localIdentity &&
        isPrimaryDevice(localIdentity) &&
        isGroupOwner(g, localIdentity.master.publicKey)
      );
    const addable = canManage
      ? visibleContacts.filter(
          (contact) =>
            (!!contact.bundle ||
              !!contact.peerDeviceList?.devices.some(
                (device) => !!device.signedPreKey,
              )) &&
            !g.members.some((member) =>
              bytesEqual(memberMasterPub(member), contact.peerMasterPub),
            ),
        )
      : [];
    return renderMessengerShell(
      <div className="subview">
        <div className="subhead">
          <button className="back" onClick={() => setView('chat')} aria-label={t('Zurück')}>
            <IconBack />
          </button>
          <div className="h">{t('Gruppe verwalten')}</div>
        </div>
        <div className="subbody">
          <div className="field-lbl">{t('Gruppenname')}</div>
          <div className="rename-row" style={{ marginBottom: 18 }}>
            <input
              className="name-input"
              value={groupRenameInput}
              disabled={!canManage}
              onChange={(e) => setGroupRenameInput(e.target.value)}
            />
            {canManage && (
              <button
                className="btn btn-primary"
                style={{ width: 'auto' }}
                onClick={() =>
                  launchRuntimeOperation(() =>
                    renameGroup(g, groupRenameInput),
                  )
                }
              >
                ✓
              </button>
            )}
          </div>
          {!canManage && (
            <p className="share-hint" style={{ textAlign: 'left' }}>
              {t('Nur das primäre Owner-Gerät kann Name und Mitglieder ändern.')}
            </p>
          )}

          <div className="sect-lbl">{t('Mitglieder ({n})', { n: g.members.length + 1 })}</div>
          <div className="card pad16">
            <div className="member-row">
              {myAvatarB64 ? (
                <img className="avatar-img sm" src={avatarSrc(myAvatarB64)} alt="" />
              ) : (
                <div className="avatar sm">
                  <Identicon seed={'me-' + fingerprint} />
                </div>
              )}
              <span className="conv-name">{t('Du')}</span>
            </div>
            {g.members.map((m, i) => {
              const masterPub = memberMasterPub(m);
              const officialAdmin = isOfficialAdminMaster(
                masterPub,
                officialAccountTrustRef.current,
              );
              const revokedOfficialAdmin = isRevokedOfficialAdminMaster(
                masterPub,
                officialAccountTrustRef.current,
              );
              const memberName =
                officialAdmin || revokedOfficialAdmin
                  ? OFFICIAL_ACCOUNT_DISPLAY_NAME
                  : m.name || '…';
              return (
                <div key={i} className="member-row">
                  <div className="avatar sm">
                    <Identicon seed={hexOf(m.dhPub)} />
                  </div>
                  <span className="conv-name">{memberName}</span>
                  {officialAdmin && <OfficialAdminBadge />}
                  {revokedOfficialAdmin && <RevokedOfficialAdminBadge />}
                  {canManage && (
                    <button
                      className="icon-mini danger"
                      aria-label={t('Entfernen')}
                      onClick={() => {
                        if (confirm(t('{name} entfernen?', { name: memberName }))) {
                          launchRuntimeOperation(() =>
                            removeMemberFromGroup(g, m),
                          );
                        }
                      }}
                    >
                      <IconTrash size={15} />
                    </button>
                  )}
                </div>
              );
            })}
          </div>

          {addable.length > 0 && (
            <>
              <div className="sect-lbl" style={{ marginTop: 18 }}>
                {t('Hinzufügen')}
              </div>
              <div className="card pad16">
                {addable.map((c) => {
                  const on = groupSel.has(c.roomId);
                  const officialAdmin = !!trustedOfficialAccountFor(c);
                  const revokedOfficialAdmin = !!revokedOfficialAccountFor(c);
                  return (
                    <button
                      key={c.roomId}
                      className={`member-row${on ? ' on' : ''}`}
                      disabled={revokedOfficialAdmin}
                      onClick={() => {
                        const s = new Set(groupSel);
                        if (on) s.delete(c.roomId);
                        else s.add(c.roomId);
                        setGroupSel(s);
                      }}
                    >
                      {c.peerAvatarB64 ? (
                        <img className="avatar-img sm" src={avatarSrc(c.peerAvatarB64)} alt="" />
                      ) : (
                        <div className="avatar sm">
                          <Identicon seed={c.roomId} />
                        </div>
                      )}
                      <span className="conv-name">{displayName(c)}</span>
                      {officialAdmin && <OfficialAdminBadge />}
                      {revokedOfficialAdmin && <RevokedOfficialAdminBadge />}
                      <span className={`check${on ? ' on' : ''}`}>{on ? '✓' : ''}</span>
                    </button>
                  );
                })}
                <button
                  className="btn btn-primary"
                  style={{ marginTop: 12 }}
                  disabled={groupSel.size === 0}
                  onClick={() =>
                    launchRuntimeOperation(async () => {
                      await addMembersToGroup(g, [...groupSel]);
                      setGroupSel(new Set());
                    })
                  }
                >
                  {t('{n} hinzufügen', { n: groupSel.size })}
                </button>
              </div>
            </>
          )}

          {error && <div className="err-note">{error}</div>}
          <button
            className="btn btn-outline danger-btn"
            style={{ marginTop: 18 }}
            onClick={() => {
              if (
                confirm(
                  canManage && !!g.ownerMasterPub
                    ? t('Gruppe wirklich für alle auflösen?')
                    : t('Gruppe wirklich verlassen?'),
                )
              ) {
                launchRuntimeOperation(() => leaveGroup(g));
              }
            }}
          >
            {canManage && !!g.ownerMasterPub
              ? t('Gruppe auflösen')
              : t('Gruppe verlassen')}
          </button>
        </div>
      </div>
    );
  }

  return null;
}
