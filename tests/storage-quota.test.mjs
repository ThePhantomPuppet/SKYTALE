// Incoming attachment quota + account-wipe push teardown.
// Each policy has a bug-shaped negative control.
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as S from './.bundle/entry.js';

let pass = 0, fail = 0;
const ok = (name, condition) => {
  if (condition) {
    pass++;
    console.log('  ok  ', name);
  } else {
    fail++;
    console.log('  FAIL', name);
  }
};

const MiB = 1024 * 1024;

console.log('\n[Attachment-Quota: pro Kontakt]');
const received = [
  { mine: false, file: { attId: 'a', size: 10 * MiB } },
  { mine: false, file: { attId: 'a', size: 10 * MiB } }, // same stored object, count once
  { mine: false, file: { attId: 'b', size: 20 * MiB } },
  { mine: true, file: { attId: 'mine', size: 500 * MiB } },
  { mine: false, file: { attId: 'pending', size: 25 * MiB, pull: { total: 2 } } },
];
ok('nur distinct vollständig gespeicherte empfangene Anhänge zählen',
  S.storedReceivedAttachmentBytes(received) === 30 * MiB);
ok('Auto-Empfang bis exakt 32 MiB ist zulässig',
  S.mayAutoReceiveAttachment(received, 2 * MiB));
ok('ein weiteres Byte über 32 MiB wird abgelehnt',
  !S.mayAutoReceiveAttachment(received, 2 * MiB + 1));
const active = [
  { roomId: 'room-a', automatic: true, size: 1 * MiB, receivedBytes: 0 },
  { roomId: 'room-b', automatic: true, size: 20 * MiB, receivedBytes: 10 * MiB },
  { roomId: 'room-a', automatic: false, size: 500 * MiB, receivedBytes: 0 },
];
ok('laufende automatische Transfers werden ihrem Kontakt voll angerechnet',
  S.automaticRecvReservationBytes(active, 'room-a') === 1 * MiB &&
  S.mayAutoReceiveAttachment(received, 1 * MiB, 32 * MiB, 1 * MiB) &&
  !S.mayAutoReceiveAttachment(received, 1 * MiB + 1, 32 * MiB, 1 * MiB));
ok('Legacy-Marker ohne Quota-Eigentümer blockiert neue Auto-Transfers',
  S.automaticRecvReservationBytes([{ size: 1, receivedBytes: 0 }], 'room-a') === Number.MAX_SAFE_INTEGER);
const tinyRecordFloodCharge = S.attachmentRecvReservationBytes(1, 800);
ok('tausende Tiny-Chunk-Records werden nicht als praktisch null Byte verbucht',
  tinyRecordFloodCharge ===
    1 + S.RECV_TRANSFER_FIXED_OVERHEAD_BYTES +
      800 * S.RECV_CHUNK_RECORD_OVERHEAD_BYTES);
ok('persistierte Chunk-Record-Kosten bleiben nach Abschluss im Kontaktcap',
  S.storedReceivedAttachmentBytes([
    { mine: false, file: { attId: 'tiny-flood', size: 1, storageBytes: tinyRecordFloodCharge } },
  ]) === tinyRecordFloodCharge);
ok('fehlende Größenmetadaten failen geschlossen',
  !S.mayAutoReceiveAttachment([{ mine: false, file: { attId: 'legacy' } }], 1));
ok('inline empfangene Bytes im Message-Record zählen ebenfalls',
  S.storedReceivedAttachmentBytes([
    { mine: false, file: { dataB64: 'AQID' } },
    { mine: true, file: { dataB64: 'AQID' } },
  ]) === 3);
ok('missgebildetes Inline-Base64 failt geschlossen',
  S.storedReceivedAttachmentBytes([
    { mine: false, file: { dataB64: '%%%not-base64%%%' } },
  ]) === Number.MAX_SAFE_INTEGER);
// NEGATIVE CONTROL: the old per-file-only policy admitted every individually small file.
const oldPerFileOnly = (bytes) => bytes <= 30 * MiB;
ok('Negativkontrolle: alte Einzeldateigrenze hätte kumulatives Flooding erlaubt',
  oldPerFileOnly(3 * MiB) && !S.mayAutoReceiveAttachment(received, 3 * MiB));

console.log('\n[Attachment-Quota: Origin-Headroom + Reservierungen]');
ok('Marker reservieren nur ihre noch fehlenden Bytes',
  S.remainingRecvReservationBytes([
    { size: 12 * MiB, receivedBytes: 2 * MiB },
    { size: 5 * MiB, receivedBytes: 5 * MiB },
  ]) === 10 * MiB);
ok('korrupter Marker failt geschlossen',
  S.remainingRecvReservationBytes([{ size: 1, receivedBytes: 2 }]) === Number.MAX_SAFE_INTEGER);
ok('nicht lesbarer persistierter Marker failt ebenfalls geschlossen',
  S.remainingRecvReservationBytes([null]) === Number.MAX_SAFE_INTEGER);
ok('64 MiB Mindestreserve darf exakt stehen bleiben',
  S.hasOriginStorageHeadroom(
    { quota: 200 * MiB, usage: 100 * MiB },
    30 * MiB,
    6 * MiB,
  ));
ok('unter 64 MiB Restreserve wird abgelehnt',
  !S.hasOriginStorageHeadroom(
    { quota: 200 * MiB, usage: 100 * MiB },
    30 * MiB,
    6 * MiB + 1,
  ));
ok('bei großer Quota dominiert die 20-Prozent-Reserve',
  !S.hasOriginStorageHeadroom(
    { quota: 1024 * MiB, usage: 700 * MiB },
    120 * MiB,
    0,
  ));
ok('fehlende Browser-Schätzung failt geschlossen',
  !S.hasOriginStorageHeadroom(null, 1, 0));
// NEGATIVE CONTROL: usage-only ignores promised bytes from other live transfers.
const oldUsageOnly = ({ quota, usage }, requested) => quota - usage >= requested + 64 * MiB;
ok('Negativkontrolle: usage-only übersieht persistierte Restreservierungen',
  oldUsageOnly({ quota: 200 * MiB, usage: 100 * MiB }, 30 * MiB) &&
  !S.hasOriginStorageHeadroom({ quota: 200 * MiB, usage: 100 * MiB }, 30 * MiB, 20 * MiB));

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const messenger = readFileSync(join(root, 'src', 'Messenger.tsx'), 'utf8');
const receiveStart = messenger.indexOf('async function receiveChunk');
const receiveEnd = messenger.indexOf('\n  // Serialize every inbox task', receiveStart);
const receiveSource = messenger.slice(receiveStart, receiveEnd);
ok('neuer Chunk-Marker prüft Kontaktcap und Storage vor dem Persistieren',
  receiveSource.indexOf('mayAutoReceiveAttachment') >= 0 &&
  receiveSource.indexOf('originCanReserve') > receiveSource.indexOf('mayAutoReceiveAttachment') &&
  receiveSource.indexOf('putRecvMarker(dek, c.tid, candidate)') > receiveSource.indexOf('originCanReserve'));
ok('abgelehnte Transfers kehren normal zurück und werden dadurch geackt',
  receiveSource.includes('markRecvDropped(c.tid); // return normally → onInbox acks'));
ok('leere/tiny Chunk-Floods und globale Attachment-ID-Aliase werden vor Storage abgewiesen',
  receiveSource.includes('c.total > c.size || c.data.length === 0') &&
  receiveSource.includes('const aliasesExistingAttachment = Object.entries(messagesRef.current).some'));
ok('Finalize verlangt exakte Bytezahl und persistiert die Record-Overhead-Quote',
  receiveSource.includes('if (marker.receivedBytes !== marker.size)') &&
  receiveSource.includes('storageBytes, attId: c.tid'));
ok('Auto-Pull ist ausdrücklich nicht als Nutzer-Pull markiert',
  /void pullAttachment\([\s\S]*?false,\s*\);/.test(messenger));
ok('R2-Downloads laufen durch dieselbe globale Reservierungsprüfung',
  /downloadR2Message[\s\S]*?originCanReserve\(valid\.size\)[\s\S]*?r2ReservationsRef\.current\.set/.test(messenger));
ok('Datei, Reply, Self-Sync und Gruppe nutzen das gemeinsame Inline-Admission-Gate',
  messenger.includes('async function inboundFileRefFor') &&
  messenger.includes('await inboundFileRefFor(inboundRoomId') &&
  messenger.includes('await inboundFileRefFor(\n          groupId') &&
  messenger.includes('appendFreshInboundMessage(displayRoom, synced)'));

console.log('\n[Account-Wipe: Push-Reihenfolge]');
const wipeStart = messenger.indexOf('async function doWipeAccount');
const wipeEnd = messenger.indexOf('// ── Device linking', wipeStart);
const wipeSource = messenger.slice(wipeStart, wipeEnd);
const getEndpointAt = wipeSource.indexOf('currentSubscription()');
const serverUnsubscribeAt = wipeSource.indexOf('unsubscribePush(subscription.endpoint)');
const localDisableAt = wipeSource.indexOf('disablePush()');
const wipeAt = wipeSource.indexOf('wipeAccount({ pushTeardownStarted: true })');
ok('Wipe versucht Server-Unsubscribe vor lokalem Disable und Datentilgung',
  getEndpointAt >= 0 &&
  serverUnsubscribeAt > getEndpointAt &&
  localDisableAt > serverUnsubscribeAt &&
  wipeAt > localDisableAt);
ok('Server-Unsubscribe besitzt ein kurzes Timeout',
  wipeSource.includes('PUSH_UNSUBSCRIBE_TIMEOUT_MS'));
ok('Push-Teardown wird vor dem Wipe nur einmal gestartet',
  wipeSource.includes('wipeAccount({ pushTeardownStarted: true })') &&
  !wipeSource.includes('pushAlreadyHandled'));

const sw = readFileSync(join(root, 'src', 'sw.ts'), 'utf8');
const changeStart = sw.indexOf("addEventListener('pushsubscriptionchange'");
const changeEnd = sw.indexOf("addEventListener('notificationclick'", changeStart);
const changeSource = sw.slice(changeStart, changeEnd);
ok('Push-Rotation respektiert den persistenten Disable-Marker',
  changeSource.indexOf('control.match(disabledKey)') >= 0 &&
  changeSource.indexOf('pushManager.subscribe') > changeSource.indexOf('control.match(disabledKey)'));

const messengerSource = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), '..', 'src', 'Messenger.tsx'),
  'utf8',
);
const inboundSource = messengerSource.slice(
  messengerSource.indexOf('async function inboundFileRefFor'),
  messengerSource.indexOf('function quoteFrom'),
);
const lowFree = { usage: 100 * MiB, quota: 110 * MiB };   // 10 MiB frei
const nearlyFull = { usage: 109 * MiB, quota: 110 * MiB }; // 1 MiB frei
ok('kleiner Inline-Write braucht nur das kleine Headroom-Floor, ein großer das volle',
  S.ALWAYS_RECEIVE_INLINE_BYTES > 0 &&
  S.ALWAYS_RECEIVE_INLINE_BYTES < S.AUTO_RECEIVE_CONTACT_CAP_BYTES &&
  S.hasOriginStorageHeadroom(lowFree, 1024, 0, true) === true &&
  // Negativkontrolle: ohne smallWrite lehnt dasselbe knappe Estimate ab
  S.hasOriginStorageHeadroom(lowFree, 1024, 0, false) === false &&
  // Negativkontrolle: auch ein kleiner Write scheitert, wenn wirklich (fast) voll
  S.hasOriginStorageHeadroom(nearlyFull, 1024, 0, true) === false);
ok('Inline-Empfang: Per-Kontakt-Cap gilt IMMER; die Estimate-Vorprüfung entfällt für Inline (der echte Write entscheidet)',
  inboundSource.includes('mayAutoReceiveAttachment(') &&
  // Inline pre-gatet NICHT mehr auf das (auf iOS unzuverlässige) Storage-Estimate …
  !inboundSource.includes('originCanReserve(') &&
  // … sondern versucht den echten Write und fängt nur ein WIRKLICHES Storage-Full ab
  inboundSource.includes('if (isStorageFull(error))') &&
  // Negativkontrolle: der Cap steht NICHT hinter einer Größen-Bedingung (immer aktiv)
  !inboundSource.includes('if (data.length > ALWAYS_RECEIVE_INLINE_BYTES)') &&
  // Negativkontrolle: das alte 256-KB-Gate ist WEG
  !inboundSource.includes('data.length <= ALWAYS_RECEIVE_INLINE_BYTES'));

const reserveSource = messengerSource.slice(
  messengerSource.indexOf('async function originCanReserve'),
  messengerSource.indexOf('function markRecvDropped'),
);
ok('originCanReserve bleibt konservativ (nur große Auto-Downloads): unbekanntes Estimate → ablehnen',
  reserveSource.includes('if (!navigator.storage?.estimate) return false;') &&
  reserveSource.includes('} catch {\n      return false;') &&
  reserveSource.includes('hasOriginStorageHeadroom(estimate, requestedBytes, reserved, smallWrite)') &&
  // Negativkontrolle: keine Inline-Sonderbehandlung mehr (kein accept-if-fits, kein `return smallWrite`)
  !reserveSource.includes('return smallWrite') &&
  !reserveSource.includes('requestedBytes <= (estimate?.quota'));

// A SINGLE malformed/legacy recv marker (missing roomId/automatic) makes the per-contact
// reservation fail CLOSED to MAX_SAFE_INTEGER — for EVERY room — which blocks every inbound
// attachment with the "not saved" placeholder. This is the fail-closed the boot sweep must
// clear by dropping such markers.
ok('malformter/legacy Recv-Marker vergiftet den Cap (MAX_SAFE_INTEGER) für ALLE Räume',
  S.automaticRecvReservationBytes([{ size: 10, receivedBytes: 0 }], 'room') === Number.MAX_SAFE_INTEGER &&
  S.automaticRecvReservationBytes([null], 'room') === Number.MAX_SAFE_INTEGER &&
  // Negativkontrolle: ein wohlgeformter Marker eines ANDEREN Raums vergiftet NICHT
  S.automaticRecvReservationBytes([{ size: 10, receivedBytes: 0, roomId: 'other', automatic: true }], 'room') === 0);

const sweepSource = messengerSource.slice(
  messengerSource.indexOf('async function sweepOrphanAttachments'),
  messengerSource.indexOf('async function sweepOrphanAttachments') + 3200,
);
ok('Boot-Sweep entfernt unparsebare/malformte/stale Recv-Marker (nicht nur reine TTL)',
  sweepSource.includes("typeof marker.roomId === 'string'") &&
  sweepSource.includes("typeof marker.automatic === 'boolean'") &&
  sweepSource.includes('Number.isSafeInteger(marker.size)') &&
  sweepSource.includes('Date.now() - marker.ts <= RECV_TTL_MS') &&
  // Negativkontrolle: die alte reine „> TTL"-Bedingung ist WEG (die malformte/null-Marker durchließ)
  !sweepSource.includes('marker && Date.now() - marker.ts > RECV_TTL_MS'));

console.log(`\n${pass} ok, ${fail} fail`);
process.exit(fail ? 1 : 0);
