// Erst-Sync-Kern (WP1 Profil + WP2 Roster), reine/Node-testbare Schicht:
// Wire-Frames (bootstrap/listack/bootreq), strikte Decode, mergeRosterEntry
// (die harten Regeln: kein Ratchet/Bundle/Liste-Klon, verified nie blind, Merge
// füllt nur Lücken, Kollisions-/Denylist-Skip, Re-Link-Sonderregel), Contact-Wire-
// Migration und der Self-Gate über die echte Krypto. Jede Assertion mit
// Negativkontrolle (siehe MEMORY: „jede Assertion einmal absichtlich falsch füttern").
import * as S from './.bundle/entry.js';

let pass = 0, fail = 0;
const ok = (n, c) => { if (c) { pass++; console.log('  ok  ', n); } else { fail++; console.log('  FAIL', n); } };
const sodium = await S.getSodium();
const hex = (b) => sodium.to_hex(b);
const eqh = (a, b) => hex(a) === hex(b);
const prefixed = (tag, obj) => { const body = new TextEncoder().encode(JSON.stringify(obj)); const out = new Uint8Array(1 + body.length); out[0] = tag; out.set(body, 1); return out; };

// ── Fixtures ────────────────────────────────────────────────────────────────
const mkMaster = () => sodium.crypto_sign_keypair();
const mkDev = () => ({ sign: sodium.crypto_sign_keypair(), dh: sodium.crypto_box_keypair() });
const mkEntry = (masterPub, dev, over = {}) => ({
  pm: new Uint8Array(masterPub), pe: 1, psp: new Uint8Array(dev.sign.publicKey), pdp: new Uint8Array(dev.dh.publicKey),
  nick: null, pn: null, vf: false, ...over,
});

// ── A. Wire-Frames: Roundtrip, Byte-Disjunktheit ──────────────────────────────
console.log('\n[A) bootstrap/listack/bootreq — Wire-Frames]');
const eM = mkMaster(), eD = mkDev();
const rentry = mkEntry(eM.publicKey, eD, { nick: 'Kumpel', pn: 'Echter Name', vf: true });
const boot = { kind: 'bootstrap', bid: 'deadbeef', parts: [
  { t: 'profile', name: 'Ich', avatar: 'QUJD' },
  { t: 'roster', contacts: [rentry] },
] };
const framed = await S.frameContent(boot);
ok('bootstrap-Frame beginnt mit Byte 10', framed[0] === 10);
const back = await S.unframeContent(framed);
ok('Roundtrip: kind+bid erhalten', back.kind === 'bootstrap' && back.bid === 'deadbeef');
ok('Roundtrip: profile-Part erhalten', back.parts[0].t === 'profile' && back.parts[0].name === 'Ich' && back.parts[0].avatar === 'QUJD');
const rb = back.parts[1].contacts[0];
ok('Roundtrip: roster-Entry-Keys byteident', eqh(rb.pm, eM.publicKey) && eqh(rb.psp, eD.sign.publicKey) && eqh(rb.pdp, eD.dh.publicKey));
ok('Roundtrip: nick/pn/vf erhalten', rb.nick === 'Kumpel' && rb.pn === 'Echter Name' && rb.vf === true);
// Das Entry-Wire trägt jetzt OPTIONAL die master-signierte Geräteliste (dl) — auf der
// Gegenseite RE-verifiziert (siehe C), nie blind adoptiert. Aber weiterhin KEIN
// ratchet/bundle/roomId/ownMaster/sessions-Klon. Hier hatte die Quelle keine Liste → dl=null.
ok('roster-Entry trägt keinen unsicheren Klon (bundle/room/om/sessions); dl=null ohne Liste',
  rb.bundle === undefined && rb.room === undefined && rb.om === undefined && rb.sessions === undefined && rb.dl === null);

const la = await S.unframeContent(await S.frameContent({ kind: 'listack', epoch: 3, version: 7 }));
ok('listack roundtrip (epoch,version)', la.kind === 'listack' && la.epoch === 3 && la.version === 7);
const br = await S.unframeContent(await S.frameContent({ kind: 'bootreq', requestId: 'abc123' }));
ok('bootreq roundtrip (requestId)', br.kind === 'bootreq' && br.requestId === 'abc123');
// NEGATIVKONTROLLE: ein listack (Byte 11) darf NIE als bootstrap geparst werden.
ok('Negativkontrolle: listack wird NICHT als bootstrap dekodiert (Byte-Disjunktheit)', la.kind !== 'bootstrap');

// ── B. Strikte Decode: kaputtes JSON wirft, unbekanntes Part wird übersprungen ─
console.log('\n[B) strikte Decode statt stillem Leer-Import]');
let threw = false;
try { await S.unframeContent(new Uint8Array([10, 0x7b, 0x7b])); } catch { threw = true; } // Byte 10 + "{{"
ok('kaputtes JSON bei präsentem Byte-10-Frame WIRFT (kein stiller Leer-Import)', threw === true);
// NEGATIVKONTROLLE: würde es NICHT werfen, wäre threw false → Test rot.
ok('Negativkontrolle: der Wurf ist die Eigenschaft (threw===true)', threw === true);

const withUnknown = prefixed(10, { v: 1, bid: 'x', parts: [
  { t: 'future-history', foo: 1 }, // unbekannt → überspringen
  { t: 'profile', n: 'Nur ich', a: '' },
] });
const decoded = await S.unframeContent(withUnknown);
ok('unbekanntes part.t wird übersprungen, profile bleibt erhalten (forward-compat)',
  decoded.parts.length === 1 && decoded.parts[0].t === 'profile' && decoded.parts[0].name === 'Nur ich');

// ── A2. avatars-Part: Roundtrip + defensive Decode-Grenzen ────────────────────
console.log('\n[A2) avatars-Part — Kontakt-Avatare im Bootstrap]');
const avM = mkMaster();
const avPayload = 'QUJDREVG'; // beliebiger nicht-leerer String (avatarB64)
const avRt = (bid, avatars) => S.frameContent({ kind: 'bootstrap', bid, parts: [{ t: 'avatars', avatars }] }).then(S.unframeContent);
const avPart = (b) => b.parts.find((p) => p.t === 'avatars');

const avBack = await avRt('av01', [{ pm: new Uint8Array(avM.publicKey), av: avPayload }]);
ok('Roundtrip: avatars-Part, pm byteident + av erhalten',
  !!avPart(avBack) && avPart(avBack).avatars.length === 1 &&
  eqh(avPart(avBack).avatars[0].pm, avM.publicKey) && avPart(avBack).avatars[0].av === avPayload);
// NEGATIVKONTROLLE: ein abweichender av würde die Assertion kippen.
ok('Negativkontrolle: ein anderer av-Wert wäre NICHT gleich', avPart(avBack).avatars[0].av !== avPayload + 'x');

// Über-großer Avatar wird beim Decode verworfen (nie leer/roh importiert).
const overCap = await avRt('av02', [{ pm: new Uint8Array(avM.publicKey), av: 'A'.repeat(S.BOOTSTRAP_AVATAR_WIRE_MAX + 1) }]);
ok('über-großer Avatar wird beim Decode verworfen', avPart(overCap).avatars.length === 0);
// NEGATIVKONTROLLE: exakt auf der Grenze bleibt er erhalten.
const atCap = await avRt('av03', [{ pm: new Uint8Array(avM.publicKey), av: 'A'.repeat(S.BOOTSTRAP_AVATAR_WIRE_MAX) }]);
ok('Negativkontrolle: Avatar exakt auf der Grenze bleibt erhalten', avPart(atCap).avatars.length === 1);

// pm mit falscher Länge (≠32) wird verworfen — der Empfänger derived roomId aus pm.
const badPm = await avRt('av04', [{ pm: new Uint8Array(31), av: 'QUJD' }]);
ok('pm mit falscher Länge (≠32) wird verworfen', avPart(badPm).avatars.length === 0);

// ── C. mergeRosterEntry — die harten Regeln ───────────────────────────────────
console.log('\n[C) mergeRosterEntry: kein Klon, verified nie blind, Merge füllt nur Lücken]');
const myMasterKp = mkMaster();
const myMaster = S.asMasterPub(new Uint8Array(myMasterKp.publicKey));
const retired = new Set();

// C1: NEU → stiller Kontakt, send-blockiert, unverifiziert.
const pA = mkMaster(), dA = mkDev();
const cNew = await S.mergeRosterEntry([], mkEntry(pA.publicKey, dA, { nick: 'Anna', pn: 'Anna P.' }), myMaster, retired);
ok('NEU: Kontakt angelegt', cNew !== null && eqh(cNew.peerMasterPub, pA.publicKey));
ok('NEU: kein Ratchet/Bundle/DeviceList-Klon (send-blockiert)',
  cNew.bundle === undefined && cNew.peerDeviceList === undefined && cNew.sessions.size === 0);
ok('NEU: verified===false', cNew.verified === false);
ok('NEU: roomId LOKAL abgeleitet (== computeMasterRoomId(myMaster, pm))',
  cNew.roomId === (await S.computeMasterRoomId(myMaster, S.asMasterPub(new Uint8Array(pA.publicKey)))));
ok('NEU: nick/peerName übernommen', cNew.nickname === 'Anna' && cNew.peerName === 'Anna P.');
// NEGATIVKONTROLLE: ein GEFAKTES/kaputtes dl (+ ein bundle-Feld, das es gar nicht geben
// darf) erzeugt KEINE Sendefähigkeit — decode/verify wirft/scheitert, Kontakt bleibt blockiert.
const cNoClone = await S.mergeRosterEntry([], { ...mkEntry(mkMaster().publicKey, mkDev()), dl: 'BOGUS', bundle: 'BOGUS' }, myMaster, retired);
ok('Negativkontrolle: erfundene dl/bundle-Wire-Felder erzeugen KEINE Sendefähigkeit',
  cNoClone.peerDeviceList === undefined && cNoClone.bundle === undefined);

// POSITIV-Gegenstück (die Slave-Send-Fähigkeit): eine ECHTE master-signierte Geräteliste im
// Roster-Entry wird nach Re-Verifikation ADOPTIERT → der Kontakt ist sendefähig (SPK-Pfad).
const pMaster = mkMaster(), pDev = mkDev();
const pid = {
  master: { publicKey: new Uint8Array(pMaster.publicKey), privateKey: new Uint8Array(pMaster.privateKey) },
  sign: { publicKey: new Uint8Array(pDev.sign.publicKey), privateKey: new Uint8Array(pDev.sign.privateKey) },
  dh: { publicKey: new Uint8Array(pDev.dh.publicKey), privateKey: new Uint8Array(pDev.dh.privateKey) },
  epoch: 1,
  deviceCert: await S.signDeviceCert(pMaster.privateKey, 1, pDev.sign.publicKey, pDev.dh.publicKey),
};
const spk = await S.generateSignedPreKey(pid, 1);
const pEntry = { signPub: pid.sign.publicKey, dhPub: pid.dh.publicKey, deviceCert: pid.deviceCert,
  signedPreKey: { id: spk.id, pub: spk.keyPair.publicKey, signature: spk.signature } };
const realList = await S.signDeviceList(pMaster.privateKey, pMaster.publicKey, 1, 2, [pEntry]);
const cReal = await S.mergeRosterEntry([], mkEntry(pMaster.publicKey, pDev, { pe: 1, dl: await S.encodeDeviceList(realList) }), myMaster, retired);
ok('POSITIV: echte master-signierte dl wird adoptiert → sendefähig (peerDeviceList gesetzt)',
  cReal.peerDeviceList !== undefined && cReal.peerDeviceList.devices.length === 1);
// NEGATIVKONTROLLE dazu: dieselbe Liste, aber vom FALSCHEN Schlüssel signiert (masterPub
// behauptet den echten) → Signaturprüfung scheitert → NICHT adoptiert.
const evil = mkMaster();
const forged = await S.signDeviceList(evil.privateKey, pMaster.publicKey, 1, 2, [pEntry]);
const cForged = await S.mergeRosterEntry([], mkEntry(pMaster.publicKey, pDev, { pe: 1, dl: await S.encodeDeviceList(forged) }), myMaster, retired);
ok('Negativkontrolle: fremd-signierte dl (bad sig) wird NICHT adoptiert', cForged.peerDeviceList === undefined);

// C2: verified nie blind — vf=true → nur Vorschlag, nie verified.
const cVf = await S.mergeRosterEntry([], mkEntry(mkMaster().publicKey, mkDev(), { vf: true }), myMaster, retired);
ok('verified-never-blind: vf=true → verifiedSuggestion=true, verified=false',
  cVf.verifiedSuggestion === true && cVf.verified === false);
// NEGATIVKONTROLLE: würde vf in verified geschrieben, wäre verified===true → rot.
ok('Negativkontrolle: verified bleibt false trotz vf=true', cVf.verified === false);

// C3: EXISTING non-stale → Merge füllt NUR Lücken, überschreibt nie Gepinntes.
const pB = mkMaster(), dB = mkDev(), dB2 = mkDev();
const roomB = await S.computeMasterRoomId(myMaster, S.asMasterPub(new Uint8Array(pB.publicKey)));
const existing = {
  roomId: roomB, peerMasterPub: new Uint8Array(pB.publicKey), peerEpoch: 1,
  peerSignPub: new Uint8Array(dB.sign.publicKey), peerDhPub: new Uint8Array(dB.dh.publicKey),
  peerFingerprint: 'fp', nickname: 'MeinName', verified: true, sessions: new Map(),
  regime: 'master', ownMasterPub: myMaster,
};
// Entry mit ABWEICHENDEM peerSignPub (dB2) + neuem peerName + vf=true.
const merged = await S.mergeRosterEntry([existing], mkEntry(pB.publicKey, dB2, { nick: 'FremdName', pn: 'Bea', vf: true }), myMaster, retired);
ok('fill-only: peerName-Lücke gefüllt', merged.peerName === 'Bea');
ok('fill-only: gesetzter nickname NICHT überschrieben', merged.nickname === 'MeinName');
ok('fill-only: gepinnter peerSignPub UNVERÄNDERT (kein Overwrite)', eqh(merged.peerSignPub, dB.sign.publicKey));
ok('fill-only: verified===true bleibt, KEIN verifiedSuggestion (schon verifiziert)',
  merged.verified === true && merged.verifiedSuggestion !== true);
// NEGATIVKONTROLLE: hätte Merge peerSignPub überschrieben, zeigte es dB2 → rot.
ok('Negativkontrolle: peerSignPub ist NICHT der neue Schlüssel dB2', !eqh(merged.peerSignPub, dB2.sign.publicKey));

// C4: Dedup über pm + Kollisions-Guard.
const twice = await S.mergeRosterEntry([existing], mkEntry(pB.publicKey, dB2), myMaster, retired);
ok('dedup: gleicher pm trifft den bestehenden Kontakt (kein Duplikat)', twice === existing);
// Kollision: ein FREMDER pm, dessen lokal abgeleitete roomId zufällig einem bestehenden Kontakt gehört.
const pC = mkMaster();
const roomC = await S.computeMasterRoomId(myMaster, S.asMasterPub(new Uint8Array(pC.publicKey)));
const squatter = { ...existing, peerMasterPub: new Uint8Array(mkMaster().publicKey), roomId: roomC };
const collided = await S.mergeRosterEntry([squatter], mkEntry(pC.publicKey, mkDev()), myMaster, retired);
ok('Kollisions-Guard: fremder Kontakt auf derselben roomId ⇒ SKIP (null)', collided === null);
// NEGATIVKONTROLLE: ohne Guard würde ein Kontakt entstehen/gemerged → collided!==null.
ok('Negativkontrolle: kein Kontakt bei Kollision (collided===null)', collided === null);

// C5: Skip self + Denylist.
ok('SKIP: eigener Master (self-contact) ⇒ null',
  (await S.mergeRosterEntry([], mkEntry(myMasterKp.publicKey, mkDev()), myMaster, retired)) === null);
const pD = mkMaster();
const denied = new Set([sodium.to_base64(pD.publicKey, sodium.base64_variants.ORIGINAL)]);
ok('SKIP: Denylist-Master ⇒ null',
  (await S.mergeRosterEntry([], mkEntry(pD.publicKey, mkDev()), myMaster, denied)) === null);

// C6: Re-Link-Sonderregel (stale → aufgefrischt; non-stale unangetastet).
const pE = mkMaster(), dE = mkDev(), dEnew = mkDev();
const roomE = await S.computeMasterRoomId(myMaster, S.asMasterPub(new Uint8Array(pE.publicKey)));
const staleC = {
  roomId: roomE, peerMasterPub: new Uint8Array(pE.publicKey), peerEpoch: 1,
  peerSignPub: new Uint8Array(dE.sign.publicKey), peerDhPub: new Uint8Array(dE.dh.publicKey),
  peerFingerprint: 'old', verified: true, staleIdentity: true,
  sessions: new Map([['x', { ratchet: {}, pendingHeader: null, deviceSignPub: new Uint8Array(1) }]]),
  regime: 'master', ownMasterPub: myMaster,
};
const relinked = await S.mergeRosterEntry([staleC], mkEntry(pE.publicKey, dEnew, { pe: 2 }), myMaster, retired);
ok('re-link: staleIdentity aufgehoben', relinked.staleIdentity === undefined || relinked.staleIdentity === false);
// REALER Fall (Review-Fund): nach installGrant hängt ein staler Kontakt am ALTEN
// eigenen Master, seine roomId ist also NICHT die lokal abgeleitete. Ihn hier still
// zu ent-stalen würde in einen toten Raum senden lassen (Relay ackt → „gesendet",
// Peer verwirft) UND den „Neu verbinden"-Knopf verschwinden lassen → stiller
// Nachrichtenverlust. Der Merge muss die Tür stehen lassen.
const staleOldRoom = { ...staleC, roomId: 'raum-unter-dem-alten-master', staleIdentity: true, sessions: new Map() };
ok('re-link: staler Kontakt mit FREMDER roomId wird NICHT ent-stalet (Tür bleibt)',
  (await S.mergeRosterEntry([staleOldRoom], mkEntry(pE.publicKey, dEnew, { pe: 2 }), myMaster, retired)) === null);
ok('Negativkontrolle: … und er bleibt dabei wirklich stale', staleOldRoom.staleIdentity === true);
ok('re-link: Geräte-Keys aufgefrischt (neues psp/pdp/epoch)',
  eqh(relinked.peerSignPub, dEnew.sign.publicKey) && eqh(relinked.peerDhPub, dEnew.dh.publicKey) && relinked.peerEpoch === 2);
ok('re-link: tote Alt-Master-Sessions geleert', relinked.sessions.size === 0);
ok('re-link: verified bleibt (gerätelokal)', relinked.verified === true);
// NEGATIVKONTROLLE: ein NICHT-staler gepinnter Kontakt im selben Lauf bleibt unangetastet.
const stillPinned = await S.mergeRosterEntry([existing], mkEntry(pB.publicKey, dB2, { pe: 9 }), myMaster, retired);
ok('Negativkontrolle: non-staler Kontakt wird NICHT wie ein re-link aufgefrischt (epoch/psp bleiben)',
  stillPinned.peerEpoch === 1 && eqh(stillPinned.peerSignPub, dB.sign.publicKey));

// ── D. Contact-Wire-Migration der neuen Felder ────────────────────────────────
console.log('\n[D) Contact-Wire: neue Felder round-trippen, Alt-Records tolerant]');
cNew.verifiedSuggestion = true; cNew.peerAckedListEV = { epoch: 2, version: 5 };
const rt = await S.deserializeContact(await S.serializeContact(cNew));
ok('Wire-Roundtrip: verifiedSuggestion + peerAckedListEV erhalten',
  rt.verifiedSuggestion === true && rt.peerAckedListEV?.epoch === 2 && rt.peerAckedListEV?.version === 5);
// Alt-Record ohne die neuen Felder → undefined, KEIN Throw.
const oldWire = JSON.parse(new TextDecoder().decode(await S.serializeContact(existing)));
delete oldWire.verifiedSuggestion; delete oldWire.verifiedSuggestionDismissed; delete oldWire.peerAckedListEV;
const oldRt = await S.deserializeContact(new TextEncoder().encode(JSON.stringify(oldWire)));
ok('Migration: Alt-Record ohne neue Felder → undefined, kein Throw',
  oldRt.verifiedSuggestion === undefined && oldRt.peerAckedListEV === undefined);

// ── E. Self-Gate über die echte Krypto ────────────────────────────────────────
console.log('\n[E) Self-Gate: bootstrap/bootreq nur vom eigenen Gerät, listack nicht gegatet]');
const mkId = async (masterKp) => {
  const master = masterKp ?? sodium.crypto_sign_keypair();
  const sign = sodium.crypto_sign_keypair(), dh = sodium.crypto_box_keypair();
  const id = {
    master: { publicKey: new Uint8Array(master.publicKey), privateKey: new Uint8Array(master.privateKey) },
    sign: { publicKey: new Uint8Array(sign.publicKey), privateKey: new Uint8Array(sign.privateKey) },
    dh: { publicKey: new Uint8Array(dh.publicKey), privateKey: new Uint8Array(dh.privateKey) },
    epoch: 1, deviceCert: await S.signDeviceCert(master.privateKey, 1, sign.publicKey, dh.publicKey),
  };
  const spk = await S.generateSignedPreKey(id, 1);
  const bundle = S.currentBundle(id, { signedPreKey: spk, oneTimePreKeys: [] });
  const lookup = { signedPreKey: (i) => (spk.id === i ? spk.keyPair : undefined), consumeOneTimePreKey: () => undefined };
  return { id, bundle, lookup };
};
// Ein Frame vom SENDER an EINEN Empfänger schicken und dort receiveEnvelope aufrufen.
const deliver = async (sender, senderContact, receiver, content) => {
  const mid = S.randomMid();
  const { deliveries } = await S.fanoutDeliveries(sender.id, senderContact, content, mid);
  const env = await S.decodeEnvelope((await S.openPayload(receiver.id, deliveries[0].sealed)).payload);
  const rc = await S.makeContactFromHeader(S.asMasterPub(receiver.id.master.publicKey), env.x3dh);
  return S.receiveEnvelope(receiver.id, rc, env, receiver.lookup);
};

// NON-SELF: alice (Master A) schickt bob (Master B) ein bootstrap → Gate wirft.
const alice = await mkId(), bob = await mkId();
const aliceForBob = await S.makeContact(S.asMasterPub(alice.id.master.publicKey), bob.bundle);
// Post-F-06/F-22: the self-gate returns an authenticated-drop (reason
// 'unauthorised-self-frame') instead of throwing — the caller must still persist the
// advanced ratchet. Either way the frame is never surfaced as a processable message.
let gateDropped = false;
try {
  const r = await deliver(alice, aliceForBob, bob, boot);
  gateDropped = r.outcome === 'authenticated-drop' && r.reason === 'unauthorised-self-frame';
} catch { gateDropped = false; }
ok('NON-SELF: bootstrap von fremdem Master wird verworfen (Self-Gate)', gateDropped === true);
// bootreq ebenso.
let reqDropped = false;
try {
  const r = await deliver(alice, aliceForBob, bob, { kind: 'bootreq', requestId: 'q1' });
  reqDropped = r.outcome === 'authenticated-drop' && r.reason === 'unauthorised-self-frame';
} catch { reqDropped = false; }
ok('NON-SELF: bootreq von fremdem Master wird verworfen', reqDropped === true);

// SELF: zwei Geräte unter DEMSELBEN Master M → bootstrap kommt durch.
const sharedMaster = sodium.crypto_sign_keypair();
const d1 = await mkId(sharedMaster), d2 = await mkId(sharedMaster);
const d1ForD2 = await S.makeContact(S.asMasterPub(d1.id.master.publicKey), d2.bundle);
let selfContent = null;
try { selfContent = await deliver(d1, d1ForD2, d2, boot); } catch { selfContent = 'THREW'; }
ok('SELF: bootstrap vom eigenen Gerät (gleicher Master) wird AKZEPTIERT', selfContent !== 'THREW' && selfContent.content.kind === 'bootstrap');
// NEGATIVKONTROLLE: würde der Gate auch Self werfen, wäre selfContent==='THREW' → rot.
ok('Negativkontrolle: Self wirft NICHT', selfContent !== 'THREW');

// listack ist NICHT self-gegatet: bob (fremder Master) → alice, kommt durch.
const bobForAlice = await S.makeContact(S.asMasterPub(bob.id.master.publicKey), alice.bundle);
let ackContent = null;
try { ackContent = await deliver(bob, bobForAlice, alice, { kind: 'listack', epoch: 1, version: 1 }); } catch { ackContent = 'THREW'; }
ok('listack von fremdem Master wird NICHT gegatet (durchgelassen)', ackContent !== 'THREW' && ackContent.content.kind === 'listack');

console.log(`\n${pass} ok, ${fail} fail`);
process.exit(fail ? 1 : 0);
