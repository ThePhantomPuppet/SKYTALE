/**
 * Bundle entry for the Node test suites.
 *
 * The app code is browser-oriented (IndexedDB, Web Crypto, React), but the
 * crypto and conversation layers are deliberately transport- and
 * storage-agnostic, so they run under Node once bundled. `tests/run.mjs` bundles
 * this file with esbuild and each suite imports the result.
 *
 * Everything security-relevant that a suite needs must be re-exported here.
 */
export * from '../src/crypto/index';
export * from '../src/crypto/sodium';
export * from '../src/lib/session';
export {
  createFreshPreKeyState,
  loadOrCreatePreKeys,
  serializePreKeys,
  findSignedPreKey,
  findOneTimePreKey,
  consumeOneTimePreKey,
  currentBundle,
  ownSpkPublic,
} from '../src/lib/prekeys';
export { loadOrCreateIdentity } from '../src/lib/identity';
export { loadDeviceNames } from '../src/lib/devicenames';
export {
  startLinkOnN,
  offerReceivedOnN,
  beginLinkOnP,
  confirmLinkSession,
  createConfirmedNewDeviceLinkIntent,
  restoreConfirmedNewDeviceLinkSession,
  restoreDiscardedNewDeviceLinkSession,
  verifyConfirmedNewDeviceLinkGrant,
  verifyDiscardedNewDeviceLinkGrant,
  confirmedLinkGrantRows,
  confirmedLinkGrantAlreadyInstalled,
  completeLinkOnN,
  completeLinkOnP,
  LinkGrantDeliveryCancelledError,
  LinkGrantDeliveryPendingError,
  abortLink,
} from '../src/lib/linkflow';
export {
  CONFIRMED_NEW_DEVICE_LINK_KEY,
  classifyLinkGrantRelayRow,
  drainLinkGrantCandidates,
  saveConfirmedNewDeviceLinkIntent,
  loadConfirmedNewDeviceLinkIntent,
  loadDiscardedNewDeviceLinkIntents,
  discardConfirmedNewDeviceLinkIntent,
  clearConfirmedNewDeviceLinkIntent,
} from '../src/lib/linkRecovery';
export {
  PENDING_LINK_GRANT_KEY,
  PendingLinkGrantCorruptionError,
  sealPendingLinkGrantRecord,
  loadPendingLinkGrant,
  clearPendingLinkGrant,
  clearPendingLinkGrantAndRecover,
  recoverPendingLinkGrantAtBoot,
} from '../src/lib/linkIntent';
export {
  cancelPendingLinkGrantAndRevokeDevice,
  loadOrCreateOwnDeviceList,
  revokeDevice,
} from '../src/lib/devices';
export {
  aggregateDelivery,
  hasMessage,
  recallRegistryKey,
  recallRegistryHas,
  isValidRecallMid,
  normalizeRecallRegistry,
  addRecallRegistryEntry,
  MAX_RECALLS_PER_SCOPE,
  MAX_RECALLED_MIDS,
  migrateLegacyRecalledMids,
  moveRecallRegistryRoom,
  applyRecallRegistry,
  prepareRecalledMessageForAppend,
} from '../src/lib/messages';
export { loadContacts } from '../src/lib/store';
export { DECOY_CONTENT } from '../src/lib/decoyContent';
export { prepareOwnerRelaySlot, RelayClient } from '../src/lib/relay';
export {
  withVaultDb,
  switchVaultDb,
  currentDbName,
  deleteVaultDb,
  neutralizeVaultDb,
  vaultDbExists,
  loadVaultDbEnvelope,
  migrateVaultDb,
  fenceVaultDbWrites,
  ACCOUNT_RESTORE_LEASE_MS,
  beginAccountRestore,
  cancelAccountRestore,
  stageRestoreRecord,
  loadHeader,
  saveHeader,
  compareAndSwapHeader,
  compareAndSwapRecordsWithDeletes,
  saveRecord,
  loadRecord,
  pinTaskAccount,
  clearTaskAccount,
} from '../src/lib/db';
export {
  createBoundVault,
  unlockBoundVault,
  setDuressPassword,
  removeDuressPassword,
  openDecoyForPopulate,
  completeDecoyPromotion,
  completeDuressRemoval,
  duressEnabled,
  DuressEqualsRealError,
} from '../src/lib/vaultService';
export {
  PROMOTE_MARKER,
  promoteMarkerPresent,
  decoyPromotionJournal,
  markPromoteDecoy,
  markPromoteDecoyCopied,
  clearPromoteDecoy,
  DURESS_REMOVE_MARKER,
  duressRemovalMarkerPresent,
  markDuressRemoval,
  clearDuressRemoval,
} from '../src/lib/wipe';
export { derivePrfKek } from '../src/lib/biometric';
export {
  GROUP_PROTOCOL_VERSION,
  MAX_GROUP_MEMBERS,
  MAX_GROUP_DEVICES_PER_MEMBER,
  MAX_GROUP_FANOUT_DEVICES,
  MAX_GROUP_NAME_BYTES,
  MAX_GROUP_INLINE_ATTACHMENT_BYTES,
  MAX_GROUP_ATTACHMENT_FANOUT_BYTES,
  randomGroupId,
  memberMasterPub,
  memberEpoch,
  mergeGroupDirectories,
  groupBroadcastBundle,
  signGroupState,
  verifyGroupState,
  toGroupStateProof,
  fromGroupStateProof,
  toInvite,
  fromInvite,
  isGroupMember,
  isGroupMemberMaster,
  isGroupOwner,
  decideInvite,
  classifyGroupFrame,
  nextGroupRevision,
  applyGroupMemberDeviceList,
  groupFanoutToDevices,
  boundedGroupAttachmentPolicy,
} from '../src/lib/groups';
export {
  commitGroupMutation,
  loadPendingGroupMutationSnapshots,
  replacePendingGroupMutation,
  savePendingGroupMutation,
  loadPendingGroupMutations,
  clearPendingGroupMutation,
} from '../src/lib/groupMutations';
export {
  saveGroupRemovalTombstone,
  loadGroupRemovalTombstone,
  loadGroupRemovalTombstones,
  clearGroupRemovalTombstone,
  toGroupRemovalTombstoneWire,
  fromGroupRemovalTombstoneWire,
  sealGroupRemovalTombstoneRecord,
  groupRemovalTombstoneRecordKey,
  permitsGroupReadd,
} from '../src/lib/groupTombstones';
export { encSection, decSection, backupMetaAad, backupAttAad } from '../src/lib/backupSections';
export {
  exportBackup,
  importBackup,
  validateBackupManifest,
  regenerateBackupCryptoForRestore,
  sanitizeContactForRestore,
  remapDeviceNamesForRestore,
  LinkedDeviceBackupUnsupportedError,
} from '../src/lib/backup';
export { encryptBlob, decryptBlob, BLOB_CHUNK } from '../src/crypto/blob';
export { backgroundLockExpired } from '../src/lib/backgroundLock';
export { createVaultRuntimeLockManager } from '../src/lib/runtimeLock';
export {
  beginVaultRuntimeQuiesce,
  registerVaultRuntimeQuiescer,
} from '../src/lib/runtimeQuiesce';
export { requireExactBootstrapDelivery } from '../src/lib/bootstrap';
export { consumeExactByteStream, ExactStreamLengthError } from '../src/lib/exactStream';
export {
  MAX_AUDIO_ANALYSIS_BYTES,
  MAX_INLINE_IMAGE_BYTES,
  mayAnalyzeAudio,
  mayRenderInlineImage,
} from '../src/lib/mediaPolicy';
export {
  MAX_R2_PLAINTEXT_BYTES,
  InvalidR2DescriptorError,
  assertExactR2ContentLength,
  r2CiphertextLength,
  tryValidateR2Descriptor,
  validateR2Descriptor,
  validateR2UploadSession,
} from '../src/lib/r2Descriptor';
export {
  PRECACHE_PREFIX,
  assertStrictShellCsp,
  isScytalePrecache,
  matchVerifiedManifestAsset,
  matchVerifiedShell,
  navigationFallbackResponse,
  populateBuildPrecache,
  versionedPrecacheName,
} from '../src/lib/swPrecache';
export {
  ALWAYS_RECEIVE_INLINE_BYTES,
  AUTO_RECEIVE_CONTACT_CAP_BYTES,
  MIN_ORIGIN_HEADROOM_BYTES,
  MIN_ORIGIN_HEADROOM_FRACTION,
  RECV_CHUNK_RECORD_OVERHEAD_BYTES,
  RECV_TRANSFER_FIXED_OVERHEAD_BYTES,
  attachmentRecvReservationBytes,
  automaticRecvReservationBytes,
  hasOriginStorageHeadroom,
  mayAutoReceiveAttachment,
  remainingRecvReservationBytes,
  storedReceivedAttachmentBytes,
} from '../src/lib/storageQuota';
export { createKeyedSerialQueue } from '../src/lib/keyedQueue';
export {
  createContactInvite,
  decodeContactCode,
  publishContactInvite,
  resolveContactInvite,
  openContactInvite,
} from '../src/lib/contactCode';
export {
  OFFICIAL_ACCOUNT_ALIAS,
  OFFICIAL_ACCOUNT_BADGE,
  OFFICIAL_ACCOUNT_DISPLAY_NAME,
  OFFICIAL_ACCOUNT_MAX_DOCUMENT_BYTES,
  OFFICIAL_ACCOUNT_MANIFEST_SCHEMA,
  OFFICIAL_ACCOUNT_ROLE,
  OFFICIAL_ACCOUNT_ROOT_KEY_ID,
  OfficialAccountManifestError,
  assertCurrentOfficialAccountManifest,
  assertTimelyOfficialAccountManifest,
  base64urlDecode,
  base64urlEncode,
  canonicalOfficialAccountManifestJson,
  officialAccountManifestDigest,
  officialAccountSigningBytes,
  parseOfficialAccountManifest,
  unsignedOfficialAccountManifest,
  verifyOfficialAccountManifestSignature,
} from '../src/lib/officialAccountManifest';
export {
  OfficialAccountError,
  canonicalOfficialAccountDocument,
  extractOfficialAccountAlias,
  isOfficialAdminContact,
  isOfficialAdminMaster,
  isRevokedOfficialAdminContact,
  isRevokedOfficialAdminMaster,
  officialAccountConfigured,
  resolveOfficialAccount,
  verifyOfficialAccountDocument,
} from '../src/lib/officialAccount';
export {
  OFFICIAL_ACCOUNT_TRUST_RECORD_KEY,
  OfficialAccountTrustCorruptError,
  loadOfficialAccountTrust,
  saveOfficialAccountTrust,
} from '../src/lib/officialAccountStore';
