#![forbid(unsafe_code)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, FileTimes, Metadata, OpenOptions},
    io::{self, Write},
    path::{Component, Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use orbit_content::{ChunkingConfig, ChunkingError};
use orbit_core::{
    ChangeRecord, ChangeRecordKind, ChunkRef, ContentId, DeviceId, FileId, FileManifest, PathError,
    PathId, ReconcileAction, ReconcileError, RelativePath, RevisionId, Tombstone, VersionVector,
    VersionVectorError, conflict_copy_path, reconcile_change,
};
use orbit_crypto::{
    ChangeAuthorization, CryptoError, DeviceIdentity, EncryptedObject, EnvelopeError, GroupKeys,
    ObjectKind,
};
use orbit_protocol::{
    ManifestError, ProtocolError, ProtocolLimits, decode_change_record, encode_change_record,
    validate_change_batch, wire,
};
use orbit_store::{Admission, LocalHead, MemberStatus, PendingMaterialization, Store, StoreError};
use tempfile::TempPath;
use thiserror::Error;
use uuid::Uuid;
use walkdir::WalkDir;

pub const DEFAULT_MAXIMUM_READ_ATTEMPTS: usize = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FullScanner {
    chunking: ChunkingConfig,
    maximum_read_attempts: usize,
}

impl FullScanner {
    pub fn new(chunking: ChunkingConfig, maximum_read_attempts: usize) -> Result<Self, ScanError> {
        if maximum_read_attempts == 0 {
            return Err(ScanError::InvalidMaximumReadAttempts);
        }
        Ok(Self {
            chunking,
            maximum_read_attempts,
        })
    }

    pub fn scan(
        &self,
        root: impl AsRef<Path>,
        identity: &DeviceIdentity,
        keys: &GroupKeys,
        store: &mut Store,
    ) -> Result<ScanReport, ScanError> {
        let device_id = identity.device_id();
        let member = store
            .group_member(keys.group_id(), device_id)?
            .ok_or(StoreError::UnknownGroupMember { device_id })?;
        if member.status != MemberStatus::Active {
            return Err(StoreError::MemberRevoked { device_id }.into());
        }
        let pending_materializations = store.pending_materializations(keys.group_id())?.len();
        if pending_materializations != 0 {
            return Err(ScanError::PendingMaterializations {
                count: pending_materializations,
            });
        }
        let files = discover_files(root.as_ref(), store)?;
        let mut report = ScanReport {
            files_discovered: files.len(),
            ..ScanReport::default()
        };
        let mut seen_paths = BTreeSet::new();

        for file in files {
            let path_id = keys.identify_path(&file.relative_path);
            seen_paths.insert(path_id);
            let outcome = self.ingest_file(&file, path_id, identity, keys, store)?;
            report.plaintext_bytes = report
                .plaintext_bytes
                .saturating_add(outcome.plaintext_bytes);
            report.chunks_stored = report.chunks_stored.saturating_add(outcome.chunks_stored);
            report.chunks_reused = report.chunks_reused.saturating_add(outcome.chunks_reused);
            if outcome.changed {
                report.file_changes += 1;
            } else {
                report.files_unchanged += 1;
            }
        }

        for head in store.local_heads(keys.group_id())? {
            if head.kind == ChangeRecordKind::File && !seen_paths.contains(&head.path_id) {
                commit_tombstone(head, identity, keys, store)?;
                report.tombstones_created += 1;
            }
        }

        Ok(report)
    }

    fn ingest_file(
        &self,
        file: &DiscoveredFile,
        path_id: PathId,
        identity: &DeviceIdentity,
        keys: &GroupKeys,
        store: &mut Store,
    ) -> Result<FileOutcome, ScanError> {
        let previous_head = store.local_head(keys.group_id(), path_id)?;
        let previous_record = previous_head
            .map(|head| load_local_record(head, keys, store))
            .transpose()?;
        let ingested = self.read_stable_file(file, keys, store)?;

        if let Some(ChangeRecord::File(previous)) = &previous_record {
            if previous.relative_path == file.relative_path
                && previous.size == ingested.plaintext_bytes
                && previous.modified_at_unix_ms == ingested.modified_at_unix_ms
                && previous.chunks == ingested.chunks
            {
                return Ok(FileOutcome {
                    changed: false,
                    plaintext_bytes: ingested.plaintext_bytes,
                    chunks_stored: ingested.chunks_stored,
                    chunks_reused: ingested.chunks_reused,
                });
            }
        }

        let (file_id, mut version) = match previous_record {
            Some(ChangeRecord::File(previous)) => (previous.file_id, previous.version),
            Some(ChangeRecord::Tombstone(previous)) => (previous.file_id, previous.version),
            None => (FileId::new(), VersionVector::default()),
        };
        version.increment(identity.device_id())?;
        let revision_id = RevisionId::new();
        let record = ChangeRecord::File(FileManifest {
            file_id,
            revision_id,
            relative_path: file.relative_path.clone(),
            size: ingested.plaintext_bytes,
            modified_at_unix_ms: ingested.modified_at_unix_ms,
            version,
            chunks: ingested.chunks,
        });
        commit_local_record(
            record,
            path_id,
            previous_head.map(|head| head.content_id),
            identity,
            keys,
            store,
        )?;

        Ok(FileOutcome {
            changed: true,
            plaintext_bytes: ingested.plaintext_bytes,
            chunks_stored: ingested.chunks_stored,
            chunks_reused: ingested.chunks_reused,
        })
    }

    fn read_stable_file(
        &self,
        discovered: &DiscoveredFile,
        keys: &GroupKeys,
        store: &mut Store,
    ) -> Result<IngestedFile, ScanError> {
        let mut chunks_stored = 0_usize;
        let mut chunks_reused = 0_usize;

        for _ in 0..self.maximum_read_attempts {
            let mut file =
                File::open(&discovered.absolute_path).map_err(|source| ScanError::Io {
                    path: discovered.absolute_path.clone(),
                    source,
                })?;
            let before = file_snapshot(
                file.metadata().map_err(|source| ScanError::Io {
                    path: discovered.absolute_path.clone(),
                    source,
                })?,
                &discovered.absolute_path,
            )?;
            let mut chunks = Vec::new();

            if before.length != 0 {
                for payload in self.chunking.stream(&mut file, keys) {
                    let payload = payload?;
                    let content_id = payload.content_id();
                    if store.has_object(keys.group_id(), content_id)? {
                        chunks_reused += 1;
                    } else {
                        let encrypted = keys.seal_chunk(payload.data())?;
                        let encrypted_bytes = encrypted.to_bytes()?;
                        match store.admit_object(
                            keys,
                            ObjectKind::Chunk,
                            content_id,
                            &encrypted_bytes,
                        )? {
                            Admission::Stored => chunks_stored += 1,
                            Admission::AlreadyPresent => chunks_reused += 1,
                        }
                    }
                    chunks.push(payload.descriptor().chunk_ref());
                }
            }

            let after_handle = file_snapshot(
                file.metadata().map_err(|source| ScanError::Io {
                    path: discovered.absolute_path.clone(),
                    source,
                })?,
                &discovered.absolute_path,
            )?;
            let after_path = match fs::metadata(&discovered.absolute_path) {
                Ok(metadata) => file_snapshot(metadata, &discovered.absolute_path)?,
                Err(source) if source.kind() == io::ErrorKind::NotFound => continue,
                Err(source) => {
                    return Err(ScanError::Io {
                        path: discovered.absolute_path.clone(),
                        source,
                    });
                }
            };
            if before == after_handle && before == after_path {
                return Ok(IngestedFile {
                    plaintext_bytes: before.length,
                    modified_at_unix_ms: unix_milliseconds(before.modified_at)?,
                    chunks,
                    chunks_stored,
                    chunks_reused,
                });
            }
        }

        Err(ScanError::FileChangedDuringRead {
            path: discovered.absolute_path.clone(),
            attempts: self.maximum_read_attempts,
        })
    }
}

impl Default for FullScanner {
    fn default() -> Self {
        Self {
            chunking: ChunkingConfig::default(),
            maximum_read_attempts: DEFAULT_MAXIMUM_READ_ATTEMPTS,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ScanReport {
    pub files_discovered: usize,
    pub file_changes: usize,
    pub files_unchanged: usize,
    pub tombstones_created: usize,
    pub chunks_stored: usize,
    pub chunks_reused: usize,
    pub plaintext_bytes: u64,
}

impl ScanReport {
    #[must_use]
    pub const fn changes_committed(self) -> usize {
        self.file_changes + self.tombstones_created
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IncomingApplier;

pub fn build_change_batch(
    keys: &GroupKeys,
    store: &mut Store,
    after_sequence: u64,
    maximum_records: usize,
) -> Result<wire::ChangeBatch, ChangeBatchBuildError> {
    let page = store.changes_after(keys.group_id(), after_sequence, maximum_records)?;
    let has_more = page
        .records
        .last()
        .map_or(page.high_watermark > after_sequence, |record| {
            record.sequence < page.high_watermark
        });
    let mut records = Vec::with_capacity(page.records.len());
    for record in page.records {
        let authentication = store
            .change_authentication(keys.group_id(), record.revision_id)?
            .ok_or(ChangeBatchBuildError::UnsignedChange {
                revision_id: record.revision_id,
            })?;
        if authentication.content_id != record.content_id {
            return Err(ChangeBatchBuildError::AuthenticationContentMismatch {
                revision_id: record.revision_id,
            });
        }
        let encrypted_record = store.load_object(keys, ObjectKind::Manifest, record.content_id)?;
        records.push(wire::EncryptedChange {
            sequence: record.sequence,
            revision_id: record.revision_id.as_uuid().as_bytes().to_vec(),
            content_id: record.content_id.as_bytes().to_vec(),
            encrypted_record,
            author_device_id: authentication
                .authorization
                .author_device_id
                .as_uuid()
                .as_bytes()
                .to_vec(),
            signature: authentication.authorization.signature.as_bytes().to_vec(),
        });
    }

    Ok(wire::ChangeBatch {
        records,
        high_watermark: page.high_watermark,
        has_more,
    })
}

#[derive(Debug, Error)]
pub enum ChangeBatchBuildError {
    #[error("revision {revision_id} has no signed provenance")]
    UnsignedChange { revision_id: RevisionId },
    #[error("revision {revision_id} authentication refers to another manifest")]
    AuthenticationContentMismatch { revision_id: RevisionId },
    #[error("durable store operation failed: {0}")]
    Store(#[from] StoreError),
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ChangeBatchAdmissionReport {
    pub records_committed: usize,
    pub records_replayed: usize,
    pub missing_content_ids: Vec<ContentId>,
    pub peer_high_watermark: u64,
}

pub fn admit_change_batch(
    peer_device_id: DeviceId,
    batch: &wire::ChangeBatch,
    keys: &GroupKeys,
    store: &mut Store,
    limits: ProtocolLimits,
) -> Result<ChangeBatchAdmissionReport, ChangeBatchAdmissionError> {
    let group_id = keys.group_id();
    let peer =
        store
            .group_member(group_id, peer_device_id)?
            .ok_or(StoreError::UnknownGroupMember {
                device_id: peer_device_id,
            })?;
    if peer.status != MemberStatus::Active {
        return Err(StoreError::MemberRevoked {
            device_id: peer_device_id,
        }
        .into());
    }

    let validated = validate_change_batch(batch, limits)?;
    let mut report = ChangeBatchAdmissionReport {
        peer_high_watermark: store.peer_high_watermark(group_id, peer_device_id)?,
        ..ChangeBatchAdmissionReport::default()
    };
    let mut missing_content_ids = BTreeSet::new();

    for change in &validated.records {
        let object = EncryptedObject::from_bytes(&change.encrypted_record)?;
        let plaintext = keys.open_manifest(change.content_id, &object)?;
        let record = decode_change_record(&plaintext)?;
        if record.revision_id() != change.revision_id {
            return Err(ChangeBatchAdmissionError::RevisionMismatch {
                advertised: change.revision_id,
                manifest: record.revision_id(),
            });
        }
        store.admit_object(
            keys,
            ObjectKind::Manifest,
            change.content_id,
            &change.encrypted_record,
        )?;
        store.admit_change_authentication(
            group_id,
            change.revision_id,
            change.content_id,
            change.authorization,
        )?;

        let referenced_chunks = match &record {
            ChangeRecord::File(manifest) => manifest
                .chunks
                .iter()
                .map(|chunk| chunk.content_id)
                .collect::<BTreeSet<_>>(),
            ChangeRecord::Tombstone(_) => BTreeSet::new(),
        };
        let mut record_missing = false;
        for &content_id in &referenced_chunks {
            if !store.has_object(group_id, content_id)? {
                record_missing = true;
                missing_content_ids.insert(content_id);
            }
        }
        if record_missing {
            continue;
        }

        let commit = store.commit_signed_change(
            keys,
            change.revision_id,
            change.content_id,
            change.authorization,
            &change.encrypted_record,
            referenced_chunks,
        )?;
        if commit.inserted {
            report.records_committed += 1;
        } else {
            report.records_replayed += 1;
        }
    }

    if !missing_content_ids.is_empty() {
        store.queue_object_requests(
            group_id,
            peer_device_id,
            missing_content_ids.iter().copied(),
        )?;
        report.missing_content_ids = missing_content_ids.into_iter().collect();
        return Ok(report);
    }

    let accepted_through = if validated.has_more {
        validated
            .records
            .last()
            .map_or(report.peer_high_watermark, |record| record.sequence)
    } else {
        validated.high_watermark
    };
    report.peer_high_watermark =
        store.record_peer_high_watermark(group_id, peer_device_id, accepted_through)?;
    Ok(report)
}

#[derive(Debug, Error)]
pub enum ChangeBatchAdmissionError {
    #[error("wire protocol rejected a change batch: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("change advertises revision {advertised}, manifest contains {manifest}")]
    RevisionMismatch {
        advertised: RevisionId,
        manifest: RevisionId,
    },
    #[error("cryptographic operation failed: {0}")]
    Crypto(#[from] CryptoError),
    #[error("encrypted object envelope is invalid: {0}")]
    Envelope(#[from] EnvelopeError),
    #[error("manifest codec rejected a record: {0}")]
    Manifest(#[from] ManifestError),
    #[error("durable store operation failed: {0}")]
    Store(#[from] StoreError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApplyOutcome {
    NoChange,
    KeptLocal {
        revision_id: RevisionId,
    },
    Applied {
        revision_id: RevisionId,
        kind: ChangeRecordKind,
    },
    MissingObjects {
        content_ids: Vec<ContentId>,
    },
    KeptBoth {
        canonical_revision: RevisionId,
        conflict_revision: RevisionId,
        conflict_path: RelativePath,
    },
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MaterializationRecoveryReport {
    pub completed: usize,
    pub blocked: Vec<BlockedMaterialization>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockedMaterialization {
    pub path_id: PathId,
    pub missing_content_ids: Vec<ContentId>,
}

impl IncomingApplier {
    pub fn apply(
        &self,
        root: impl AsRef<Path>,
        target_content_id: ContentId,
        authorization: ChangeAuthorization,
        keys: &GroupKeys,
        store: &mut Store,
    ) -> Result<ApplyOutcome, ApplyError> {
        let root = checked_sync_root(root.as_ref(), store)?;
        let mut loaded = load_record_object(target_content_id, keys, store)?;
        attach_incoming_authorization(&mut loaded, authorization, keys, store)?;
        let path_id = keys.identify_path(loaded.record.relative_path());

        if let Some(pending) = store
            .pending_materializations(keys.group_id())?
            .into_iter()
            .find(|pending| pending.path_id == path_id)
        {
            if pending.target_content_id != target_content_id {
                return Err(ApplyError::PendingTargetMismatch {
                    path_id,
                    pending: pending.target_content_id,
                    requested: target_content_id,
                });
            }
            let missing = preflight_chunks(&loaded.record, keys, store)?;
            if !missing.is_empty() {
                return Ok(ApplyOutcome::MissingObjects {
                    content_ids: missing,
                });
            }
            replay_materialization(&root, &pending, &loaded, keys, store)?;
            return Ok(applied_outcome(&loaded.record));
        }

        let local_head = store.local_head(keys.group_id(), path_id)?;
        let local_record = local_head
            .map(|head| load_head_record(head, keys, store))
            .transpose()?;
        let action = if let Some(local) = &local_record {
            reconcile_change(local, &loaded.record)?
        } else {
            ReconcileAction::UseIncoming
        };

        match action {
            ReconcileAction::NoChange => Ok(ApplyOutcome::NoChange),
            ReconcileAction::KeepLocal => Ok(ApplyOutcome::KeptLocal {
                revision_id: local_record
                    .as_ref()
                    .expect("KeepLocal requires a local record")
                    .revision_id(),
            }),
            ReconcileAction::KeepBoth {
                canonical_revision,
                conflict_revision,
            } => apply_keep_both(
                &root,
                local_head.expect("KeepBoth requires a local head"),
                local_record
                    .as_ref()
                    .expect("KeepBoth requires a local record"),
                &loaded,
                canonical_revision,
                conflict_revision,
                keys,
                store,
            ),
            ReconcileAction::UseIncoming => {
                let missing = preflight_chunks(&loaded.record, keys, store)?;
                if !missing.is_empty() {
                    return Ok(ApplyOutcome::MissingObjects {
                        content_ids: missing,
                    });
                }

                let stage_name = match loaded.record.kind() {
                    ChangeRecordKind::File => Some(random_stage_name()?),
                    ChangeRecordKind::Tombstone => None,
                };
                let expected_previous_content_id = local_head.map(|head| head.content_id);
                store.begin_signed_materialization(
                    keys.group_id(),
                    path_id,
                    loaded.record.revision_id(),
                    target_content_id,
                    expected_previous_content_id,
                    loaded.record.kind(),
                    stage_name.as_deref(),
                    loaded
                        .authorization
                        .expect("incoming records always have authorization"),
                )?;
                let pending = PendingMaterialization {
                    path_id,
                    target_content_id,
                    expected_previous_content_id,
                    kind: loaded.record.kind(),
                    stage_name,
                };
                replay_materialization(&root, &pending, &loaded, keys, store)?;
                Ok(applied_outcome(&loaded.record))
            }
        }
    }

    pub fn recover_pending_materializations(
        &self,
        root: impl AsRef<Path>,
        keys: &GroupKeys,
        store: &mut Store,
    ) -> Result<MaterializationRecoveryReport, ApplyError> {
        let root = checked_sync_root(root.as_ref(), store)?;
        let pending = store.pending_materializations(keys.group_id())?;
        let mut report = MaterializationRecoveryReport::default();

        for pending in pending {
            let loaded = load_record_object(pending.target_content_id, keys, store)?;
            validate_pending_record(&pending, &loaded.record, keys)?;
            let missing = preflight_chunks(&loaded.record, keys, store)?;
            if !missing.is_empty() {
                report.blocked.push(BlockedMaterialization {
                    path_id: pending.path_id,
                    missing_content_ids: missing,
                });
                continue;
            }
            replay_materialization(&root, &pending, &loaded, keys, store)?;
            report.completed += 1;
        }

        Ok(report)
    }
}

#[derive(Debug)]
struct LoadedRecord {
    record: ChangeRecord,
    content_id: ContentId,
    authorization: Option<ChangeAuthorization>,
    encrypted_bytes: Vec<u8>,
}

fn applied_outcome(record: &ChangeRecord) -> ApplyOutcome {
    ApplyOutcome::Applied {
        revision_id: record.revision_id(),
        kind: record.kind(),
    }
}

fn load_record_object(
    content_id: ContentId,
    keys: &GroupKeys,
    store: &mut Store,
) -> Result<LoadedRecord, ApplyError> {
    let encrypted_bytes = store.load_object(keys, ObjectKind::Manifest, content_id)?;
    let object = EncryptedObject::from_bytes(&encrypted_bytes)?;
    let plaintext = keys.open_manifest(content_id, &object)?;
    let record = decode_change_record(&plaintext)?;
    let authentication = store.change_authentication(keys.group_id(), record.revision_id())?;
    if authentication.is_some_and(|authentication| authentication.content_id != content_id) {
        return Err(ApplyError::AuthenticationContentMismatch {
            revision_id: record.revision_id(),
        });
    }
    Ok(LoadedRecord {
        record,
        content_id,
        authorization: authentication.map(|authentication| authentication.authorization),
        encrypted_bytes,
    })
}

fn attach_incoming_authorization(
    loaded: &mut LoadedRecord,
    authorization: ChangeAuthorization,
    keys: &GroupKeys,
    store: &mut Store,
) -> Result<(), ApplyError> {
    if let Some(existing) = loaded.authorization {
        if existing != authorization {
            return Err(ApplyError::ChangeAuthorizationMismatch {
                revision_id: loaded.record.revision_id(),
            });
        }
    } else {
        store.admit_change_authentication(
            keys.group_id(),
            loaded.record.revision_id(),
            loaded.content_id,
            authorization,
        )?;
        loaded.authorization = Some(authorization);
    }
    Ok(())
}

fn load_head_record(
    head: LocalHead,
    keys: &GroupKeys,
    store: &mut Store,
) -> Result<ChangeRecord, ApplyError> {
    let loaded = load_record_object(head.content_id, keys, store)?;
    if loaded.record.kind() != head.kind {
        return Err(ApplyError::RecordKindMismatch {
            path_id: head.path_id,
            expected: head.kind,
            actual: loaded.record.kind(),
        });
    }
    let actual_path_id = keys.identify_path(loaded.record.relative_path());
    if actual_path_id != head.path_id {
        return Err(ApplyError::RecordPathMismatch {
            expected: head.path_id,
            actual: actual_path_id,
        });
    }
    Ok(loaded.record)
}

fn validate_pending_record(
    pending: &PendingMaterialization,
    record: &ChangeRecord,
    keys: &GroupKeys,
) -> Result<(), ApplyError> {
    let actual_path_id = keys.identify_path(record.relative_path());
    if actual_path_id != pending.path_id {
        return Err(ApplyError::RecordPathMismatch {
            expected: pending.path_id,
            actual: actual_path_id,
        });
    }
    if record.kind() != pending.kind {
        return Err(ApplyError::RecordKindMismatch {
            path_id: pending.path_id,
            expected: pending.kind,
            actual: record.kind(),
        });
    }
    Ok(())
}

fn preflight_chunks(
    record: &ChangeRecord,
    keys: &GroupKeys,
    store: &mut Store,
) -> Result<Vec<ContentId>, ApplyError> {
    let ChangeRecord::File(manifest) = record else {
        return Ok(Vec::new());
    };
    let content_ids = manifest
        .chunks
        .iter()
        .map(|chunk| chunk.content_id)
        .collect::<BTreeSet<_>>();
    let mut missing = Vec::new();
    for content_id in content_ids {
        if !store.has_object(keys.group_id(), content_id)? {
            missing.push(content_id);
            continue;
        }
        store.load_object(keys, ObjectKind::Chunk, content_id)?;
    }
    Ok(missing)
}

#[allow(clippy::too_many_arguments)]
fn apply_keep_both(
    root: &Path,
    local_head: LocalHead,
    local: &ChangeRecord,
    incoming: &LoadedRecord,
    canonical_revision: RevisionId,
    conflict_revision: RevisionId,
    keys: &GroupKeys,
    store: &mut Store,
) -> Result<ApplyOutcome, ApplyError> {
    let (ChangeRecord::File(local), ChangeRecord::File(incoming_manifest)) =
        (local, &incoming.record)
    else {
        return Err(ApplyError::InvalidKeepBothDecision);
    };
    let incoming_is_canonical = if incoming_manifest.revision_id == canonical_revision
        && local.revision_id == conflict_revision
    {
        true
    } else if local.revision_id == canonical_revision
        && incoming_manifest.revision_id == conflict_revision
    {
        false
    } else {
        return Err(ApplyError::InvalidKeepBothDecision);
    };

    let local_missing = preflight_chunks(&ChangeRecord::File(local.clone()), keys, store)?;
    let incoming_missing = preflight_chunks(&incoming.record, keys, store)?;
    let missing = local_missing
        .into_iter()
        .chain(incoming_missing)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Ok(ApplyOutcome::MissingObjects {
            content_ids: missing,
        });
    }

    let conflict_source = if incoming_is_canonical {
        local
    } else {
        incoming_manifest
    };
    let conflict = derive_conflict_record(conflict_source, keys, store)?;
    let conflict_path = conflict.record.relative_path().clone();
    ensure_materialized(root, &conflict, None, true, keys, store)?;
    if incoming_is_canonical {
        ensure_materialized(
            root,
            incoming,
            Some(local_head.content_id),
            false,
            keys,
            store,
        )?;
    }

    Ok(ApplyOutcome::KeptBoth {
        canonical_revision,
        conflict_revision,
        conflict_path,
    })
}

fn derive_conflict_record(
    source: &FileManifest,
    keys: &GroupKeys,
    store: &mut Store,
) -> Result<LoadedRecord, ApplyError> {
    let device_label = source
        .version
        .iter()
        .max_by(
            |(left_device, left_counter), (right_device, right_counter)| {
                left_counter
                    .cmp(right_counter)
                    .then_with(|| left_device.cmp(right_device))
            },
        )
        .map_or_else(
            || "device".to_owned(),
            |(device_id, _)| {
                let device = device_id.as_uuid().simple().to_string();
                format!("device-{}", &device[..8])
            },
        );
    let relative_path = conflict_copy_path(
        &source.relative_path,
        &device_label,
        source.modified_at_unix_ms,
        source.revision_id,
    )?;
    let file_id = FileId::from_uuid(derive_conflict_uuid(
        keys,
        b"orbit/conflict-file-id/v1",
        source,
        &relative_path,
    ));
    let revision_id = RevisionId::from_uuid(derive_conflict_uuid(
        keys,
        b"orbit/conflict-revision-id/v1",
        source,
        &relative_path,
    ));
    let record = ChangeRecord::File(FileManifest {
        file_id,
        revision_id,
        relative_path,
        size: source.size,
        modified_at_unix_ms: source.modified_at_unix_ms,
        version: source.version.clone(),
        chunks: source.chunks.clone(),
    });
    let plaintext = encode_change_record(&record)?;
    let encrypted = keys.seal_manifest(&plaintext)?;
    let content_id = encrypted.content_id();
    let encrypted_bytes = encrypted.to_bytes()?;
    store.admit_object(keys, ObjectKind::Manifest, content_id, &encrypted_bytes)?;
    Ok(LoadedRecord {
        record,
        content_id,
        authorization: None,
        encrypted_bytes,
    })
}

fn derive_conflict_uuid(
    keys: &GroupKeys,
    domain: &[u8],
    source: &FileManifest,
    relative_path: &RelativePath,
) -> Uuid {
    let mut input = Vec::with_capacity(domain.len() + 32 + relative_path.as_str().len());
    input.extend_from_slice(domain);
    input.extend_from_slice(source.file_id.as_uuid().as_bytes());
    input.extend_from_slice(source.revision_id.as_uuid().as_bytes());
    input.extend_from_slice(relative_path.as_str().as_bytes());
    let digest = keys.identify_manifest(&input);
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn ensure_materialized(
    root: &Path,
    loaded: &LoadedRecord,
    expected_previous_content_id: Option<ContentId>,
    reject_occupied_path: bool,
    keys: &GroupKeys,
    store: &mut Store,
) -> Result<(), ApplyError> {
    let path_id = keys.identify_path(loaded.record.relative_path());
    if let Some(pending) = store
        .pending_materializations(keys.group_id())?
        .into_iter()
        .find(|pending| pending.path_id == path_id)
    {
        if pending.target_content_id != loaded.content_id {
            return Err(ApplyError::PendingTargetMismatch {
                path_id,
                pending: pending.target_content_id,
                requested: loaded.content_id,
            });
        }
        replay_materialization(root, &pending, loaded, keys, store)?;
        return Ok(());
    }

    if let Some(head) = store.local_head(keys.group_id(), path_id)? {
        if head.content_id == loaded.content_id {
            let existing = load_head_record(head, keys, store)?;
            if existing == loaded.record {
                return Ok(());
            }
            return Err(ApplyError::RecordContentMismatch { path_id });
        }
        if reject_occupied_path {
            return Err(ApplyError::ConflictPathOccupied {
                path: loaded.record.relative_path().clone(),
                existing: head.content_id,
                target: loaded.content_id,
            });
        }
    }

    let stage_name = match loaded.record.kind() {
        ChangeRecordKind::File => Some(random_stage_name()?),
        ChangeRecordKind::Tombstone => None,
    };
    if let Some(authorization) = loaded.authorization {
        store.begin_signed_materialization(
            keys.group_id(),
            path_id,
            loaded.record.revision_id(),
            loaded.content_id,
            expected_previous_content_id,
            loaded.record.kind(),
            stage_name.as_deref(),
            authorization,
        )?;
    } else {
        store.begin_materialization(
            keys.group_id(),
            path_id,
            loaded.content_id,
            expected_previous_content_id,
            loaded.record.kind(),
            stage_name.as_deref(),
        )?;
    }
    let pending = PendingMaterialization {
        path_id,
        target_content_id: loaded.content_id,
        expected_previous_content_id,
        kind: loaded.record.kind(),
        stage_name,
    };
    replay_materialization(root, &pending, loaded, keys, store)
}

fn replay_materialization(
    root: &Path,
    pending: &PendingMaterialization,
    loaded: &LoadedRecord,
    keys: &GroupKeys,
    store: &mut Store,
) -> Result<(), ApplyError> {
    validate_pending_record(pending, &loaded.record, keys)?;
    match &loaded.record {
        ChangeRecord::File(manifest) => {
            let stage_name = pending
                .stage_name
                .as_deref()
                .ok_or(ApplyError::MissingStageName(pending.path_id))?;
            materialize_file(root, manifest, stage_name, keys, store)?;
        }
        ChangeRecord::Tombstone(tombstone) => {
            materialize_tombstone(root, &tombstone.relative_path)?;
        }
    }

    let referenced_chunks = match &loaded.record {
        ChangeRecord::File(manifest) => manifest
            .chunks
            .iter()
            .map(|chunk| chunk.content_id)
            .collect::<Vec<_>>(),
        ChangeRecord::Tombstone(_) => Vec::new(),
    };
    if let Some(authorization) = loaded.authorization {
        store.commit_signed_local_change(
            keys,
            pending.path_id,
            pending.expected_previous_content_id,
            loaded.record.revision_id(),
            loaded.record.kind(),
            pending.target_content_id,
            authorization,
            &loaded.encrypted_bytes,
            referenced_chunks,
        )?;
    } else {
        store.commit_local_only_head(
            keys,
            pending.path_id,
            pending.expected_previous_content_id,
            loaded.record.kind(),
            pending.target_content_id,
            &loaded.encrypted_bytes,
            referenced_chunks,
        )?;
    }
    if !store.complete_materialization(
        keys.group_id(),
        pending.path_id,
        pending.target_content_id,
    )? {
        return Err(ApplyError::MaterializationJournalMissing {
            path_id: pending.path_id,
            target_content_id: pending.target_content_id,
        });
    }
    Ok(())
}

fn materialize_file(
    root: &Path,
    manifest: &FileManifest,
    stage_name: &str,
    keys: &GroupKeys,
    store: &mut Store,
) -> Result<(), ApplyError> {
    let destination = checked_destination(root, &manifest.relative_path, true)?;
    let parent = destination
        .parent()
        .expect("portable relative paths always have a parent");
    let stage_path = parent.join(stage_name);
    remove_existing_stage(&stage_path)?;
    let mut stage = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&stage_path)
        .map_err(|source| ApplyError::Io {
            path: stage_path.clone(),
            source,
        })?;
    let mut written = 0_u64;
    for chunk in &manifest.chunks {
        let encrypted = store.load_object(keys, ObjectKind::Chunk, chunk.content_id)?;
        let object = EncryptedObject::from_bytes(&encrypted)?;
        let plaintext = keys.open_chunk(chunk.content_id, &object)?;
        if plaintext.len() != chunk.plaintext_size as usize {
            return Err(ApplyError::ChunkSizeMismatch {
                content_id: chunk.content_id,
                expected: chunk.plaintext_size,
                actual: plaintext.len(),
            });
        }
        stage
            .write_all(&plaintext)
            .map_err(|source| ApplyError::Io {
                path: stage_path.clone(),
                source,
            })?;
        written = written
            .checked_add(u64::from(chunk.plaintext_size))
            .ok_or(ApplyError::FileSizeOverflow)?;
    }
    if written != manifest.size {
        return Err(ApplyError::FileSizeMismatch {
            expected: manifest.size,
            actual: written,
        });
    }
    stage.sync_all().map_err(|source| ApplyError::Io {
        path: stage_path.clone(),
        source,
    })?;
    drop(stage);

    TempPath::try_from_path(stage_path.clone())
        .map_err(|source| ApplyError::Io {
            path: stage_path.clone(),
            source,
        })?
        .persist(&destination)
        .map_err(|error| ApplyError::Io {
            path: destination.clone(),
            source: error.error,
        })?;
    let materialized = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&destination)
        .map_err(|source| ApplyError::Io {
            path: destination.clone(),
            source,
        })?;
    let modified = system_time_from_unix_milliseconds(manifest.modified_at_unix_ms)?;
    materialized
        .set_times(FileTimes::new().set_modified(modified))
        .map_err(|source| ApplyError::Io {
            path: destination.clone(),
            source,
        })?;
    materialized.sync_all().map_err(|source| ApplyError::Io {
        path: destination.clone(),
        source,
    })?;
    sync_directory(parent).map_err(|source| ApplyError::Io {
        path: parent.to_path_buf(),
        source,
    })?;
    Ok(())
}

fn materialize_tombstone(root: &Path, relative_path: &RelativePath) -> Result<(), ApplyError> {
    let destination = checked_destination(root, relative_path, false)?;
    match fs::symlink_metadata(&destination) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(ApplyError::SymbolicLink(destination))
        }
        Ok(metadata) if metadata.is_file() => {
            fs::remove_file(&destination).map_err(|source| ApplyError::Io {
                path: destination.clone(),
                source,
            })?;
            if let Some(parent) = destination.parent() {
                sync_directory(parent).map_err(|source| ApplyError::Io {
                    path: parent.to_path_buf(),
                    source,
                })?;
            }
            Ok(())
        }
        Ok(_) => Err(ApplyError::UnsupportedFileType(destination)),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(ApplyError::Io {
            path: destination,
            source,
        }),
    }
}

fn checked_sync_root(root: &Path, store: &Store) -> Result<PathBuf, ApplyError> {
    let metadata = fs::symlink_metadata(root).map_err(|source| ApplyError::Io {
        path: root.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() {
        return Err(ApplyError::SymbolicLink(root.to_path_buf()));
    }
    if !metadata.is_dir() {
        return Err(ApplyError::RootNotDirectory(root.to_path_buf()));
    }
    let root = root.canonicalize().map_err(|source| ApplyError::Io {
        path: root.to_path_buf(),
        source,
    })?;
    let store_root = store
        .root()
        .canonicalize()
        .map_err(|source| ApplyError::Io {
            path: store.root().to_path_buf(),
            source,
        })?;
    if root.starts_with(&store_root) || store_root.starts_with(&root) {
        return Err(ApplyError::RootStoreOverlap { root, store_root });
    }
    Ok(root)
}

fn checked_destination(
    root: &Path,
    relative_path: &RelativePath,
    create_parents: bool,
) -> Result<PathBuf, ApplyError> {
    let components = relative_path.as_str().split('/').collect::<Vec<_>>();
    let mut parent = root.to_path_buf();
    for component in &components[..components.len() - 1] {
        parent.push(component);
        match fs::symlink_metadata(&parent) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(ApplyError::SymbolicLink(parent));
            }
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => return Err(ApplyError::UnsupportedFileType(parent)),
            Err(source) if source.kind() == io::ErrorKind::NotFound && create_parents => {
                fs::create_dir(&parent).map_err(|source| ApplyError::Io {
                    path: parent.clone(),
                    source,
                })?;
            }
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                return Ok(root.join(relative_path.as_str()));
            }
            Err(source) => {
                return Err(ApplyError::Io {
                    path: parent,
                    source,
                });
            }
        }
    }
    let destination = parent.join(components[components.len() - 1]);
    match fs::symlink_metadata(&destination) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(ApplyError::SymbolicLink(destination))
        }
        Ok(metadata) if metadata.is_file() => Ok(destination),
        Ok(_) => Err(ApplyError::UnsupportedFileType(destination)),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(destination),
        Err(source) => Err(ApplyError::Io {
            path: destination,
            source,
        }),
    }
}

fn remove_existing_stage(stage_path: &Path) -> Result<(), ApplyError> {
    match fs::symlink_metadata(stage_path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(ApplyError::SymbolicLink(stage_path.to_path_buf()))
        }
        Ok(metadata) if metadata.is_file() => {
            fs::remove_file(stage_path).map_err(|source| ApplyError::Io {
                path: stage_path.to_path_buf(),
                source,
            })?;
            Ok(())
        }
        Ok(_) => Err(ApplyError::UnsupportedFileType(stage_path.to_path_buf())),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(ApplyError::Io {
            path: stage_path.to_path_buf(),
            source,
        }),
    }
}

fn random_stage_name() -> Result<String, ApplyError> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(|_| ApplyError::Randomness)?;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(random.len() * 2);
    for byte in random {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    Ok(format!(".orbit-stage-{encoded}.tmp"))
}

fn system_time_from_unix_milliseconds(value: i64) -> Result<SystemTime, ApplyError> {
    let duration = Duration::from_millis(value.unsigned_abs());
    if value >= 0 {
        UNIX_EPOCH
            .checked_add(duration)
            .ok_or(ApplyError::TimestampOutOfRange)
    } else {
        UNIX_EPOCH
            .checked_sub(duration)
            .ok_or(ApplyError::TimestampOutOfRange)
    }
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[derive(Debug, Error)]
pub enum ApplyError {
    #[error("sync root is not a directory: {0}")]
    RootNotDirectory(PathBuf),
    #[error("sync root {root} overlaps Orbit store {store_root}")]
    RootStoreOverlap { root: PathBuf, store_root: PathBuf },
    #[error("refusing to traverse symbolic link: {0}")]
    SymbolicLink(PathBuf),
    #[error("path has an unsupported file type: {0}")]
    UnsupportedFileType(PathBuf),
    #[error("failed to access {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("manifest resolves to path {actual:?}, expected {expected:?}")]
    RecordPathMismatch { expected: PathId, actual: PathId },
    #[error("manifest for {path_id:?} contains {actual:?}, expected {expected:?}")]
    RecordKindMismatch {
        path_id: PathId,
        expected: ChangeRecordKind,
        actual: ChangeRecordKind,
    },
    #[error("manifest content does not match the existing local head at {path_id:?}")]
    RecordContentMismatch { path_id: PathId },
    #[error("revision {revision_id} authentication refers to another manifest")]
    AuthenticationContentMismatch { revision_id: RevisionId },
    #[error("revision {revision_id} already has different signed provenance")]
    ChangeAuthorizationMismatch { revision_id: RevisionId },
    #[error("reconciliation returned an inconsistent keep-both decision")]
    InvalidKeepBothDecision,
    #[error("conflict path {path} is occupied by {existing:?}, cannot store {target:?}")]
    ConflictPathOccupied {
        path: RelativePath,
        existing: ContentId,
        target: ContentId,
    },
    #[error("path {path_id:?} is applying {pending:?}, not requested target {requested:?}")]
    PendingTargetMismatch {
        path_id: PathId,
        pending: ContentId,
        requested: ContentId,
    },
    #[error("file materialization for {0:?} has no staging filename")]
    MissingStageName(PathId),
    #[error("chunk {content_id:?} decrypted to {actual} bytes, expected {expected}")]
    ChunkSizeMismatch {
        content_id: ContentId,
        expected: u32,
        actual: usize,
    },
    #[error("materialized file has {actual} bytes, expected {expected}")]
    FileSizeMismatch { expected: u64, actual: u64 },
    #[error("materialized file size overflowed u64")]
    FileSizeOverflow,
    #[error("manifest timestamp is outside the platform SystemTime range")]
    TimestampOutOfRange,
    #[error(
        "materialization journal disappeared for path {path_id:?} target {target_content_id:?}"
    )]
    MaterializationJournalMissing {
        path_id: PathId,
        target_content_id: ContentId,
    },
    #[error("operating system randomness is unavailable")]
    Randomness,
    #[error("change reconciliation failed: {0}")]
    Reconcile(#[from] ReconcileError),
    #[error("conflict path is invalid: {0}")]
    Path(#[from] PathError),
    #[error("cryptographic operation failed: {0}")]
    Crypto(#[from] CryptoError),
    #[error("encrypted object envelope is invalid: {0}")]
    Envelope(#[from] EnvelopeError),
    #[error("manifest codec rejected a record: {0}")]
    Manifest(#[from] ManifestError),
    #[error("durable store operation failed: {0}")]
    Store(#[from] StoreError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileSnapshot {
    length: u64,
    modified_at: SystemTime,
}

#[derive(Debug)]
struct IngestedFile {
    plaintext_bytes: u64,
    modified_at_unix_ms: i64,
    chunks: Vec<ChunkRef>,
    chunks_stored: usize,
    chunks_reused: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileOutcome {
    changed: bool,
    plaintext_bytes: u64,
    chunks_stored: usize,
    chunks_reused: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DiscoveredFile {
    absolute_path: PathBuf,
    relative_path: RelativePath,
}

fn discover_files(root: &Path, store: &Store) -> Result<Vec<DiscoveredFile>, ScanError> {
    let root = root.canonicalize().map_err(|source| ScanError::Io {
        path: root.to_path_buf(),
        source,
    })?;
    if !root.is_dir() {
        return Err(ScanError::RootNotDirectory(root));
    }
    let store_root = store
        .root()
        .canonicalize()
        .map_err(|source| ScanError::Io {
            path: store.root().to_path_buf(),
            source,
        })?;
    if root.starts_with(&store_root) || store_root.starts_with(&root) {
        return Err(ScanError::RootStoreOverlap { root, store_root });
    }

    let mut by_comparison_key: BTreeMap<String, DiscoveredFile> = BTreeMap::new();
    for entry in WalkDir::new(&root).follow_links(false) {
        let entry = entry.map_err(|source| ScanError::Walk {
            path: source.path().map(Path::to_path_buf),
            source,
        })?;
        if entry.depth() == 0 || !entry.file_type().is_file() {
            continue;
        }

        let relative_path = portable_relative_path(&root, entry.path())?;
        let discovered = DiscoveredFile {
            absolute_path: entry.path().to_path_buf(),
            relative_path: relative_path.clone(),
        };
        if let Some(existing) =
            by_comparison_key.insert(relative_path.comparison_key().to_owned(), discovered)
        {
            return Err(ScanError::PathCollision {
                first: existing.relative_path,
                second: relative_path,
            });
        }
    }

    let mut files = by_comparison_key.into_values().collect::<Vec<_>>();
    files.sort_by(|left, right| {
        left.relative_path
            .as_str()
            .cmp(right.relative_path.as_str())
    });
    Ok(files)
}

fn portable_relative_path(root: &Path, path: &Path) -> Result<RelativePath, ScanError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| ScanError::DiscoveredPathOutsideRoot {
            root: root.to_path_buf(),
            path: path.to_path_buf(),
        })?;
    let mut components = Vec::new();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(ScanError::InvalidPathComponent(path.to_path_buf()));
        };
        let component = component
            .to_str()
            .ok_or_else(|| ScanError::NonUnicodePath(path.to_path_buf()))?;
        components.push(component);
    }
    RelativePath::new(components.join("/")).map_err(|source| ScanError::InvalidPortablePath {
        path: path.to_path_buf(),
        source,
    })
}

fn file_snapshot(metadata: Metadata, path: &Path) -> Result<FileSnapshot, ScanError> {
    if !metadata.is_file() {
        return Err(ScanError::FileTypeChanged(path.to_path_buf()));
    }
    Ok(FileSnapshot {
        length: metadata.len(),
        modified_at: metadata.modified().map_err(|source| ScanError::Io {
            path: path.to_path_buf(),
            source,
        })?,
    })
}

fn unix_milliseconds(value: SystemTime) -> Result<i64, ScanError> {
    match value.duration_since(UNIX_EPOCH) {
        Ok(duration) => {
            i64::try_from(duration.as_millis()).map_err(|_| ScanError::TimestampOutOfRange)
        }
        Err(error) => {
            let magnitude = i64::try_from(error.duration().as_millis())
                .map_err(|_| ScanError::TimestampOutOfRange)?;
            magnitude
                .checked_neg()
                .ok_or(ScanError::TimestampOutOfRange)
        }
    }
}

fn load_local_record(
    head: LocalHead,
    keys: &GroupKeys,
    store: &mut Store,
) -> Result<ChangeRecord, ScanError> {
    let encrypted_bytes = store.load_object(keys, ObjectKind::Manifest, head.content_id)?;
    let object = EncryptedObject::from_bytes(&encrypted_bytes)?;
    let plaintext = keys.open_manifest(head.content_id, &object)?;
    let record = decode_change_record(&plaintext)?;
    if record.kind() != head.kind {
        return Err(ScanError::LocalHeadKindMismatch {
            path_id: head.path_id,
            expected: head.kind,
            actual: record.kind(),
        });
    }
    let relative_path = match &record {
        ChangeRecord::File(manifest) => &manifest.relative_path,
        ChangeRecord::Tombstone(tombstone) => &tombstone.relative_path,
    };
    if keys.identify_path(relative_path) != head.path_id {
        return Err(ScanError::LocalHeadPathMismatch {
            path_id: head.path_id,
        });
    }
    Ok(record)
}

fn commit_local_record(
    record: ChangeRecord,
    path_id: PathId,
    expected_previous: Option<ContentId>,
    identity: &DeviceIdentity,
    keys: &GroupKeys,
    store: &mut Store,
) -> Result<(), ScanError> {
    let (revision_id, referenced_chunks) = match &record {
        ChangeRecord::File(manifest) => (
            manifest.revision_id,
            manifest
                .chunks
                .iter()
                .map(|chunk| chunk.content_id)
                .collect::<Vec<_>>(),
        ),
        ChangeRecord::Tombstone(tombstone) => (tombstone.revision_id, Vec::new()),
    };
    let plaintext = encode_change_record(&record)?;
    let encrypted = keys.seal_manifest(&plaintext)?;
    let content_id = encrypted.content_id();
    let encrypted_bytes = encrypted.to_bytes()?;
    let authorization = identity.authorize_change(keys.group_id(), revision_id, content_id);
    store.commit_signed_local_change(
        keys,
        path_id,
        expected_previous,
        revision_id,
        record.kind(),
        content_id,
        authorization,
        &encrypted_bytes,
        referenced_chunks,
    )?;
    Ok(())
}

fn commit_tombstone(
    head: LocalHead,
    identity: &DeviceIdentity,
    keys: &GroupKeys,
    store: &mut Store,
) -> Result<(), ScanError> {
    let previous = load_local_record(head, keys, store)?;
    let ChangeRecord::File(previous) = previous else {
        return Err(ScanError::LocalHeadKindMismatch {
            path_id: head.path_id,
            expected: ChangeRecordKind::File,
            actual: ChangeRecordKind::Tombstone,
        });
    };
    let mut version = previous.version;
    version.increment(identity.device_id())?;
    let record = ChangeRecord::Tombstone(Tombstone {
        file_id: previous.file_id,
        revision_id: RevisionId::new(),
        relative_path: previous.relative_path,
        deleted_at_unix_ms: unix_milliseconds(SystemTime::now())?,
        version,
    });
    commit_local_record(
        record,
        head.path_id,
        Some(head.content_id),
        identity,
        keys,
        store,
    )
}

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("maximum read attempts must be at least one")]
    InvalidMaximumReadAttempts,
    #[error("scan root is not a directory: {0}")]
    RootNotDirectory(PathBuf),
    #[error("scan root {root} overlaps Orbit store {store_root}")]
    RootStoreOverlap { root: PathBuf, store_root: PathBuf },
    #[error("cannot scan while {count} materialization operations require recovery")]
    PendingMaterializations { count: usize },
    #[error("failed to access {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to walk {path:?}: {source}")]
    Walk {
        path: Option<PathBuf>,
        #[source]
        source: walkdir::Error,
    },
    #[error("discovered path {path} is outside scan root {root}")]
    DiscoveredPathOutsideRoot { root: PathBuf, path: PathBuf },
    #[error("discovered path has an unsupported component: {0}")]
    InvalidPathComponent(PathBuf),
    #[error("discovered path is not valid Unicode: {0}")]
    NonUnicodePath(PathBuf),
    #[error("discovered path {path} is not portable: {source}")]
    InvalidPortablePath {
        path: PathBuf,
        #[source]
        source: PathError,
    },
    #[error("portable paths {first} and {second} collide")]
    PathCollision {
        first: RelativePath,
        second: RelativePath,
    },
    #[error("file type changed while scanning {0}")]
    FileTypeChanged(PathBuf),
    #[error("file {path} kept changing across {attempts} read attempts")]
    FileChangedDuringRead { path: PathBuf, attempts: usize },
    #[error("filesystem timestamp is outside Orbit's millisecond representation")]
    TimestampOutOfRange,
    #[error("local head {path_id:?} stores {expected:?} but its manifest contains {actual:?}")]
    LocalHeadKindMismatch {
        path_id: PathId,
        expected: ChangeRecordKind,
        actual: ChangeRecordKind,
    },
    #[error("local head {path_id:?} manifest resolves to a different path")]
    LocalHeadPathMismatch { path_id: PathId },
    #[error("content chunking failed: {0}")]
    Chunking(#[from] ChunkingError),
    #[error("cryptographic operation failed: {0}")]
    Crypto(#[from] CryptoError),
    #[error("encrypted object envelope is invalid: {0}")]
    Envelope(#[from] EnvelopeError),
    #[error("manifest codec rejected a record: {0}")]
    Manifest(#[from] ManifestError),
    #[error("version vector update failed: {0}")]
    Version(#[from] VersionVectorError),
    #[error("durable store operation failed: {0}")]
    Store(#[from] StoreError),
}

#[cfg(test)]
mod tests {
    use std::fs;

    use orbit_core::GroupId;
    use orbit_crypto::{ChangeSignature, GroupSecret, IdentityError};
    use orbit_protocol::{ProtocolLimits, validate_change_batch};
    use orbit_store::MemberRole;

    use super::*;

    fn group(value: u128) -> GroupId {
        format!("{value:032x}").parse().unwrap()
    }

    fn keys() -> GroupKeys {
        GroupSecret::from_bytes([61; 32])
            .derive_keys(group(1))
            .unwrap()
    }

    fn identity(value: u8) -> DeviceIdentity {
        DeviceIdentity::from_secret_bytes([value; 32])
    }

    fn register_identity(value: u8, keys: &GroupKeys, store: &mut Store) -> DeviceIdentity {
        let identity = identity(value);
        store
            .add_group_member(keys.group_id(), identity.public_key(), MemberRole::Member)
            .unwrap();
        identity
    }

    fn scan_as(
        scanner: &FullScanner,
        root: &Path,
        identity_value: u8,
        keys: &GroupKeys,
        store: &mut Store,
    ) -> Result<ScanReport, ScanError> {
        let identity = register_identity(identity_value, keys, store);
        scanner.scan(root, &identity, keys, store)
    }

    fn apply_as(
        root: &Path,
        target_content_id: ContentId,
        record: &ChangeRecord,
        author_value: u8,
        keys: &GroupKeys,
        store: &mut Store,
    ) -> Result<ApplyOutcome, ApplyError> {
        let author = register_identity(author_value, keys, store);
        let authorization =
            author.authorize_change(keys.group_id(), record.revision_id(), target_content_id);
        IncomingApplier.apply(root, target_content_id, authorization, keys, store)
    }

    fn local_record(path: &str, keys: &GroupKeys, store: &mut Store) -> ChangeRecord {
        let relative_path = RelativePath::new(path).unwrap();
        let head = store
            .local_head(keys.group_id(), keys.identify_path(&relative_path))
            .unwrap()
            .unwrap();
        load_local_record(head, keys, store).unwrap()
    }

    fn reconstruct(manifest: &FileManifest, keys: &GroupKeys, store: &mut Store) -> Vec<u8> {
        let mut plaintext = Vec::new();
        for chunk in &manifest.chunks {
            let encrypted = store
                .load_object(keys, ObjectKind::Chunk, chunk.content_id)
                .unwrap();
            let object = EncryptedObject::from_bytes(&encrypted).unwrap();
            plaintext.extend_from_slice(&keys.open_chunk(chunk.content_id, &object).unwrap());
        }
        plaintext
    }

    fn admit_chunk(plaintext: &[u8], keys: &GroupKeys, store: &mut Store) -> ChunkRef {
        let encrypted = keys.seal_chunk(plaintext).unwrap();
        let content_id = encrypted.content_id();
        store
            .admit_object(
                keys,
                ObjectKind::Chunk,
                content_id,
                &encrypted.to_bytes().unwrap(),
            )
            .unwrap();
        ChunkRef {
            content_id,
            plaintext_size: u32::try_from(plaintext.len()).unwrap(),
        }
    }

    fn admit_record(record: &ChangeRecord, keys: &GroupKeys, store: &mut Store) -> ContentId {
        let plaintext = encode_change_record(record).unwrap();
        let encrypted = keys.seal_manifest(&plaintext).unwrap();
        let content_id = encrypted.content_id();
        store
            .admit_object(
                keys,
                ObjectKind::Manifest,
                content_id,
                &encrypted.to_bytes().unwrap(),
            )
            .unwrap();
        content_id
    }

    #[test]
    fn incoming_descendant_replaces_the_file_without_scanner_echo() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let root = temporary_directory.path().join("sync");
        let store_root = temporary_directory.path().join("store");
        fs::create_dir_all(root.join("docs")).unwrap();
        let destination = root.join("docs").join("report.txt");
        fs::write(&destination, b"local version").unwrap();
        let keys = keys();
        let scanner = FullScanner::default();
        let mut store = Store::open(&store_root).unwrap();
        scan_as(&scanner, &root, 1, &keys, &mut store).unwrap();

        let relative_path = RelativePath::new("docs/report.txt").unwrap();
        let path_id = keys.identify_path(&relative_path);
        let initial_head = store.local_head(keys.group_id(), path_id).unwrap().unwrap();
        let ChangeRecord::File(previous) =
            load_local_record(initial_head, &keys, &mut store).unwrap()
        else {
            panic!("expected file manifest");
        };
        let incoming_bytes = b"authenticated incoming version";
        let chunk = admit_chunk(incoming_bytes, &keys, &mut store);
        let mut version = previous.version.clone();
        version.increment(identity(2).device_id()).unwrap();
        let revision_id = RevisionId::new();
        let modified_at_unix_ms = 1_700_000_000_123_i64;
        let incoming = ChangeRecord::File(FileManifest {
            file_id: previous.file_id,
            revision_id,
            relative_path,
            size: incoming_bytes.len() as u64,
            modified_at_unix_ms,
            version,
            chunks: vec![chunk],
        });
        let target_content_id = admit_record(&incoming, &keys, &mut store);

        assert_eq!(
            apply_as(&root, target_content_id, &incoming, 2, &keys, &mut store,).unwrap(),
            ApplyOutcome::Applied {
                revision_id,
                kind: ChangeRecordKind::File,
            }
        );
        assert_eq!(fs::read(&destination).unwrap(), incoming_bytes);
        assert_eq!(
            unix_milliseconds(fs::metadata(&destination).unwrap().modified().unwrap()).unwrap(),
            modified_at_unix_ms
        );
        assert_eq!(
            store
                .local_head(keys.group_id(), path_id)
                .unwrap()
                .unwrap()
                .content_id,
            target_content_id
        );
        assert!(
            store
                .pending_materializations(keys.group_id())
                .unwrap()
                .is_empty()
        );

        let repeat = scan_as(&scanner, &root, 1, &keys, &mut store).unwrap();
        assert_eq!(repeat.changes_committed(), 0);
        assert_eq!(repeat.files_unchanged, 1);
        assert_eq!(
            apply_as(
                &root,
                initial_head.content_id,
                &ChangeRecord::File(previous),
                1,
                &keys,
                &mut store,
            )
            .unwrap(),
            ApplyOutcome::KeptLocal { revision_id }
        );
        assert_eq!(fs::read(&destination).unwrap(), incoming_bytes);
    }

    #[test]
    fn concurrent_files_materialize_a_deterministic_tracked_conflict_copy() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let root = temporary_directory.path().join("sync");
        let store_root = temporary_directory.path().join("store");
        fs::create_dir_all(root.join("docs")).unwrap();
        let destination = root.join("docs").join("report.txt");
        fs::write(&destination, b"common base").unwrap();
        let keys = keys();
        let scanner = FullScanner::default();
        let mut store = Store::open(&store_root).unwrap();
        scan_as(&scanner, &root, 1, &keys, &mut store).unwrap();
        let ChangeRecord::File(base) = local_record("docs/report.txt", &keys, &mut store) else {
            panic!("expected file manifest");
        };

        fs::write(&destination, b"losing local edit").unwrap();
        scan_as(&scanner, &root, 2, &keys, &mut store).unwrap();
        let ChangeRecord::File(local) = local_record("docs/report.txt", &keys, &mut store) else {
            panic!("expected file manifest");
        };
        let local_revision = local.revision_id;
        let incoming_bytes = b"canonical incoming edit";
        let incoming_chunk = admit_chunk(incoming_bytes, &keys, &mut store);
        let mut incoming_version = base.version;
        incoming_version.increment(identity(1).device_id()).unwrap();
        let incoming_revision = RevisionId::new();
        let incoming = ChangeRecord::File(FileManifest {
            file_id: base.file_id,
            revision_id: incoming_revision,
            relative_path: base.relative_path,
            size: incoming_bytes.len() as u64,
            modified_at_unix_ms: 1_700_000_000_123,
            version: incoming_version,
            chunks: vec![incoming_chunk],
        });
        let target_content_id = admit_record(&incoming, &keys, &mut store);

        let outcome = apply_as(&root, target_content_id, &incoming, 1, &keys, &mut store).unwrap();
        let ApplyOutcome::KeptBoth {
            canonical_revision,
            conflict_revision,
            conflict_path,
        } = outcome
        else {
            panic!("expected keep-both outcome");
        };
        assert_eq!(canonical_revision, incoming_revision);
        assert_eq!(conflict_revision, local_revision);
        assert_eq!(fs::read(&destination).unwrap(), incoming_bytes);
        let conflict_destination = root.join(conflict_path.as_str());
        assert_eq!(
            fs::read(&conflict_destination).unwrap(),
            b"losing local edit"
        );

        let original_head = store
            .local_head(
                keys.group_id(),
                keys.identify_path(incoming.relative_path()),
            )
            .unwrap()
            .unwrap();
        assert_eq!(original_head.content_id, target_content_id);
        let conflict_head = store
            .local_head(keys.group_id(), keys.identify_path(&conflict_path))
            .unwrap()
            .unwrap();
        let ChangeRecord::File(conflict_record) =
            load_local_record(conflict_head, &keys, &mut store).unwrap()
        else {
            panic!("expected conflict file manifest");
        };
        assert_ne!(conflict_record.file_id, local.file_id);
        assert_ne!(conflict_record.revision_id, local.revision_id);
        assert_eq!(conflict_record.relative_path, conflict_path);
        assert_eq!(conflict_record.version, local.version);
        assert_eq!(conflict_record.chunks, local.chunks);
        assert!(
            store
                .change_authentication(keys.group_id(), conflict_record.revision_id)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store
                .changes_after(keys.group_id(), 0, 10)
                .unwrap()
                .records
                .len(),
            3
        );

        let derived_again = derive_conflict_record(&local, &keys, &mut store).unwrap();
        assert_eq!(derived_again.content_id, conflict_head.content_id);
        assert_eq!(derived_again.record, ChangeRecord::File(conflict_record));
        assert_eq!(
            scan_as(&scanner, &root, 2, &keys, &mut store)
                .unwrap()
                .changes_committed(),
            0
        );
        assert_eq!(
            apply_as(&root, target_content_id, &incoming, 1, &keys, &mut store,).unwrap(),
            ApplyOutcome::NoChange
        );
    }

    #[test]
    fn concurrent_incoming_loser_is_materialized_without_replacing_local() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let root = temporary_directory.path().join("sync");
        let store_root = temporary_directory.path().join("store");
        fs::create_dir_all(&root).unwrap();
        let destination = root.join("report.txt");
        fs::write(&destination, b"common base").unwrap();
        let keys = keys();
        let scanner = FullScanner::default();
        let mut store = Store::open(&store_root).unwrap();
        scan_as(&scanner, &root, 1, &keys, &mut store).unwrap();
        let ChangeRecord::File(base) = local_record("report.txt", &keys, &mut store) else {
            panic!("expected file manifest");
        };

        fs::write(&destination, b"canonical local edit").unwrap();
        scan_as(&scanner, &root, 1, &keys, &mut store).unwrap();
        let ChangeRecord::File(local) = local_record("report.txt", &keys, &mut store) else {
            panic!("expected file manifest");
        };
        let incoming_bytes = b"losing incoming edit";
        let chunk = admit_chunk(incoming_bytes, &keys, &mut store);
        let mut version = base.version;
        version.increment(identity(2).device_id()).unwrap();
        let incoming_revision = RevisionId::new();
        let incoming = ChangeRecord::File(FileManifest {
            file_id: base.file_id,
            revision_id: incoming_revision,
            relative_path: base.relative_path,
            size: incoming_bytes.len() as u64,
            modified_at_unix_ms: 1_700_000_000_123,
            version,
            chunks: vec![chunk],
        });
        let target_content_id = admit_record(&incoming, &keys, &mut store);

        let ApplyOutcome::KeptBoth {
            canonical_revision,
            conflict_revision,
            conflict_path,
        } = apply_as(&root, target_content_id, &incoming, 2, &keys, &mut store).unwrap()
        else {
            panic!("expected keep-both outcome");
        };
        assert_eq!(canonical_revision, local.revision_id);
        assert_eq!(conflict_revision, incoming_revision);
        assert_eq!(fs::read(&destination).unwrap(), b"canonical local edit");
        assert_eq!(
            fs::read(root.join(conflict_path.as_str())).unwrap(),
            incoming_bytes
        );
        assert_eq!(
            scan_as(&scanner, &root, 1, &keys, &mut store)
                .unwrap()
                .changes_committed(),
            0
        );
    }

    #[test]
    fn edit_delete_reconciliation_keeps_concurrent_edits_and_applies_descendants() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let root = temporary_directory.path().join("sync");
        let store_root = temporary_directory.path().join("store");
        fs::create_dir_all(&root).unwrap();
        let destination = root.join("report.txt");
        fs::write(&destination, b"live local edit").unwrap();
        let keys = keys();
        let mut store = Store::open(&store_root).unwrap();
        scan_as(&FullScanner::default(), &root, 1, &keys, &mut store).unwrap();
        let ChangeRecord::File(local) = local_record("report.txt", &keys, &mut store) else {
            panic!("expected file manifest");
        };

        let mut concurrent_version = VersionVector::default();
        concurrent_version
            .increment(identity(2).device_id())
            .unwrap();
        let concurrent_tombstone = ChangeRecord::Tombstone(Tombstone {
            file_id: local.file_id,
            revision_id: RevisionId::new(),
            relative_path: local.relative_path.clone(),
            deleted_at_unix_ms: 1_700_000_000_123,
            version: concurrent_version,
        });
        let concurrent_content_id = admit_record(&concurrent_tombstone, &keys, &mut store);
        assert_eq!(
            apply_as(
                &root,
                concurrent_content_id,
                &concurrent_tombstone,
                2,
                &keys,
                &mut store,
            )
            .unwrap(),
            ApplyOutcome::KeptLocal {
                revision_id: local.revision_id,
            }
        );
        assert_eq!(fs::read(&destination).unwrap(), b"live local edit");

        let mut descendant_version = local.version.clone();
        descendant_version
            .increment(identity(2).device_id())
            .unwrap();
        let descendant_revision = RevisionId::new();
        let descendant_tombstone = ChangeRecord::Tombstone(Tombstone {
            file_id: local.file_id,
            revision_id: descendant_revision,
            relative_path: local.relative_path,
            deleted_at_unix_ms: 1_700_000_000_456,
            version: descendant_version,
        });
        let descendant_content_id = admit_record(&descendant_tombstone, &keys, &mut store);
        assert_eq!(
            apply_as(
                &root,
                descendant_content_id,
                &descendant_tombstone,
                2,
                &keys,
                &mut store,
            )
            .unwrap(),
            ApplyOutcome::Applied {
                revision_id: descendant_revision,
                kind: ChangeRecordKind::Tombstone,
            }
        );
        assert!(!destination.exists());
    }

    #[test]
    fn missing_chunks_are_reported_before_filesystem_or_journal_mutation() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let root = temporary_directory.path().join("sync");
        let store_root = temporary_directory.path().join("store");
        fs::create_dir_all(&root).unwrap();
        let keys = keys();
        let mut store = Store::open(&store_root).unwrap();
        let plaintext = b"not downloaded yet";
        let missing = keys.identify_chunk(plaintext);
        let relative_path = RelativePath::new("docs/missing.txt").unwrap();
        let path_id = keys.identify_path(&relative_path);
        let mut version = VersionVector::default();
        version.increment(identity(2).device_id()).unwrap();
        let record = ChangeRecord::File(FileManifest {
            file_id: FileId::new(),
            revision_id: RevisionId::new(),
            relative_path,
            size: plaintext.len() as u64,
            modified_at_unix_ms: 1_700_000_000_123,
            version,
            chunks: vec![ChunkRef {
                content_id: missing,
                plaintext_size: plaintext.len() as u32,
            }],
        });
        let target_content_id = admit_record(&record, &keys, &mut store);
        let author = register_identity(2, &keys, &mut store);
        let authorization =
            author.authorize_change(keys.group_id(), record.revision_id(), target_content_id);

        assert_eq!(
            IncomingApplier
                .apply(&root, target_content_id, authorization, &keys, &mut store,)
                .unwrap(),
            ApplyOutcome::MissingObjects {
                content_ids: vec![missing],
            }
        );
        assert!(
            store
                .change_authentication(keys.group_id(), record.revision_id())
                .unwrap()
                .is_some()
        );
        store
            .revoke_group_member(keys.group_id(), author.device_id())
            .unwrap();
        assert_eq!(
            IncomingApplier
                .apply(&root, target_content_id, authorization, &keys, &mut store,)
                .unwrap(),
            ApplyOutcome::MissingObjects {
                content_ids: vec![missing],
            }
        );
        assert!(!root.join("docs").exists());
        assert!(
            store
                .local_head(keys.group_id(), path_id)
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .pending_materializations(keys.group_id())
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn recovery_replays_partial_file_stages_and_tombstones_after_restart() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let root = temporary_directory.path().join("sync");
        let store_root = temporary_directory.path().join("store");
        fs::create_dir_all(root.join("docs")).unwrap();
        let destination = root.join("docs").join("report.txt");
        fs::write(&destination, b"old bytes").unwrap();
        let keys = keys();
        let scanner = FullScanner::default();
        let mut store = Store::open(&store_root).unwrap();
        scan_as(&scanner, &root, 1, &keys, &mut store).unwrap();

        let relative_path = RelativePath::new("docs/report.txt").unwrap();
        let path_id = keys.identify_path(&relative_path);
        let previous_head = store.local_head(keys.group_id(), path_id).unwrap().unwrap();
        let ChangeRecord::File(previous) =
            load_local_record(previous_head, &keys, &mut store).unwrap()
        else {
            panic!("expected file manifest");
        };
        let incoming_bytes = b"complete bytes reconstructed after restart";
        let chunk = admit_chunk(incoming_bytes, &keys, &mut store);
        let mut version = previous.version;
        version.increment(identity(2).device_id()).unwrap();
        let incoming = ChangeRecord::File(FileManifest {
            file_id: previous.file_id,
            revision_id: RevisionId::new(),
            relative_path: relative_path.clone(),
            size: incoming_bytes.len() as u64,
            modified_at_unix_ms: 1_700_000_000_123,
            version,
            chunks: vec![chunk],
        });
        let incoming_content_id = admit_record(&incoming, &keys, &mut store);
        let remote_identity = register_identity(2, &keys, &mut store);
        let incoming_authorization = remote_identity.authorize_change(
            keys.group_id(),
            incoming.revision_id(),
            incoming_content_id,
        );
        let stage_name = ".orbit-stage-00000000000000000000000000000001.tmp";
        store
            .begin_signed_materialization(
                keys.group_id(),
                path_id,
                incoming.revision_id(),
                incoming_content_id,
                Some(previous_head.content_id),
                ChangeRecordKind::File,
                Some(stage_name),
                incoming_authorization,
            )
            .unwrap();
        let stage_path = root.join("docs").join(stage_name);
        fs::write(&stage_path, b"partial plaintext").unwrap();
        assert!(
            store
                .revoke_group_member(keys.group_id(), remote_identity.device_id())
                .unwrap()
        );
        drop(store);

        let mut store = Store::open(&store_root).unwrap();
        assert!(matches!(
            scan_as(&scanner, &root, 1, &keys, &mut store),
            Err(ScanError::PendingMaterializations { count: 1 })
        ));
        assert_eq!(
            IncomingApplier
                .recover_pending_materializations(&root, &keys, &mut store)
                .unwrap(),
            MaterializationRecoveryReport {
                completed: 1,
                blocked: Vec::new(),
            }
        );
        assert_eq!(fs::read(&destination).unwrap(), incoming_bytes);
        assert!(!stage_path.exists());
        assert_eq!(
            IncomingApplier
                .recover_pending_materializations(&root, &keys, &mut store)
                .unwrap(),
            MaterializationRecoveryReport::default()
        );

        let ChangeRecord::File(incoming_manifest) = incoming else {
            unreachable!();
        };
        let mut tombstone_version = incoming_manifest.version;
        tombstone_version
            .increment(identity(3).device_id())
            .unwrap();
        let tombstone = ChangeRecord::Tombstone(Tombstone {
            file_id: incoming_manifest.file_id,
            revision_id: RevisionId::new(),
            relative_path,
            deleted_at_unix_ms: 1_700_000_000_456,
            version: tombstone_version,
        });
        let tombstone_content_id = admit_record(&tombstone, &keys, &mut store);
        let tombstone_author = register_identity(3, &keys, &mut store);
        let tombstone_authorization = tombstone_author.authorize_change(
            keys.group_id(),
            tombstone.revision_id(),
            tombstone_content_id,
        );
        store
            .begin_signed_materialization(
                keys.group_id(),
                path_id,
                tombstone.revision_id(),
                tombstone_content_id,
                Some(incoming_content_id),
                ChangeRecordKind::Tombstone,
                None,
                tombstone_authorization,
            )
            .unwrap();
        drop(store);

        let mut store = Store::open(&store_root).unwrap();
        assert_eq!(
            IncomingApplier
                .recover_pending_materializations(&root, &keys, &mut store)
                .unwrap()
                .completed,
            1
        );
        assert!(!destination.exists());
        let head = store.local_head(keys.group_id(), path_id).unwrap().unwrap();
        assert_eq!(head.content_id, tombstone_content_id);
        assert_eq!(head.kind, ChangeRecordKind::Tombstone);
        assert_eq!(
            scan_as(&scanner, &root, 1, &keys, &mut store)
                .unwrap()
                .changes_committed(),
            0
        );
    }

    #[test]
    fn tampered_chunks_are_rejected_before_materialization() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let root = temporary_directory.path().join("sync");
        let store_root = temporary_directory.path().join("store");
        fs::create_dir_all(&root).unwrap();
        let keys = keys();
        let mut store = Store::open(&store_root).unwrap();
        let plaintext = b"tamper target";
        let chunk = admit_chunk(plaintext, &keys, &mut store);
        let object_path = store.object_path(keys.group_id(), chunk.content_id);
        let mut encrypted = fs::read(&object_path).unwrap();
        *encrypted.last_mut().unwrap() ^= 0x01;
        fs::write(&object_path, encrypted).unwrap();
        let relative_path = RelativePath::new("tampered.txt").unwrap();
        let path_id = keys.identify_path(&relative_path);
        let mut version = VersionVector::default();
        version.increment(identity(2).device_id()).unwrap();
        let record = ChangeRecord::File(FileManifest {
            file_id: FileId::new(),
            revision_id: RevisionId::new(),
            relative_path,
            size: plaintext.len() as u64,
            modified_at_unix_ms: 1_700_000_000_123,
            version,
            chunks: vec![chunk],
        });
        let target_content_id = admit_record(&record, &keys, &mut store);

        assert!(matches!(
            apply_as(&root, target_content_id, &record, 2, &keys, &mut store,),
            Err(ApplyError::Store(StoreError::Crypto(
                CryptoError::Authentication
            )))
        ));
        assert!(!root.join("tampered.txt").exists());
        assert!(
            store
                .local_head(keys.group_id(), path_id)
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .pending_materializations(keys.group_id())
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn discovery_is_sorted_and_rejects_portable_collisions_before_mutation() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let root = temporary_directory.path().join("sync");
        let store_root = temporary_directory.path().join("store");
        fs::create_dir_all(root.join("docs")).unwrap();
        fs::write(root.join("z.txt"), b"z").unwrap();
        fs::write(root.join("docs").join("a.txt"), b"a").unwrap();
        let store = Store::open(&store_root).unwrap();

        let files = discover_files(&root, &store).unwrap();
        assert_eq!(
            files
                .iter()
                .map(|file| file.relative_path.as_str())
                .collect::<Vec<_>>(),
            vec!["docs/a.txt", "z.txt"]
        );

        fs::write(root.join("Straße.txt"), b"first").unwrap();
        fs::write(root.join("STRASSE.txt"), b"second").unwrap();
        assert!(matches!(
            discover_files(&root, &store),
            Err(ScanError::PathCollision { .. })
        ));
    }

    #[test]
    fn discovery_rejects_a_store_inside_the_scan_root() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let root = temporary_directory.path().join("sync");
        let store_root = root.join(".orbit");
        fs::create_dir_all(&root).unwrap();
        let store = Store::open(&store_root).unwrap();

        assert!(matches!(
            discover_files(&root, &store),
            Err(ScanError::RootStoreOverlap { .. })
        ));
    }

    #[test]
    fn full_scan_tracks_file_lifecycle_idempotently_across_restart() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let root = temporary_directory.path().join("sync");
        let store_root = temporary_directory.path().join("store");
        fs::create_dir_all(root.join("docs")).unwrap();
        let path = root.join("docs").join("report.txt");
        fs::write(&path, b"first version").unwrap();
        let keys = keys();
        let scanner = FullScanner::default();
        let mut store = Store::open(&store_root).unwrap();
        let local_identity = register_identity(7, &keys, &mut store);
        let local_device = local_identity.device_id();

        let initial = scanner
            .scan(&root, &local_identity, &keys, &mut store)
            .unwrap();
        assert_eq!(initial.files_discovered, 1);
        assert_eq!(initial.changes_committed(), 1);
        assert_eq!(initial.chunks_stored, 1);
        let first = match local_record("docs/report.txt", &keys, &mut store) {
            ChangeRecord::File(manifest) => manifest,
            ChangeRecord::Tombstone(_) => panic!("expected file manifest"),
        };
        assert_eq!(first.version.counter(local_device), 1);
        assert_eq!(reconstruct(&first, &keys, &mut store), b"first version");

        let repeat = scanner
            .scan(&root, &local_identity, &keys, &mut store)
            .unwrap();
        assert_eq!(repeat.file_changes, 0);
        assert_eq!(repeat.files_unchanged, 1);
        assert_eq!(repeat.chunks_reused, 1);
        assert_eq!(
            store
                .changes_after(keys.group_id(), 0, 10)
                .unwrap()
                .records
                .len(),
            1
        );
        drop(store);

        let mut store = Store::open(&store_root).unwrap();
        let after_restart = scanner
            .scan(&root, &local_identity, &keys, &mut store)
            .unwrap();
        assert_eq!(after_restart.changes_committed(), 0);
        fs::write(&path, b"second version is longer").unwrap();

        let modified = scanner
            .scan(&root, &local_identity, &keys, &mut store)
            .unwrap();
        assert_eq!(modified.file_changes, 1);
        let second = match local_record("docs/report.txt", &keys, &mut store) {
            ChangeRecord::File(manifest) => manifest,
            ChangeRecord::Tombstone(_) => panic!("expected file manifest"),
        };
        assert_eq!(second.file_id, first.file_id);
        assert_eq!(second.version.counter(local_device), 2);
        assert_eq!(
            reconstruct(&second, &keys, &mut store),
            b"second version is longer"
        );

        fs::remove_file(&path).unwrap();
        let deleted = scanner
            .scan(&root, &local_identity, &keys, &mut store)
            .unwrap();
        assert_eq!(deleted.tombstones_created, 1);
        let tombstone = match local_record("docs/report.txt", &keys, &mut store) {
            ChangeRecord::File(_) => panic!("expected tombstone"),
            ChangeRecord::Tombstone(tombstone) => tombstone,
        };
        assert_eq!(tombstone.file_id, first.file_id);
        assert_eq!(tombstone.version.counter(local_device), 3);

        fs::write(&path, b"restored").unwrap();
        let restored = scanner
            .scan(&root, &local_identity, &keys, &mut store)
            .unwrap();
        assert_eq!(restored.file_changes, 1);
        let restored = match local_record("docs/report.txt", &keys, &mut store) {
            ChangeRecord::File(manifest) => manifest,
            ChangeRecord::Tombstone(_) => panic!("expected restored file"),
        };
        assert_eq!(restored.file_id, first.file_id);
        assert_eq!(restored.version.counter(local_device), 4);
    }

    #[test]
    fn empty_files_have_canonical_zero_chunk_manifests() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let root = temporary_directory.path().join("sync");
        let store_root = temporary_directory.path().join("store");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("empty.txt"), []).unwrap();
        let keys = keys();
        let mut store = Store::open(&store_root).unwrap();

        let report = scan_as(&FullScanner::default(), &root, 1, &keys, &mut store).unwrap();
        assert_eq!(report.chunks_stored, 0);
        let manifest = match local_record("empty.txt", &keys, &mut store) {
            ChangeRecord::File(manifest) => manifest,
            ChangeRecord::Tombstone(_) => panic!("expected file manifest"),
        };
        assert_eq!(manifest.size, 0);
        assert!(manifest.chunks.is_empty());
    }

    #[test]
    fn case_only_renames_retain_file_identity() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let root = temporary_directory.path().join("sync");
        let store_root = temporary_directory.path().join("store");
        fs::create_dir_all(&root).unwrap();
        let original_path = root.join("Report.txt");
        fs::write(&original_path, b"same bytes").unwrap();
        let keys = keys();
        let mut store = Store::open(&store_root).unwrap();
        let local_identity = register_identity(1, &keys, &mut store);
        let local_device = local_identity.device_id();
        let scanner = FullScanner::default();
        scanner
            .scan(&root, &local_identity, &keys, &mut store)
            .unwrap();
        let original = match local_record("Report.txt", &keys, &mut store) {
            ChangeRecord::File(manifest) => manifest,
            ChangeRecord::Tombstone(_) => panic!("expected file manifest"),
        };

        let intermediate_path = root.join("rename-in-progress.tmp");
        fs::rename(&original_path, &intermediate_path).unwrap();
        fs::rename(&intermediate_path, root.join("report.txt")).unwrap();
        let report = scanner
            .scan(&root, &local_identity, &keys, &mut store)
            .unwrap();

        assert_eq!(report.file_changes, 1);
        assert_eq!(report.tombstones_created, 0);
        assert_eq!(store.local_heads(keys.group_id()).unwrap().len(), 1);
        let renamed = match local_record("report.txt", &keys, &mut store) {
            ChangeRecord::File(manifest) => manifest,
            ChangeRecord::Tombstone(_) => panic!("expected file manifest"),
        };
        assert_eq!(renamed.file_id, original.file_id);
        assert_eq!(renamed.version.counter(local_device), 2);
        assert_eq!(renamed.relative_path.as_str(), "report.txt");
    }

    #[cfg(unix)]
    #[test]
    fn scanner_does_not_follow_symbolic_links() {
        use std::os::unix::fs::symlink;

        let temporary_directory = tempfile::tempdir().unwrap();
        let root = temporary_directory.path().join("sync");
        let store_root = temporary_directory.path().join("store");
        fs::create_dir_all(&root).unwrap();
        let outside = temporary_directory.path().join("outside.txt");
        fs::write(&outside, b"outside").unwrap();
        symlink(&outside, root.join("linked.txt")).unwrap();
        let keys = keys();
        let mut store = Store::open(&store_root).unwrap();

        let report = scan_as(&FullScanner::default(), &root, 1, &keys, &mut store).unwrap();
        assert_eq!(report.files_discovered, 0);
        assert_eq!(report.changes_committed(), 0);
    }

    #[test]
    fn middle_insertions_reuse_existing_fastcdc_chunks() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let root = temporary_directory.path().join("sync");
        let store_root = temporary_directory.path().join("store");
        fs::create_dir_all(&root).unwrap();
        let path = root.join("large.bin");
        let original = (0..64 * 1024)
            .map(|index| ((index * 31) % 251) as u8)
            .collect::<Vec<_>>();
        fs::write(&path, &original).unwrap();
        let keys = keys();
        let mut store = Store::open(&store_root).unwrap();
        let scanner = FullScanner::new(ChunkingConfig::new(64, 256, 1024).unwrap(), 3).unwrap();
        scan_as(&scanner, &root, 1, &keys, &mut store).unwrap();

        let mut edited = original;
        edited.splice(32 * 1024..32 * 1024, b"inserted bytes".iter().copied());
        fs::write(&path, &edited).unwrap();
        let report = scan_as(&scanner, &root, 1, &keys, &mut store).unwrap();

        assert_eq!(report.file_changes, 1);
        assert!(report.chunks_stored > 0);
        assert!(report.chunks_reused > 0);
        let manifest = match local_record("large.bin", &keys, &mut store) {
            ChangeRecord::File(manifest) => manifest,
            ChangeRecord::Tombstone(_) => panic!("expected file manifest"),
        };
        assert_eq!(reconstruct(&manifest, &keys, &mut store), edited);
    }

    #[test]
    fn incomplete_discovery_never_infers_deletions() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let root = temporary_directory.path().join("sync");
        let store_root = temporary_directory.path().join("store");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("removed.txt"), b"keep its live head").unwrap();
        let keys = keys();
        let mut store = Store::open(&store_root).unwrap();
        let scanner = FullScanner::default();
        scan_as(&scanner, &root, 1, &keys, &mut store).unwrap();
        fs::remove_file(root.join("removed.txt")).unwrap();
        fs::write(root.join("Straße.txt"), b"first").unwrap();
        fs::write(root.join("STRASSE.txt"), b"second").unwrap();

        assert!(matches!(
            scan_as(&scanner, &root, 1, &keys, &mut store),
            Err(ScanError::PathCollision { .. })
        ));
        assert!(matches!(
            local_record("removed.txt", &keys, &mut store),
            ChangeRecord::File(_)
        ));
        assert_eq!(
            store
                .changes_after(keys.group_id(), 0, 10)
                .unwrap()
                .records
                .len(),
            1
        );
    }

    #[test]
    fn outbound_batches_include_signed_provenance_and_paginate() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let root = temporary_directory.path().join("sync");
        let store_root = temporary_directory.path().join("store");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("a.txt"), b"first").unwrap();
        fs::write(root.join("b.txt"), b"second").unwrap();
        let keys = keys();
        let mut store = Store::open(&store_root).unwrap();
        let author = register_identity(1, &keys, &mut store);
        FullScanner::default()
            .scan(&root, &author, &keys, &mut store)
            .unwrap();

        let first = build_change_batch(&keys, &mut store, 0, 1).unwrap();
        assert_eq!(first.records.len(), 1);
        assert!(first.has_more);
        let first_validated = validate_change_batch(&first, ProtocolLimits::default()).unwrap();
        assert_eq!(first_validated.records.len(), 1);
        assert_eq!(
            first_validated.records[0].authorization.author_device_id,
            author.device_id()
        );

        let second =
            build_change_batch(&keys, &mut store, first_validated.records[0].sequence, 1).unwrap();
        assert_eq!(second.records.len(), 1);
        assert!(!second.has_more);
        assert_eq!(second.high_watermark, first.high_watermark);
        validate_change_batch(&second, ProtocolLimits::default()).unwrap();
    }

    #[test]
    fn outbound_batches_refuse_unsigned_changes() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let keys = keys();
        let mut store = Store::open(temporary_directory.path()).unwrap();
        let relative_path = RelativePath::new("legacy.txt").unwrap();
        let mut version = VersionVector::default();
        version.increment(identity(1).device_id()).unwrap();
        let record = ChangeRecord::File(FileManifest {
            file_id: FileId::new(),
            revision_id: RevisionId::new(),
            relative_path,
            size: 0,
            modified_at_unix_ms: 1_700_000_000_123,
            version,
            chunks: Vec::new(),
        });
        let plaintext = encode_change_record(&record).unwrap();
        let encrypted = keys.seal_manifest(&plaintext).unwrap();
        let content_id = encrypted.content_id();
        store
            .commit_change(
                &keys,
                record.revision_id(),
                content_id,
                &encrypted.to_bytes().unwrap(),
                [],
            )
            .unwrap();

        assert!(matches!(
            build_change_batch(&keys, &mut store, 0, 10),
            Err(ChangeBatchBuildError::UnsignedChange { revision_id })
                if revision_id == record.revision_id()
        ));
    }

    #[test]
    fn signed_change_pages_wait_for_resumable_objects_before_advancing() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let source_root = temporary_directory.path().join("source-sync");
        let source_store_root = temporary_directory.path().join("source-store");
        let receiver_store_root = temporary_directory.path().join("receiver-store");
        fs::create_dir_all(&source_root).unwrap();
        fs::write(source_root.join("payload.bin"), b"peer transfer payload").unwrap();
        let keys = keys();
        let mut source_store = Store::open(&source_store_root).unwrap();
        let source_identity = register_identity(1, &keys, &mut source_store);
        FullScanner::default()
            .scan(&source_root, &source_identity, &keys, &mut source_store)
            .unwrap();
        let batch = build_change_batch(&keys, &mut source_store, 0, 10).unwrap();
        let ChangeRecord::File(manifest) = local_record("payload.bin", &keys, &mut source_store)
        else {
            panic!("expected file manifest");
        };
        let chunk_id = manifest.chunks[0].content_id;
        let encrypted_chunk = source_store
            .load_object(&keys, ObjectKind::Chunk, chunk_id)
            .unwrap();

        let mut receiver_store = Store::open(&receiver_store_root).unwrap();
        register_identity(1, &keys, &mut receiver_store);
        let blocked = admit_change_batch(
            source_identity.device_id(),
            &batch,
            &keys,
            &mut receiver_store,
            ProtocolLimits::default(),
        )
        .unwrap();
        assert_eq!(
            blocked,
            ChangeBatchAdmissionReport {
                records_committed: 0,
                records_replayed: 0,
                missing_content_ids: vec![chunk_id],
                peer_high_watermark: 0,
            }
        );
        assert_eq!(
            receiver_store
                .pending_object_requests(keys.group_id(), source_identity.device_id(), 10)
                .unwrap()[0]
                .content_id,
            chunk_id
        );

        receiver_store
            .begin_object_transfer(
                keys.group_id(),
                source_identity.device_id(),
                Uuid::from_u128(41),
                chunk_id,
                encrypted_chunk.len() as u64,
            )
            .unwrap();
        let split = encrypted_chunk.len() / 2;
        receiver_store
            .append_object_transfer(
                keys.group_id(),
                source_identity.device_id(),
                chunk_id,
                0,
                &encrypted_chunk[..split],
            )
            .unwrap();
        drop(receiver_store);

        let mut receiver_store = Store::open(&receiver_store_root).unwrap();
        receiver_store
            .begin_object_transfer(
                keys.group_id(),
                source_identity.device_id(),
                Uuid::from_u128(42),
                chunk_id,
                encrypted_chunk.len() as u64,
            )
            .unwrap();
        receiver_store
            .append_object_transfer(
                keys.group_id(),
                source_identity.device_id(),
                chunk_id,
                split as u64,
                &encrypted_chunk[split..],
            )
            .unwrap();
        receiver_store
            .complete_object_transfer(&keys, source_identity.device_id(), chunk_id)
            .unwrap();

        let admitted = admit_change_batch(
            source_identity.device_id(),
            &batch,
            &keys,
            &mut receiver_store,
            ProtocolLimits::default(),
        )
        .unwrap();
        assert_eq!(admitted.records_committed, 1);
        assert_eq!(admitted.peer_high_watermark, batch.high_watermark);
        assert!(admitted.missing_content_ids.is_empty());

        let replayed = admit_change_batch(
            source_identity.device_id(),
            &batch,
            &keys,
            &mut receiver_store,
            ProtocolLimits::default(),
        )
        .unwrap();
        assert_eq!(replayed.records_replayed, 1);
        assert_eq!(replayed.peer_high_watermark, batch.high_watermark);
        assert_eq!(
            receiver_store
                .changes_after(keys.group_id(), 0, 10)
                .unwrap()
                .records
                .len(),
            1
        );
    }

    #[test]
    fn scanner_rejects_unknown_and_revoked_identities_before_mutation() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let root = temporary_directory.path().join("sync");
        let store_root = temporary_directory.path().join("store");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("blocked.txt"), b"must not be admitted").unwrap();
        let keys = keys();
        let identity = identity(9);
        let mut store = Store::open(&store_root).unwrap();

        assert!(matches!(
            FullScanner::default().scan(&root, &identity, &keys, &mut store),
            Err(ScanError::Store(StoreError::UnknownGroupMember { device_id }))
                if device_id == identity.device_id()
        ));
        assert!(store.local_heads(keys.group_id()).unwrap().is_empty());
        assert!(
            store
                .changes_after(keys.group_id(), 0, 10)
                .unwrap()
                .records
                .is_empty()
        );

        store
            .add_group_member(keys.group_id(), identity.public_key(), MemberRole::Member)
            .unwrap();
        store
            .revoke_group_member(keys.group_id(), identity.device_id())
            .unwrap();
        assert!(matches!(
            FullScanner::default().scan(&root, &identity, &keys, &mut store),
            Err(ScanError::Store(StoreError::MemberRevoked { device_id }))
                if device_id == identity.device_id()
        ));
        assert!(store.local_heads(keys.group_id()).unwrap().is_empty());
    }

    #[test]
    fn incoming_apply_rejects_unknown_revoked_and_invalid_authors_before_mutation() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let root = temporary_directory.path().join("sync");
        let store_root = temporary_directory.path().join("store");
        fs::create_dir_all(&root).unwrap();
        let keys = keys();
        let author = identity(8);
        let mut store = Store::open(&store_root).unwrap();
        let relative_path = RelativePath::new("blocked.txt").unwrap();
        let path_id = keys.identify_path(&relative_path);
        let mut version = VersionVector::default();
        version.increment(author.device_id()).unwrap();
        let record = ChangeRecord::File(FileManifest {
            file_id: FileId::new(),
            revision_id: RevisionId::new(),
            relative_path,
            size: 0,
            modified_at_unix_ms: 1_700_000_000_123,
            version,
            chunks: Vec::new(),
        });
        let content_id = admit_record(&record, &keys, &mut store);
        let authorization =
            author.authorize_change(keys.group_id(), record.revision_id(), content_id);

        assert!(matches!(
            IncomingApplier.apply(&root, content_id, authorization, &keys, &mut store),
            Err(ApplyError::Store(StoreError::UnknownGroupMember { device_id }))
                if device_id == author.device_id()
        ));
        store
            .add_group_member(keys.group_id(), author.public_key(), MemberRole::Member)
            .unwrap();
        let mut invalid_signature = *authorization.signature.as_bytes();
        invalid_signature[0] ^= 0x01;
        let invalid_authorization = ChangeAuthorization {
            author_device_id: author.device_id(),
            signature: ChangeSignature::from_bytes(invalid_signature),
        };
        assert!(matches!(
            IncomingApplier.apply(&root, content_id, invalid_authorization, &keys, &mut store,),
            Err(ApplyError::Store(StoreError::Identity(
                IdentityError::InvalidSignature
            )))
        ));
        store
            .revoke_group_member(keys.group_id(), author.device_id())
            .unwrap();
        assert!(matches!(
            IncomingApplier.apply(&root, content_id, authorization, &keys, &mut store),
            Err(ApplyError::Store(StoreError::MemberRevoked { device_id }))
                if device_id == author.device_id()
        ));

        assert!(!root.join("blocked.txt").exists());
        assert!(
            store
                .local_head(keys.group_id(), path_id)
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .pending_materializations(keys.group_id())
                .unwrap()
                .is_empty()
        );
        assert!(
            store
                .change_authentication(keys.group_id(), record.revision_id())
                .unwrap()
                .is_none()
        );
    }
}
