#![forbid(unsafe_code)]

use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, SystemTimeError, UNIX_EPOCH},
};

use orbit_core::{ChangeRecordKind, ContentId, DeviceId, GroupId, PathId, RevisionId};
use orbit_crypto::{
    ChangeAuthorization, ChangeSignature, CryptoError, DevicePublicKey, EncryptedObject,
    EnvelopeError, GroupKeys, IdentityError, ObjectKind,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

const DATABASE_FILENAME: &str = "catalog.sqlite3";
const OBJECTS_DIRECTORY: &str = "objects";
const STAGING_DIRECTORY: &str = "staging";
const TRANSFERS_DIRECTORY: &str = "transfers";
const MATERIALIZATION_STAGE_PREFIX: &str = ".orbit-stage-";
const MATERIALIZATION_STAGE_SUFFIX: &str = ".tmp";
const MATERIALIZATION_STAGE_RANDOM_HEX_LENGTH: usize = 32;
const SCHEMA_VERSION: i64 = 7;
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
pub const MAXIMUM_ENCRYPTED_OBJECT_BYTES: usize = 64 * 1024 * 1024;

pub struct Store {
    root: PathBuf,
    connection: Connection,
    recovery_report: RecoveryReport,
}

impl Store {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, StoreError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join(OBJECTS_DIRECTORY))?;
        fs::create_dir_all(root.join(TRANSFERS_DIRECTORY))?;
        let staging_directory = root.join(STAGING_DIRECTORY);
        fs::create_dir_all(&staging_directory)?;
        let removed_staging_files = cleanup_staging(&staging_directory)?;

        let mut connection = Connection::open(root.join(DATABASE_FILENAME))?;
        connection.busy_timeout(BUSY_TIMEOUT)?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        migrate(&mut connection)?;
        recover_incoming_object_transfers(&root, &connection)?;
        let removed_missing_objects = recover_missing_objects(&root, &connection)?;

        Ok(Self {
            root,
            connection,
            recovery_report: RecoveryReport {
                removed_staging_files,
                removed_missing_objects,
            },
        })
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub fn database_path(&self) -> PathBuf {
        self.root.join(DATABASE_FILENAME)
    }

    #[must_use]
    pub const fn recovery_report(&self) -> RecoveryReport {
        self.recovery_report
    }

    pub fn schema_version(&self) -> Result<i64, StoreError> {
        Ok(self
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))?)
    }

    pub fn add_group_member(
        &mut self,
        group_id: GroupId,
        public_key: DevicePublicKey,
        role: MemberRole,
    ) -> Result<MembershipAdmission, StoreError> {
        let device_id = public_key.device_id();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing = query_group_member(&transaction, group_id, device_id)?;
        if let Some(existing) = existing {
            if existing.public_key != public_key {
                return Err(StoreError::MemberKeyMismatch { device_id });
            }
            if existing.role != role {
                return Err(StoreError::MemberRoleMismatch {
                    device_id,
                    expected: existing.role,
                    actual: role,
                });
            }
            if existing.status == MemberStatus::Revoked {
                return Err(StoreError::MemberRevoked { device_id });
            }
            transaction.commit()?;
            return Ok(MembershipAdmission::AlreadyActive);
        }

        transaction.execute(
            "INSERT INTO group_members (
                group_id, device_id, public_key, role, status,
                added_at_unix_ms, revoked_at_unix_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)",
            params![
                &group_id.as_uuid().as_bytes()[..],
                &device_id.as_uuid().as_bytes()[..],
                &public_key.as_bytes()[..],
                encode_member_role(role),
                encode_member_status(MemberStatus::Active),
                current_unix_ms()?,
            ],
        )?;
        transaction.commit()?;
        Ok(MembershipAdmission::Added)
    }

    pub fn group_member(
        &self,
        group_id: GroupId,
        device_id: DeviceId,
    ) -> Result<Option<GroupMember>, StoreError> {
        query_group_member(&self.connection, group_id, device_id)
    }

    pub fn revoke_group_member(
        &self,
        group_id: GroupId,
        device_id: DeviceId,
    ) -> Result<bool, StoreError> {
        Ok(self.connection.execute(
            "UPDATE group_members
             SET status = ?3, revoked_at_unix_ms = ?4
             WHERE group_id = ?1 AND device_id = ?2 AND status = ?5",
            params![
                &group_id.as_uuid().as_bytes()[..],
                &device_id.as_uuid().as_bytes()[..],
                encode_member_status(MemberStatus::Revoked),
                current_unix_ms()?,
                encode_member_status(MemberStatus::Active),
            ],
        )? == 1)
    }

    pub fn verify_change_authorization(
        &self,
        group_id: GroupId,
        revision_id: RevisionId,
        content_id: ContentId,
        authorization: ChangeAuthorization,
    ) -> Result<(), StoreError> {
        let member = self
            .group_member(group_id, authorization.author_device_id)?
            .ok_or(StoreError::UnknownGroupMember {
                device_id: authorization.author_device_id,
            })?;
        if member.status != MemberStatus::Active {
            return Err(StoreError::MemberRevoked {
                device_id: member.device_id,
            });
        }
        member
            .public_key
            .verify_change(group_id, revision_id, content_id, authorization)?;
        Ok(())
    }

    pub fn change_authentication(
        &self,
        group_id: GroupId,
        revision_id: RevisionId,
    ) -> Result<Option<StoredChangeAuthentication>, StoreError> {
        query_change_authentication(&self.connection, group_id, revision_id)
    }

    pub fn admit_change_authentication(
        &mut self,
        group_id: GroupId,
        revision_id: RevisionId,
        content_id: ContentId,
        authorization: ChangeAuthorization,
    ) -> Result<ChangeAuthenticationAdmission, StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let admission = authenticate_change(
            &transaction,
            group_id,
            revision_id,
            content_id,
            authorization,
        )?;
        transaction.commit()?;
        Ok(admission)
    }

    #[must_use]
    pub fn object_path(&self, group_id: GroupId, content_id: ContentId) -> PathBuf {
        object_path_for(&self.root, group_id, content_id)
    }

    pub fn has_object(&self, group_id: GroupId, content_id: ContentId) -> Result<bool, StoreError> {
        let available = self
            .connection
            .query_row(
                "SELECT available FROM objects WHERE group_id = ?1 AND content_id = ?2",
                params![
                    &group_id.as_uuid().as_bytes()[..],
                    &content_id.as_bytes()[..]
                ],
                |row| row.get::<_, bool>(0),
            )
            .optional()?
            .unwrap_or(false);

        if !available {
            return Ok(false);
        }
        if self.object_path(group_id, content_id).is_file() {
            return Ok(true);
        }

        self.connection.execute(
            "UPDATE objects SET available = 0
             WHERE group_id = ?1 AND content_id = ?2",
            params![
                &group_id.as_uuid().as_bytes()[..],
                &content_id.as_bytes()[..]
            ],
        )?;
        Ok(false)
    }

    pub fn queue_object_requests(
        &mut self,
        group_id: GroupId,
        peer_device_id: DeviceId,
        content_ids: impl IntoIterator<Item = ContentId>,
    ) -> Result<usize, StoreError> {
        let mut candidates = Vec::new();
        for content_id in content_ids.into_iter().collect::<BTreeSet<_>>() {
            if !self.has_object(group_id, content_id)? {
                candidates.push(content_id);
            }
        }
        if candidates.is_empty() {
            return Ok(0);
        }

        let requested_at_unix_ms = current_unix_ms()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut inserted = 0;
        for content_id in candidates {
            inserted += transaction.execute(
                "INSERT INTO object_requests (
                    group_id, peer_device_id, content_id, requested_at_unix_ms
                )
                SELECT ?1, ?2, ?3, ?4
                WHERE NOT EXISTS (
                    SELECT 1 FROM objects
                    WHERE group_id = ?1 AND content_id = ?3 AND available = 1
                )
                ON CONFLICT(group_id, peer_device_id, content_id) DO NOTHING",
                params![
                    &group_id.as_uuid().as_bytes()[..],
                    &peer_device_id.as_uuid().as_bytes()[..],
                    &content_id.as_bytes()[..],
                    requested_at_unix_ms,
                ],
            )?;
        }
        transaction.commit()?;
        Ok(inserted)
    }

    pub fn pending_object_requests(
        &self,
        group_id: GroupId,
        peer_device_id: DeviceId,
        maximum: usize,
    ) -> Result<Vec<ObjectRequestState>, StoreError> {
        let maximum = i64::try_from(maximum).unwrap_or(i64::MAX);
        let mut statement = self.connection.prepare(
            "SELECT content_id, requested_at_unix_ms, attempt_count, last_attempt_at_unix_ms
             FROM object_requests
             WHERE group_id = ?1 AND peer_device_id = ?2
             ORDER BY requested_at_unix_ms, content_id
             LIMIT ?3",
        )?;
        let rows = statement
            .query_map(
                params![
                    &group_id.as_uuid().as_bytes()[..],
                    &peer_device_id.as_uuid().as_bytes()[..],
                    maximum,
                ],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, u64>(2)?,
                        row.get::<_, Option<i64>>(3)?,
                    ))
                },
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        rows.into_iter()
            .map(
                |(content_id, requested_at_unix_ms, attempt_count, last_attempt_at_unix_ms)| {
                    Ok(ObjectRequestState {
                        content_id: decode_content_id("object_requests.content_id", &content_id)?,
                        requested_at_unix_ms,
                        attempt_count,
                        last_attempt_at_unix_ms,
                    })
                },
            )
            .collect()
    }

    pub fn mark_object_request_attempt(
        &self,
        group_id: GroupId,
        peer_device_id: DeviceId,
        content_id: ContentId,
    ) -> Result<bool, StoreError> {
        let changed = self.connection.execute(
            "UPDATE object_requests
             SET attempt_count = attempt_count + 1, last_attempt_at_unix_ms = ?4
             WHERE group_id = ?1 AND peer_device_id = ?2 AND content_id = ?3",
            params![
                &group_id.as_uuid().as_bytes()[..],
                &peer_device_id.as_uuid().as_bytes()[..],
                &content_id.as_bytes()[..],
                current_unix_ms()?,
            ],
        )?;
        Ok(changed == 1)
    }

    pub fn begin_object_transfer(
        &mut self,
        group_id: GroupId,
        peer_device_id: DeviceId,
        request_id: Uuid,
        content_id: ContentId,
        encrypted_size: u64,
    ) -> Result<ObjectTransferAdmission, StoreError> {
        if request_id.is_nil() {
            return Err(StoreError::NilTransferRequestId);
        }
        let encrypted_size = checked_transfer_size(encrypted_size)?;
        if self.has_object(group_id, content_id)? {
            return Ok(ObjectTransferAdmission::AlreadyPresent);
        }
        let requested = self.connection.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM object_requests
                WHERE group_id = ?1 AND peer_device_id = ?2 AND content_id = ?3
             )",
            params![
                &group_id.as_uuid().as_bytes()[..],
                &peer_device_id.as_uuid().as_bytes()[..],
                &content_id.as_bytes()[..],
            ],
            |row| row.get::<_, bool>(0),
        )?;
        if !requested {
            return Err(StoreError::ObjectNotRequested {
                peer_device_id,
                content_id,
            });
        }

        if let Some(existing) =
            query_incoming_object_transfer(&self.connection, group_id, peer_device_id, content_id)?
        {
            if existing.encrypted_size != encrypted_size {
                return Err(StoreError::TransferSizeMismatch {
                    content_id,
                    expected: existing.encrypted_size,
                    actual: encrypted_size,
                });
            }
            self.connection.execute(
                "UPDATE incoming_object_transfers
                 SET request_id = ?4, updated_at_unix_ms = ?5
                 WHERE group_id = ?1 AND peer_device_id = ?2 AND content_id = ?3",
                params![
                    &group_id.as_uuid().as_bytes()[..],
                    &peer_device_id.as_uuid().as_bytes()[..],
                    &content_id.as_bytes()[..],
                    &request_id.as_bytes()[..],
                    current_unix_ms()?,
                ],
            )?;
            return Ok(ObjectTransferAdmission::Resuming {
                received_size: existing.received_size,
            });
        }

        let path = incoming_transfer_path_for(&self.root, group_id, peer_device_id, content_id);
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        file.sync_all()?;
        drop(file);
        let inserted = self.connection.execute(
            "INSERT INTO incoming_object_transfers (
                group_id, peer_device_id, request_id, content_id,
                encrypted_size, received_size, updated_at_unix_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6)",
            params![
                &group_id.as_uuid().as_bytes()[..],
                &peer_device_id.as_uuid().as_bytes()[..],
                &request_id.as_bytes()[..],
                &content_id.as_bytes()[..],
                encrypted_size,
                current_unix_ms()?,
            ],
        );
        if let Err(error) = inserted {
            let _ = fs::remove_file(path);
            return Err(error.into());
        }
        Ok(ObjectTransferAdmission::Started)
    }

    pub fn incoming_object_transfer(
        &self,
        group_id: GroupId,
        peer_device_id: DeviceId,
        content_id: ContentId,
    ) -> Result<Option<IncomingObjectTransfer>, StoreError> {
        query_incoming_object_transfer(&self.connection, group_id, peer_device_id, content_id)
    }

    pub fn append_object_transfer(
        &self,
        group_id: GroupId,
        peer_device_id: DeviceId,
        content_id: ContentId,
        expected_offset: u64,
        bytes: &[u8],
    ) -> Result<u64, StoreError> {
        let transfer =
            query_incoming_object_transfer(&self.connection, group_id, peer_device_id, content_id)?
                .ok_or(StoreError::ObjectTransferNotFound {
                    peer_device_id,
                    content_id,
                })?;
        if transfer.received_size != expected_offset {
            return Err(StoreError::TransferOffsetMismatch {
                content_id,
                expected: transfer.received_size,
                actual: expected_offset,
            });
        }
        if bytes.is_empty() {
            return Ok(transfer.received_size);
        }
        let byte_count = u64::try_from(bytes.len()).map_err(|_| StoreError::ObjectTooLarge {
            actual: bytes.len(),
            maximum: MAXIMUM_ENCRYPTED_OBJECT_BYTES,
        })?;
        let received_size = transfer.received_size.checked_add(byte_count).ok_or(
            StoreError::TransferExceedsExpectedSize {
                content_id,
                expected: transfer.encrypted_size,
                actual: u64::MAX,
            },
        )?;
        if received_size > transfer.encrypted_size {
            return Err(StoreError::TransferExceedsExpectedSize {
                content_id,
                expected: transfer.encrypted_size,
                actual: received_size,
            });
        }

        let path = incoming_transfer_path_for(&self.root, group_id, peer_device_id, content_id);
        let actual_file_size = fs::metadata(&path)?.len();
        if actual_file_size != transfer.received_size {
            return Err(StoreError::TransferFileLengthMismatch {
                content_id,
                catalog: transfer.received_size,
                actual: actual_file_size,
            });
        }
        let mut file = OpenOptions::new().append(true).open(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);

        self.connection.execute(
            "UPDATE incoming_object_transfers
             SET received_size = ?4, updated_at_unix_ms = ?5
             WHERE group_id = ?1 AND peer_device_id = ?2 AND content_id = ?3",
            params![
                &group_id.as_uuid().as_bytes()[..],
                &peer_device_id.as_uuid().as_bytes()[..],
                &content_id.as_bytes()[..],
                sequence_to_i64(received_size)?,
                current_unix_ms()?,
            ],
        )?;
        Ok(received_size)
    }

    pub fn complete_object_transfer(
        &mut self,
        keys: &GroupKeys,
        peer_device_id: DeviceId,
        content_id: ContentId,
    ) -> Result<Admission, StoreError> {
        let group_id = keys.group_id();
        let transfer =
            query_incoming_object_transfer(&self.connection, group_id, peer_device_id, content_id)?
                .ok_or(StoreError::ObjectTransferNotFound {
                    peer_device_id,
                    content_id,
                })?;
        if transfer.received_size != transfer.encrypted_size {
            return Err(StoreError::ObjectTransferIncomplete {
                content_id,
                expected: transfer.encrypted_size,
                actual: transfer.received_size,
            });
        }
        let path = incoming_transfer_path_for(&self.root, group_id, peer_device_id, content_id);
        let encrypted_bytes = read_bounded(&path)?;
        let object = EncryptedObject::from_bytes(&encrypted_bytes)?;
        let admission = self.admit_object(keys, object.kind(), content_id, &encrypted_bytes)?;
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(StoreError::Io(error)),
        }
        Ok(admission)
    }

    pub fn cancel_object_transfer(
        &self,
        group_id: GroupId,
        peer_device_id: DeviceId,
        content_id: ContentId,
    ) -> Result<bool, StoreError> {
        let removed = self.connection.execute(
            "DELETE FROM incoming_object_transfers
             WHERE group_id = ?1 AND peer_device_id = ?2 AND content_id = ?3",
            params![
                &group_id.as_uuid().as_bytes()[..],
                &peer_device_id.as_uuid().as_bytes()[..],
                &content_id.as_bytes()[..],
            ],
        )? == 1;
        if removed {
            let path = incoming_transfer_path_for(&self.root, group_id, peer_device_id, content_id);
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(StoreError::Io(error)),
            }
        }
        Ok(removed)
    }

    pub fn local_head(
        &self,
        group_id: GroupId,
        path_id: PathId,
    ) -> Result<Option<LocalHead>, StoreError> {
        self.connection
            .query_row(
                "SELECT content_id, kind FROM local_heads
                 WHERE group_id = ?1 AND path_id = ?2",
                params![&group_id.as_uuid().as_bytes()[..], &path_id.as_bytes()[..]],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?
            .map(|(content_id, kind)| {
                Ok(LocalHead {
                    path_id,
                    content_id: decode_content_id("local_heads.content_id", &content_id)?,
                    kind: decode_change_record_kind("local_heads.kind", kind)?,
                })
            })
            .transpose()
    }

    pub fn local_heads(&self, group_id: GroupId) -> Result<Vec<LocalHead>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT path_id, content_id, kind FROM local_heads
             WHERE group_id = ?1 ORDER BY path_id",
        )?;
        let rows = statement
            .query_map(params![&group_id.as_uuid().as_bytes()[..]], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter()
            .map(|(path_id, content_id, kind)| {
                Ok(LocalHead {
                    path_id: decode_path_id("local_heads.path_id", &path_id)?,
                    content_id: decode_content_id("local_heads.content_id", &content_id)?,
                    kind: decode_change_record_kind("local_heads.kind", kind)?,
                })
            })
            .collect()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn begin_materialization(
        &mut self,
        group_id: GroupId,
        path_id: PathId,
        target_content_id: ContentId,
        expected_previous_content_id: Option<ContentId>,
        kind: ChangeRecordKind,
        stage_name: Option<&str>,
    ) -> Result<MaterializationAdmission, StoreError> {
        validate_materialization_stage(kind, stage_name)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_object_kind(
            &transaction,
            group_id,
            target_content_id,
            ObjectKind::Manifest,
        )?;
        let admission = begin_materialization_transaction(
            &transaction,
            group_id,
            path_id,
            target_content_id,
            expected_previous_content_id,
            kind,
            stage_name,
        )?;
        transaction.commit()?;
        Ok(admission)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn begin_signed_materialization(
        &mut self,
        group_id: GroupId,
        path_id: PathId,
        revision_id: RevisionId,
        target_content_id: ContentId,
        expected_previous_content_id: Option<ContentId>,
        kind: ChangeRecordKind,
        stage_name: Option<&str>,
        authorization: ChangeAuthorization,
    ) -> Result<MaterializationAdmission, StoreError> {
        validate_materialization_stage(kind, stage_name)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        authenticate_change(
            &transaction,
            group_id,
            revision_id,
            target_content_id,
            authorization,
        )?;
        let admission = begin_materialization_transaction(
            &transaction,
            group_id,
            path_id,
            target_content_id,
            expected_previous_content_id,
            kind,
            stage_name,
        )?;
        transaction.commit()?;
        Ok(admission)
    }

    pub fn pending_materializations(
        &self,
        group_id: GroupId,
    ) -> Result<Vec<PendingMaterialization>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT path_id, target_content_id, expected_previous_content_id, kind, stage_name
             FROM pending_materializations
             WHERE group_id = ?1
             ORDER BY path_id",
        )?;
        let rows = statement
            .query_map(params![&group_id.as_uuid().as_bytes()[..]], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter()
            .map(
                |(path_id, target_content_id, expected_previous, kind, stage_name)| {
                    let kind = decode_change_record_kind("pending_materializations.kind", kind)?;
                    validate_materialization_stage(kind, stage_name.as_deref())?;
                    Ok(PendingMaterialization {
                        path_id: decode_path_id("pending_materializations.path_id", &path_id)?,
                        target_content_id: decode_content_id(
                            "pending_materializations.target_content_id",
                            &target_content_id,
                        )?,
                        expected_previous_content_id: expected_previous
                            .map(|value| {
                                decode_content_id(
                                    "pending_materializations.expected_previous_content_id",
                                    &value,
                                )
                            })
                            .transpose()?,
                        kind,
                        stage_name,
                    })
                },
            )
            .collect()
    }

    pub fn complete_materialization(
        &self,
        group_id: GroupId,
        path_id: PathId,
        target_content_id: ContentId,
    ) -> Result<bool, StoreError> {
        Ok(self.connection.execute(
            "DELETE FROM pending_materializations
             WHERE group_id = ?1 AND path_id = ?2 AND target_content_id = ?3
               AND EXISTS (
                   SELECT 1 FROM local_heads
                   WHERE group_id = ?1 AND path_id = ?2 AND content_id = ?3
               )",
            params![
                &group_id.as_uuid().as_bytes()[..],
                &path_id.as_bytes()[..],
                &target_content_id.as_bytes()[..],
            ],
        )? == 1)
    }

    pub fn commit_change(
        &mut self,
        keys: &GroupKeys,
        revision_id: RevisionId,
        content_id: ContentId,
        encrypted_record: &[u8],
        referenced_chunks: impl IntoIterator<Item = ContentId>,
    ) -> Result<ChangeCommit, StoreError> {
        self.admit_object(keys, ObjectKind::Manifest, content_id, encrypted_record)?;

        let group_id = keys.group_id();
        let referenced_chunks = referenced_chunks.into_iter().collect::<BTreeSet<_>>();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let commit = commit_change_graph(
            &transaction,
            group_id,
            revision_id,
            content_id,
            &referenced_chunks,
        )?;
        transaction.commit()?;
        Ok(commit)
    }

    pub fn commit_signed_change(
        &mut self,
        keys: &GroupKeys,
        revision_id: RevisionId,
        content_id: ContentId,
        authorization: ChangeAuthorization,
        encrypted_record: &[u8],
        referenced_chunks: impl IntoIterator<Item = ContentId>,
    ) -> Result<ChangeCommit, StoreError> {
        self.admit_object(keys, ObjectKind::Manifest, content_id, encrypted_record)?;

        let group_id = keys.group_id();
        let referenced_chunks = referenced_chunks.into_iter().collect::<BTreeSet<_>>();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        authenticate_change(
            &transaction,
            group_id,
            revision_id,
            content_id,
            authorization,
        )?;
        let commit = commit_change_graph(
            &transaction,
            group_id,
            revision_id,
            content_id,
            &referenced_chunks,
        )?;
        transaction.commit()?;
        Ok(commit)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn commit_local_change(
        &mut self,
        keys: &GroupKeys,
        path_id: PathId,
        expected_previous: Option<ContentId>,
        revision_id: RevisionId,
        kind: ChangeRecordKind,
        content_id: ContentId,
        encrypted_record: &[u8],
        referenced_chunks: impl IntoIterator<Item = ContentId>,
    ) -> Result<ChangeCommit, StoreError> {
        self.admit_object(keys, ObjectKind::Manifest, content_id, encrypted_record)?;

        let group_id = keys.group_id();
        let referenced_chunks = referenced_chunks.into_iter().collect::<BTreeSet<_>>();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let actual = query_local_head(&transaction, group_id, path_id)?;
        if let Some(pending) = query_pending_materialization(&transaction, group_id, path_id)? {
            if pending.target_content_id != content_id {
                return Err(StoreError::MaterializationInProgress { path_id });
            }
        }

        if let Some(actual) = actual {
            if actual.content_id == content_id {
                if actual.kind != kind {
                    return Err(StoreError::LocalHeadKindMismatch {
                        path_id,
                        expected: kind,
                        actual: actual.kind,
                    });
                }
                let commit = commit_change_graph(
                    &transaction,
                    group_id,
                    revision_id,
                    content_id,
                    &referenced_chunks,
                )?;
                transaction.commit()?;
                return Ok(commit);
            }
        }

        let actual_content_id = actual.map(|head| head.content_id);
        if actual_content_id != expected_previous {
            return Err(StoreError::StaleLocalHead {
                path_id,
                expected: expected_previous,
                actual: actual_content_id,
            });
        }

        let commit = commit_change_graph(
            &transaction,
            group_id,
            revision_id,
            content_id,
            &referenced_chunks,
        )?;
        transaction.execute(
            "INSERT INTO local_heads (group_id, path_id, content_id, kind, updated_at_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(group_id, path_id) DO UPDATE SET
                content_id = excluded.content_id,
                kind = excluded.kind,
                updated_at_unix_ms = excluded.updated_at_unix_ms",
            params![
                &group_id.as_uuid().as_bytes()[..],
                &path_id.as_bytes()[..],
                &content_id.as_bytes()[..],
                encode_change_record_kind(kind),
                current_unix_ms()?,
            ],
        )?;
        transaction.commit()?;
        Ok(commit)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn commit_local_only_head(
        &mut self,
        keys: &GroupKeys,
        path_id: PathId,
        expected_previous: Option<ContentId>,
        kind: ChangeRecordKind,
        content_id: ContentId,
        encrypted_record: &[u8],
        referenced_chunks: impl IntoIterator<Item = ContentId>,
    ) -> Result<(), StoreError> {
        self.admit_object(keys, ObjectKind::Manifest, content_id, encrypted_record)?;

        let group_id = keys.group_id();
        let referenced_chunks = referenced_chunks.into_iter().collect::<BTreeSet<_>>();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let actual = query_local_head(&transaction, group_id, path_id)?;
        if let Some(pending) = query_pending_materialization(&transaction, group_id, path_id)? {
            if pending.target_content_id != content_id {
                return Err(StoreError::MaterializationInProgress { path_id });
            }
        }

        if let Some(actual) = actual {
            if actual.content_id == content_id {
                if actual.kind != kind {
                    return Err(StoreError::LocalHeadKindMismatch {
                        path_id,
                        expected: kind,
                        actual: actual.kind,
                    });
                }
                transaction.commit()?;
                return Ok(());
            }
        }

        let actual_content_id = actual.map(|head| head.content_id);
        if actual_content_id != expected_previous {
            return Err(StoreError::StaleLocalHead {
                path_id,
                expected: expected_previous,
                actual: actual_content_id,
            });
        }

        require_object_kind(&transaction, group_id, content_id, ObjectKind::Manifest)?;
        for &referenced_content_id in &referenced_chunks {
            require_object_kind(
                &transaction,
                group_id,
                referenced_content_id,
                ObjectKind::Chunk,
            )?;
            transaction.execute(
                "INSERT INTO object_references (
                    group_id, owner_content_id, referenced_content_id
                 ) VALUES (?1, ?2, ?3)
                 ON CONFLICT(group_id, owner_content_id, referenced_content_id) DO NOTHING",
                params![
                    &group_id.as_uuid().as_bytes()[..],
                    &content_id.as_bytes()[..],
                    &referenced_content_id.as_bytes()[..],
                ],
            )?;
        }
        transaction.execute(
            "INSERT INTO local_heads (group_id, path_id, content_id, kind, updated_at_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(group_id, path_id) DO UPDATE SET
                content_id = excluded.content_id,
                kind = excluded.kind,
                updated_at_unix_ms = excluded.updated_at_unix_ms",
            params![
                &group_id.as_uuid().as_bytes()[..],
                &path_id.as_bytes()[..],
                &content_id.as_bytes()[..],
                encode_change_record_kind(kind),
                current_unix_ms()?,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn commit_signed_local_change(
        &mut self,
        keys: &GroupKeys,
        path_id: PathId,
        expected_previous: Option<ContentId>,
        revision_id: RevisionId,
        kind: ChangeRecordKind,
        content_id: ContentId,
        authorization: ChangeAuthorization,
        encrypted_record: &[u8],
        referenced_chunks: impl IntoIterator<Item = ContentId>,
    ) -> Result<ChangeCommit, StoreError> {
        self.admit_object(keys, ObjectKind::Manifest, content_id, encrypted_record)?;

        let group_id = keys.group_id();
        let referenced_chunks = referenced_chunks.into_iter().collect::<BTreeSet<_>>();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        authenticate_change(
            &transaction,
            group_id,
            revision_id,
            content_id,
            authorization,
        )?;
        let actual = query_local_head(&transaction, group_id, path_id)?;
        if let Some(pending) = query_pending_materialization(&transaction, group_id, path_id)? {
            if pending.target_content_id != content_id {
                return Err(StoreError::MaterializationInProgress { path_id });
            }
        }

        if let Some(actual) = actual {
            if actual.content_id == content_id {
                if actual.kind != kind {
                    return Err(StoreError::LocalHeadKindMismatch {
                        path_id,
                        expected: kind,
                        actual: actual.kind,
                    });
                }
                let commit = commit_change_graph(
                    &transaction,
                    group_id,
                    revision_id,
                    content_id,
                    &referenced_chunks,
                )?;
                transaction.commit()?;
                return Ok(commit);
            }
        }

        let actual_content_id = actual.map(|head| head.content_id);
        if actual_content_id != expected_previous {
            return Err(StoreError::StaleLocalHead {
                path_id,
                expected: expected_previous,
                actual: actual_content_id,
            });
        }

        let commit = commit_change_graph(
            &transaction,
            group_id,
            revision_id,
            content_id,
            &referenced_chunks,
        )?;
        transaction.execute(
            "INSERT INTO local_heads (group_id, path_id, content_id, kind, updated_at_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(group_id, path_id) DO UPDATE SET
                content_id = excluded.content_id,
                kind = excluded.kind,
                updated_at_unix_ms = excluded.updated_at_unix_ms",
            params![
                &group_id.as_uuid().as_bytes()[..],
                &path_id.as_bytes()[..],
                &content_id.as_bytes()[..],
                encode_change_record_kind(kind),
                current_unix_ms()?,
            ],
        )?;
        transaction.commit()?;
        Ok(commit)
    }

    pub fn changes_after(
        &self,
        group_id: GroupId,
        after_sequence: u64,
        maximum: usize,
    ) -> Result<ChangePage, StoreError> {
        let after_sequence = sequence_to_i64(after_sequence)?;
        let maximum = i64::try_from(maximum).unwrap_or(i64::MAX);
        let high_watermark = self.connection.query_row(
            "SELECT COALESCE(MAX(sequence), 0) FROM changes WHERE group_id = ?1",
            params![&group_id.as_uuid().as_bytes()[..]],
            |row| row.get::<_, i64>(0),
        )?;
        let mut statement = self.connection.prepare(
            "SELECT sequence, revision_id, content_id
             FROM changes
             WHERE group_id = ?1 AND sequence > ?2
             ORDER BY sequence
             LIMIT ?3",
        )?;
        let rows = statement
            .query_map(
                params![&group_id.as_uuid().as_bytes()[..], after_sequence, maximum,],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let records = rows
            .into_iter()
            .map(|(sequence, revision_id, content_id)| {
                Ok(StoredChange {
                    sequence: decode_sequence("changes.sequence", sequence)?,
                    revision_id: decode_revision_id("changes.revision_id", &revision_id)?,
                    content_id: decode_content_id("changes.content_id", &content_id)?,
                })
            })
            .collect::<Result<Vec<_>, StoreError>>()?;

        Ok(ChangePage {
            records,
            high_watermark: decode_sequence("changes.high_watermark", high_watermark)?,
        })
    }

    pub fn record_peer_high_watermark(
        &self,
        group_id: GroupId,
        peer_device_id: DeviceId,
        sequence: u64,
    ) -> Result<u64, StoreError> {
        let sequence = sequence_to_i64(sequence)?;
        self.connection.execute(
            "INSERT INTO peer_high_watermarks (
                group_id, peer_device_id, sequence, updated_at_unix_ms
            ) VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(group_id, peer_device_id) DO UPDATE SET
                sequence = MAX(peer_high_watermarks.sequence, excluded.sequence),
                updated_at_unix_ms = excluded.updated_at_unix_ms",
            params![
                &group_id.as_uuid().as_bytes()[..],
                &peer_device_id.as_uuid().as_bytes()[..],
                sequence,
                current_unix_ms()?,
            ],
        )?;
        self.peer_high_watermark(group_id, peer_device_id)
    }

    pub fn peer_high_watermark(
        &self,
        group_id: GroupId,
        peer_device_id: DeviceId,
    ) -> Result<u64, StoreError> {
        let sequence = self
            .connection
            .query_row(
                "SELECT sequence FROM peer_high_watermarks
                 WHERE group_id = ?1 AND peer_device_id = ?2",
                params![
                    &group_id.as_uuid().as_bytes()[..],
                    &peer_device_id.as_uuid().as_bytes()[..]
                ],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .unwrap_or_default();
        decode_sequence("peer_high_watermarks.sequence", sequence)
    }

    pub fn object_reference_count(
        &self,
        group_id: GroupId,
        content_id: ContentId,
    ) -> Result<Option<u64>, StoreError> {
        self.connection
            .query_row(
                "SELECT reference_count FROM objects
                 WHERE group_id = ?1 AND content_id = ?2",
                params![
                    &group_id.as_uuid().as_bytes()[..],
                    &content_id.as_bytes()[..]
                ],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .map(|count| decode_sequence("objects.reference_count", count))
            .transpose()
    }

    pub fn collect_garbage(
        &mut self,
        group_id: GroupId,
        verified_before_unix_ms: i64,
        maximum: usize,
    ) -> Result<GarbageCollectionReport, StoreError> {
        if maximum == 0 {
            return Ok(GarbageCollectionReport::default());
        }

        let maximum = i64::try_from(maximum).unwrap_or(i64::MAX);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let candidates = {
            let mut statement = transaction.prepare(
                "SELECT content_id, encrypted_size FROM objects
                 WHERE group_id = ?1
                   AND reference_count = 0
                   AND verified_at_unix_ms <= ?2
                 ORDER BY verified_at_unix_ms, content_id
                 LIMIT ?3",
            )?;
            statement
                .query_map(
                    params![
                        &group_id.as_uuid().as_bytes()[..],
                        verified_before_unix_ms,
                        maximum,
                    ],
                    |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };

        let mut removed = Vec::new();
        for (content_id_bytes, encrypted_size) in candidates {
            let content_id = decode_content_id("objects.content_id", &content_id_bytes)?;
            if transaction.execute(
                "DELETE FROM objects
                 WHERE group_id = ?1 AND content_id = ?2 AND reference_count = 0",
                params![&group_id.as_uuid().as_bytes()[..], content_id_bytes],
            )? == 1
            {
                removed.push((
                    content_id,
                    decode_sequence("objects.encrypted_size", encrypted_size)?,
                ));
            }
        }
        transaction.commit()?;

        let mut report = GarbageCollectionReport::default();
        for (content_id, encrypted_size) in removed {
            let path = self.object_path(group_id, content_id);
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(StoreError::Io(error)),
            }
            report.removed_objects += 1;
            report.removed_encrypted_bytes = report
                .removed_encrypted_bytes
                .saturating_add(encrypted_size);
        }
        Ok(report)
    }

    pub fn admit_object(
        &mut self,
        keys: &GroupKeys,
        expected_kind: ObjectKind,
        expected_content_id: ContentId,
        encrypted_bytes: &[u8],
    ) -> Result<Admission, StoreError> {
        let object = verify_object(keys, expected_kind, expected_content_id, encrypted_bytes)?;
        let group_id = keys.group_id();
        let final_path = self.object_path(group_id, expected_content_id);

        if final_path.is_file() {
            let existing_bytes = read_bounded(&final_path)?;
            if let Ok(existing_object) =
                verify_object(keys, expected_kind, expected_content_id, &existing_bytes)
            {
                self.catalog_object(group_id, &existing_object, existing_bytes.len())?;
                return Ok(Admission::AlreadyPresent);
            }

            self.invalidate_object(group_id, expected_content_id, &final_path)?;
        }

        let parent = final_path
            .parent()
            .expect("object paths always have a parent directory");
        fs::create_dir_all(parent)?;
        let staged_path = self.staging_path(group_id, expected_content_id);
        let staged_file = StagedFile::write(&staged_path, encrypted_bytes)?;

        if let Err(rename_error) = fs::rename(staged_file.path(), &final_path) {
            if final_path.is_file() {
                let existing_bytes = read_bounded(&final_path)?;
                if let Ok(existing_object) =
                    verify_object(keys, expected_kind, expected_content_id, &existing_bytes)
                {
                    self.catalog_object(group_id, &existing_object, existing_bytes.len())?;
                    return Ok(Admission::AlreadyPresent);
                }
            }
            return Err(StoreError::Io(rename_error));
        }

        sync_directory(parent)?;
        self.catalog_object(group_id, &object, encrypted_bytes.len())?;
        Ok(Admission::Stored)
    }

    pub fn load_object(
        &mut self,
        keys: &GroupKeys,
        expected_kind: ObjectKind,
        expected_content_id: ContentId,
    ) -> Result<Vec<u8>, StoreError> {
        let group_id = keys.group_id();
        if !self.has_object(group_id, expected_content_id)? {
            return Err(StoreError::ObjectNotFound {
                group_id,
                content_id: expected_content_id,
            });
        }

        let path = self.object_path(group_id, expected_content_id);
        let encrypted_bytes = match read_bounded(&path) {
            Ok(bytes) => bytes,
            Err(error) => {
                self.invalidate_object(group_id, expected_content_id, &path)?;
                return Err(error);
            }
        };

        if let Err(error) =
            verify_object(keys, expected_kind, expected_content_id, &encrypted_bytes)
        {
            self.invalidate_object(group_id, expected_content_id, &path)?;
            return Err(error);
        }

        Ok(encrypted_bytes)
    }

    pub fn load_object_range(
        &mut self,
        keys: &GroupKeys,
        content_id: ContentId,
        start_offset: u64,
    ) -> Result<EncryptedObjectRange, StoreError> {
        let group_id = keys.group_id();
        if !self.has_object(group_id, content_id)? {
            return Err(StoreError::ObjectNotFound {
                group_id,
                content_id,
            });
        }
        let path = self.object_path(group_id, content_id);
        let encrypted_bytes = read_bounded(&path)?;
        let object = EncryptedObject::from_bytes(&encrypted_bytes)?;
        verify_object(keys, object.kind(), content_id, &encrypted_bytes)?;
        let encrypted_size =
            u64::try_from(encrypted_bytes.len()).map_err(|_| StoreError::ObjectTooLarge {
                actual: encrypted_bytes.len(),
                maximum: MAXIMUM_ENCRYPTED_OBJECT_BYTES,
            })?;
        if start_offset >= encrypted_size {
            return Err(StoreError::ObjectRangeStartOutOfBounds {
                content_id,
                start_offset,
                encrypted_size,
            });
        }
        let start =
            usize::try_from(start_offset).map_err(|_| StoreError::ObjectRangeStartOutOfBounds {
                content_id,
                start_offset,
                encrypted_size,
            })?;
        Ok(EncryptedObjectRange {
            content_id,
            encrypted_size,
            start_offset,
            encrypted_bytes: encrypted_bytes[start..].to_vec(),
        })
    }

    fn staging_path(&self, group_id: GroupId, content_id: ContentId) -> PathBuf {
        self.root.join(STAGING_DIRECTORY).join(format!(
            "{}-{}-{}.part",
            group_id.as_uuid().simple(),
            encode_content_id(content_id),
            Uuid::new_v4().simple()
        ))
    }

    fn catalog_object(
        &mut self,
        group_id: GroupId,
        object: &EncryptedObject,
        encrypted_size: usize,
    ) -> Result<(), StoreError> {
        let encrypted_size =
            i64::try_from(encrypted_size).map_err(|_| StoreError::ObjectTooLarge {
                actual: encrypted_size,
                maximum: MAXIMUM_ENCRYPTED_OBJECT_BYTES,
            })?;
        let verified_at_unix_ms = current_unix_ms()?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT INTO objects (
                group_id, content_id, kind, format_version, encrypted_size,
                verified_at_unix_ms, available
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1)
            ON CONFLICT(group_id, content_id) DO UPDATE SET
                kind = excluded.kind,
                format_version = excluded.format_version,
                encrypted_size = excluded.encrypted_size,
                verified_at_unix_ms = excluded.verified_at_unix_ms,
                available = 1",
            params![
                &group_id.as_uuid().as_bytes()[..],
                &object.content_id().as_bytes()[..],
                i64::from(object.kind() as u8),
                i64::from(object.format_version()),
                encrypted_size,
                verified_at_unix_ms,
            ],
        )?;
        transaction.execute(
            "DELETE FROM object_requests WHERE group_id = ?1 AND content_id = ?2",
            params![
                &group_id.as_uuid().as_bytes()[..],
                &object.content_id().as_bytes()[..]
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    fn invalidate_object(
        &self,
        group_id: GroupId,
        content_id: ContentId,
        path: &Path,
    ) -> Result<(), StoreError> {
        self.connection.execute(
            "UPDATE objects SET available = 0
             WHERE group_id = ?1 AND content_id = ?2",
            params![
                &group_id.as_uuid().as_bytes()[..],
                &content_id.as_bytes()[..]
            ],
        )?;

        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(StoreError::Io(error)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Admission {
    Stored,
    AlreadyPresent,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RecoveryReport {
    pub removed_staging_files: usize,
    pub removed_missing_objects: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectRequestState {
    pub content_id: ContentId,
    pub requested_at_unix_ms: i64,
    pub attempt_count: u64,
    pub last_attempt_at_unix_ms: Option<i64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IncomingObjectTransfer {
    pub request_id: Uuid,
    pub content_id: ContentId,
    pub encrypted_size: u64,
    pub received_size: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedObjectRange {
    pub content_id: ContentId,
    pub encrypted_size: u64,
    pub start_offset: u64,
    pub encrypted_bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectTransferAdmission {
    Started,
    Resuming { received_size: u64 },
    AlreadyPresent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalHead {
    pub path_id: PathId,
    pub content_id: ContentId,
    pub kind: ChangeRecordKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingMaterialization {
    pub path_id: PathId,
    pub target_content_id: ContentId,
    pub expected_previous_content_id: Option<ContentId>,
    pub kind: ChangeRecordKind,
    pub stage_name: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemberRole {
    Owner,
    Member,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemberStatus {
    Active,
    Revoked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GroupMember {
    pub device_id: DeviceId,
    pub public_key: DevicePublicKey,
    pub role: MemberRole,
    pub status: MemberStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MembershipAdmission {
    Added,
    AlreadyActive,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChangeAuthenticationAdmission {
    Authenticated,
    AlreadyAuthenticated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoredChangeAuthentication {
    pub revision_id: RevisionId,
    pub content_id: ContentId,
    pub authorization: ChangeAuthorization,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaterializationAdmission {
    Queued,
    AlreadyPending,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChangeCommit {
    pub sequence: u64,
    pub inserted: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoredChange {
    pub sequence: u64,
    pub revision_id: RevisionId,
    pub content_id: ContentId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChangePage {
    pub records: Vec<StoredChange>,
    pub high_watermark: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GarbageCollectionReport {
    pub removed_objects: usize,
    pub removed_encrypted_bytes: u64,
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("storage I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("SQLite catalog operation failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("encrypted object envelope is invalid: {0}")]
    Envelope(#[from] EnvelopeError),
    #[error("encrypted object verification failed: {0}")]
    Crypto(#[from] CryptoError),
    #[error("device identity verification failed: {0}")]
    Identity(#[from] IdentityError),
    #[error("encrypted object is too large: {actual} bytes, maximum {maximum}")]
    ObjectTooLarge { actual: usize, maximum: usize },
    #[error("object {content_id:?} in group {group_id} was not found")]
    ObjectNotFound {
        group_id: GroupId,
        content_id: ContentId,
    },
    #[error("object {content_id:?} in group {group_id} has kind {actual}, expected {expected:?}")]
    ObjectKindMismatch {
        group_id: GroupId,
        content_id: ContentId,
        expected: ObjectKind,
        actual: i64,
    },
    #[error("revision {revision_id} is already bound to a different manifest")]
    RevisionContentMismatch { revision_id: RevisionId },
    #[error("local head {path_id:?} changed: expected {expected:?}, found {actual:?}")]
    StaleLocalHead {
        path_id: PathId,
        expected: Option<ContentId>,
        actual: Option<ContentId>,
    },
    #[error("local head {path_id:?} has kind {actual:?}, expected {expected:?}")]
    LocalHeadKindMismatch {
        path_id: PathId,
        expected: ChangeRecordKind,
        actual: ChangeRecordKind,
    },
    #[error("path {path_id:?} already has a different materialization in progress")]
    MaterializationInProgress { path_id: PathId },
    #[error("device {device_id} is not a member of this group")]
    UnknownGroupMember { device_id: DeviceId },
    #[error("object {content_id:?} is not queued from peer {peer_device_id}")]
    ObjectNotRequested {
        peer_device_id: DeviceId,
        content_id: ContentId,
    },
    #[error("object transfer request ID must not be nil")]
    NilTransferRequestId,
    #[error("encrypted transfer size {actual} is outside 1..={maximum}")]
    InvalidTransferSize { actual: u64, maximum: usize },
    #[error("object {content_id:?} transfer size changed from {expected} to {actual}")]
    TransferSizeMismatch {
        content_id: ContentId,
        expected: u64,
        actual: u64,
    },
    #[error("object {content_id:?} transfer offset is {actual}, expected {expected}")]
    TransferOffsetMismatch {
        content_id: ContentId,
        expected: u64,
        actual: u64,
    },
    #[error("object {content_id:?} transfer reached {actual} bytes, expected at most {expected}")]
    TransferExceedsExpectedSize {
        content_id: ContentId,
        expected: u64,
        actual: u64,
    },
    #[error("object {content_id:?} transfer file has {actual} bytes, catalog has {catalog}")]
    TransferFileLengthMismatch {
        content_id: ContentId,
        catalog: u64,
        actual: u64,
    },
    #[error("object {content_id:?} has no incoming transfer from peer {peer_device_id}")]
    ObjectTransferNotFound {
        peer_device_id: DeviceId,
        content_id: ContentId,
    },
    #[error("object {content_id:?} transfer has {actual} of {expected} bytes")]
    ObjectTransferIncomplete {
        content_id: ContentId,
        expected: u64,
        actual: u64,
    },
    #[error(
        "object {content_id:?} range starts at {start_offset}, encrypted size is {encrypted_size}"
    )]
    ObjectRangeStartOutOfBounds {
        content_id: ContentId,
        start_offset: u64,
        encrypted_size: u64,
    },
    #[error("device {device_id} has been revoked from this group")]
    MemberRevoked { device_id: DeviceId },
    #[error("device {device_id} is already bound to a different public key")]
    MemberKeyMismatch { device_id: DeviceId },
    #[error("device {device_id} has role {expected:?}, not {actual:?}")]
    MemberRoleMismatch {
        device_id: DeviceId,
        expected: MemberRole,
        actual: MemberRole,
    },
    #[error("revision {revision_id} already has different signed provenance")]
    ChangeAuthenticationMismatch { revision_id: RevisionId },
    #[error("file materializations require one safe staging filename")]
    InvalidMaterializationStage,
    #[error("sequence {0} exceeds SQLite's signed integer range")]
    SequenceOutOfRange(u64),
    #[error("the system clock is before the Unix epoch: {0}")]
    Clock(#[from] SystemTimeError),
    #[error("catalog field {field} has {actual} bytes, expected {expected}")]
    CorruptCatalogIdentifier {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("catalog field {field} has invalid negative value {value}")]
    CorruptCatalogInteger { field: &'static str, value: i64 },
    #[error("catalog field {field} has unknown change-record kind {value}")]
    CorruptChangeRecordKind { field: &'static str, value: i64 },
    #[error("catalog field {field} has unknown member role {value}")]
    CorruptMemberRole { field: &'static str, value: i64 },
    #[error("catalog field {field} has unknown member status {value}")]
    CorruptMemberStatus { field: &'static str, value: i64 },
    #[error("unsupported catalog schema version {0}")]
    UnsupportedSchemaVersion(i64),
}

struct StagedFile {
    path: PathBuf,
}

impl StagedFile {
    fn write(path: &Path, bytes: &[u8]) -> Result<Self, StoreError> {
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        let staged_file = Self {
            path: path.to_path_buf(),
        };
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        Ok(staged_file)
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for StagedFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn verify_object(
    keys: &GroupKeys,
    expected_kind: ObjectKind,
    expected_content_id: ContentId,
    encrypted_bytes: &[u8],
) -> Result<EncryptedObject, StoreError> {
    if encrypted_bytes.len() > MAXIMUM_ENCRYPTED_OBJECT_BYTES {
        return Err(StoreError::ObjectTooLarge {
            actual: encrypted_bytes.len(),
            maximum: MAXIMUM_ENCRYPTED_OBJECT_BYTES,
        });
    }

    let object = EncryptedObject::from_bytes(encrypted_bytes)?;
    let _plaintext = Zeroizing::new(keys.open(expected_kind, expected_content_id, &object)?);
    Ok(object)
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, StoreError> {
    let encrypted_size = fs::metadata(path)?.len();
    if encrypted_size > MAXIMUM_ENCRYPTED_OBJECT_BYTES as u64 {
        return Err(StoreError::ObjectTooLarge {
            actual: usize::try_from(encrypted_size).unwrap_or(usize::MAX),
            maximum: MAXIMUM_ENCRYPTED_OBJECT_BYTES,
        });
    }
    let bytes = fs::read(path)?;
    if bytes.len() > MAXIMUM_ENCRYPTED_OBJECT_BYTES {
        return Err(StoreError::ObjectTooLarge {
            actual: bytes.len(),
            maximum: MAXIMUM_ENCRYPTED_OBJECT_BYTES,
        });
    }
    Ok(bytes)
}

fn current_unix_ms() -> Result<i64, StoreError> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH)?;
    Ok(i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX))
}

fn cleanup_staging(staging_directory: &Path) -> Result<usize, StoreError> {
    let mut removed = 0;
    for entry in fs::read_dir(staging_directory)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_file() || file_type.is_symlink() {
            fs::remove_file(entry.path())?;
            removed += 1;
        }
    }
    Ok(removed)
}

fn recover_missing_objects(root: &Path, connection: &Connection) -> Result<usize, StoreError> {
    let rows = {
        let mut statement =
            connection.prepare("SELECT group_id, content_id FROM objects WHERE available = 1")?;
        statement
            .query_map([], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };

    let mut removed = 0;
    for (group_id_bytes, content_id_bytes) in rows {
        let group_id = decode_group_id("objects.group_id", &group_id_bytes)?;
        let content_id = decode_content_id("objects.content_id", &content_id_bytes)?;
        if !object_path_for(root, group_id, content_id).is_file() {
            removed += connection.execute(
                "UPDATE objects SET available = 0
                 WHERE group_id = ?1 AND content_id = ?2 AND available = 1",
                params![group_id_bytes, content_id_bytes],
            )?;
        }
    }
    Ok(removed)
}

fn recover_incoming_object_transfers(
    root: &Path,
    connection: &Connection,
) -> Result<(), StoreError> {
    let rows = {
        let mut statement = connection.prepare(
            "SELECT group_id, peer_device_id, content_id, encrypted_size, received_size
             FROM incoming_object_transfers",
        )?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };

    let mut retained_paths = BTreeSet::new();
    for (group_bytes, peer_bytes, content_bytes, encrypted_size, received_size) in rows {
        let group_id = decode_group_id("incoming_object_transfers.group_id", &group_bytes)?;
        let peer_device_id =
            decode_device_id("incoming_object_transfers.peer_device_id", &peer_bytes)?;
        let content_id = decode_content_id("incoming_object_transfers.content_id", &content_bytes)?;
        let encrypted_size =
            decode_sequence("incoming_object_transfers.encrypted_size", encrypted_size)?;
        let received_size =
            decode_sequence("incoming_object_transfers.received_size", received_size)?;
        let path = incoming_transfer_path_for(root, group_id, peer_device_id, content_id);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_file() => metadata,
            Ok(metadata) if metadata.file_type().is_symlink() => {
                fs::remove_file(&path)?;
                delete_incoming_object_transfer(
                    connection,
                    &group_bytes,
                    &peer_bytes,
                    &content_bytes,
                )?;
                continue;
            }
            Ok(_) => {
                delete_incoming_object_transfer(
                    connection,
                    &group_bytes,
                    &peer_bytes,
                    &content_bytes,
                )?;
                continue;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                delete_incoming_object_transfer(
                    connection,
                    &group_bytes,
                    &peer_bytes,
                    &content_bytes,
                )?;
                continue;
            }
            Err(error) => return Err(StoreError::Io(error)),
        };
        let actual_size = metadata.len();
        if actual_size > encrypted_size {
            fs::remove_file(&path)?;
            delete_incoming_object_transfer(connection, &group_bytes, &peer_bytes, &content_bytes)?;
            continue;
        }
        if actual_size != received_size {
            connection.execute(
                "UPDATE incoming_object_transfers
                 SET received_size = ?4, updated_at_unix_ms = ?5
                 WHERE group_id = ?1 AND peer_device_id = ?2 AND content_id = ?3",
                params![
                    &group_bytes,
                    &peer_bytes,
                    &content_bytes,
                    sequence_to_i64(actual_size)?,
                    current_unix_ms()?,
                ],
            )?;
        }
        retained_paths.insert(path);
    }

    for entry in fs::read_dir(root.join(TRANSFERS_DIRECTORY))? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if (file_type.is_file() || file_type.is_symlink())
            && !retained_paths.contains(&entry.path())
        {
            fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

fn delete_incoming_object_transfer(
    connection: &Connection,
    group_id: &[u8],
    peer_device_id: &[u8],
    content_id: &[u8],
) -> Result<(), StoreError> {
    connection.execute(
        "DELETE FROM incoming_object_transfers
         WHERE group_id = ?1 AND peer_device_id = ?2 AND content_id = ?3",
        params![group_id, peer_device_id, content_id],
    )?;
    Ok(())
}

fn query_incoming_object_transfer(
    connection: &Connection,
    group_id: GroupId,
    peer_device_id: DeviceId,
    content_id: ContentId,
) -> Result<Option<IncomingObjectTransfer>, StoreError> {
    connection
        .query_row(
            "SELECT request_id, content_id, encrypted_size, received_size
             FROM incoming_object_transfers
             WHERE group_id = ?1 AND peer_device_id = ?2 AND content_id = ?3",
            params![
                &group_id.as_uuid().as_bytes()[..],
                &peer_device_id.as_uuid().as_bytes()[..],
                &content_id.as_bytes()[..],
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?
        .map(|(request_id, content_id, encrypted_size, received_size)| {
            let request_id = decode_uuid("incoming_object_transfers.request_id", &request_id)?;
            if request_id.is_nil() {
                return Err(StoreError::NilTransferRequestId);
            }
            Ok(IncomingObjectTransfer {
                request_id,
                content_id: decode_content_id("incoming_object_transfers.content_id", &content_id)?,
                encrypted_size: decode_sequence(
                    "incoming_object_transfers.encrypted_size",
                    encrypted_size,
                )?,
                received_size: decode_sequence(
                    "incoming_object_transfers.received_size",
                    received_size,
                )?,
            })
        })
        .transpose()
}

fn checked_transfer_size(encrypted_size: u64) -> Result<u64, StoreError> {
    if encrypted_size == 0 || encrypted_size > MAXIMUM_ENCRYPTED_OBJECT_BYTES as u64 {
        return Err(StoreError::InvalidTransferSize {
            actual: encrypted_size,
            maximum: MAXIMUM_ENCRYPTED_OBJECT_BYTES,
        });
    }
    Ok(encrypted_size)
}

fn incoming_transfer_path_for(
    root: &Path,
    group_id: GroupId,
    peer_device_id: DeviceId,
    content_id: ContentId,
) -> PathBuf {
    root.join(TRANSFERS_DIRECTORY).join(format!(
        "{}-{}-{}.part",
        group_id.as_uuid().simple(),
        peer_device_id.as_uuid().simple(),
        encode_content_id(content_id),
    ))
}

fn decode_group_id(field: &'static str, value: &[u8]) -> Result<GroupId, StoreError> {
    let actual = value.len();
    let bytes: [u8; 16] = value
        .try_into()
        .map_err(|_| StoreError::CorruptCatalogIdentifier {
            field,
            expected: 16,
            actual,
        })?;
    Ok(GroupId::from_uuid(Uuid::from_bytes(bytes)))
}

fn decode_uuid(field: &'static str, value: &[u8]) -> Result<Uuid, StoreError> {
    let actual = value.len();
    let bytes: [u8; 16] = value
        .try_into()
        .map_err(|_| StoreError::CorruptCatalogIdentifier {
            field,
            expected: 16,
            actual,
        })?;
    Ok(Uuid::from_bytes(bytes))
}

fn decode_device_id(field: &'static str, value: &[u8]) -> Result<DeviceId, StoreError> {
    let actual = value.len();
    let bytes: [u8; 16] = value
        .try_into()
        .map_err(|_| StoreError::CorruptCatalogIdentifier {
            field,
            expected: 16,
            actual,
        })?;
    Ok(DeviceId::from_uuid(Uuid::from_bytes(bytes)))
}

fn decode_revision_id(field: &'static str, value: &[u8]) -> Result<RevisionId, StoreError> {
    let actual = value.len();
    let bytes: [u8; 16] = value
        .try_into()
        .map_err(|_| StoreError::CorruptCatalogIdentifier {
            field,
            expected: 16,
            actual,
        })?;
    Ok(RevisionId::from_uuid(Uuid::from_bytes(bytes)))
}

fn decode_content_id(field: &'static str, value: &[u8]) -> Result<ContentId, StoreError> {
    let actual = value.len();
    let bytes: [u8; 32] = value
        .try_into()
        .map_err(|_| StoreError::CorruptCatalogIdentifier {
            field,
            expected: 32,
            actual,
        })?;
    Ok(ContentId::from_bytes(bytes))
}

fn decode_path_id(field: &'static str, value: &[u8]) -> Result<PathId, StoreError> {
    let actual = value.len();
    let bytes: [u8; 32] = value
        .try_into()
        .map_err(|_| StoreError::CorruptCatalogIdentifier {
            field,
            expected: 32,
            actual,
        })?;
    Ok(PathId::from_bytes(bytes))
}

const fn encode_change_record_kind(kind: ChangeRecordKind) -> i64 {
    match kind {
        ChangeRecordKind::File => 1,
        ChangeRecordKind::Tombstone => 2,
    }
}

fn decode_change_record_kind(
    field: &'static str,
    value: i64,
) -> Result<ChangeRecordKind, StoreError> {
    match value {
        1 => Ok(ChangeRecordKind::File),
        2 => Ok(ChangeRecordKind::Tombstone),
        value => Err(StoreError::CorruptChangeRecordKind { field, value }),
    }
}

fn decode_sequence(field: &'static str, value: i64) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_| StoreError::CorruptCatalogInteger { field, value })
}

const fn encode_member_role(role: MemberRole) -> i64 {
    match role {
        MemberRole::Owner => 1,
        MemberRole::Member => 2,
    }
}

fn decode_member_role(field: &'static str, value: i64) -> Result<MemberRole, StoreError> {
    match value {
        1 => Ok(MemberRole::Owner),
        2 => Ok(MemberRole::Member),
        value => Err(StoreError::CorruptMemberRole { field, value }),
    }
}

const fn encode_member_status(status: MemberStatus) -> i64 {
    match status {
        MemberStatus::Active => 1,
        MemberStatus::Revoked => 2,
    }
}

fn decode_member_status(field: &'static str, value: i64) -> Result<MemberStatus, StoreError> {
    match value {
        1 => Ok(MemberStatus::Active),
        2 => Ok(MemberStatus::Revoked),
        value => Err(StoreError::CorruptMemberStatus { field, value }),
    }
}

fn query_group_member(
    connection: &Connection,
    group_id: GroupId,
    device_id: DeviceId,
) -> Result<Option<GroupMember>, StoreError> {
    connection
        .query_row(
            "SELECT public_key, role, status FROM group_members
             WHERE group_id = ?1 AND device_id = ?2",
            params![
                &group_id.as_uuid().as_bytes()[..],
                &device_id.as_uuid().as_bytes()[..],
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()?
        .map(|(public_key, role, status)| {
            let public_key: [u8; 32] = public_key.as_slice().try_into().map_err(|_| {
                StoreError::CorruptCatalogIdentifier {
                    field: "group_members.public_key",
                    expected: 32,
                    actual: public_key.len(),
                }
            })?;
            let public_key = DevicePublicKey::from_bytes(public_key)?;
            if public_key.device_id() != device_id {
                return Err(StoreError::MemberKeyMismatch { device_id });
            }
            Ok(GroupMember {
                device_id,
                public_key,
                role: decode_member_role("group_members.role", role)?,
                status: decode_member_status("group_members.status", status)?,
            })
        })
        .transpose()
}

fn query_change_authentication(
    connection: &Connection,
    group_id: GroupId,
    revision_id: RevisionId,
) -> Result<Option<StoredChangeAuthentication>, StoreError> {
    connection
        .query_row(
            "SELECT content_id, author_device_id, signature
             FROM change_authentications
             WHERE group_id = ?1 AND revision_id = ?2",
            params![
                &group_id.as_uuid().as_bytes()[..],
                &revision_id.as_uuid().as_bytes()[..],
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )
        .optional()?
        .map(|(content_id, author_device_id, signature)| {
            let author_device_id =
                decode_device_id("change_authentications.author_device_id", &author_device_id)?;
            let signature: [u8; 64] = signature.as_slice().try_into().map_err(|_| {
                StoreError::CorruptCatalogIdentifier {
                    field: "change_authentications.signature",
                    expected: 64,
                    actual: signature.len(),
                }
            })?;
            Ok(StoredChangeAuthentication {
                revision_id,
                content_id: decode_content_id("change_authentications.content_id", &content_id)?,
                authorization: ChangeAuthorization {
                    author_device_id,
                    signature: ChangeSignature::from_bytes(signature),
                },
            })
        })
        .transpose()
}

fn authenticate_change(
    transaction: &rusqlite::Transaction<'_>,
    group_id: GroupId,
    revision_id: RevisionId,
    content_id: ContentId,
    authorization: ChangeAuthorization,
) -> Result<ChangeAuthenticationAdmission, StoreError> {
    if let Some(existing) = query_change_authentication(transaction, group_id, revision_id)? {
        if existing.content_id == content_id && existing.authorization == authorization {
            return Ok(ChangeAuthenticationAdmission::AlreadyAuthenticated);
        }
        return Err(StoreError::ChangeAuthenticationMismatch { revision_id });
    }

    require_object_kind(transaction, group_id, content_id, ObjectKind::Manifest)?;
    let member = query_group_member(transaction, group_id, authorization.author_device_id)?.ok_or(
        StoreError::UnknownGroupMember {
            device_id: authorization.author_device_id,
        },
    )?;
    if member.status != MemberStatus::Active {
        return Err(StoreError::MemberRevoked {
            device_id: member.device_id,
        });
    }
    member
        .public_key
        .verify_change(group_id, revision_id, content_id, authorization)?;
    transaction.execute(
        "INSERT INTO change_authentications (
            group_id, revision_id, content_id, author_device_id,
            signature, authenticated_at_unix_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            &group_id.as_uuid().as_bytes()[..],
            &revision_id.as_uuid().as_bytes()[..],
            &content_id.as_bytes()[..],
            &authorization.author_device_id.as_uuid().as_bytes()[..],
            &authorization.signature.as_bytes()[..],
            current_unix_ms()?,
        ],
    )?;
    Ok(ChangeAuthenticationAdmission::Authenticated)
}

fn validate_materialization_stage(
    kind: ChangeRecordKind,
    stage_name: Option<&str>,
) -> Result<(), StoreError> {
    match (kind, stage_name) {
        (ChangeRecordKind::Tombstone, None) => Ok(()),
        (ChangeRecordKind::File, Some(stage_name)) => {
            let random = stage_name
                .strip_prefix(MATERIALIZATION_STAGE_PREFIX)
                .and_then(|value| value.strip_suffix(MATERIALIZATION_STAGE_SUFFIX));
            if random.is_some_and(|random| {
                random.len() == MATERIALIZATION_STAGE_RANDOM_HEX_LENGTH
                    && random
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            }) {
                Ok(())
            } else {
                Err(StoreError::InvalidMaterializationStage)
            }
        }
        (ChangeRecordKind::File, None) | (ChangeRecordKind::Tombstone, Some(_)) => {
            Err(StoreError::InvalidMaterializationStage)
        }
    }
}

fn sequence_to_i64(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::SequenceOutOfRange(value))
}

fn require_object_kind(
    transaction: &rusqlite::Transaction<'_>,
    group_id: GroupId,
    content_id: ContentId,
    expected: ObjectKind,
) -> Result<(), StoreError> {
    let actual = transaction
        .query_row(
            "SELECT kind FROM objects
             WHERE group_id = ?1 AND content_id = ?2 AND available = 1",
            params![
                &group_id.as_uuid().as_bytes()[..],
                &content_id.as_bytes()[..]
            ],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .ok_or(StoreError::ObjectNotFound {
            group_id,
            content_id,
        })?;
    if actual != i64::from(expected as u8) {
        return Err(StoreError::ObjectKindMismatch {
            group_id,
            content_id,
            expected,
            actual,
        });
    }
    Ok(())
}

fn query_local_head(
    transaction: &rusqlite::Transaction<'_>,
    group_id: GroupId,
    path_id: PathId,
) -> Result<Option<LocalHead>, StoreError> {
    transaction
        .query_row(
            "SELECT content_id, kind FROM local_heads
             WHERE group_id = ?1 AND path_id = ?2",
            params![&group_id.as_uuid().as_bytes()[..], &path_id.as_bytes()[..]],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()?
        .map(|(content_id, kind)| {
            Ok(LocalHead {
                path_id,
                content_id: decode_content_id("local_heads.content_id", &content_id)?,
                kind: decode_change_record_kind("local_heads.kind", kind)?,
            })
        })
        .transpose()
}

fn query_pending_materialization(
    transaction: &rusqlite::Transaction<'_>,
    group_id: GroupId,
    path_id: PathId,
) -> Result<Option<PendingMaterialization>, StoreError> {
    transaction
        .query_row(
            "SELECT target_content_id, expected_previous_content_id, kind, stage_name
             FROM pending_materializations
             WHERE group_id = ?1 AND path_id = ?2",
            params![&group_id.as_uuid().as_bytes()[..], &path_id.as_bytes()[..]],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Option<Vec<u8>>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<String>>(3)?,
                ))
            },
        )
        .optional()?
        .map(|(target_content_id, expected_previous, kind, stage_name)| {
            let kind = decode_change_record_kind("pending_materializations.kind", kind)?;
            validate_materialization_stage(kind, stage_name.as_deref())?;
            Ok(PendingMaterialization {
                path_id,
                target_content_id: decode_content_id(
                    "pending_materializations.target_content_id",
                    &target_content_id,
                )?,
                expected_previous_content_id: expected_previous
                    .map(|value| {
                        decode_content_id(
                            "pending_materializations.expected_previous_content_id",
                            &value,
                        )
                    })
                    .transpose()?,
                kind,
                stage_name,
            })
        })
        .transpose()
}

#[allow(clippy::too_many_arguments)]
fn begin_materialization_transaction(
    transaction: &rusqlite::Transaction<'_>,
    group_id: GroupId,
    path_id: PathId,
    target_content_id: ContentId,
    expected_previous_content_id: Option<ContentId>,
    kind: ChangeRecordKind,
    stage_name: Option<&str>,
) -> Result<MaterializationAdmission, StoreError> {
    let actual_previous =
        query_local_head(transaction, group_id, path_id)?.map(|head| head.content_id);
    if let Some(existing) = query_pending_materialization(transaction, group_id, path_id)? {
        let requested = PendingMaterialization {
            path_id,
            target_content_id,
            expected_previous_content_id,
            kind,
            stage_name: stage_name.map(str::to_owned),
        };
        if existing == requested {
            if actual_previous != expected_previous_content_id
                && actual_previous != Some(target_content_id)
            {
                return Err(StoreError::StaleLocalHead {
                    path_id,
                    expected: expected_previous_content_id,
                    actual: actual_previous,
                });
            }
            return Ok(MaterializationAdmission::AlreadyPending);
        }
        return Err(StoreError::MaterializationInProgress { path_id });
    }
    if actual_previous != expected_previous_content_id {
        return Err(StoreError::StaleLocalHead {
            path_id,
            expected: expected_previous_content_id,
            actual: actual_previous,
        });
    }

    let expected_previous_bytes = expected_previous_content_id.map(ContentId::into_bytes);
    transaction.execute(
        "INSERT INTO pending_materializations (
            group_id, path_id, target_content_id, expected_previous_content_id,
            kind, stage_name, created_at_unix_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            &group_id.as_uuid().as_bytes()[..],
            &path_id.as_bytes()[..],
            &target_content_id.as_bytes()[..],
            expected_previous_bytes.as_ref().map(|bytes| &bytes[..]),
            encode_change_record_kind(kind),
            stage_name,
            current_unix_ms()?,
        ],
    )?;
    Ok(MaterializationAdmission::Queued)
}

fn commit_change_graph(
    transaction: &rusqlite::Transaction<'_>,
    group_id: GroupId,
    revision_id: RevisionId,
    content_id: ContentId,
    referenced_chunks: &BTreeSet<ContentId>,
) -> Result<ChangeCommit, StoreError> {
    let existing = transaction
        .query_row(
            "SELECT sequence, content_id FROM changes
             WHERE group_id = ?1 AND revision_id = ?2",
            params![
                &group_id.as_uuid().as_bytes()[..],
                &revision_id.as_uuid().as_bytes()[..]
            ],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?;
    if let Some((sequence, existing_content_id)) = existing {
        let existing_content_id = decode_content_id("changes.content_id", &existing_content_id)?;
        if existing_content_id != content_id {
            return Err(StoreError::RevisionContentMismatch { revision_id });
        }
        return Ok(ChangeCommit {
            sequence: decode_sequence("changes.sequence", sequence)?,
            inserted: false,
        });
    }

    require_object_kind(transaction, group_id, content_id, ObjectKind::Manifest)?;
    for &referenced_content_id in referenced_chunks {
        require_object_kind(
            transaction,
            group_id,
            referenced_content_id,
            ObjectKind::Chunk,
        )?;
    }

    transaction.execute(
        "INSERT INTO changes (
            group_id, revision_id, content_id, created_at_unix_ms
        ) VALUES (?1, ?2, ?3, ?4)",
        params![
            &group_id.as_uuid().as_bytes()[..],
            &revision_id.as_uuid().as_bytes()[..],
            &content_id.as_bytes()[..],
            current_unix_ms()?,
        ],
    )?;
    let sequence = decode_sequence("changes.sequence", transaction.last_insert_rowid())?;

    for referenced_content_id in referenced_chunks {
        transaction.execute(
            "INSERT INTO object_references (
                group_id, owner_content_id, referenced_content_id
            ) VALUES (?1, ?2, ?3)
            ON CONFLICT(group_id, owner_content_id, referenced_content_id) DO NOTHING",
            params![
                &group_id.as_uuid().as_bytes()[..],
                &content_id.as_bytes()[..],
                &referenced_content_id.as_bytes()[..],
            ],
        )?;
    }

    Ok(ChangeCommit {
        sequence,
        inserted: true,
    })
}

fn object_path_for(root: &Path, group_id: GroupId, content_id: ContentId) -> PathBuf {
    let content_id = encode_content_id(content_id);
    root.join(OBJECTS_DIRECTORY)
        .join(group_id.as_uuid().simple().to_string())
        .join(&content_id[..2])
        .join(format!("{content_id}.orbit"))
}

fn encode_content_id(content_id: ContentId) -> String {
    const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for &byte in content_id.as_bytes() {
        encoded.push(HEX_DIGITS[usize::from(byte >> 4)] as char);
        encoded.push(HEX_DIGITS[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> io::Result<()> {
    fs::File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

fn migrate(connection: &mut Connection) -> Result<(), StoreError> {
    let mut version = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version > SCHEMA_VERSION {
        return Err(StoreError::UnsupportedSchemaVersion(version));
    }

    if version == 0 {
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(
            "CREATE TABLE objects (
                group_id BLOB NOT NULL CHECK(length(group_id) = 16),
                content_id BLOB NOT NULL CHECK(length(content_id) = 32),
                kind INTEGER NOT NULL CHECK(kind IN (1, 2)),
                format_version INTEGER NOT NULL,
                encrypted_size INTEGER NOT NULL CHECK(encrypted_size >= 0),
                reference_count INTEGER NOT NULL DEFAULT 0 CHECK(reference_count >= 0),
                verified_at_unix_ms INTEGER NOT NULL,
                PRIMARY KEY (group_id, content_id)
            ) STRICT;",
        )?;
        transaction.pragma_update(None, "user_version", 1)?;
        transaction.commit()?;
        version = 1;
    }

    if version == 1 {
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(
            "CREATE TABLE object_requests (
                group_id BLOB NOT NULL CHECK(length(group_id) = 16),
                peer_device_id BLOB NOT NULL CHECK(length(peer_device_id) = 16),
                content_id BLOB NOT NULL CHECK(length(content_id) = 32),
                requested_at_unix_ms INTEGER NOT NULL,
                attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count >= 0),
                last_attempt_at_unix_ms INTEGER,
                PRIMARY KEY (group_id, peer_device_id, content_id)
            ) STRICT;
            CREATE INDEX object_requests_order
                ON object_requests(group_id, peer_device_id, requested_at_unix_ms);",
        )?;
        transaction.pragma_update(None, "user_version", 2)?;
        transaction.commit()?;
        version = 2;
    }

    if version == 2 {
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(
            "ALTER TABLE objects ADD COLUMN available INTEGER NOT NULL DEFAULT 1
                CHECK(available IN (0, 1));

            CREATE TABLE changes (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id BLOB NOT NULL CHECK(length(group_id) = 16),
                revision_id BLOB NOT NULL CHECK(length(revision_id) = 16),
                content_id BLOB NOT NULL CHECK(length(content_id) = 32),
                created_at_unix_ms INTEGER NOT NULL,
                UNIQUE (group_id, revision_id),
                FOREIGN KEY (group_id, content_id)
                    REFERENCES objects(group_id, content_id) ON DELETE RESTRICT
            ) STRICT;
            CREATE INDEX changes_by_group_sequence
                ON changes(group_id, sequence);

            CREATE TABLE object_references (
                group_id BLOB NOT NULL CHECK(length(group_id) = 16),
                owner_content_id BLOB NOT NULL CHECK(length(owner_content_id) = 32),
                referenced_content_id BLOB NOT NULL CHECK(length(referenced_content_id) = 32),
                PRIMARY KEY (group_id, owner_content_id, referenced_content_id),
                FOREIGN KEY (group_id, owner_content_id)
                    REFERENCES objects(group_id, content_id) ON DELETE CASCADE,
                FOREIGN KEY (group_id, referenced_content_id)
                    REFERENCES objects(group_id, content_id) ON DELETE RESTRICT
            ) STRICT;
            CREATE INDEX object_references_by_target
                ON object_references(group_id, referenced_content_id);

            CREATE TABLE peer_high_watermarks (
                group_id BLOB NOT NULL CHECK(length(group_id) = 16),
                peer_device_id BLOB NOT NULL CHECK(length(peer_device_id) = 16),
                sequence INTEGER NOT NULL CHECK(sequence >= 0),
                updated_at_unix_ms INTEGER NOT NULL,
                PRIMARY KEY (group_id, peer_device_id)
            ) STRICT;

            CREATE TRIGGER changes_pin_manifest
            AFTER INSERT ON changes
            BEGIN
                UPDATE objects
                SET reference_count = reference_count + 1
                WHERE group_id = NEW.group_id AND content_id = NEW.content_id;
            END;

            CREATE TRIGGER changes_unpin_manifest
            AFTER DELETE ON changes
            BEGIN
                UPDATE objects
                SET reference_count = reference_count - 1
                WHERE group_id = OLD.group_id AND content_id = OLD.content_id;
            END;

            CREATE TRIGGER object_references_pin_target
            AFTER INSERT ON object_references
            BEGIN
                UPDATE objects
                SET reference_count = reference_count + 1
                WHERE group_id = NEW.group_id
                  AND content_id = NEW.referenced_content_id;
            END;

            CREATE TRIGGER object_references_unpin_target
            AFTER DELETE ON object_references
            BEGIN
                UPDATE objects
                SET reference_count = reference_count - 1
                WHERE group_id = OLD.group_id
                  AND content_id = OLD.referenced_content_id;
            END;",
        )?;
        transaction.pragma_update(None, "user_version", 3)?;
        transaction.commit()?;
        version = 3;
    }

    if version == 3 {
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(
            "CREATE TABLE local_heads (
                group_id BLOB NOT NULL CHECK(length(group_id) = 16),
                path_id BLOB NOT NULL CHECK(length(path_id) = 32),
                content_id BLOB NOT NULL CHECK(length(content_id) = 32),
                kind INTEGER NOT NULL CHECK(kind IN (1, 2)),
                updated_at_unix_ms INTEGER NOT NULL,
                PRIMARY KEY (group_id, path_id),
                FOREIGN KEY (group_id, content_id)
                    REFERENCES objects(group_id, content_id) ON DELETE RESTRICT
            ) STRICT;
            CREATE INDEX local_heads_by_manifest
                ON local_heads(group_id, content_id);

            CREATE TRIGGER local_heads_pin_manifest
            AFTER INSERT ON local_heads
            BEGIN
                UPDATE objects
                SET reference_count = reference_count + 1
                WHERE group_id = NEW.group_id AND content_id = NEW.content_id;
            END;

            CREATE TRIGGER local_heads_replace_manifest
            AFTER UPDATE OF content_id ON local_heads
            WHEN OLD.content_id != NEW.content_id
            BEGIN
                UPDATE objects
                SET reference_count = reference_count - 1
                WHERE group_id = OLD.group_id AND content_id = OLD.content_id;
                UPDATE objects
                SET reference_count = reference_count + 1
                WHERE group_id = NEW.group_id AND content_id = NEW.content_id;
            END;

            CREATE TRIGGER local_heads_unpin_manifest
            AFTER DELETE ON local_heads
            BEGIN
                UPDATE objects
                SET reference_count = reference_count - 1
                WHERE group_id = OLD.group_id AND content_id = OLD.content_id;
            END;",
        )?;
        transaction.pragma_update(None, "user_version", 4)?;
        transaction.commit()?;
        version = 4;
    }

    if version == 4 {
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(
            "CREATE TABLE pending_materializations (
                group_id BLOB NOT NULL CHECK(length(group_id) = 16),
                path_id BLOB NOT NULL CHECK(length(path_id) = 32),
                target_content_id BLOB NOT NULL CHECK(length(target_content_id) = 32),
                expected_previous_content_id BLOB
                    CHECK(expected_previous_content_id IS NULL
                        OR length(expected_previous_content_id) = 32),
                kind INTEGER NOT NULL CHECK(kind IN (1, 2)),
                stage_name TEXT,
                created_at_unix_ms INTEGER NOT NULL,
                PRIMARY KEY (group_id, path_id),
                CHECK((kind = 1 AND stage_name IS NOT NULL)
                    OR (kind = 2 AND stage_name IS NULL)),
                FOREIGN KEY (group_id, target_content_id)
                    REFERENCES objects(group_id, content_id) ON DELETE RESTRICT
            ) STRICT;

            CREATE TRIGGER pending_materializations_pin_manifest
            AFTER INSERT ON pending_materializations
            BEGIN
                UPDATE objects
                SET reference_count = reference_count + 1
                WHERE group_id = NEW.group_id AND content_id = NEW.target_content_id;
            END;

            CREATE TRIGGER pending_materializations_unpin_manifest
            AFTER DELETE ON pending_materializations
            BEGIN
                UPDATE objects
                SET reference_count = reference_count - 1
                WHERE group_id = OLD.group_id AND content_id = OLD.target_content_id;
            END;",
        )?;
        transaction.pragma_update(None, "user_version", 5)?;
        transaction.commit()?;
        version = 5;
    }

    if version == 5 {
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(
            "CREATE TABLE group_members (
                group_id BLOB NOT NULL CHECK(length(group_id) = 16),
                device_id BLOB NOT NULL CHECK(length(device_id) = 16),
                public_key BLOB NOT NULL CHECK(length(public_key) = 32),
                role INTEGER NOT NULL CHECK(role IN (1, 2)),
                status INTEGER NOT NULL CHECK(status IN (1, 2)),
                added_at_unix_ms INTEGER NOT NULL,
                revoked_at_unix_ms INTEGER,
                PRIMARY KEY (group_id, device_id),
                UNIQUE (group_id, public_key),
                CHECK((status = 1 AND revoked_at_unix_ms IS NULL)
                    OR (status = 2 AND revoked_at_unix_ms IS NOT NULL))
            ) STRICT;

            CREATE TABLE change_authentications (
                group_id BLOB NOT NULL CHECK(length(group_id) = 16),
                revision_id BLOB NOT NULL CHECK(length(revision_id) = 16),
                content_id BLOB NOT NULL CHECK(length(content_id) = 32),
                author_device_id BLOB NOT NULL CHECK(length(author_device_id) = 16),
                signature BLOB NOT NULL CHECK(length(signature) = 64),
                authenticated_at_unix_ms INTEGER NOT NULL,
                PRIMARY KEY (group_id, revision_id),
                FOREIGN KEY (group_id, content_id)
                    REFERENCES objects(group_id, content_id) ON DELETE RESTRICT,
                FOREIGN KEY (group_id, author_device_id)
                    REFERENCES group_members(group_id, device_id) ON DELETE RESTRICT
            ) STRICT;
            CREATE INDEX change_authentications_by_author
                ON change_authentications(group_id, author_device_id);

            CREATE TRIGGER change_authentications_pin_manifest
            AFTER INSERT ON change_authentications
            BEGIN
                UPDATE objects
                SET reference_count = reference_count + 1
                WHERE group_id = NEW.group_id AND content_id = NEW.content_id;
            END;

            CREATE TRIGGER change_authentications_unpin_manifest
            AFTER DELETE ON change_authentications
            BEGIN
                UPDATE objects
                SET reference_count = reference_count - 1
                WHERE group_id = OLD.group_id AND content_id = OLD.content_id;
            END;",
        )?;
        transaction.pragma_update(None, "user_version", 6)?;
        transaction.commit()?;
        version = 6;
    }

    if version == 6 {
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(
            "CREATE TABLE incoming_object_transfers (
                group_id BLOB NOT NULL CHECK(length(group_id) = 16),
                peer_device_id BLOB NOT NULL CHECK(length(peer_device_id) = 16),
                request_id BLOB NOT NULL CHECK(length(request_id) = 16),
                content_id BLOB NOT NULL CHECK(length(content_id) = 32),
                encrypted_size INTEGER NOT NULL
                    CHECK(encrypted_size > 0 AND encrypted_size <= 67108864),
                received_size INTEGER NOT NULL
                    CHECK(received_size >= 0 AND received_size <= encrypted_size),
                updated_at_unix_ms INTEGER NOT NULL,
                PRIMARY KEY (group_id, peer_device_id, content_id),
                FOREIGN KEY (group_id, peer_device_id, content_id)
                    REFERENCES object_requests(group_id, peer_device_id, content_id)
                    ON DELETE CASCADE
            ) STRICT;
            CREATE INDEX incoming_object_transfers_by_request
                ON incoming_object_transfers(group_id, peer_device_id, request_id);",
        )?;
        transaction.pragma_update(None, "user_version", 7)?;
        transaction.commit()?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use orbit_crypto::{DeviceIdentity, GroupSecret};

    fn group(value: u128) -> GroupId {
        format!("{value:032x}").parse().unwrap()
    }

    fn keys() -> GroupKeys {
        GroupSecret::from_bytes([7; 32])
            .derive_keys(group(1))
            .unwrap()
    }

    fn device_identity(value: u8) -> DeviceIdentity {
        DeviceIdentity::from_secret_bytes([value; 32])
    }

    fn device(value: u128) -> DeviceId {
        format!("{value:032x}").parse().unwrap()
    }

    fn revision(value: u128) -> RevisionId {
        format!("{value:032x}").parse().unwrap()
    }

    fn path(value: u8) -> PathId {
        PathId::from_bytes([value; 32])
    }

    #[test]
    fn opens_a_wal_catalog_and_applies_migrations() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let store = Store::open(temporary_directory.path()).unwrap();

        let journal_mode: String = store
            .connection
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .unwrap();

        assert_eq!(journal_mode, "wal");
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        assert!(store.database_path().is_file());
        assert!(store.root().join(OBJECTS_DIRECTORY).is_dir());
        assert!(store.root().join(STAGING_DIRECTORY).is_dir());
    }

    #[test]
    fn rejects_catalogs_from_a_newer_schema() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let database_path = temporary_directory.path().join(DATABASE_FILENAME);
        let connection = Connection::open(database_path).unwrap();
        connection
            .pragma_update(None, "user_version", SCHEMA_VERSION + 1)
            .unwrap();
        drop(connection);

        assert!(matches!(
            Store::open(temporary_directory.path()),
            Err(StoreError::UnsupportedSchemaVersion(version)) if version == SCHEMA_VERSION + 1
        ));
    }

    #[test]
    fn migrates_a_schema_v3_catalog_without_losing_objects() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let keys = keys();
        let mut store = Store::open(temporary_directory.path()).unwrap();
        let object = keys.seal_chunk(b"survives schema migration").unwrap();
        store
            .admit_object(
                &keys,
                ObjectKind::Chunk,
                object.content_id(),
                &object.to_bytes().unwrap(),
            )
            .unwrap();
        drop(store);

        let connection =
            Connection::open(temporary_directory.path().join(DATABASE_FILENAME)).unwrap();
        connection
            .execute_batch(
                "DROP TABLE incoming_object_transfers;
                 DROP TABLE change_authentications;
                 DROP TABLE group_members;
                 DROP TABLE pending_materializations;
                 DROP TABLE local_heads;
                 PRAGMA user_version = 3;",
            )
            .unwrap();
        drop(connection);

        let migrated = Store::open(temporary_directory.path()).unwrap();
        assert_eq!(migrated.schema_version().unwrap(), SCHEMA_VERSION);
        assert!(
            migrated
                .has_object(keys.group_id(), object.content_id())
                .unwrap()
        );
        assert!(migrated.local_heads(keys.group_id()).unwrap().is_empty());
    }

    #[test]
    fn migrates_a_schema_v4_catalog_with_an_empty_materialization_journal() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let store = Store::open(temporary_directory.path()).unwrap();
        drop(store);

        let connection =
            Connection::open(temporary_directory.path().join(DATABASE_FILENAME)).unwrap();
        connection
            .execute_batch(
                "DROP TABLE incoming_object_transfers;
                 DROP TABLE change_authentications;
                 DROP TABLE group_members;
                 DROP TABLE pending_materializations;
                 PRAGMA user_version = 4;",
            )
            .unwrap();
        drop(connection);

        let migrated = Store::open(temporary_directory.path()).unwrap();
        assert_eq!(migrated.schema_version().unwrap(), SCHEMA_VERSION);
        assert!(
            migrated
                .pending_materializations(keys().group_id())
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn migrates_schema_v5_with_an_empty_member_registry() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let store = Store::open(temporary_directory.path()).unwrap();
        drop(store);

        let connection =
            Connection::open(temporary_directory.path().join(DATABASE_FILENAME)).unwrap();
        connection
            .execute_batch(
                "DROP TABLE incoming_object_transfers;
                 DROP TABLE change_authentications;
                 DROP TABLE group_members;
                 PRAGMA user_version = 5;",
            )
            .unwrap();
        drop(connection);

        let migrated = Store::open(temporary_directory.path()).unwrap();
        assert_eq!(migrated.schema_version().unwrap(), SCHEMA_VERSION);
        assert!(
            migrated
                .group_member(keys().group_id(), device_identity(1).device_id())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn migrates_schema_v6_and_preserves_queued_object_requests() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let keys = keys();
        let peer = device(61);
        let content_id = ContentId::from_bytes([62; 32]);
        let mut store = Store::open(temporary_directory.path()).unwrap();
        store
            .queue_object_requests(keys.group_id(), peer, [content_id])
            .unwrap();
        drop(store);

        let connection =
            Connection::open(temporary_directory.path().join(DATABASE_FILENAME)).unwrap();
        connection
            .execute_batch(
                "DROP TABLE incoming_object_transfers;
                 PRAGMA user_version = 6;",
            )
            .unwrap();
        drop(connection);

        let mut migrated = Store::open(temporary_directory.path()).unwrap();
        assert_eq!(migrated.schema_version().unwrap(), SCHEMA_VERSION);
        assert_eq!(
            migrated
                .pending_object_requests(keys.group_id(), peer, 10)
                .unwrap()[0]
                .content_id,
            content_id
        );
        assert_eq!(
            migrated
                .begin_object_transfer(keys.group_id(), peer, Uuid::from_u128(63), content_id, 128,)
                .unwrap(),
            ObjectTransferAdmission::Started
        );
        assert_eq!(
            migrated
                .incoming_object_transfer(keys.group_id(), peer, content_id)
                .unwrap()
                .unwrap()
                .received_size,
            0
        );
    }

    #[test]
    fn group_membership_is_persistent_idempotent_and_revocable() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let keys = keys();
        let identity = device_identity(41);
        let other = device_identity(42);
        let revision_id = revision(1);
        let content_id = ContentId::from_bytes([2; 32]);
        let authorization = identity.authorize_change(keys.group_id(), revision_id, content_id);
        let mut store = Store::open(temporary_directory.path()).unwrap();

        assert_eq!(
            store
                .add_group_member(keys.group_id(), identity.public_key(), MemberRole::Owner)
                .unwrap(),
            MembershipAdmission::Added
        );
        assert_eq!(
            store
                .add_group_member(keys.group_id(), identity.public_key(), MemberRole::Owner)
                .unwrap(),
            MembershipAdmission::AlreadyActive
        );
        assert!(matches!(
            store.add_group_member(keys.group_id(), identity.public_key(), MemberRole::Member,),
            Err(StoreError::MemberRoleMismatch { .. })
        ));
        assert_eq!(
            store
                .group_member(keys.group_id(), identity.device_id())
                .unwrap(),
            Some(GroupMember {
                device_id: identity.device_id(),
                public_key: identity.public_key(),
                role: MemberRole::Owner,
                status: MemberStatus::Active,
            })
        );
        store
            .verify_change_authorization(keys.group_id(), revision_id, content_id, authorization)
            .unwrap();
        assert!(matches!(
            store.verify_change_authorization(
                keys.group_id(),
                revision_id,
                content_id,
                other.authorize_change(keys.group_id(), revision_id, content_id),
            ),
            Err(StoreError::UnknownGroupMember { .. })
        ));
        drop(store);

        let reopened = Store::open(temporary_directory.path()).unwrap();
        assert!(
            reopened
                .revoke_group_member(keys.group_id(), identity.device_id())
                .unwrap()
        );
        assert!(
            !reopened
                .revoke_group_member(keys.group_id(), identity.device_id())
                .unwrap()
        );
        assert_eq!(
            reopened
                .group_member(keys.group_id(), identity.device_id())
                .unwrap()
                .unwrap()
                .status,
            MemberStatus::Revoked
        );
        assert!(matches!(
            reopened.verify_change_authorization(
                keys.group_id(),
                revision_id,
                content_id,
                authorization,
            ),
            Err(StoreError::MemberRevoked { .. })
        ));
    }

    #[test]
    fn admits_and_loads_only_verified_encrypted_objects() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let mut store = Store::open(temporary_directory.path()).unwrap();
        let keys = keys();
        let plaintext = b"durable private content";
        let content_id = keys.identify_chunk(plaintext);
        let encrypted_bytes = keys.seal_chunk(plaintext).unwrap().to_bytes().unwrap();

        assert_eq!(
            store
                .admit_object(&keys, ObjectKind::Chunk, content_id, &encrypted_bytes)
                .unwrap(),
            Admission::Stored
        );
        assert!(store.has_object(keys.group_id(), content_id).unwrap());
        assert_eq!(
            store
                .load_object(&keys, ObjectKind::Chunk, content_id)
                .unwrap(),
            encrypted_bytes
        );
        assert_eq!(
            store
                .admit_object(&keys, ObjectKind::Chunk, content_id, &encrypted_bytes)
                .unwrap(),
            Admission::AlreadyPresent
        );
    }

    #[test]
    fn rejects_tampered_input_without_catalog_or_staging_visibility() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let mut store = Store::open(temporary_directory.path()).unwrap();
        let keys = keys();
        let plaintext = b"authenticate before promotion";
        let content_id = keys.identify_chunk(plaintext);
        let mut encrypted_bytes = keys.seal_chunk(plaintext).unwrap().to_bytes().unwrap();
        *encrypted_bytes.last_mut().unwrap() ^= 0x80;

        assert!(matches!(
            store.admit_object(&keys, ObjectKind::Chunk, content_id, &encrypted_bytes),
            Err(StoreError::Crypto(CryptoError::Authentication))
        ));
        assert!(!store.has_object(keys.group_id(), content_id).unwrap());
        assert!(!store.object_path(keys.group_id(), content_id).exists());
        assert_eq!(
            fs::read_dir(store.root().join(STAGING_DIRECTORY))
                .unwrap()
                .count(),
            0
        );
    }

    #[test]
    fn demotes_a_stored_object_when_verification_fails() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let mut store = Store::open(temporary_directory.path()).unwrap();
        let keys = keys();
        let plaintext = b"detect corruption at rest";
        let content_id = keys.identify_chunk(plaintext);
        let encrypted_bytes = keys.seal_chunk(plaintext).unwrap().to_bytes().unwrap();
        store
            .admit_object(&keys, ObjectKind::Chunk, content_id, &encrypted_bytes)
            .unwrap();

        let path = store.object_path(keys.group_id(), content_id);
        let mut tampered = fs::read(&path).unwrap();
        *tampered.last_mut().unwrap() ^= 0x01;
        fs::write(&path, tampered).unwrap();

        assert!(matches!(
            store.load_object(&keys, ObjectKind::Chunk, content_id),
            Err(StoreError::Crypto(CryptoError::Authentication))
        ));
        assert!(!store.has_object(keys.group_id(), content_id).unwrap());
        assert!(!path.exists());
    }

    #[test]
    fn recovery_removes_staging_files_and_missing_catalog_entries() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let mut store = Store::open(temporary_directory.path()).unwrap();
        let keys = keys();
        let plaintext = b"crash recovery";
        let content_id = keys.identify_chunk(plaintext);
        let encrypted_bytes = keys.seal_chunk(plaintext).unwrap().to_bytes().unwrap();
        store
            .admit_object(&keys, ObjectKind::Chunk, content_id, &encrypted_bytes)
            .unwrap();
        fs::remove_file(store.object_path(keys.group_id(), content_id)).unwrap();
        fs::write(
            store.root().join(STAGING_DIRECTORY).join("abandoned.part"),
            b"partial",
        )
        .unwrap();
        drop(store);

        let recovered = Store::open(temporary_directory.path()).unwrap();

        assert_eq!(
            recovered.recovery_report(),
            RecoveryReport {
                removed_staging_files: 1,
                removed_missing_objects: 1,
            }
        );
        assert!(!recovered.has_object(keys.group_id(), content_id).unwrap());
    }

    #[test]
    fn readmission_recovers_an_object_promoted_before_catalog_commit() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let mut store = Store::open(temporary_directory.path()).unwrap();
        let keys = keys();
        let plaintext = b"promoted before catalog commit";
        let content_id = keys.identify_chunk(plaintext);
        let encrypted_bytes = keys.seal_chunk(plaintext).unwrap().to_bytes().unwrap();
        let path = store.object_path(keys.group_id(), content_id);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, &encrypted_bytes).unwrap();

        assert!(!store.has_object(keys.group_id(), content_id).unwrap());
        assert_eq!(
            store
                .admit_object(&keys, ObjectKind::Chunk, content_id, &encrypted_bytes)
                .unwrap(),
            Admission::AlreadyPresent
        );
        assert!(store.has_object(keys.group_id(), content_id).unwrap());
    }

    #[test]
    fn object_request_journal_is_persistent_idempotent_and_cleared_on_admission() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let keys = keys();
        let peer = device(9);
        let first_plaintext = b"first missing object";
        let first = keys.identify_chunk(first_plaintext);
        let second = keys.identify_chunk(b"second missing object");
        let mut store = Store::open(temporary_directory.path()).unwrap();

        assert_eq!(
            store
                .queue_object_requests(keys.group_id(), peer, [first, second, first])
                .unwrap(),
            2
        );
        assert_eq!(
            store
                .queue_object_requests(keys.group_id(), peer, [first])
                .unwrap(),
            0
        );
        assert!(
            store
                .mark_object_request_attempt(keys.group_id(), peer, first)
                .unwrap()
        );
        drop(store);

        let mut reopened = Store::open(temporary_directory.path()).unwrap();
        let pending = reopened
            .pending_object_requests(keys.group_id(), peer, 10)
            .unwrap();
        assert_eq!(pending.len(), 2);
        assert_eq!(
            pending.iter().map(|state| state.attempt_count).sum::<u64>(),
            1
        );

        let encrypted_bytes = keys
            .seal_chunk(first_plaintext)
            .unwrap()
            .to_bytes()
            .unwrap();
        reopened
            .admit_object(&keys, ObjectKind::Chunk, first, &encrypted_bytes)
            .unwrap();

        let pending = reopened
            .pending_object_requests(keys.group_id(), peer, 10)
            .unwrap();
        assert_eq!(
            pending
                .iter()
                .map(|state| state.content_id)
                .collect::<Vec<_>>(),
            vec![second]
        );
        assert_eq!(
            reopened
                .queue_object_requests(keys.group_id(), peer, [first])
                .unwrap(),
            0
        );
    }

    #[test]
    fn commits_opaque_changes_idempotently_and_pins_their_object_graph() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let mut store = Store::open(temporary_directory.path()).unwrap();
        let keys = keys();
        let first_chunk = keys.seal_chunk(b"first referenced chunk").unwrap();
        let second_chunk = keys.seal_chunk(b"second referenced chunk").unwrap();
        let unreferenced_chunk = keys.seal_chunk(b"unreferenced chunk").unwrap();
        for chunk in [&first_chunk, &second_chunk, &unreferenced_chunk] {
            let encrypted_bytes = chunk.to_bytes().unwrap();
            store
                .admit_object(
                    &keys,
                    ObjectKind::Chunk,
                    chunk.content_id(),
                    &encrypted_bytes,
                )
                .unwrap();
        }
        let manifest = keys.seal_manifest(b"opaque file manifest").unwrap();
        let encrypted_manifest = manifest.to_bytes().unwrap();

        let first_commit = store
            .commit_change(
                &keys,
                revision(1),
                manifest.content_id(),
                &encrypted_manifest,
                [
                    first_chunk.content_id(),
                    second_chunk.content_id(),
                    first_chunk.content_id(),
                ],
            )
            .unwrap();
        let duplicate_commit = store
            .commit_change(
                &keys,
                revision(1),
                manifest.content_id(),
                &encrypted_manifest,
                [],
            )
            .unwrap();

        assert_eq!(
            first_commit,
            ChangeCommit {
                sequence: 1,
                inserted: true,
            }
        );
        assert_eq!(
            duplicate_commit,
            ChangeCommit {
                sequence: 1,
                inserted: false,
            }
        );
        assert_eq!(
            store.changes_after(keys.group_id(), 0, 10).unwrap(),
            ChangePage {
                records: vec![StoredChange {
                    sequence: 1,
                    revision_id: revision(1),
                    content_id: manifest.content_id(),
                }],
                high_watermark: 1,
            }
        );
        assert_eq!(
            store
                .object_reference_count(keys.group_id(), manifest.content_id())
                .unwrap(),
            Some(1)
        );
        assert_eq!(
            store
                .object_reference_count(keys.group_id(), first_chunk.content_id())
                .unwrap(),
            Some(1)
        );
        assert_eq!(
            store
                .object_reference_count(keys.group_id(), second_chunk.content_id())
                .unwrap(),
            Some(1)
        );

        let report = store
            .collect_garbage(keys.group_id(), i64::MAX, 10)
            .unwrap();
        assert_eq!(report.removed_objects, 1);
        assert_eq!(
            report.removed_encrypted_bytes,
            u64::try_from(unreferenced_chunk.to_bytes().unwrap().len()).unwrap()
        );
        assert!(
            store
                .has_object(keys.group_id(), manifest.content_id())
                .unwrap()
        );
        assert!(
            store
                .has_object(keys.group_id(), first_chunk.content_id())
                .unwrap()
        );
        assert!(
            !store
                .has_object(keys.group_id(), unreferenced_chunk.content_id())
                .unwrap()
        );
    }

    #[test]
    fn signed_changes_persist_provenance_atomically_and_retry_after_revocation() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let mut store = Store::open(temporary_directory.path()).unwrap();
        let keys = keys();
        let identity = device_identity(51);
        store
            .add_group_member(keys.group_id(), identity.public_key(), MemberRole::Member)
            .unwrap();
        let manifest = keys.seal_manifest(b"signed opaque manifest").unwrap();
        let manifest_bytes = manifest.to_bytes().unwrap();
        let revision_id = revision(51);
        let authorization =
            identity.authorize_change(keys.group_id(), revision_id, manifest.content_id());

        assert_eq!(
            store
                .commit_signed_change(
                    &keys,
                    revision_id,
                    manifest.content_id(),
                    authorization,
                    &manifest_bytes,
                    [],
                )
                .unwrap(),
            ChangeCommit {
                sequence: 1,
                inserted: true,
            }
        );
        assert_eq!(
            store
                .change_authentication(keys.group_id(), revision_id)
                .unwrap(),
            Some(StoredChangeAuthentication {
                revision_id,
                content_id: manifest.content_id(),
                authorization,
            })
        );
        assert_eq!(
            store
                .object_reference_count(keys.group_id(), manifest.content_id())
                .unwrap(),
            Some(2)
        );

        assert!(
            store
                .revoke_group_member(keys.group_id(), identity.device_id())
                .unwrap()
        );
        assert_eq!(
            store
                .commit_signed_change(
                    &keys,
                    revision_id,
                    manifest.content_id(),
                    authorization,
                    &manifest_bytes,
                    [],
                )
                .unwrap(),
            ChangeCommit {
                sequence: 1,
                inserted: false,
            }
        );

        let rejected_revision = revision(52);
        let rejected = keys.seal_manifest(b"tampered signed manifest").unwrap();
        let rejected_bytes = rejected.to_bytes().unwrap();
        let mut invalid_signature = *identity
            .authorize_change(keys.group_id(), rejected_revision, rejected.content_id())
            .signature
            .as_bytes();
        invalid_signature[0] ^= 0x80;
        let invalid = ChangeAuthorization {
            author_device_id: identity.device_id(),
            signature: ChangeSignature::from_bytes(invalid_signature),
        };
        assert!(matches!(
            store.commit_signed_change(
                &keys,
                rejected_revision,
                rejected.content_id(),
                invalid,
                &rejected_bytes,
                [],
            ),
            Err(StoreError::MemberRevoked { .. })
        ));
        assert!(
            store
                .change_authentication(keys.group_id(), rejected_revision)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store
                .changes_after(keys.group_id(), 0, 10)
                .unwrap()
                .records
                .len(),
            1
        );
        assert_eq!(
            store
                .object_reference_count(keys.group_id(), rejected.content_id())
                .unwrap(),
            Some(0)
        );
    }

    #[test]
    fn peer_high_watermarks_are_monotonic_and_persistent() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let group_id = keys().group_id();
        let peer = device(10);
        let store = Store::open(temporary_directory.path()).unwrap();

        assert_eq!(store.peer_high_watermark(group_id, peer).unwrap(), 0);
        assert_eq!(
            store
                .record_peer_high_watermark(group_id, peer, 12)
                .unwrap(),
            12
        );
        assert_eq!(
            store.record_peer_high_watermark(group_id, peer, 8).unwrap(),
            12
        );
        drop(store);

        let reopened = Store::open(temporary_directory.path()).unwrap();
        assert_eq!(reopened.peer_high_watermark(group_id, peer).unwrap(), 12);
    }

    #[test]
    fn recovery_preserves_references_while_demoting_missing_bytes() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let mut store = Store::open(temporary_directory.path()).unwrap();
        let keys = keys();
        let chunk = keys
            .seal_chunk(b"referenced bytes lost after commit")
            .unwrap();
        let encrypted_chunk = chunk.to_bytes().unwrap();
        store
            .admit_object(
                &keys,
                ObjectKind::Chunk,
                chunk.content_id(),
                &encrypted_chunk,
            )
            .unwrap();
        let manifest = keys.seal_manifest(b"manifest survives byte loss").unwrap();
        let encrypted_manifest = manifest.to_bytes().unwrap();
        store
            .commit_change(
                &keys,
                revision(2),
                manifest.content_id(),
                &encrypted_manifest,
                [chunk.content_id()],
            )
            .unwrap();
        fs::remove_file(store.object_path(keys.group_id(), chunk.content_id())).unwrap();
        drop(store);

        let mut reopened = Store::open(temporary_directory.path()).unwrap();
        assert_eq!(reopened.recovery_report().removed_missing_objects, 1);
        assert!(
            !reopened
                .has_object(keys.group_id(), chunk.content_id())
                .unwrap()
        );
        assert_eq!(
            reopened
                .object_reference_count(keys.group_id(), chunk.content_id())
                .unwrap(),
            Some(1)
        );
        assert_eq!(
            reopened
                .queue_object_requests(keys.group_id(), device(11), [chunk.content_id()])
                .unwrap(),
            1
        );

        reopened
            .admit_object(
                &keys,
                ObjectKind::Chunk,
                chunk.content_id(),
                &encrypted_chunk,
            )
            .unwrap();
        assert!(
            reopened
                .has_object(keys.group_id(), chunk.content_id())
                .unwrap()
        );
        assert_eq!(
            reopened
                .object_reference_count(keys.group_id(), chunk.content_id())
                .unwrap(),
            Some(1)
        );
        assert!(
            reopened
                .pending_object_requests(keys.group_id(), device(11), 10)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn local_head_commits_are_atomic_idempotent_and_reference_counted() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let mut store = Store::open(temporary_directory.path()).unwrap();
        let keys = keys();
        let path_id = path(4);
        let chunk = keys.seal_chunk(b"local file bytes").unwrap();
        store
            .admit_object(
                &keys,
                ObjectKind::Chunk,
                chunk.content_id(),
                &chunk.to_bytes().unwrap(),
            )
            .unwrap();
        let first = keys.seal_manifest(b"first local manifest").unwrap();
        let first_bytes = first.to_bytes().unwrap();

        let committed = store
            .commit_local_change(
                &keys,
                path_id,
                None,
                revision(20),
                ChangeRecordKind::File,
                first.content_id(),
                &first_bytes,
                [chunk.content_id()],
            )
            .unwrap();
        assert_eq!(
            committed,
            ChangeCommit {
                sequence: 1,
                inserted: true,
            }
        );
        assert_eq!(
            store.local_head(keys.group_id(), path_id).unwrap(),
            Some(LocalHead {
                path_id,
                content_id: first.content_id(),
                kind: ChangeRecordKind::File,
            })
        );
        assert_eq!(
            store
                .object_reference_count(keys.group_id(), first.content_id())
                .unwrap(),
            Some(2)
        );

        let rejected = keys.seal_manifest(b"stale scan manifest").unwrap();
        let rejected_bytes = rejected.to_bytes().unwrap();
        assert!(matches!(
            store.commit_local_change(
                &keys,
                path_id,
                Some(ContentId::from_bytes([9; 32])),
                revision(21),
                ChangeRecordKind::File,
                rejected.content_id(),
                &rejected_bytes,
                [chunk.content_id()],
            ),
            Err(StoreError::StaleLocalHead { .. })
        ));
        assert_eq!(
            store
                .changes_after(keys.group_id(), 0, 10)
                .unwrap()
                .records
                .len(),
            1
        );
        assert_eq!(
            store
                .object_reference_count(keys.group_id(), rejected.content_id())
                .unwrap(),
            Some(0)
        );
        assert_eq!(
            store
                .collect_garbage(keys.group_id(), i64::MAX, 10)
                .unwrap()
                .removed_objects,
            1
        );

        let second = keys.seal_manifest(b"second local manifest").unwrap();
        let second_bytes = second.to_bytes().unwrap();
        let advanced = store
            .commit_local_change(
                &keys,
                path_id,
                Some(first.content_id()),
                revision(22),
                ChangeRecordKind::Tombstone,
                second.content_id(),
                &second_bytes,
                [],
            )
            .unwrap();
        assert_eq!(advanced.sequence, 2);
        assert!(advanced.inserted);
        assert_eq!(
            store
                .commit_local_change(
                    &keys,
                    path_id,
                    Some(first.content_id()),
                    revision(22),
                    ChangeRecordKind::Tombstone,
                    second.content_id(),
                    &second_bytes,
                    [],
                )
                .unwrap(),
            ChangeCommit {
                sequence: 2,
                inserted: false,
            }
        );
        assert_eq!(
            store.local_heads(keys.group_id()).unwrap(),
            vec![LocalHead {
                path_id,
                content_id: second.content_id(),
                kind: ChangeRecordKind::Tombstone,
            }]
        );
        assert_eq!(
            store
                .object_reference_count(keys.group_id(), first.content_id())
                .unwrap(),
            Some(1)
        );
        assert_eq!(
            store
                .object_reference_count(keys.group_id(), second.content_id())
                .unwrap(),
            Some(2)
        );
        drop(store);

        let reopened = Store::open(temporary_directory.path()).unwrap();
        assert_eq!(
            reopened.local_head(keys.group_id(), path_id).unwrap(),
            Some(LocalHead {
                path_id,
                content_id: second.content_id(),
                kind: ChangeRecordKind::Tombstone,
            })
        );
    }

    #[test]
    fn local_only_heads_pin_objects_without_entering_the_change_log() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let mut store = Store::open(temporary_directory.path()).unwrap();
        let keys = keys();
        let path_id = path(8);
        let chunk = keys.seal_chunk(b"local-only conflict bytes").unwrap();
        store
            .admit_object(
                &keys,
                ObjectKind::Chunk,
                chunk.content_id(),
                &chunk.to_bytes().unwrap(),
            )
            .unwrap();
        let manifest = keys.seal_manifest(b"local-only conflict manifest").unwrap();
        let manifest_bytes = manifest.to_bytes().unwrap();

        store
            .commit_local_only_head(
                &keys,
                path_id,
                None,
                ChangeRecordKind::File,
                manifest.content_id(),
                &manifest_bytes,
                [chunk.content_id()],
            )
            .unwrap();
        store
            .commit_local_only_head(
                &keys,
                path_id,
                None,
                ChangeRecordKind::File,
                manifest.content_id(),
                &manifest_bytes,
                [],
            )
            .unwrap();

        assert_eq!(
            store.local_head(keys.group_id(), path_id).unwrap(),
            Some(LocalHead {
                path_id,
                content_id: manifest.content_id(),
                kind: ChangeRecordKind::File,
            })
        );
        assert!(
            store
                .changes_after(keys.group_id(), 0, 10)
                .unwrap()
                .records
                .is_empty()
        );
        assert_eq!(
            store
                .object_reference_count(keys.group_id(), manifest.content_id())
                .unwrap(),
            Some(1)
        );
        assert_eq!(
            store
                .object_reference_count(keys.group_id(), chunk.content_id())
                .unwrap(),
            Some(1)
        );
        assert_eq!(
            store
                .collect_garbage(keys.group_id(), i64::MAX, 10)
                .unwrap(),
            GarbageCollectionReport::default()
        );
    }

    #[test]
    fn incoming_object_transfers_resume_and_authenticate_after_restart() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let keys = keys();
        let peer = device(11);
        let object = keys.seal_chunk(b"encrypted transfer payload").unwrap();
        let content_id = object.content_id();
        let encrypted_bytes = object.to_bytes().unwrap();
        let split = encrypted_bytes.len() / 2;
        let mut store = Store::open(temporary_directory.path()).unwrap();
        store
            .queue_object_requests(keys.group_id(), peer, [content_id])
            .unwrap();

        assert_eq!(
            store
                .begin_object_transfer(
                    keys.group_id(),
                    peer,
                    Uuid::from_u128(1),
                    content_id,
                    encrypted_bytes.len() as u64,
                )
                .unwrap(),
            ObjectTransferAdmission::Started
        );
        assert_eq!(
            store
                .append_object_transfer(
                    keys.group_id(),
                    peer,
                    content_id,
                    0,
                    &encrypted_bytes[..split],
                )
                .unwrap(),
            split as u64
        );
        drop(store);

        let mut store = Store::open(temporary_directory.path()).unwrap();
        assert_eq!(
            store
                .begin_object_transfer(
                    keys.group_id(),
                    peer,
                    Uuid::from_u128(2),
                    content_id,
                    encrypted_bytes.len() as u64,
                )
                .unwrap(),
            ObjectTransferAdmission::Resuming {
                received_size: split as u64,
            }
        );
        assert!(matches!(
            store.append_object_transfer(
                keys.group_id(),
                peer,
                content_id,
                0,
                &encrypted_bytes[split..],
            ),
            Err(StoreError::TransferOffsetMismatch { .. })
        ));
        store
            .append_object_transfer(
                keys.group_id(),
                peer,
                content_id,
                split as u64,
                &encrypted_bytes[split..],
            )
            .unwrap();
        assert_eq!(
            store
                .complete_object_transfer(&keys, peer, content_id)
                .unwrap(),
            Admission::Stored
        );
        assert_eq!(
            store
                .load_object(&keys, ObjectKind::Chunk, content_id)
                .unwrap(),
            encrypted_bytes
        );
        assert!(
            store
                .incoming_object_transfer(keys.group_id(), peer, content_id)
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .pending_object_requests(keys.group_id(), peer, 10)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn transfer_recovery_adopts_fsynced_bytes_and_removes_orphans() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let keys = keys();
        let peer = device(12);
        let object = keys
            .seal_manifest(b"recoverable encrypted manifest")
            .unwrap();
        let content_id = object.content_id();
        let encrypted_bytes = object.to_bytes().unwrap();
        let mut store = Store::open(temporary_directory.path()).unwrap();
        store
            .queue_object_requests(keys.group_id(), peer, [content_id])
            .unwrap();
        store
            .begin_object_transfer(
                keys.group_id(),
                peer,
                Uuid::from_u128(3),
                content_id,
                encrypted_bytes.len() as u64,
            )
            .unwrap();
        let transfer_path = incoming_transfer_path_for(
            temporary_directory.path(),
            keys.group_id(),
            peer,
            content_id,
        );
        let mut transfer_file = OpenOptions::new()
            .append(true)
            .open(&transfer_path)
            .unwrap();
        transfer_file.write_all(&encrypted_bytes).unwrap();
        transfer_file.sync_all().unwrap();
        drop(transfer_file);
        let orphan_path = temporary_directory
            .path()
            .join(TRANSFERS_DIRECTORY)
            .join("orphan.part");
        fs::write(&orphan_path, b"orphan").unwrap();
        drop(store);

        let mut store = Store::open(temporary_directory.path()).unwrap();
        assert_eq!(
            store
                .incoming_object_transfer(keys.group_id(), peer, content_id)
                .unwrap()
                .unwrap()
                .received_size,
            encrypted_bytes.len() as u64
        );
        assert!(!orphan_path.exists());
        assert_eq!(
            store
                .complete_object_transfer(&keys, peer, content_id)
                .unwrap(),
            Admission::Stored
        );
    }

    #[test]
    fn materialization_journal_is_persistent_idempotent_and_pins_its_target() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let mut store = Store::open(temporary_directory.path()).unwrap();
        let keys = keys();
        let path_id = path(7);
        let target = keys.seal_manifest(b"pending incoming manifest").unwrap();
        let target_bytes = target.to_bytes().unwrap();
        store
            .admit_object(
                &keys,
                ObjectKind::Manifest,
                target.content_id(),
                &target_bytes,
            )
            .unwrap();

        assert_eq!(
            store
                .begin_materialization(
                    keys.group_id(),
                    path_id,
                    target.content_id(),
                    None,
                    ChangeRecordKind::File,
                    Some(".orbit-stage-00000000000000000000000000000001.tmp"),
                )
                .unwrap(),
            MaterializationAdmission::Queued
        );
        assert_eq!(
            store
                .begin_materialization(
                    keys.group_id(),
                    path_id,
                    target.content_id(),
                    None,
                    ChangeRecordKind::File,
                    Some(".orbit-stage-00000000000000000000000000000001.tmp"),
                )
                .unwrap(),
            MaterializationAdmission::AlreadyPending
        );
        assert_eq!(
            store
                .object_reference_count(keys.group_id(), target.content_id())
                .unwrap(),
            Some(1)
        );
        assert!(matches!(
            store.begin_materialization(
                keys.group_id(),
                path_id,
                target.content_id(),
                None,
                ChangeRecordKind::Tombstone,
                None,
            ),
            Err(StoreError::MaterializationInProgress { .. })
        ));
        assert!(matches!(
            store.begin_materialization(
                keys.group_id(),
                path(8),
                target.content_id(),
                None,
                ChangeRecordKind::File,
                Some("../escape.tmp"),
            ),
            Err(StoreError::InvalidMaterializationStage)
        ));
        drop(store);

        let reopened = Store::open(temporary_directory.path()).unwrap();
        assert_eq!(
            reopened.pending_materializations(keys.group_id()).unwrap(),
            vec![PendingMaterialization {
                path_id,
                target_content_id: target.content_id(),
                expected_previous_content_id: None,
                kind: ChangeRecordKind::File,
                stage_name: Some(".orbit-stage-00000000000000000000000000000001.tmp".to_owned(),),
            }]
        );
        let mut reopened = reopened;
        reopened
            .commit_local_change(
                &keys,
                path_id,
                None,
                revision(30),
                ChangeRecordKind::File,
                target.content_id(),
                &target_bytes,
                [],
            )
            .unwrap();
        assert_eq!(
            reopened
                .begin_materialization(
                    keys.group_id(),
                    path_id,
                    target.content_id(),
                    None,
                    ChangeRecordKind::File,
                    Some(".orbit-stage-00000000000000000000000000000001.tmp"),
                )
                .unwrap(),
            MaterializationAdmission::AlreadyPending
        );
        assert!(
            reopened
                .complete_materialization(keys.group_id(), path_id, target.content_id())
                .unwrap()
        );
        assert_eq!(
            reopened
                .object_reference_count(keys.group_id(), target.content_id())
                .unwrap(),
            Some(2)
        );
    }

    #[test]
    fn rejects_corrupt_persisted_materialization_stage_names() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let mut store = Store::open(temporary_directory.path()).unwrap();
        let keys = keys();
        let path_id = path(7);
        let target = keys.seal_manifest(b"pending incoming manifest").unwrap();
        store
            .admit_object(
                &keys,
                ObjectKind::Manifest,
                target.content_id(),
                &target.to_bytes().unwrap(),
            )
            .unwrap();
        store
            .begin_materialization(
                keys.group_id(),
                path_id,
                target.content_id(),
                None,
                ChangeRecordKind::File,
                Some(".orbit-stage-00000000000000000000000000000001.tmp"),
            )
            .unwrap();
        store
            .connection
            .execute(
                "UPDATE pending_materializations SET stage_name = '../escape.tmp'
                 WHERE group_id = ?1 AND path_id = ?2",
                params![
                    &keys.group_id().as_uuid().as_bytes()[..],
                    &path_id.as_bytes()[..],
                ],
            )
            .unwrap();

        assert!(matches!(
            store.pending_materializations(keys.group_id()),
            Err(StoreError::InvalidMaterializationStage)
        ));
    }
}
