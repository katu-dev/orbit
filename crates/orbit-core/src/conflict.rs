use thiserror::Error;

use crate::{
    ChangeRecord, FileId, FileManifest, PathError, RelativePath, RevisionId, VersionRelation,
};

const MAX_COMPONENT_BYTES: usize = 255;
const MAX_DEVICE_LABEL_BYTES: usize = 48;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconcileAction {
    NoChange,
    KeepLocal,
    UseIncoming,
    KeepBoth {
        canonical_revision: RevisionId,
        conflict_revision: RevisionId,
    },
}

pub fn reconcile_change(
    local: &ChangeRecord,
    incoming: &ChangeRecord,
) -> Result<ReconcileAction, ReconcileError> {
    if local.file_id() != incoming.file_id() {
        return Err(ReconcileError::DifferentFiles {
            local: local.file_id(),
            incoming: incoming.file_id(),
        });
    }
    if local.revision_id() == incoming.revision_id() {
        return if local == incoming {
            Ok(ReconcileAction::NoChange)
        } else {
            Err(ReconcileError::RevisionCollision {
                revision_id: local.revision_id(),
            })
        };
    }

    match (local, incoming) {
        (ChangeRecord::File(local), ChangeRecord::File(incoming)) => {
            reconcile_file(local, incoming)
        }
        (ChangeRecord::Tombstone(_), ChangeRecord::Tombstone(_)) => {
            Ok(select_single_winner(local, incoming))
        }
        (ChangeRecord::File(_), ChangeRecord::Tombstone(_)) => Ok(reconcile_edit_delete(
            local,
            incoming,
            ReconcileAction::KeepLocal,
        )),
        (ChangeRecord::Tombstone(_), ChangeRecord::File(_)) => Ok(reconcile_edit_delete(
            local,
            incoming,
            ReconcileAction::UseIncoming,
        )),
    }
}

pub fn reconcile_file(
    local: &FileManifest,
    incoming: &FileManifest,
) -> Result<ReconcileAction, ReconcileError> {
    if local.file_id != incoming.file_id {
        return Err(ReconcileError::DifferentFiles {
            local: local.file_id,
            incoming: incoming.file_id,
        });
    }
    if local.revision_id == incoming.revision_id {
        return if local == incoming {
            Ok(ReconcileAction::NoChange)
        } else {
            Err(ReconcileError::RevisionCollision {
                revision_id: local.revision_id,
            })
        };
    }

    match local.version.relation(&incoming.version) {
        VersionRelation::Ancestor => Ok(ReconcileAction::UseIncoming),
        VersionRelation::Descendant => Ok(ReconcileAction::KeepLocal),
        VersionRelation::Equal | VersionRelation::Concurrent => {
            let (canonical_revision, conflict_revision) = if (&local.version, local.revision_id)
                >= (&incoming.version, incoming.revision_id)
            {
                (local.revision_id, incoming.revision_id)
            } else {
                (incoming.revision_id, local.revision_id)
            };

            Ok(ReconcileAction::KeepBoth {
                canonical_revision,
                conflict_revision,
            })
        }
    }
}

fn reconcile_edit_delete(
    local: &ChangeRecord,
    incoming: &ChangeRecord,
    concurrent_winner: ReconcileAction,
) -> ReconcileAction {
    match local.version().relation(incoming.version()) {
        VersionRelation::Ancestor => ReconcileAction::UseIncoming,
        VersionRelation::Descendant => ReconcileAction::KeepLocal,
        VersionRelation::Equal | VersionRelation::Concurrent => concurrent_winner,
    }
}

fn select_single_winner(local: &ChangeRecord, incoming: &ChangeRecord) -> ReconcileAction {
    match local.version().relation(incoming.version()) {
        VersionRelation::Ancestor => ReconcileAction::UseIncoming,
        VersionRelation::Descendant => ReconcileAction::KeepLocal,
        VersionRelation::Equal | VersionRelation::Concurrent => {
            if (local.version(), local.revision_id())
                >= (incoming.version(), incoming.revision_id())
            {
                ReconcileAction::KeepLocal
            } else {
                ReconcileAction::UseIncoming
            }
        }
    }
}

pub fn conflict_copy_path(
    original: &RelativePath,
    device_label: &str,
    timestamp_unix_ms: i64,
    revision_id: RevisionId,
) -> Result<RelativePath, PathError> {
    let (parent, file_name) = original
        .as_str()
        .rsplit_once('/')
        .map_or((None, original.file_name()), |(parent, file_name)| {
            (Some(parent), file_name)
        });
    let (stem, extension) = split_extension(file_name);
    let device_label = portable_device_label(device_label);
    let revision = revision_id.as_uuid().simple().to_string();
    let suffix = format!(
        " (Orbit conflict {device_label} {timestamp_unix_ms} {})",
        &revision[..8]
    );
    let extension = extension.map_or(String::new(), |value| format!(".{value}"));
    let maximum_stem_bytes = MAX_COMPONENT_BYTES.saturating_sub(suffix.len() + extension.len());
    let stem = truncate_utf8(stem, maximum_stem_bytes);
    let conflict_name = format!("{stem}{suffix}{extension}");
    let display = parent.map_or(conflict_name.clone(), |parent| {
        format!("{parent}/{conflict_name}")
    });

    RelativePath::new(display)
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ReconcileError {
    #[error("cannot reconcile different files: local {local}, incoming {incoming}")]
    DifferentFiles { local: FileId, incoming: FileId },
    #[error("revision {revision_id} identifies different change records")]
    RevisionCollision { revision_id: RevisionId },
}

fn split_extension(file_name: &str) -> (&str, Option<&str>) {
    match file_name.rsplit_once('.') {
        Some((stem, extension)) if !stem.is_empty() && !extension.is_empty() => {
            (stem, Some(extension))
        }
        _ => (file_name, None),
    }
}

fn portable_device_label(value: &str) -> String {
    let sanitized: String = value
        .chars()
        .map(|character| {
            if character.is_control() || r#"<>:"/\|?*"#.contains(character) {
                '_'
            } else {
                character
            }
        })
        .collect();
    let sanitized = sanitized.trim().trim_end_matches(['.', ' ']);
    let sanitized = if sanitized.is_empty() {
        "device"
    } else {
        sanitized
    };

    truncate_utf8(sanitized, MAX_DEVICE_LABEL_BYTES).to_owned()
}

fn truncate_utf8(value: &str, maximum_bytes: usize) -> &str {
    if value.len() <= maximum_bytes {
        return value;
    }

    let mut boundary = maximum_bytes;
    while !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    &value[..boundary]
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;
    use crate::{ChunkRef, ContentId, DeviceId, Tombstone, VersionVector};

    fn manifest(file_id: FileId, revision: u128, device: u128) -> FileManifest {
        let mut version = VersionVector::default();
        version
            .increment(DeviceId::from_uuid(Uuid::from_u128(device)))
            .unwrap();

        FileManifest {
            file_id,
            revision_id: RevisionId::from_uuid(Uuid::from_u128(revision)),
            relative_path: RelativePath::new("docs/report.txt").unwrap(),
            size: 4,
            modified_at_unix_ms: 1,
            version,
            chunks: vec![ChunkRef {
                content_id: ContentId::from_bytes([1; 32]),
                plaintext_size: 4,
            }],
        }
    }

    #[test]
    fn selects_newer_descendant() {
        let file_id = FileId::from_uuid(Uuid::from_u128(1));
        let local = manifest(file_id, 10, 100);
        let mut incoming = local.clone();
        incoming
            .version
            .increment(DeviceId::from_uuid(Uuid::from_u128(100)))
            .unwrap();
        incoming.revision_id = RevisionId::from_uuid(Uuid::from_u128(11));

        assert_eq!(
            reconcile_file(&local, &incoming).unwrap(),
            ReconcileAction::UseIncoming
        );
    }

    #[test]
    fn concurrent_choice_is_independent_of_arrival_order() {
        let file_id = FileId::from_uuid(Uuid::from_u128(1));
        let left = manifest(file_id, 10, 100);
        let right = manifest(file_id, 20, 200);

        let forward = reconcile_file(&left, &right).unwrap();
        let reverse = reconcile_file(&right, &left).unwrap();

        assert_eq!(forward, reverse);
        assert!(matches!(forward, ReconcileAction::KeepBoth { .. }));
    }

    #[test]
    fn conflict_name_is_portable_and_preserves_extension() {
        let original = RelativePath::new("docs/quarterly.report.pdf").unwrap();
        let revision = RevisionId::from_uuid(Uuid::from_u128(0x1234));

        let conflict = conflict_copy_path(&original, "Eloi/Desktop:1", 1_700_000, revision)
            .expect("conflict path should remain portable");

        assert_eq!(
            conflict.as_str(),
            "docs/quarterly.report (Orbit conflict Eloi_Desktop_1 1700000 00000000).pdf"
        );
    }

    #[test]
    fn concurrent_edit_delete_keeps_the_edit_independent_of_arrival_order() {
        let file_id = FileId::from_uuid(Uuid::from_u128(1));
        let file = ChangeRecord::File(manifest(file_id, 10, 100));
        let tombstone = ChangeRecord::Tombstone(Tombstone {
            file_id,
            revision_id: RevisionId::from_uuid(Uuid::from_u128(20)),
            relative_path: RelativePath::new("docs/report.txt").unwrap(),
            deleted_at_unix_ms: 2,
            version: VersionVector::from_entries([(DeviceId::from_uuid(Uuid::from_u128(200)), 1)])
                .unwrap(),
        });

        assert_eq!(
            reconcile_change(&file, &tombstone).unwrap(),
            ReconcileAction::KeepLocal
        );
        assert_eq!(
            reconcile_change(&tombstone, &file).unwrap(),
            ReconcileAction::UseIncoming
        );
    }

    #[test]
    fn descendant_delete_wins_and_concurrent_tombstones_converge() {
        let file_id = FileId::from_uuid(Uuid::from_u128(1));
        let file = ChangeRecord::File(manifest(file_id, 10, 100));
        let mut delete_version = file.version().clone();
        delete_version
            .increment(DeviceId::from_uuid(Uuid::from_u128(100)))
            .unwrap();
        let delete = ChangeRecord::Tombstone(Tombstone {
            file_id,
            revision_id: RevisionId::from_uuid(Uuid::from_u128(20)),
            relative_path: RelativePath::new("docs/report.txt").unwrap(),
            deleted_at_unix_ms: 2,
            version: delete_version,
        });
        assert_eq!(
            reconcile_change(&file, &delete).unwrap(),
            ReconcileAction::UseIncoming
        );

        let left = ChangeRecord::Tombstone(Tombstone {
            file_id,
            revision_id: RevisionId::from_uuid(Uuid::from_u128(30)),
            relative_path: RelativePath::new("docs/report.txt").unwrap(),
            deleted_at_unix_ms: 3,
            version: VersionVector::from_entries([(DeviceId::from_uuid(Uuid::from_u128(1)), 1)])
                .unwrap(),
        });
        let right = ChangeRecord::Tombstone(Tombstone {
            file_id,
            revision_id: RevisionId::from_uuid(Uuid::from_u128(40)),
            relative_path: RelativePath::new("docs/report.txt").unwrap(),
            deleted_at_unix_ms: 4,
            version: VersionVector::from_entries([(DeviceId::from_uuid(Uuid::from_u128(2)), 1)])
                .unwrap(),
        });
        assert_eq!(
            reconcile_change(&left, &right).unwrap(),
            ReconcileAction::UseIncoming
        );
        assert_eq!(
            reconcile_change(&right, &left).unwrap(),
            ReconcileAction::KeepLocal
        );
    }
}
