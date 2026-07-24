use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    str::FromStr,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

mod conflict;
mod path;

pub use conflict::{
    ReconcileAction, ReconcileError, conflict_copy_path, reconcile_change, reconcile_file,
};
pub use path::{PathError, RelativePath};

pub const PROTOCOL_VERSION: u16 = 1;

macro_rules! define_id {
    ($name:ident) => {
        #[derive(
            Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
        )]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }

            #[must_use]
            pub const fn from_uuid(value: Uuid) -> Self {
                Self(value)
            }

            #[must_use]
            pub const fn as_uuid(&self) -> &Uuid {
                &self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = uuid::Error;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(value).map(Self)
            }
        }
    };
}

define_id!(DeviceId);
define_id!(FileId);
define_id!(GroupId);
define_id!(RevisionId);

macro_rules! define_digest_id {
    ($name:ident) => {
        #[derive(
            Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
        )]
        #[serde(transparent)]
        pub struct $name([u8; 32]);

        impl $name {
            #[must_use]
            pub const fn from_bytes(value: [u8; 32]) -> Self {
                Self(value)
            }

            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            #[must_use]
            pub const fn into_bytes(self) -> [u8; 32] {
                self.0
            }
        }
    };
}

define_digest_id!(ContentId);
define_digest_id!(PathId);

#[derive(Clone, Debug, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct VersionVector(BTreeMap<DeviceId, u64>);

impl VersionVector {
    pub fn from_entries(
        entries: impl IntoIterator<Item = (DeviceId, u64)>,
    ) -> Result<Self, VersionVectorError> {
        let mut counters = BTreeMap::new();
        for (device_id, counter) in entries {
            if counter == 0 {
                return Err(VersionVectorError::ZeroCounter { device_id });
            }
            if counters.insert(device_id, counter).is_some() {
                return Err(VersionVectorError::DuplicateDevice { device_id });
            }
        }
        Ok(Self(counters))
    }

    #[must_use]
    pub fn counter(&self, device_id: DeviceId) -> u64 {
        self.0.get(&device_id).copied().unwrap_or_default()
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = (DeviceId, u64)> + '_ {
        self.0
            .iter()
            .map(|(&device_id, &counter)| (device_id, counter))
    }

    pub fn increment(&mut self, device_id: DeviceId) -> Result<u64, VersionVectorError> {
        let counter = self.0.entry(device_id).or_default();
        *counter = counter
            .checked_add(1)
            .ok_or(VersionVectorError::CounterOverflow { device_id })?;
        Ok(*counter)
    }

    pub fn merge(&mut self, other: &Self) {
        for (&device_id, &other_counter) in &other.0 {
            let counter = self.0.entry(device_id).or_default();
            *counter = (*counter).max(other_counter);
        }
    }

    #[must_use]
    pub fn relation(&self, other: &Self) -> VersionRelation {
        let devices: BTreeSet<_> = self.0.keys().chain(other.0.keys()).copied().collect();
        let mut self_is_ahead = false;
        let mut other_is_ahead = false;

        for device_id in devices {
            match self.counter(device_id).cmp(&other.counter(device_id)) {
                std::cmp::Ordering::Less => other_is_ahead = true,
                std::cmp::Ordering::Greater => self_is_ahead = true,
                std::cmp::Ordering::Equal => {}
            }

            if self_is_ahead && other_is_ahead {
                return VersionRelation::Concurrent;
            }
        }

        match (self_is_ahead, other_is_ahead) {
            (false, false) => VersionRelation::Equal,
            (false, true) => VersionRelation::Ancestor,
            (true, false) => VersionRelation::Descendant,
            (true, true) => VersionRelation::Concurrent,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VersionRelation {
    Equal,
    Ancestor,
    Descendant,
    Concurrent,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum VersionVectorError {
    #[error("version counter overflow for device {device_id}")]
    CounterOverflow { device_id: DeviceId },
    #[error("version counter for device {device_id} cannot be zero")]
    ZeroCounter { device_id: DeviceId },
    #[error("version vector contains duplicate device {device_id}")]
    DuplicateDevice { device_id: DeviceId },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChunkRef {
    pub content_id: ContentId,
    pub plaintext_size: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FileManifest {
    pub file_id: FileId,
    pub revision_id: RevisionId,
    pub relative_path: RelativePath,
    pub size: u64,
    pub modified_at_unix_ms: i64,
    pub version: VersionVector,
    pub chunks: Vec<ChunkRef>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Tombstone {
    pub file_id: FileId,
    pub revision_id: RevisionId,
    pub relative_path: RelativePath,
    pub deleted_at_unix_ms: i64,
    pub version: VersionVector,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ChangeRecord {
    File(FileManifest),
    Tombstone(Tombstone),
}

impl ChangeRecord {
    #[must_use]
    pub const fn kind(&self) -> ChangeRecordKind {
        match self {
            Self::File(_) => ChangeRecordKind::File,
            Self::Tombstone(_) => ChangeRecordKind::Tombstone,
        }
    }

    #[must_use]
    pub const fn file_id(&self) -> FileId {
        match self {
            Self::File(manifest) => manifest.file_id,
            Self::Tombstone(tombstone) => tombstone.file_id,
        }
    }

    #[must_use]
    pub const fn revision_id(&self) -> RevisionId {
        match self {
            Self::File(manifest) => manifest.revision_id,
            Self::Tombstone(tombstone) => tombstone.revision_id,
        }
    }

    #[must_use]
    pub const fn relative_path(&self) -> &RelativePath {
        match self {
            Self::File(manifest) => &manifest.relative_path,
            Self::Tombstone(tombstone) => &tombstone.relative_path,
        }
    }

    #[must_use]
    pub const fn version(&self) -> &VersionVector {
        match self {
            Self::File(manifest) => &manifest.version,
            Self::Tombstone(tombstone) => &tombstone.version,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ChangeRecordKind {
    File,
    Tombstone,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(value: u128) -> DeviceId {
        DeviceId::from_uuid(Uuid::from_u128(value))
    }

    #[test]
    fn empty_vectors_are_equal() {
        assert_eq!(
            VersionVector::default().relation(&VersionVector::default()),
            VersionRelation::Equal
        );
    }

    #[test]
    fn detects_ancestor_and_descendant() {
        let first = device(1);
        let mut older = VersionVector::default();
        older.increment(first).unwrap();

        let mut newer = older.clone();
        newer.increment(first).unwrap();

        assert_eq!(older.relation(&newer), VersionRelation::Ancestor);
        assert_eq!(newer.relation(&older), VersionRelation::Descendant);
    }

    #[test]
    fn detects_concurrent_updates() {
        let mut left = VersionVector::default();
        left.increment(device(1)).unwrap();

        let mut right = VersionVector::default();
        right.increment(device(2)).unwrap();

        assert_eq!(left.relation(&right), VersionRelation::Concurrent);
        assert_eq!(right.relation(&left), VersionRelation::Concurrent);
    }

    #[test]
    fn merge_takes_each_devices_highest_counter() {
        let first = device(1);
        let second = device(2);
        let mut left = VersionVector::default();
        left.increment(first).unwrap();

        let mut right = VersionVector::default();
        right.increment(first).unwrap();
        right.increment(first).unwrap();
        right.increment(second).unwrap();

        left.merge(&right);

        assert_eq!(left.counter(first), 2);
        assert_eq!(left.counter(second), 1);
        assert_eq!(left.relation(&right), VersionRelation::Equal);
    }

    #[test]
    fn checked_entries_are_sorted_for_canonical_encoding() {
        let first = device(1);
        let second = device(2);
        let version = VersionVector::from_entries([(second, 4), (first, 2)]).unwrap();

        assert_eq!(
            version.iter().collect::<Vec<_>>(),
            vec![(first, 2), (second, 4)]
        );
    }

    #[test]
    fn checked_entries_reject_zero_and_duplicate_counters() {
        let first = device(1);

        assert_eq!(
            VersionVector::from_entries([(first, 0)]),
            Err(VersionVectorError::ZeroCounter { device_id: first })
        );
        assert_eq!(
            VersionVector::from_entries([(first, 1), (first, 2)]),
            Err(VersionVectorError::DuplicateDevice { device_id: first })
        );
    }
}
