#![forbid(unsafe_code)]

use std::{collections::HashSet, io::Read};

use fastcdc::v2020::{
    AVERAGE_MAX, AVERAGE_MIN, FastCDC, MAXIMUM_MAX, MAXIMUM_MIN, MINIMUM_MAX, MINIMUM_MIN,
    StreamCDC,
};
use orbit_core::{ChunkRef, ContentId};
use orbit_crypto::GroupKeys;
use thiserror::Error;

pub const DEFAULT_MINIMUM_CHUNK_SIZE: usize = 64 * 1024;
pub const DEFAULT_AVERAGE_CHUNK_SIZE: usize = 256 * 1024;
pub const DEFAULT_MAXIMUM_CHUNK_SIZE: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChunkingConfig {
    minimum_size: usize,
    average_size: usize,
    maximum_size: usize,
}

impl ChunkingConfig {
    pub fn new(
        minimum_size: usize,
        average_size: usize,
        maximum_size: usize,
    ) -> Result<Self, ChunkingError> {
        if !(MINIMUM_MIN..=MINIMUM_MAX).contains(&minimum_size) {
            return Err(ChunkingError::MinimumSizeOutOfRange {
                value: minimum_size,
                minimum: MINIMUM_MIN,
                maximum: MINIMUM_MAX,
            });
        }
        if !(AVERAGE_MIN..=AVERAGE_MAX).contains(&average_size) {
            return Err(ChunkingError::AverageSizeOutOfRange {
                value: average_size,
                minimum: AVERAGE_MIN,
                maximum: AVERAGE_MAX,
            });
        }
        if !(MAXIMUM_MIN..=MAXIMUM_MAX).contains(&maximum_size) {
            return Err(ChunkingError::MaximumSizeOutOfRange {
                value: maximum_size,
                minimum: MAXIMUM_MIN,
                maximum: MAXIMUM_MAX,
            });
        }
        if minimum_size > average_size || average_size > maximum_size {
            return Err(ChunkingError::InvalidSizeOrder {
                minimum: minimum_size,
                average: average_size,
                maximum: maximum_size,
            });
        }
        if !average_size.is_power_of_two() {
            return Err(ChunkingError::AverageSizeNotPowerOfTwo(average_size));
        }

        Ok(Self {
            minimum_size,
            average_size,
            maximum_size,
        })
    }

    #[must_use]
    pub const fn minimum_size(self) -> usize {
        self.minimum_size
    }

    #[must_use]
    pub const fn average_size(self) -> usize {
        self.average_size
    }

    #[must_use]
    pub const fn maximum_size(self) -> usize {
        self.maximum_size
    }

    pub fn chunk_slice(self, source: &[u8], keys: &GroupKeys) -> Result<ChunkPlan, ChunkingError> {
        let mut descriptors = Vec::new();

        for chunk in FastCDC::new(
            source,
            self.minimum_size,
            self.average_size,
            self.maximum_size,
        ) {
            let end = chunk
                .offset
                .checked_add(chunk.length)
                .ok_or(ChunkingError::InvalidChunkBoundary)?;
            let data = source
                .get(chunk.offset..end)
                .ok_or(ChunkingError::InvalidChunkBoundary)?;
            descriptors.push(ChunkDescriptor::new(
                u64::try_from(chunk.offset).map_err(|_| ChunkingError::SourceTooLarge)?,
                chunk.length,
                keys.identify_chunk(data),
            )?);
        }

        Ok(ChunkPlan {
            total_size: u64::try_from(source.len()).map_err(|_| ChunkingError::SourceTooLarge)?,
            chunks: descriptors,
        })
    }

    #[must_use]
    pub fn stream<'keys, R: Read>(
        self,
        source: R,
        keys: &'keys GroupKeys,
    ) -> ChunkStream<'keys, R> {
        ChunkStream {
            inner: StreamCDC::new(
                source,
                self.minimum_size,
                self.average_size,
                self.maximum_size,
            ),
            keys,
        }
    }

    pub fn chunk_reader<R: Read>(
        self,
        source: R,
        keys: &GroupKeys,
    ) -> Result<ChunkPlan, ChunkingError> {
        let mut chunks = Vec::new();
        let mut total_size = 0_u64;

        for chunk in self.stream(source, keys) {
            let chunk = chunk?;
            total_size = chunk
                .offset
                .checked_add(u64::from(chunk.plaintext_size()))
                .ok_or(ChunkingError::SourceTooLarge)?;
            chunks.push(chunk.descriptor());
        }

        Ok(ChunkPlan { total_size, chunks })
    }
}

impl Default for ChunkingConfig {
    fn default() -> Self {
        Self {
            minimum_size: DEFAULT_MINIMUM_CHUNK_SIZE,
            average_size: DEFAULT_AVERAGE_CHUNK_SIZE,
            maximum_size: DEFAULT_MAXIMUM_CHUNK_SIZE,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChunkDescriptor {
    offset: u64,
    plaintext_size: u32,
    content_id: ContentId,
}

impl ChunkDescriptor {
    fn new(
        offset: u64,
        plaintext_size: usize,
        content_id: ContentId,
    ) -> Result<Self, ChunkingError> {
        Ok(Self {
            offset,
            plaintext_size: u32::try_from(plaintext_size)
                .map_err(|_| ChunkingError::ChunkTooLarge(plaintext_size))?,
            content_id,
        })
    }

    #[must_use]
    pub const fn offset(&self) -> u64 {
        self.offset
    }

    #[must_use]
    pub const fn plaintext_size(&self) -> u32 {
        self.plaintext_size
    }

    #[must_use]
    pub const fn content_id(&self) -> ContentId {
        self.content_id
    }

    #[must_use]
    pub const fn chunk_ref(&self) -> ChunkRef {
        ChunkRef {
            content_id: self.content_id,
            plaintext_size: self.plaintext_size,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChunkPlan {
    total_size: u64,
    chunks: Vec<ChunkDescriptor>,
}

impl ChunkPlan {
    #[must_use]
    pub const fn total_size(&self) -> u64 {
        self.total_size
    }

    #[must_use]
    pub fn chunks(&self) -> &[ChunkDescriptor] {
        &self.chunks
    }

    pub fn chunk_refs(&self) -> impl ExactSizeIterator<Item = ChunkRef> + '_ {
        self.chunks.iter().map(ChunkDescriptor::chunk_ref)
    }

    pub fn delta_against<I>(&self, available_content: I) -> DeltaPlan
    where
        I: IntoIterator<Item = ContentId>,
    {
        let available: HashSet<_> = available_content.into_iter().collect();
        let mut reusable = available;
        let mut required = Vec::new();
        let mut reused_chunks = 0_usize;
        let mut reused_bytes = 0_u64;
        let mut transfer_bytes = 0_u64;

        for chunk in &self.chunks {
            if reusable.insert(chunk.content_id) {
                let chunk_ref = chunk.chunk_ref();
                transfer_bytes += u64::from(chunk_ref.plaintext_size);
                required.push(chunk_ref);
            } else {
                reused_chunks += 1;
                reused_bytes += u64::from(chunk.plaintext_size);
            }
        }

        DeltaPlan {
            required,
            reused_chunks,
            reused_bytes,
            transfer_bytes,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChunkPayload {
    offset: u64,
    content_id: ContentId,
    data: Vec<u8>,
}

impl ChunkPayload {
    #[must_use]
    pub const fn offset(&self) -> u64 {
        self.offset
    }

    #[must_use]
    pub const fn content_id(&self) -> ContentId {
        self.content_id
    }

    #[must_use]
    pub fn plaintext_size(&self) -> u32 {
        u32::try_from(self.data.len()).expect("validated FastCDC chunk size fits in u32")
    }

    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    #[must_use]
    pub fn into_data(self) -> Vec<u8> {
        self.data
    }

    #[must_use]
    pub fn descriptor(&self) -> ChunkDescriptor {
        ChunkDescriptor {
            offset: self.offset,
            plaintext_size: self.plaintext_size(),
            content_id: self.content_id,
        }
    }
}

pub struct ChunkStream<'keys, R: Read> {
    inner: StreamCDC<R>,
    keys: &'keys GroupKeys,
}

impl<R: Read> Iterator for ChunkStream<'_, R> {
    type Item = Result<ChunkPayload, ChunkingError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|result| {
            let chunk = result.map_err(ChunkingError::from_fastcdc)?;
            if u32::try_from(chunk.length).is_err() {
                return Err(ChunkingError::ChunkTooLarge(chunk.length));
            }
            let content_id = self.keys.identify_chunk(&chunk.data);
            Ok(ChunkPayload {
                offset: chunk.offset,
                content_id,
                data: chunk.data,
            })
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeltaPlan {
    required: Vec<ChunkRef>,
    reused_chunks: usize,
    reused_bytes: u64,
    transfer_bytes: u64,
}

impl DeltaPlan {
    #[must_use]
    pub fn required(&self) -> &[ChunkRef] {
        &self.required
    }

    #[must_use]
    pub const fn reused_chunks(&self) -> usize {
        self.reused_chunks
    }

    #[must_use]
    pub const fn reused_bytes(&self) -> u64 {
        self.reused_bytes
    }

    #[must_use]
    pub const fn transfer_bytes(&self) -> u64 {
        self.transfer_bytes
    }

    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.required.is_empty()
    }
}

#[derive(Debug, Error)]
pub enum ChunkingError {
    #[error("minimum chunk size {value} is outside {minimum}..={maximum}")]
    MinimumSizeOutOfRange {
        value: usize,
        minimum: usize,
        maximum: usize,
    },
    #[error("average chunk size {value} is outside {minimum}..={maximum}")]
    AverageSizeOutOfRange {
        value: usize,
        minimum: usize,
        maximum: usize,
    },
    #[error("maximum chunk size {value} is outside {minimum}..={maximum}")]
    MaximumSizeOutOfRange {
        value: usize,
        minimum: usize,
        maximum: usize,
    },
    #[error(
        "chunk sizes must satisfy minimum <= average <= maximum, got {minimum}, {average}, {maximum}"
    )]
    InvalidSizeOrder {
        minimum: usize,
        average: usize,
        maximum: usize,
    },
    #[error("average chunk size {0} must be a power of two")]
    AverageSizeNotPowerOfTwo(usize),
    #[error("chunk size {0} cannot be represented in a manifest")]
    ChunkTooLarge(usize),
    #[error("source is too large to represent")]
    SourceTooLarge,
    #[error("FastCDC returned an invalid chunk boundary")]
    InvalidChunkBoundary,
    #[error("failed to read chunk source")]
    Read(#[source] std::io::Error),
    #[error("FastCDC failed: {0}")]
    FastCdc(String),
}

impl ChunkingError {
    fn from_fastcdc(error: fastcdc::v2020::Error) -> Self {
        match error {
            fastcdc::v2020::Error::IoError(error) => Self::Read(error),
            fastcdc::v2020::Error::Empty => Self::FastCdc("unexpected end of source".into()),
            fastcdc::v2020::Error::Other(message) => Self::FastCdc(message),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, Cursor};

    use orbit_core::GroupId;
    use orbit_crypto::GroupSecret;

    use super::*;

    fn keys() -> GroupKeys {
        let group_id: GroupId = "00000000-0000-0000-0000-000000000001".parse().unwrap();
        GroupSecret::from_bytes([41; 32])
            .derive_keys(group_id)
            .unwrap()
    }

    fn test_config() -> ChunkingConfig {
        ChunkingConfig::new(64, 256, 1024).unwrap()
    }

    fn fixture(length: usize) -> Vec<u8> {
        let mut state = 0x4d59_5df4_d0f3_3173_u64;
        (0..length)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect()
    }

    #[test]
    fn default_profile_is_64k_256k_1m() {
        let config = ChunkingConfig::default();
        assert_eq!(config.minimum_size(), 64 * 1024);
        assert_eq!(config.average_size(), 256 * 1024);
        assert_eq!(config.maximum_size(), 1024 * 1024);
    }

    #[test]
    fn invalid_profiles_are_rejected_before_reaching_fastcdc() {
        assert!(matches!(
            ChunkingConfig::new(63, 256, 1024),
            Err(ChunkingError::MinimumSizeOutOfRange { .. })
        ));
        assert!(matches!(
            ChunkingConfig::new(512, 256, 1024),
            Err(ChunkingError::InvalidSizeOrder { .. })
        ));
        assert!(matches!(
            ChunkingConfig::new(64, 300, 1024),
            Err(ChunkingError::AverageSizeNotPowerOfTwo(300))
        ));
    }

    #[test]
    fn slice_plan_covers_source_and_hashes_each_chunk() {
        let keys = keys();
        let source = fixture(32 * 1024);
        let plan = test_config().chunk_slice(&source, &keys).unwrap();

        assert_eq!(plan.total_size(), source.len() as u64);
        assert!(!plan.chunks().is_empty());

        let mut expected_offset = 0_u64;
        for (index, chunk) in plan.chunks().iter().enumerate() {
            assert_eq!(chunk.offset(), expected_offset);
            assert!(usize::try_from(chunk.plaintext_size()).unwrap() <= 1024);
            if index + 1 < plan.chunks().len() {
                assert!(chunk.plaintext_size() >= 64);
            }
            let start = usize::try_from(chunk.offset()).unwrap();
            let end = start + usize::try_from(chunk.plaintext_size()).unwrap();
            assert_eq!(chunk.content_id(), keys.identify_chunk(&source[start..end]));
            expected_offset = end as u64;
        }
        assert_eq!(expected_offset, source.len() as u64);
    }

    #[test]
    fn slice_and_fragmented_stream_produce_identical_plans() {
        let keys = keys();
        let source = fixture(32 * 1024);
        let slice_plan = test_config().chunk_slice(&source, &keys).unwrap();
        let reader = FragmentedReader {
            inner: Cursor::new(&source),
            maximum_read: 37,
        };
        let stream_plan = test_config().chunk_reader(reader, &keys).unwrap();

        assert_eq!(stream_plan, slice_plan);
    }

    #[test]
    fn a_local_insertion_reuses_most_existing_content() {
        let keys = keys();
        let original = fixture(64 * 1024);
        let original_plan = test_config().chunk_slice(&original, &keys).unwrap();
        let available = original_plan
            .chunks()
            .iter()
            .map(ChunkDescriptor::content_id);

        let insertion_point = original.len() / 2;
        let mut modified = original[..insertion_point].to_vec();
        modified.extend_from_slice(b"an inserted Orbit delta");
        modified.extend_from_slice(&original[insertion_point..]);
        let modified_plan = test_config().chunk_slice(&modified, &keys).unwrap();
        let delta = modified_plan.delta_against(available);

        assert!(delta.reused_bytes() > modified_plan.total_size() / 2);
        assert!(delta.transfer_bytes() < modified_plan.total_size() / 2);
    }

    #[test]
    fn delta_plan_requests_a_repeated_missing_object_only_once() {
        let content_id = ContentId::from_bytes([3; 32]);
        let plan = ChunkPlan {
            total_size: 20,
            chunks: vec![
                ChunkDescriptor::new(0, 10, content_id).unwrap(),
                ChunkDescriptor::new(10, 10, content_id).unwrap(),
            ],
        };

        let delta = plan.delta_against([]);
        assert_eq!(delta.required().len(), 1);
        assert_eq!(delta.transfer_bytes(), 10);
        assert_eq!(delta.reused_chunks(), 1);
        assert_eq!(delta.reused_bytes(), 10);
    }

    #[test]
    fn stream_surfaces_reader_errors() {
        let keys = keys();
        let result = test_config().chunk_reader(FailingReader, &keys);
        assert!(matches!(result, Err(ChunkingError::Read(_))));
    }

    struct FragmentedReader<R> {
        inner: R,
        maximum_read: usize,
    }

    impl<R: Read> Read for FragmentedReader<R> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let length = buffer.len().min(self.maximum_read);
            self.inner.read(&mut buffer[..length])
        }
    }

    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("fixture failure"))
        }
    }
}
