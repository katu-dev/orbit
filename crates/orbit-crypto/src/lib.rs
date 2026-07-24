#![forbid(unsafe_code)]

use std::fmt;

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use orbit_core::{ContentId, DeviceId, GroupId, PathId, RelativePath, RevisionId};
use sha2::Sha256;
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

pub const ENCRYPTED_OBJECT_FORMAT_VERSION: u16 = 1;
pub const ENCRYPTED_OBJECT_HEADER_SIZE: usize = 72;
pub const DEVICE_PUBLIC_KEY_SIZE: usize = 32;
pub const CHANGE_SIGNATURE_SIZE: usize = 64;
pub const SESSION_SIGNATURE_SIZE: usize = 64;

const ENVELOPE_MAGIC: &[u8; 4] = b"ORBT";
const ENVELOPE_FLAGS: u8 = 0;
const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 24;
const AUTHENTICATION_TAG_SIZE: usize = 16;
const KDF_DOMAIN: &[u8] = b"orbit/key-derivation";
const CHUNK_ID_KEY_INFO: &[u8] = b"chunk-content-id";
const MANIFEST_ID_KEY_INFO: &[u8] = b"manifest-content-id";
const PATH_ID_KEY_INFO: &[u8] = b"path-id";
const CHUNK_ENCRYPTION_KEY_INFO: &[u8] = b"chunk-encryption";
const MANIFEST_ENCRYPTION_KEY_INFO: &[u8] = b"manifest-encryption";
const PEER_ENROLLMENT_KEY_INFO: &[u8] = b"peer-enrollment";
const PEER_ENROLLMENT_DOMAIN: &[u8] = b"orbit/peer-enrollment/v1";
const ASSOCIATED_DATA_DOMAIN: &[u8] = b"orbit/encrypted-object";
const DEVICE_ID_DOMAIN: &[u8] = b"orbit/device-id/v1";
const CHANGE_SIGNATURE_DOMAIN: &[u8] = b"orbit/change-signature/v1";
const SESSION_SIGNATURE_DOMAIN: &[u8] = b"orbit/session-signature/v1";

pub struct DeviceIdentity {
    signing_key: SigningKey,
}

impl DeviceIdentity {
    pub fn generate() -> Result<Self, IdentityError> {
        let mut secret = Zeroizing::new([0_u8; 32]);
        getrandom::fill(&mut secret[..]).map_err(|_| IdentityError::Randomness)?;
        Ok(Self::from_secret_bytes(*secret))
    }

    #[must_use]
    pub fn from_secret_bytes(secret: [u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&secret),
        }
    }

    #[must_use]
    pub fn public_key(&self) -> DevicePublicKey {
        DevicePublicKey(self.signing_key.verifying_key().to_bytes())
    }

    #[must_use]
    pub fn device_id(&self) -> DeviceId {
        self.public_key().device_id()
    }

    #[must_use]
    pub fn authorize_change(
        &self,
        group_id: GroupId,
        revision_id: RevisionId,
        content_id: ContentId,
    ) -> ChangeAuthorization {
        let message = change_signature_message(group_id, self.device_id(), revision_id, content_id);
        let signature = self.signing_key.sign(&message).to_bytes();
        ChangeAuthorization {
            author_device_id: self.device_id(),
            signature: ChangeSignature(signature),
        }
    }

    #[must_use]
    pub fn authorize_session(&self, transcript: &[u8]) -> SessionAuthorization {
        let message = session_signature_message(self.device_id(), transcript);
        let signature = self.signing_key.sign(&message).to_bytes();
        SessionAuthorization {
            author_device_id: self.device_id(),
            signature: SessionSignature(signature),
        }
    }
}

impl fmt::Debug for DeviceIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceIdentity")
            .field("device_id", &self.device_id())
            .field("signing_key", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DevicePublicKey([u8; DEVICE_PUBLIC_KEY_SIZE]);

impl DevicePublicKey {
    pub fn from_bytes(bytes: [u8; DEVICE_PUBLIC_KEY_SIZE]) -> Result<Self, IdentityError> {
        VerifyingKey::from_bytes(&bytes).map_err(|_| IdentityError::InvalidPublicKey)?;
        Ok(Self(bytes))
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; DEVICE_PUBLIC_KEY_SIZE] {
        &self.0
    }

    #[must_use]
    pub fn device_id(self) -> DeviceId {
        let mut hasher = blake3::Hasher::new();
        hasher.update(DEVICE_ID_DOMAIN);
        hasher.update(&self.0);
        let digest = hasher.finalize();
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&digest.as_bytes()[..16]);
        bytes[6] = (bytes[6] & 0x0f) | 0x80;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        DeviceId::from_uuid(Uuid::from_bytes(bytes))
    }

    pub fn verify_change(
        self,
        group_id: GroupId,
        revision_id: RevisionId,
        content_id: ContentId,
        authorization: ChangeAuthorization,
    ) -> Result<(), IdentityError> {
        let expected_author = self.device_id();
        if authorization.author_device_id != expected_author {
            return Err(IdentityError::AuthorKeyMismatch {
                expected: expected_author,
                actual: authorization.author_device_id,
            });
        }
        let key = VerifyingKey::from_bytes(&self.0).map_err(|_| IdentityError::InvalidPublicKey)?;
        let signature = Signature::from_bytes(authorization.signature.as_bytes());
        let message = change_signature_message(
            group_id,
            authorization.author_device_id,
            revision_id,
            content_id,
        );
        key.verify_strict(&message, &signature)
            .map_err(|_| IdentityError::InvalidSignature)
    }

    pub fn verify_session(
        self,
        transcript: &[u8],
        authorization: SessionAuthorization,
    ) -> Result<(), IdentityError> {
        let expected_author = self.device_id();
        if authorization.author_device_id != expected_author {
            return Err(IdentityError::AuthorKeyMismatch {
                expected: expected_author,
                actual: authorization.author_device_id,
            });
        }
        let key = VerifyingKey::from_bytes(&self.0).map_err(|_| IdentityError::InvalidPublicKey)?;
        let signature = Signature::from_bytes(authorization.signature.as_bytes());
        let message = session_signature_message(authorization.author_device_id, transcript);
        key.verify_strict(&message, &signature)
            .map_err(|_| IdentityError::InvalidSignature)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ChangeSignature([u8; CHANGE_SIGNATURE_SIZE]);

impl ChangeSignature {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; CHANGE_SIGNATURE_SIZE]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; CHANGE_SIGNATURE_SIZE] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ChangeAuthorization {
    pub author_device_id: DeviceId,
    pub signature: ChangeSignature,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SessionSignature([u8; SESSION_SIGNATURE_SIZE]);

impl SessionSignature {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SESSION_SIGNATURE_SIZE]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SESSION_SIGNATURE_SIZE] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SessionAuthorization {
    pub author_device_id: DeviceId,
    pub signature: SessionSignature,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum IdentityError {
    #[error("operating system randomness is unavailable")]
    Randomness,
    #[error("device public key is not a valid Ed25519 key")]
    InvalidPublicKey,
    #[error("device public key identifies {expected}, not claimed author {actual}")]
    AuthorKeyMismatch {
        expected: DeviceId,
        actual: DeviceId,
    },
    #[error("change signature is invalid")]
    InvalidSignature,
}

fn change_signature_message(
    group_id: GroupId,
    author_device_id: DeviceId,
    revision_id: RevisionId,
    content_id: ContentId,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(CHANGE_SIGNATURE_DOMAIN.len() + 80);
    message.extend_from_slice(CHANGE_SIGNATURE_DOMAIN);
    message.extend_from_slice(group_id.as_uuid().as_bytes());
    message.extend_from_slice(author_device_id.as_uuid().as_bytes());
    message.extend_from_slice(revision_id.as_uuid().as_bytes());
    message.extend_from_slice(content_id.as_bytes());
    message
}

fn session_signature_message(author_device_id: DeviceId, transcript: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(SESSION_SIGNATURE_DOMAIN.len() + 24 + transcript.len());
    message.extend_from_slice(SESSION_SIGNATURE_DOMAIN);
    message.extend_from_slice(author_device_id.as_uuid().as_bytes());
    message.extend_from_slice(&(transcript.len() as u64).to_be_bytes());
    message.extend_from_slice(transcript);
    message
}

pub struct GroupSecret {
    bytes: Zeroizing<[u8; KEY_SIZE]>,
}

impl GroupSecret {
    pub fn generate() -> Result<Self, CryptoError> {
        let mut bytes = Zeroizing::new([0; KEY_SIZE]);
        getrandom::fill(&mut bytes[..]).map_err(|_| CryptoError::Randomness)?;
        Ok(Self { bytes })
    }

    #[must_use]
    pub fn from_bytes(bytes: [u8; KEY_SIZE]) -> Self {
        Self {
            bytes: Zeroizing::new(bytes),
        }
    }

    pub fn derive_keys(&self, group_id: GroupId) -> Result<GroupKeys, CryptoError> {
        let hkdf = Hkdf::<Sha256>::new(Some(group_id.as_uuid().as_bytes()), self.bytes.as_slice());

        Ok(GroupKeys {
            group_id,
            chunk_id_key: derive_key(&hkdf, CHUNK_ID_KEY_INFO)?,
            manifest_id_key: derive_key(&hkdf, MANIFEST_ID_KEY_INFO)?,
            path_id_key: derive_key(&hkdf, PATH_ID_KEY_INFO)?,
            chunk_encryption_key: derive_key(&hkdf, CHUNK_ENCRYPTION_KEY_INFO)?,
            manifest_encryption_key: derive_key(&hkdf, MANIFEST_ENCRYPTION_KEY_INFO)?,
            peer_enrollment_key: derive_key(&hkdf, PEER_ENROLLMENT_KEY_INFO)?,
        })
    }
}

impl fmt::Debug for GroupSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GroupSecret([REDACTED])")
    }
}

pub struct GroupKeys {
    group_id: GroupId,
    chunk_id_key: Zeroizing<[u8; KEY_SIZE]>,
    manifest_id_key: Zeroizing<[u8; KEY_SIZE]>,
    path_id_key: Zeroizing<[u8; KEY_SIZE]>,
    chunk_encryption_key: Zeroizing<[u8; KEY_SIZE]>,
    manifest_encryption_key: Zeroizing<[u8; KEY_SIZE]>,
    peer_enrollment_key: Zeroizing<[u8; KEY_SIZE]>,
}

impl GroupKeys {
    #[must_use]
    pub const fn group_id(&self) -> GroupId {
        self.group_id
    }

    #[must_use]
    pub fn peer_enrollment_proof(
        &self,
        public_key: DevicePublicKey,
        nonce: &[u8],
        transport_binding: &[u8],
        listen_port: u16,
    ) -> [u8; 32] {
        let mut message = Vec::with_capacity(
            PEER_ENROLLMENT_DOMAIN.len()
                + 16
                + DEVICE_PUBLIC_KEY_SIZE
                + nonce.len()
                + transport_binding.len()
                + 2,
        );
        message.extend_from_slice(PEER_ENROLLMENT_DOMAIN);
        message.extend_from_slice(self.group_id.as_uuid().as_bytes());
        message.extend_from_slice(public_key.as_bytes());
        message.extend_from_slice(nonce);
        message.extend_from_slice(transport_binding);
        message.extend_from_slice(&listen_port.to_be_bytes());
        *blake3::keyed_hash(&self.peer_enrollment_key, &message).as_bytes()
    }

    #[must_use]
    pub fn identify(&self, kind: ObjectKind, plaintext: &[u8]) -> ContentId {
        let key = match kind {
            ObjectKind::Chunk => &*self.chunk_id_key,
            ObjectKind::Manifest => &*self.manifest_id_key,
        };
        let hash = blake3::keyed_hash(key, plaintext);
        ContentId::from_bytes(*hash.as_bytes())
    }

    #[must_use]
    pub fn identify_chunk(&self, plaintext: &[u8]) -> ContentId {
        self.identify(ObjectKind::Chunk, plaintext)
    }

    #[must_use]
    pub fn identify_manifest(&self, plaintext: &[u8]) -> ContentId {
        self.identify(ObjectKind::Manifest, plaintext)
    }

    #[must_use]
    pub fn identify_path(&self, path: &RelativePath) -> PathId {
        let hash = blake3::keyed_hash(&self.path_id_key, path.comparison_key().as_bytes());
        PathId::from_bytes(*hash.as_bytes())
    }

    pub fn seal_chunk(&self, plaintext: &[u8]) -> Result<EncryptedObject, CryptoError> {
        self.seal(ObjectKind::Chunk, plaintext)
    }

    pub fn seal_manifest(&self, plaintext: &[u8]) -> Result<EncryptedObject, CryptoError> {
        self.seal(ObjectKind::Manifest, plaintext)
    }

    pub fn seal(&self, kind: ObjectKind, plaintext: &[u8]) -> Result<EncryptedObject, CryptoError> {
        let content_id = self.identify(kind, plaintext);
        self.seal_with_content_id(kind, content_id, plaintext)
    }

    pub fn open_chunk(
        &self,
        expected_content_id: ContentId,
        object: &EncryptedObject,
    ) -> Result<Vec<u8>, CryptoError> {
        self.open(ObjectKind::Chunk, expected_content_id, object)
    }

    pub fn open_manifest(
        &self,
        expected_content_id: ContentId,
        object: &EncryptedObject,
    ) -> Result<Vec<u8>, CryptoError> {
        self.open(ObjectKind::Manifest, expected_content_id, object)
    }

    pub fn open(
        &self,
        expected_kind: ObjectKind,
        expected_content_id: ContentId,
        object: &EncryptedObject,
    ) -> Result<Vec<u8>, CryptoError> {
        if object.format_version != ENCRYPTED_OBJECT_FORMAT_VERSION {
            return Err(CryptoError::UnsupportedFormatVersion(object.format_version));
        }
        if object.kind != expected_kind {
            return Err(CryptoError::UnexpectedObjectKind {
                expected: expected_kind,
                actual: object.kind,
            });
        }
        if object.content_id != expected_content_id {
            return Err(CryptoError::UnexpectedContentId {
                expected: expected_content_id,
                actual: object.content_id,
            });
        }

        let associated_data = associated_data(
            self.group_id,
            object.format_version,
            object.kind,
            object.content_id,
        );
        let cipher = self.cipher(object.kind)?;
        let nonce = XNonce::from(object.nonce);
        let plaintext = cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &object.ciphertext,
                    aad: &associated_data,
                },
            )
            .map_err(|_| CryptoError::Authentication)?;

        if self.identify(expected_kind, &plaintext) != expected_content_id {
            return Err(CryptoError::ContentIdMismatch);
        }

        Ok(plaintext)
    }

    fn seal_with_content_id(
        &self,
        kind: ObjectKind,
        content_id: ContentId,
        plaintext: &[u8],
    ) -> Result<EncryptedObject, CryptoError> {
        let mut nonce = [0; NONCE_SIZE];
        getrandom::fill(&mut nonce).map_err(|_| CryptoError::Randomness)?;

        let associated_data = associated_data(
            self.group_id,
            ENCRYPTED_OBJECT_FORMAT_VERSION,
            kind,
            content_id,
        );
        let cipher = self.cipher(kind)?;
        let xnonce = XNonce::from(nonce);
        let ciphertext = cipher
            .encrypt(
                &xnonce,
                Payload {
                    msg: plaintext,
                    aad: &associated_data,
                },
            )
            .map_err(|_| CryptoError::Encryption)?;

        Ok(EncryptedObject {
            format_version: ENCRYPTED_OBJECT_FORMAT_VERSION,
            kind,
            content_id,
            nonce,
            ciphertext,
        })
    }

    fn cipher(&self, kind: ObjectKind) -> Result<XChaCha20Poly1305, CryptoError> {
        let key = match kind {
            ObjectKind::Chunk => self.chunk_encryption_key.as_slice(),
            ObjectKind::Manifest => self.manifest_encryption_key.as_slice(),
        };
        XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::KeyDerivation)
    }
}

impl fmt::Debug for GroupKeys {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GroupKeys")
            .field("group_id", &self.group_id)
            .field("keys", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ObjectKind {
    Chunk = 1,
    Manifest = 2,
}

impl ObjectKind {
    fn from_byte(value: u8) -> Result<Self, EnvelopeError> {
        match value {
            1 => Ok(Self::Chunk),
            2 => Ok(Self::Manifest),
            value => Err(EnvelopeError::UnknownObjectKind(value)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedObject {
    format_version: u16,
    kind: ObjectKind,
    content_id: ContentId,
    nonce: [u8; NONCE_SIZE],
    ciphertext: Vec<u8>,
}

impl EncryptedObject {
    #[must_use]
    pub const fn format_version(&self) -> u16 {
        self.format_version
    }

    #[must_use]
    pub const fn kind(&self) -> ObjectKind {
        self.kind
    }

    #[must_use]
    pub const fn content_id(&self) -> ContentId {
        self.content_id
    }

    #[must_use]
    pub const fn nonce(&self) -> &[u8; NONCE_SIZE] {
        &self.nonce
    }

    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, EnvelopeError> {
        let ciphertext_length = u64::try_from(self.ciphertext.len())
            .map_err(|_| EnvelopeError::CiphertextLengthOverflow)?;
        let capacity = ENCRYPTED_OBJECT_HEADER_SIZE
            .checked_add(self.ciphertext.len())
            .ok_or(EnvelopeError::CiphertextLengthOverflow)?;
        let mut bytes = Vec::with_capacity(capacity);
        bytes.extend_from_slice(ENVELOPE_MAGIC);
        bytes.extend_from_slice(&self.format_version.to_be_bytes());
        bytes.push(self.kind as u8);
        bytes.push(ENVELOPE_FLAGS);
        bytes.extend_from_slice(self.content_id.as_bytes());
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&ciphertext_length.to_be_bytes());
        bytes.extend_from_slice(&self.ciphertext);
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        if bytes.len() < ENCRYPTED_OBJECT_HEADER_SIZE {
            return Err(EnvelopeError::HeaderTooShort {
                actual: bytes.len(),
            });
        }
        if &bytes[..ENVELOPE_MAGIC.len()] != ENVELOPE_MAGIC {
            return Err(EnvelopeError::InvalidMagic);
        }

        let format_version = u16::from_be_bytes([bytes[4], bytes[5]]);
        if format_version != ENCRYPTED_OBJECT_FORMAT_VERSION {
            return Err(EnvelopeError::UnsupportedFormatVersion(format_version));
        }
        let kind = ObjectKind::from_byte(bytes[6])?;
        if bytes[7] != ENVELOPE_FLAGS {
            return Err(EnvelopeError::UnsupportedFlags(bytes[7]));
        }

        let mut content_id = [0; KEY_SIZE];
        content_id.copy_from_slice(&bytes[8..40]);
        let mut nonce = [0; NONCE_SIZE];
        nonce.copy_from_slice(&bytes[40..64]);
        let ciphertext_length = u64::from_be_bytes([
            bytes[64], bytes[65], bytes[66], bytes[67], bytes[68], bytes[69], bytes[70], bytes[71],
        ]);
        let actual_length = bytes.len() - ENCRYPTED_OBJECT_HEADER_SIZE;
        let declared_length = usize::try_from(ciphertext_length)
            .map_err(|_| EnvelopeError::DeclaredLengthTooLarge(ciphertext_length))?;
        if declared_length != actual_length {
            return Err(EnvelopeError::LengthMismatch {
                declared: ciphertext_length,
                actual: actual_length,
            });
        }
        if actual_length < AUTHENTICATION_TAG_SIZE {
            return Err(EnvelopeError::CiphertextTooShort {
                actual: actual_length,
            });
        }

        Ok(Self {
            format_version,
            kind,
            content_id: ContentId::from_bytes(content_id),
            nonce,
            ciphertext: bytes[ENCRYPTED_OBJECT_HEADER_SIZE..].to_vec(),
        })
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CryptoError {
    #[error("the system random source failed")]
    Randomness,
    #[error("key derivation failed")]
    KeyDerivation,
    #[error("object encryption failed")]
    Encryption,
    #[error("object authentication failed")]
    Authentication,
    #[error("unsupported encrypted object format version {0}")]
    UnsupportedFormatVersion(u16),
    #[error("expected object kind {expected:?}, found {actual:?}")]
    UnexpectedObjectKind {
        expected: ObjectKind,
        actual: ObjectKind,
    },
    #[error("the encrypted object does not match the requested content ID")]
    UnexpectedContentId {
        expected: ContentId,
        actual: ContentId,
    },
    #[error("decrypted content does not match its authenticated content ID")]
    ContentIdMismatch,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum EnvelopeError {
    #[error("encrypted object header is too short: {actual} bytes")]
    HeaderTooShort { actual: usize },
    #[error("invalid encrypted object magic")]
    InvalidMagic,
    #[error("unsupported encrypted object format version {0}")]
    UnsupportedFormatVersion(u16),
    #[error("unknown encrypted object kind {0}")]
    UnknownObjectKind(u8),
    #[error("unsupported encrypted object flags {0:#04x}")]
    UnsupportedFlags(u8),
    #[error("ciphertext length cannot be represented")]
    CiphertextLengthOverflow,
    #[error("declared ciphertext length {0} is too large for this platform")]
    DeclaredLengthTooLarge(u64),
    #[error("ciphertext length mismatch: declared {declared}, actual {actual}")]
    LengthMismatch { declared: u64, actual: usize },
    #[error("ciphertext is too short: {actual} bytes")]
    CiphertextTooShort { actual: usize },
}

fn derive_key(
    hkdf: &Hkdf<Sha256>,
    purpose: &'static [u8],
) -> Result<Zeroizing<[u8; KEY_SIZE]>, CryptoError> {
    let mut key = Zeroizing::new([0; KEY_SIZE]);
    let version = ENCRYPTED_OBJECT_FORMAT_VERSION.to_be_bytes();
    hkdf.expand_multi_info(&[KDF_DOMAIN, &version, purpose], &mut key[..])
        .map_err(|_| CryptoError::KeyDerivation)?;
    Ok(key)
}

fn associated_data(
    group_id: GroupId,
    format_version: u16,
    kind: ObjectKind,
    content_id: ContentId,
) -> Vec<u8> {
    let mut associated_data = Vec::with_capacity(
        ASSOCIATED_DATA_DOMAIN.len() + ENVELOPE_MAGIC.len() + 16 + 2 + 1 + 1 + KEY_SIZE,
    );
    associated_data.extend_from_slice(ASSOCIATED_DATA_DOMAIN);
    associated_data.extend_from_slice(ENVELOPE_MAGIC);
    associated_data.extend_from_slice(group_id.as_uuid().as_bytes());
    associated_data.extend_from_slice(&format_version.to_be_bytes());
    associated_data.push(kind as u8);
    associated_data.push(ENVELOPE_FLAGS);
    associated_data.extend_from_slice(content_id.as_bytes());
    associated_data
}

#[cfg(test)]
mod tests {
    use super::*;

    fn group(value: u128) -> GroupId {
        format!("{value:032x}").parse().unwrap()
    }

    fn keys(secret_byte: u8, group_value: u128) -> GroupKeys {
        GroupSecret::from_bytes([secret_byte; KEY_SIZE])
            .derive_keys(group(group_value))
            .unwrap()
    }

    #[test]
    fn content_ids_are_deterministic_and_domain_separated() {
        let first = keys(7, 1);
        let second_group = keys(7, 2);
        let plaintext = b"same content";

        assert_eq!(
            first.identify_chunk(plaintext),
            first.identify_chunk(plaintext)
        );
        assert_ne!(
            first.identify_chunk(plaintext),
            first.identify_manifest(plaintext)
        );
        assert_ne!(
            first.identify_chunk(plaintext),
            second_group.identify_chunk(plaintext)
        );
    }

    #[test]
    fn path_ids_are_private_canonical_and_domain_separated() {
        let first = keys(8, 1);
        let second_group = keys(8, 2);
        let display = RelativePath::new("Docs/Report.txt").unwrap();
        let equivalent = RelativePath::new("docs/report.TXT").unwrap();

        assert_eq!(
            first.identify_path(&display),
            first.identify_path(&equivalent)
        );
        assert_ne!(
            first.identify_path(&display),
            second_group.identify_path(&display)
        );
        assert_ne!(
            first.identify_path(&display).as_bytes(),
            first
                .identify_chunk(display.comparison_key().as_bytes())
                .as_bytes()
        );
        assert_ne!(
            first.identify_path(&display).as_bytes(),
            first
                .identify_manifest(display.comparison_key().as_bytes())
                .as_bytes()
        );
    }

    #[test]
    fn device_identity_is_key_derived_and_round_trips_public_bytes() {
        let identity = DeviceIdentity::from_secret_bytes([31; 32]);
        let public_key = identity.public_key();
        let decoded = DevicePublicKey::from_bytes(*public_key.as_bytes()).unwrap();

        assert_eq!(decoded, public_key);
        assert_eq!(decoded.device_id(), identity.device_id());
        assert_ne!(
            identity.device_id(),
            DeviceIdentity::from_secret_bytes([32; 32]).device_id()
        );
        let debug = format!("{identity:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("31, 31"));
    }

    #[test]
    fn signed_changes_bind_group_author_revision_and_content() {
        let identity = DeviceIdentity::from_secret_bytes([33; 32]);
        let group_id = group(1);
        let revision_id = RevisionId::from_uuid(Uuid::from_u128(2));
        let content_id = ContentId::from_bytes([3; 32]);
        let authorization = identity.authorize_change(group_id, revision_id, content_id);

        identity
            .public_key()
            .verify_change(group_id, revision_id, content_id, authorization)
            .unwrap();
        assert_eq!(authorization.author_device_id, identity.device_id());
        assert_eq!(
            identity
                .public_key()
                .verify_change(group(9), revision_id, content_id, authorization,),
            Err(IdentityError::InvalidSignature)
        );
        assert_eq!(
            identity.public_key().verify_change(
                group_id,
                RevisionId::from_uuid(Uuid::from_u128(9)),
                content_id,
                authorization,
            ),
            Err(IdentityError::InvalidSignature)
        );
        assert_eq!(
            identity.public_key().verify_change(
                group_id,
                revision_id,
                ContentId::from_bytes([9; 32]),
                authorization,
            ),
            Err(IdentityError::InvalidSignature)
        );

        let other = DeviceIdentity::from_secret_bytes([34; 32]);
        assert_eq!(
            other
                .public_key()
                .verify_change(group_id, revision_id, content_id, authorization),
            Err(IdentityError::AuthorKeyMismatch {
                expected: other.device_id(),
                actual: identity.device_id(),
            })
        );

        let mut signature = *authorization.signature.as_bytes();
        signature[0] ^= 0x80;
        let tampered = ChangeAuthorization {
            signature: ChangeSignature::from_bytes(signature),
            ..authorization
        };
        assert_eq!(
            identity
                .public_key()
                .verify_change(group_id, revision_id, content_id, tampered),
            Err(IdentityError::InvalidSignature)
        );
    }

    #[test]
    fn signed_sessions_bind_author_and_exact_transcript() {
        let identity = DeviceIdentity::from_secret_bytes([35; 32]);
        let transcript = b"canonical negotiated session transcript";
        let authorization = identity.authorize_session(transcript);

        identity
            .public_key()
            .verify_session(transcript, authorization)
            .unwrap();
        assert_eq!(authorization.author_device_id, identity.device_id());
        assert_eq!(
            identity
                .public_key()
                .verify_session(b"modified transcript", authorization),
            Err(IdentityError::InvalidSignature)
        );

        let other = DeviceIdentity::from_secret_bytes([36; 32]);
        assert_eq!(
            other.public_key().verify_session(transcript, authorization),
            Err(IdentityError::AuthorKeyMismatch {
                expected: other.device_id(),
                actual: identity.device_id(),
            })
        );
    }

    #[test]
    fn encrypted_chunk_round_trips_through_the_wire_envelope() {
        let keys = keys(11, 1);
        let plaintext = b"Orbit keeps this private";
        let expected_id = keys.identify_chunk(plaintext);
        let object = keys.seal_chunk(plaintext).unwrap();

        assert_eq!(object.kind(), ObjectKind::Chunk);
        assert_eq!(object.content_id(), expected_id);
        assert_ne!(object.ciphertext(), plaintext);

        let encoded = object.to_bytes().unwrap();
        let decoded = EncryptedObject::from_bytes(&encoded).unwrap();
        assert_eq!(decoded, object);
        assert_eq!(keys.open_chunk(expected_id, &decoded).unwrap(), plaintext);
    }

    #[test]
    fn repeated_encryption_uses_distinct_nonces() {
        let keys = keys(12, 1);
        let plaintext = b"same plaintext";
        let first = keys.seal_chunk(plaintext).unwrap();
        let second = keys.seal_chunk(plaintext).unwrap();

        assert_eq!(first.content_id(), second.content_id());
        assert_ne!(first.nonce(), second.nonce());
        assert_ne!(first.ciphertext(), second.ciphertext());
    }

    #[test]
    fn wrong_group_cannot_open_an_object() {
        let original = keys(13, 1);
        let other_group = keys(13, 2);
        let plaintext = b"group-bound content";
        let expected_id = original.identify_chunk(plaintext);
        let object = original.seal_chunk(plaintext).unwrap();

        assert_eq!(
            other_group.open_chunk(expected_id, &object),
            Err(CryptoError::Authentication)
        );
    }

    #[test]
    fn ciphertext_tampering_is_rejected() {
        let keys = keys(17, 1);
        let plaintext = b"authenticated content";
        let expected_id = keys.identify_chunk(plaintext);
        let mut object = keys.seal_chunk(plaintext).unwrap();
        object.ciphertext[0] ^= 0x80;

        assert_eq!(
            keys.open_chunk(expected_id, &object),
            Err(CryptoError::Authentication)
        );
    }

    #[test]
    fn authenticated_header_tampering_is_rejected() {
        let keys = keys(18, 1);
        let plaintext = b"header-bound content";
        let content_id = keys.identify_chunk(plaintext);
        let object = keys.seal_chunk(plaintext).unwrap();

        let mut changed_kind = object.clone();
        changed_kind.kind = ObjectKind::Manifest;
        assert_eq!(
            keys.open(ObjectKind::Manifest, content_id, &changed_kind),
            Err(CryptoError::Authentication)
        );

        let changed_content_id = ContentId::from_bytes([0xa5; KEY_SIZE]);
        let mut changed_id = object.clone();
        changed_id.content_id = changed_content_id;
        assert_eq!(
            keys.open_chunk(changed_content_id, &changed_id),
            Err(CryptoError::Authentication)
        );

        let mut changed_version = object;
        changed_version.format_version += 1;
        assert_eq!(
            keys.open_chunk(content_id, &changed_version),
            Err(CryptoError::UnsupportedFormatVersion(2))
        );
    }

    #[test]
    fn plaintext_is_verified_against_its_content_id_after_decryption() {
        let keys = keys(19, 1);
        let expected_id = keys.identify_chunk(b"expected");
        let object = keys
            .seal_with_content_id(ObjectKind::Chunk, expected_id, b"different")
            .unwrap();

        assert_eq!(
            keys.open_chunk(expected_id, &object),
            Err(CryptoError::ContentIdMismatch)
        );
    }

    #[test]
    fn malformed_envelope_lengths_are_rejected_before_allocation() {
        let keys = keys(23, 1);
        let mut encoded = keys.seal_chunk(b"payload").unwrap().to_bytes().unwrap();
        encoded[71] = encoded[71].wrapping_add(1);

        assert!(matches!(
            EncryptedObject::from_bytes(&encoded),
            Err(EnvelopeError::LengthMismatch { .. })
        ));
    }

    #[test]
    fn secret_debug_output_is_redacted() {
        let secret = GroupSecret::from_bytes([29; KEY_SIZE]);
        assert_eq!(format!("{secret:?}"), "GroupSecret([REDACTED])");
    }
}
