#![forbid(unsafe_code)]

//! Orbit's versioned control-plane protocol.
//!
//! Protobuf decoders accept unknown fields and enum values for forward
//! compatibility. Prost discards unknown fields when a message is re-encoded,
//! so Orbit forwards opaque encrypted records rather than decoding and
//! re-encoding records owned by a newer protocol version.

use std::collections::{BTreeSet, HashSet};

use orbit_core::{
    ChangeRecord, ChunkRef, ContentId, DeviceId, FileId, FileManifest, GroupId, PROTOCOL_VERSION,
    PathError, RelativePath, RevisionId, Tombstone, VersionVector, VersionVectorError,
};
use orbit_crypto::{
    CHANGE_SIGNATURE_SIZE, ChangeAuthorization, ChangeSignature, DeviceIdentity, DevicePublicKey,
    ENCRYPTED_OBJECT_HEADER_SIZE, EncryptedObject, EnvelopeError, GroupKeys, IdentityError,
    ObjectKind, SESSION_SIGNATURE_SIZE, SessionAuthorization, SessionSignature,
};
use prost::Message;
use thiserror::Error;
use uuid::Uuid;

pub mod wire {
    include!(concat!(env!("OUT_DIR"), "/orbit.v1.rs"));
}

pub use wire::handshake::Capability;

pub const CONTROL_FRAME_HEADER_SIZE: usize = 4;
pub const SESSION_NONCE_SIZE: usize = 32;
pub const SESSION_TRANSPORT_BINDING_SIZE: usize = 32;
pub const MINIMUM_CONTROL_FRAME_BYTES: usize = 1024;
pub const DEFAULT_MAXIMUM_CONTROL_FRAME_BYTES: usize = 1024 * 1024;
pub const HARD_MAXIMUM_CONTROL_FRAME_BYTES: usize = 4 * 1024 * 1024;
pub const MINIMUM_ENCRYPTED_OBJECT_BYTES: u64 = ENCRYPTED_OBJECT_HEADER_SIZE as u64 + 16;
pub const DEFAULT_MAXIMUM_ENCRYPTED_OBJECT_BYTES: u64 = 32 * 1024 * 1024;
pub const HARD_MAXIMUM_ENCRYPTED_OBJECT_BYTES: u64 = 64 * 1024 * 1024;
pub const DEFAULT_MAXIMUM_CONTENT_IDS_PER_REQUEST: usize = 4096;
pub const HARD_MAXIMUM_CONTENT_IDS_PER_REQUEST: usize = 16_384;
pub const DEFAULT_MAXIMUM_CHANGE_RECORDS_PER_BATCH: usize = 1024;
pub const HARD_MAXIMUM_CHANGE_RECORDS_PER_BATCH: usize = 4096;
pub const MANIFEST_PLAINTEXT_FORMAT_VERSION: u32 = 1;
pub const MAXIMUM_MANIFEST_CHUNKS: usize = 1_000_000;
pub const MAXIMUM_MANIFEST_PLAINTEXT_BYTES: usize =
    HARD_MAXIMUM_ENCRYPTED_OBJECT_BYTES as usize - ENCRYPTED_OBJECT_HEADER_SIZE - 16;

const SESSION_TRANSCRIPT_DOMAIN: &[u8] = b"orbit/session-transcript/v1";

pub const REQUIRED_CAPABILITIES: [Capability; 7] = [
    Capability::EncryptedObjects,
    Capability::FastCdcV2020,
    Capability::ResumableObjects,
    Capability::Tombstones,
    Capability::KeepBothConflicts,
    Capability::SignedChanges,
    Capability::AuthenticatedSessions,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtocolLimits {
    maximum_control_frame_bytes: usize,
    maximum_encrypted_object_bytes: u64,
    maximum_content_ids_per_request: usize,
    maximum_change_records_per_batch: usize,
}

impl ProtocolLimits {
    pub fn new(
        maximum_control_frame_bytes: usize,
        maximum_encrypted_object_bytes: u64,
        maximum_content_ids_per_request: usize,
        maximum_change_records_per_batch: usize,
    ) -> Result<Self, ProtocolError> {
        validate_usize_limit(
            "maximum_control_frame_bytes",
            maximum_control_frame_bytes,
            MINIMUM_CONTROL_FRAME_BYTES,
            HARD_MAXIMUM_CONTROL_FRAME_BYTES,
        )?;
        validate_u64_limit(
            "maximum_encrypted_object_bytes",
            maximum_encrypted_object_bytes,
            MINIMUM_ENCRYPTED_OBJECT_BYTES,
            HARD_MAXIMUM_ENCRYPTED_OBJECT_BYTES,
        )?;
        validate_usize_limit(
            "maximum_content_ids_per_request",
            maximum_content_ids_per_request,
            1,
            HARD_MAXIMUM_CONTENT_IDS_PER_REQUEST,
        )?;
        validate_usize_limit(
            "maximum_change_records_per_batch",
            maximum_change_records_per_batch,
            1,
            HARD_MAXIMUM_CHANGE_RECORDS_PER_BATCH,
        )?;

        Ok(Self {
            maximum_control_frame_bytes,
            maximum_encrypted_object_bytes,
            maximum_content_ids_per_request,
            maximum_change_records_per_batch,
        })
    }

    #[must_use]
    pub const fn maximum_control_frame_bytes(self) -> usize {
        self.maximum_control_frame_bytes
    }

    #[must_use]
    pub const fn maximum_encrypted_object_bytes(self) -> u64 {
        self.maximum_encrypted_object_bytes
    }

    #[must_use]
    pub const fn maximum_content_ids_per_request(self) -> usize {
        self.maximum_content_ids_per_request
    }

    #[must_use]
    pub const fn maximum_change_records_per_batch(self) -> usize {
        self.maximum_change_records_per_batch
    }
}

impl Default for ProtocolLimits {
    fn default() -> Self {
        Self {
            maximum_control_frame_bytes: DEFAULT_MAXIMUM_CONTROL_FRAME_BYTES,
            maximum_encrypted_object_bytes: DEFAULT_MAXIMUM_ENCRYPTED_OBJECT_BYTES,
            maximum_content_ids_per_request: DEFAULT_MAXIMUM_CONTENT_IDS_PER_REQUEST,
            maximum_change_records_per_batch: DEFAULT_MAXIMUM_CHANGE_RECORDS_PER_BATCH,
        }
    }
}

#[must_use]
pub fn current_handshake(
    device_id: DeviceId,
    group_id: GroupId,
    limits: ProtocolLimits,
) -> wire::Handshake {
    wire::Handshake {
        minimum_protocol_version: u32::from(PROTOCOL_VERSION),
        maximum_protocol_version: u32::from(PROTOCOL_VERSION),
        device_id: device_id.as_uuid().as_bytes().to_vec(),
        group_id: group_id.as_uuid().as_bytes().to_vec(),
        capabilities: REQUIRED_CAPABILITIES
            .iter()
            .map(|capability| *capability as i32)
            .collect(),
        maximum_control_frame_bytes: u32::try_from(limits.maximum_control_frame_bytes)
            .expect("validated control frame limit fits in u32"),
        maximum_object_bytes: limits.maximum_encrypted_object_bytes,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegotiatedSession {
    remote_device_id: DeviceId,
    group_id: GroupId,
    protocol_version: u16,
    capabilities: Vec<Capability>,
    maximum_control_frame_bytes: usize,
    maximum_encrypted_object_bytes: u64,
}

impl NegotiatedSession {
    #[must_use]
    pub const fn remote_device_id(&self) -> DeviceId {
        self.remote_device_id
    }

    #[must_use]
    pub const fn group_id(&self) -> GroupId {
        self.group_id
    }

    #[must_use]
    pub const fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    #[must_use]
    pub fn capabilities(&self) -> &[Capability] {
        &self.capabilities
    }

    #[must_use]
    pub const fn maximum_control_frame_bytes(&self) -> usize {
        self.maximum_control_frame_bytes
    }

    #[must_use]
    pub const fn maximum_encrypted_object_bytes(&self) -> u64 {
        self.maximum_encrypted_object_bytes
    }

    #[must_use]
    pub fn acknowledgement(&self) -> wire::HandshakeAck {
        wire::HandshakeAck {
            selected_protocol_version: u32::from(self.protocol_version),
            capabilities: self
                .capabilities
                .iter()
                .map(|capability| *capability as i32)
                .collect(),
            maximum_control_frame_bytes: u32::try_from(self.maximum_control_frame_bytes)
                .expect("negotiated control frame limit fits in u32"),
            maximum_object_bytes: self.maximum_encrypted_object_bytes,
        }
    }
}

pub fn negotiate_handshake(
    remote: &wire::Handshake,
    expected_group_id: GroupId,
    local_limits: ProtocolLimits,
) -> Result<NegotiatedSession, ProtocolError> {
    if remote.minimum_protocol_version > remote.maximum_protocol_version {
        return Err(ProtocolError::InvalidVersionRange {
            minimum: remote.minimum_protocol_version,
            maximum: remote.maximum_protocol_version,
        });
    }

    let local_version = u32::from(PROTOCOL_VERSION);
    if remote.minimum_protocol_version > local_version
        || remote.maximum_protocol_version < local_version
    {
        return Err(ProtocolError::IncompatibleProtocolVersion {
            local: PROTOCOL_VERSION,
            remote_minimum: remote.minimum_protocol_version,
            remote_maximum: remote.maximum_protocol_version,
        });
    }

    let remote_device_id = DeviceId::from_uuid(parse_uuid("device_id", &remote.device_id)?);
    let remote_group_id = GroupId::from_uuid(parse_uuid("group_id", &remote.group_id)?);
    if remote_group_id != expected_group_id {
        return Err(ProtocolError::GroupMismatch {
            expected: expected_group_id,
            actual: remote_group_id,
        });
    }

    let remote_capabilities: BTreeSet<_> = remote
        .capabilities
        .iter()
        .filter_map(|value| Capability::try_from(*value).ok())
        .filter(|capability| *capability != Capability::Unspecified)
        .collect();
    for required in REQUIRED_CAPABILITIES {
        if !remote_capabilities.contains(&required) {
            return Err(ProtocolError::MissingRequiredCapability(required));
        }
    }

    let remote_control_limit =
        usize::try_from(remote.maximum_control_frame_bytes).map_err(|_| {
            ProtocolError::AdvertisedLimitTooSmall {
                name: "maximum_control_frame_bytes",
                value: u64::from(remote.maximum_control_frame_bytes),
                minimum: MINIMUM_CONTROL_FRAME_BYTES as u64,
            }
        })?;
    if remote_control_limit < MINIMUM_CONTROL_FRAME_BYTES {
        return Err(ProtocolError::AdvertisedLimitTooSmall {
            name: "maximum_control_frame_bytes",
            value: u64::from(remote.maximum_control_frame_bytes),
            minimum: MINIMUM_CONTROL_FRAME_BYTES as u64,
        });
    }
    if remote.maximum_object_bytes < MINIMUM_ENCRYPTED_OBJECT_BYTES {
        return Err(ProtocolError::AdvertisedLimitTooSmall {
            name: "maximum_object_bytes",
            value: remote.maximum_object_bytes,
            minimum: MINIMUM_ENCRYPTED_OBJECT_BYTES,
        });
    }

    Ok(NegotiatedSession {
        remote_device_id,
        group_id: remote_group_id,
        protocol_version: PROTOCOL_VERSION,
        capabilities: REQUIRED_CAPABILITIES.to_vec(),
        maximum_control_frame_bytes: local_limits
            .maximum_control_frame_bytes
            .min(remote_control_limit),
        maximum_encrypted_object_bytes: local_limits
            .maximum_encrypted_object_bytes
            .min(remote.maximum_object_bytes),
    })
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SessionNonce([u8; SESSION_NONCE_SIZE]);

impl SessionNonce {
    pub fn generate() -> Result<Self, ProtocolError> {
        let mut bytes = [0_u8; SESSION_NONCE_SIZE];
        getrandom::fill(&mut bytes).map_err(|_| ProtocolError::Randomness)?;
        Ok(Self(bytes))
    }

    pub fn from_bytes(bytes: [u8; SESSION_NONCE_SIZE]) -> Result<Self, ProtocolError> {
        if bytes == [0; SESSION_NONCE_SIZE] {
            return Err(ProtocolError::ZeroSessionNonce);
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SESSION_NONCE_SIZE] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SessionTransportBinding([u8; SESSION_TRANSPORT_BINDING_SIZE]);

impl SessionTransportBinding {
    pub fn from_bytes(bytes: [u8; SESSION_TRANSPORT_BINDING_SIZE]) -> Result<Self, ProtocolError> {
        if bytes == [0; SESSION_TRANSPORT_BINDING_SIZE] {
            return Err(ProtocolError::ZeroSessionTransportBinding);
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SESSION_TRANSPORT_BINDING_SIZE] {
        &self.0
    }
}

#[must_use]
pub fn build_session_hello(
    identity: &DeviceIdentity,
    keys: &GroupKeys,
    limits: ProtocolLimits,
    nonce: SessionNonce,
    transport_binding: SessionTransportBinding,
    listen_port: u16,
) -> wire::SessionHello {
    let enrollment_proof = keys.peer_enrollment_proof(
        identity.public_key(),
        nonce.as_bytes(),
        transport_binding.as_bytes(),
        listen_port,
    );
    wire::SessionHello {
        handshake: Some(current_handshake(
            identity.device_id(),
            keys.group_id(),
            limits,
        )),
        nonce: nonce.as_bytes().to_vec(),
        transport_binding: transport_binding.as_bytes().to_vec(),
        public_key: identity.public_key().as_bytes().to_vec(),
        enrollment_proof: enrollment_proof.to_vec(),
        listen_port: u32::from(listen_port),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerEnrollment {
    pub public_key: DevicePublicKey,
    pub listen_port: Option<u16>,
}

pub fn verify_peer_enrollment(
    hello: &wire::SessionHello,
    keys: &GroupKeys,
    expected_transport_binding: SessionTransportBinding,
) -> Result<PeerEnrollment, ProtocolError> {
    let public_key_bytes: [u8; 32] = hello.public_key.as_slice().try_into().map_err(|_| {
        ProtocolError::InvalidEnrollmentPublicKeyLength {
            actual: hello.public_key.len(),
        }
    })?;
    let public_key = DevicePublicKey::from_bytes(public_key_bytes)?;
    let claimed_device_id = parse_handshake_device_id(session_hello_handshake(hello)?)?;
    if claimed_device_id != public_key.device_id() {
        return Err(ProtocolError::PeerIdentityMismatch {
            claimed: claimed_device_id,
            authenticated: public_key.device_id(),
        });
    }
    let listen_port = u16::try_from(hello.listen_port)
        .map_err(|_| ProtocolError::InvalidEnrollmentListenPort(hello.listen_port))?;
    let expected = keys.peer_enrollment_proof(
        public_key,
        &hello.nonce,
        expected_transport_binding.as_bytes(),
        listen_port,
    );
    if hello.enrollment_proof.as_slice() != expected {
        return Err(ProtocolError::InvalidEnrollmentProof);
    }
    Ok(PeerEnrollment {
        public_key,
        listen_port: (listen_port != 0).then_some(listen_port),
    })
}

pub fn accept_session_hello(
    hello: &wire::SessionHello,
    responder_identity: &DeviceIdentity,
    responder_nonce: SessionNonce,
    expected_transport_binding: SessionTransportBinding,
    expected_group_id: GroupId,
    local_limits: ProtocolLimits,
) -> Result<(NegotiatedSession, wire::SessionChallenge), ProtocolError> {
    let initiator_handshake = session_hello_handshake(hello)?;
    parse_session_nonce("session_hello.nonce", &hello.nonce)?;
    validate_session_transport_binding(hello, expected_transport_binding)?;
    let session = negotiate_handshake(initiator_handshake, expected_group_id, local_limits)?;
    if session.remote_device_id() == responder_identity.device_id() {
        return Err(ProtocolError::SelfConnection {
            device_id: responder_identity.device_id(),
        });
    }

    let responder_handshake = current_handshake(
        responder_identity.device_id(),
        expected_group_id,
        local_limits,
    );
    let acknowledgement = session.acknowledgement();
    let transcript = session_transcript(
        hello,
        &responder_handshake,
        &acknowledgement,
        responder_nonce,
    )?;
    let authorization = responder_identity.authorize_session(&transcript);
    Ok((
        session,
        wire::SessionChallenge {
            handshake: Some(responder_handshake),
            acknowledgement: Some(acknowledgement),
            nonce: responder_nonce.as_bytes().to_vec(),
            responder_signature: authorization.signature.as_bytes().to_vec(),
        },
    ))
}

pub fn answer_session_challenge(
    hello: &wire::SessionHello,
    challenge: &wire::SessionChallenge,
    initiator_identity: &DeviceIdentity,
    responder_public_key: DevicePublicKey,
    expected_transport_binding: SessionTransportBinding,
    expected_group_id: GroupId,
    local_limits: ProtocolLimits,
) -> Result<(NegotiatedSession, wire::SessionProof), ProtocolError> {
    let initiator_handshake = session_hello_handshake(hello)?;
    validate_session_transport_binding(hello, expected_transport_binding)?;
    if parse_handshake_device_id(initiator_handshake)? != initiator_identity.device_id() {
        return Err(ProtocolError::LocalIdentityMismatch);
    }
    let responder_handshake = session_challenge_handshake(challenge)?;
    let session = negotiate_handshake(responder_handshake, expected_group_id, local_limits)?;
    if session.remote_device_id() != responder_public_key.device_id() {
        return Err(ProtocolError::PeerIdentityMismatch {
            claimed: session.remote_device_id(),
            authenticated: responder_public_key.device_id(),
        });
    }
    let acknowledgement = session_challenge_acknowledgement(challenge)?;
    if *acknowledgement != session.acknowledgement() {
        return Err(ProtocolError::HandshakeAcknowledgementMismatch);
    }
    let responder_nonce = parse_session_nonce("session_challenge.nonce", &challenge.nonce)?;
    let transcript =
        session_transcript(hello, responder_handshake, acknowledgement, responder_nonce)?;
    let responder_signature = parse_session_signature(
        "session_challenge.responder_signature",
        &challenge.responder_signature,
    )?;
    responder_public_key.verify_session(
        &transcript,
        SessionAuthorization {
            author_device_id: session.remote_device_id(),
            signature: responder_signature,
        },
    )?;
    let authorization = initiator_identity.authorize_session(&transcript);
    Ok((
        session,
        wire::SessionProof {
            initiator_signature: authorization.signature.as_bytes().to_vec(),
        },
    ))
}

#[allow(clippy::too_many_arguments)]
pub fn verify_session_proof(
    hello: &wire::SessionHello,
    challenge: &wire::SessionChallenge,
    proof: &wire::SessionProof,
    responder_identity: &DeviceIdentity,
    initiator_public_key: DevicePublicKey,
    expected_transport_binding: SessionTransportBinding,
    expected_group_id: GroupId,
    local_limits: ProtocolLimits,
) -> Result<NegotiatedSession, ProtocolError> {
    let initiator_handshake = session_hello_handshake(hello)?;
    validate_session_transport_binding(hello, expected_transport_binding)?;
    let session = negotiate_handshake(initiator_handshake, expected_group_id, local_limits)?;
    if session.remote_device_id() != initiator_public_key.device_id() {
        return Err(ProtocolError::PeerIdentityMismatch {
            claimed: session.remote_device_id(),
            authenticated: initiator_public_key.device_id(),
        });
    }
    let responder_handshake = session_challenge_handshake(challenge)?;
    if parse_handshake_device_id(responder_handshake)? != responder_identity.device_id() {
        return Err(ProtocolError::LocalIdentityMismatch);
    }
    let acknowledgement = session_challenge_acknowledgement(challenge)?;
    if *acknowledgement != session.acknowledgement() {
        return Err(ProtocolError::HandshakeAcknowledgementMismatch);
    }
    let responder_nonce = parse_session_nonce("session_challenge.nonce", &challenge.nonce)?;
    let transcript =
        session_transcript(hello, responder_handshake, acknowledgement, responder_nonce)?;
    let initiator_signature = parse_session_signature(
        "session_proof.initiator_signature",
        &proof.initiator_signature,
    )?;
    initiator_public_key.verify_session(
        &transcript,
        SessionAuthorization {
            author_device_id: session.remote_device_id(),
            signature: initiator_signature,
        },
    )?;
    Ok(session)
}

fn session_hello_handshake(hello: &wire::SessionHello) -> Result<&wire::Handshake, ProtocolError> {
    hello
        .handshake
        .as_ref()
        .ok_or(ProtocolError::MissingSessionField(
            "session_hello.handshake",
        ))
}

fn session_challenge_handshake(
    challenge: &wire::SessionChallenge,
) -> Result<&wire::Handshake, ProtocolError> {
    challenge
        .handshake
        .as_ref()
        .ok_or(ProtocolError::MissingSessionField(
            "session_challenge.handshake",
        ))
}

fn session_challenge_acknowledgement(
    challenge: &wire::SessionChallenge,
) -> Result<&wire::HandshakeAck, ProtocolError> {
    challenge
        .acknowledgement
        .as_ref()
        .ok_or(ProtocolError::MissingSessionField(
            "session_challenge.acknowledgement",
        ))
}

fn parse_handshake_device_id(handshake: &wire::Handshake) -> Result<DeviceId, ProtocolError> {
    Ok(DeviceId::from_uuid(parse_uuid(
        "device_id",
        &handshake.device_id,
    )?))
}

fn parse_session_nonce(field: &'static str, bytes: &[u8]) -> Result<SessionNonce, ProtocolError> {
    let bytes: [u8; SESSION_NONCE_SIZE] =
        bytes
            .try_into()
            .map_err(|_| ProtocolError::InvalidSessionNonceLength {
                field,
                actual: bytes.len(),
            })?;
    SessionNonce::from_bytes(bytes)
}

fn parse_session_signature(
    field: &'static str,
    bytes: &[u8],
) -> Result<SessionSignature, ProtocolError> {
    let bytes: [u8; SESSION_SIGNATURE_SIZE] =
        bytes
            .try_into()
            .map_err(|_| ProtocolError::InvalidSessionSignatureLength {
                field,
                actual: bytes.len(),
            })?;
    Ok(SessionSignature::from_bytes(bytes))
}

fn validate_session_transport_binding(
    hello: &wire::SessionHello,
    expected: SessionTransportBinding,
) -> Result<(), ProtocolError> {
    let actual: [u8; SESSION_TRANSPORT_BINDING_SIZE] =
        hello.transport_binding.as_slice().try_into().map_err(|_| {
            ProtocolError::InvalidSessionTransportBindingLength {
                actual: hello.transport_binding.len(),
            }
        })?;
    if actual == [0; SESSION_TRANSPORT_BINDING_SIZE] {
        return Err(ProtocolError::ZeroSessionTransportBinding);
    }
    if actual != *expected.as_bytes() {
        return Err(ProtocolError::SessionTransportBindingMismatch);
    }
    Ok(())
}

fn session_transcript(
    hello: &wire::SessionHello,
    responder_handshake: &wire::Handshake,
    acknowledgement: &wire::HandshakeAck,
    responder_nonce: SessionNonce,
) -> Result<Vec<u8>, ProtocolError> {
    parse_session_nonce("session_hello.nonce", &hello.nonce)?;
    let mut transcript = Vec::new();
    transcript.extend_from_slice(SESSION_TRANSCRIPT_DOMAIN);
    append_transcript_message(&mut transcript, hello)?;
    append_transcript_message(&mut transcript, responder_handshake)?;
    append_transcript_message(&mut transcript, acknowledgement)?;
    transcript.extend_from_slice(responder_nonce.as_bytes());
    Ok(transcript)
}

fn append_transcript_message<M: Message>(
    transcript: &mut Vec<u8>,
    message: &M,
) -> Result<(), ProtocolError> {
    let encoded = message.encode_to_vec();
    let length = u64::try_from(encoded.len()).map_err(|_| ProtocolError::FrameLengthOverflow)?;
    transcript.extend_from_slice(&length.to_be_bytes());
    transcript.extend_from_slice(&encoded);
    Ok(())
}

pub fn encode_control_frame<M: Message>(
    message: &M,
    limits: ProtocolLimits,
) -> Result<Vec<u8>, ProtocolError> {
    let message_length = message.encoded_len();
    if message_length > limits.maximum_control_frame_bytes {
        return Err(ProtocolError::ControlFrameTooLarge {
            actual: message_length,
            maximum: limits.maximum_control_frame_bytes,
        });
    }
    let encoded_length =
        u32::try_from(message_length).map_err(|_| ProtocolError::ControlFrameTooLarge {
            actual: message_length,
            maximum: limits.maximum_control_frame_bytes,
        })?;
    let capacity = CONTROL_FRAME_HEADER_SIZE
        .checked_add(message_length)
        .ok_or(ProtocolError::FrameLengthOverflow)?;
    let mut frame = Vec::with_capacity(capacity);
    frame.extend_from_slice(&encoded_length.to_be_bytes());
    message.encode(&mut frame)?;
    Ok(frame)
}

pub fn decode_control_frame<M: Message + Default>(
    frame: &[u8],
    limits: ProtocolLimits,
) -> Result<M, ProtocolError> {
    if frame.len() < CONTROL_FRAME_HEADER_SIZE {
        return Err(ProtocolError::ControlFrameHeaderTooShort {
            actual: frame.len(),
        });
    }
    let declared = usize::try_from(u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]))
        .map_err(|_| ProtocolError::FrameLengthOverflow)?;
    if declared > limits.maximum_control_frame_bytes {
        return Err(ProtocolError::ControlFrameTooLarge {
            actual: declared,
            maximum: limits.maximum_control_frame_bytes,
        });
    }
    let actual = frame.len() - CONTROL_FRAME_HEADER_SIZE;
    if declared != actual {
        return Err(ProtocolError::ControlFrameLengthMismatch { declared, actual });
    }
    Ok(M::decode(&frame[CONTROL_FRAME_HEADER_SIZE..])?)
}

pub fn encode_change_record(record: &ChangeRecord) -> Result<Vec<u8>, ManifestError> {
    let record = match record {
        ChangeRecord::File(manifest) => {
            validate_file_manifest(manifest)?;
            wire::manifest_envelope::Record::File(wire::FileRecord {
                file_id: manifest.file_id.as_uuid().as_bytes().to_vec(),
                revision_id: manifest.revision_id.as_uuid().as_bytes().to_vec(),
                relative_path: manifest.relative_path.as_str().to_owned(),
                size: manifest.size,
                modified_at_unix_ms: manifest.modified_at_unix_ms,
                version: encode_version(&manifest.version)?,
                chunks: manifest
                    .chunks
                    .iter()
                    .map(|chunk| wire::ChunkReference {
                        content_id: chunk.content_id.as_bytes().to_vec(),
                        plaintext_size: chunk.plaintext_size,
                    })
                    .collect(),
            })
        }
        ChangeRecord::Tombstone(tombstone) => {
            validate_uuid("tombstone.file_id", *tombstone.file_id.as_uuid())?;
            validate_uuid("tombstone.revision_id", *tombstone.revision_id.as_uuid())?;
            wire::manifest_envelope::Record::Tombstone(wire::TombstoneRecord {
                file_id: tombstone.file_id.as_uuid().as_bytes().to_vec(),
                revision_id: tombstone.revision_id.as_uuid().as_bytes().to_vec(),
                relative_path: tombstone.relative_path.as_str().to_owned(),
                deleted_at_unix_ms: tombstone.deleted_at_unix_ms,
                version: encode_version(&tombstone.version)?,
            })
        }
    };
    let envelope = wire::ManifestEnvelope {
        format_version: MANIFEST_PLAINTEXT_FORMAT_VERSION,
        record: Some(record),
    };
    let encoded = envelope.encode_to_vec();
    if encoded.len() > MAXIMUM_MANIFEST_PLAINTEXT_BYTES {
        return Err(ManifestError::PlaintextTooLarge {
            actual: encoded.len(),
            maximum: MAXIMUM_MANIFEST_PLAINTEXT_BYTES,
        });
    }
    Ok(encoded)
}

pub fn decode_change_record(bytes: &[u8]) -> Result<ChangeRecord, ManifestError> {
    if bytes.len() > MAXIMUM_MANIFEST_PLAINTEXT_BYTES {
        return Err(ManifestError::PlaintextTooLarge {
            actual: bytes.len(),
            maximum: MAXIMUM_MANIFEST_PLAINTEXT_BYTES,
        });
    }
    let envelope = wire::ManifestEnvelope::decode(bytes)?;
    if envelope.format_version != MANIFEST_PLAINTEXT_FORMAT_VERSION {
        return Err(ManifestError::UnsupportedFormatVersion(
            envelope.format_version,
        ));
    }

    let record = match envelope.record.ok_or(ManifestError::MissingRecord)? {
        wire::manifest_envelope::Record::File(file) => {
            ChangeRecord::File(decode_file_record(file)?)
        }
        wire::manifest_envelope::Record::Tombstone(tombstone) => {
            ChangeRecord::Tombstone(decode_tombstone_record(tombstone)?)
        }
    };
    if encode_change_record(&record)?.as_slice() != bytes {
        return Err(ManifestError::NonCanonical);
    }
    Ok(record)
}

fn encode_version(version: &VersionVector) -> Result<Vec<wire::VersionCounter>, ManifestError> {
    if version.iter().len() == 0 {
        return Err(ManifestError::EmptyVersionVector);
    }
    version
        .iter()
        .map(|(device_id, counter)| {
            if counter == 0 {
                return Err(VersionVectorError::ZeroCounter { device_id }.into());
            }
            Ok(wire::VersionCounter {
                device_id: device_id.as_uuid().as_bytes().to_vec(),
                counter,
            })
        })
        .collect()
}

fn decode_version(entries: Vec<wire::VersionCounter>) -> Result<VersionVector, ManifestError> {
    if entries.is_empty() {
        return Err(ManifestError::EmptyVersionVector);
    }
    let mut previous = None;
    let mut decoded = Vec::with_capacity(entries.len());
    for (index, entry) in entries.into_iter().enumerate() {
        let device_id =
            DeviceId::from_uuid(decode_manifest_uuid("version.device_id", &entry.device_id)?);
        if previous.is_some_and(|previous| device_id <= previous) {
            return Err(ManifestError::VersionEntriesNotStrictlySorted { index });
        }
        previous = Some(device_id);
        decoded.push((device_id, entry.counter));
    }
    Ok(VersionVector::from_entries(decoded)?)
}

fn validate_file_manifest(manifest: &FileManifest) -> Result<(), ManifestError> {
    validate_uuid("file.file_id", *manifest.file_id.as_uuid())?;
    validate_uuid("file.revision_id", *manifest.revision_id.as_uuid())?;
    if manifest.chunks.len() > MAXIMUM_MANIFEST_CHUNKS {
        return Err(ManifestError::TooManyChunks {
            actual: manifest.chunks.len(),
            maximum: MAXIMUM_MANIFEST_CHUNKS,
        });
    }
    let mut actual_size = 0_u64;
    for (index, chunk) in manifest.chunks.iter().enumerate() {
        if chunk.plaintext_size == 0 {
            return Err(ManifestError::ZeroChunkSize { index });
        }
        actual_size = actual_size
            .checked_add(u64::from(chunk.plaintext_size))
            .ok_or(ManifestError::FileSizeOverflow)?;
    }
    if actual_size != manifest.size {
        return Err(ManifestError::FileSizeMismatch {
            declared: manifest.size,
            actual: actual_size,
        });
    }
    Ok(())
}

fn decode_file_record(file: wire::FileRecord) -> Result<FileManifest, ManifestError> {
    let chunks = file
        .chunks
        .into_iter()
        .map(|chunk| {
            Ok(ChunkRef {
                content_id: decode_manifest_content_id(
                    "file.chunks.content_id",
                    &chunk.content_id,
                )?,
                plaintext_size: chunk.plaintext_size,
            })
        })
        .collect::<Result<Vec<_>, ManifestError>>()?;
    let manifest = FileManifest {
        file_id: FileId::from_uuid(decode_manifest_uuid("file.file_id", &file.file_id)?),
        revision_id: RevisionId::from_uuid(decode_manifest_uuid(
            "file.revision_id",
            &file.revision_id,
        )?),
        relative_path: RelativePath::new(file.relative_path)?,
        size: file.size,
        modified_at_unix_ms: file.modified_at_unix_ms,
        version: decode_version(file.version)?,
        chunks,
    };
    validate_file_manifest(&manifest)?;
    Ok(manifest)
}

fn decode_tombstone_record(tombstone: wire::TombstoneRecord) -> Result<Tombstone, ManifestError> {
    Ok(Tombstone {
        file_id: FileId::from_uuid(decode_manifest_uuid(
            "tombstone.file_id",
            &tombstone.file_id,
        )?),
        revision_id: RevisionId::from_uuid(decode_manifest_uuid(
            "tombstone.revision_id",
            &tombstone.revision_id,
        )?),
        relative_path: RelativePath::new(tombstone.relative_path)?,
        deleted_at_unix_ms: tombstone.deleted_at_unix_ms,
        version: decode_version(tombstone.version)?,
    })
}

#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("failed to decode manifest plaintext")]
    Decode(#[from] prost::DecodeError),
    #[error("manifest plaintext has {actual} bytes, maximum is {maximum}")]
    PlaintextTooLarge { actual: usize, maximum: usize },
    #[error("unsupported manifest plaintext format version {0}")]
    UnsupportedFormatVersion(u32),
    #[error("manifest plaintext does not contain a record")]
    MissingRecord,
    #[error("manifest identifier {field} has {actual} bytes, expected {expected}")]
    InvalidIdentifierLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("manifest identifier {field} must not be nil")]
    NilIdentifier { field: &'static str },
    #[error("manifest path is invalid: {0}")]
    Path(#[from] PathError),
    #[error("manifest version vector is invalid: {0}")]
    Version(#[from] VersionVectorError),
    #[error("manifest version vector must contain at least one counter")]
    EmptyVersionVector,
    #[error("manifest version entry {index} is not strictly sorted by device ID")]
    VersionEntriesNotStrictlySorted { index: usize },
    #[error("manifest has {actual} chunks, maximum is {maximum}")]
    TooManyChunks { actual: usize, maximum: usize },
    #[error("manifest chunk {index} has a zero plaintext size")]
    ZeroChunkSize { index: usize },
    #[error("manifest chunk sizes overflow the file-size representation")]
    FileSizeOverflow,
    #[error("manifest declares {declared} bytes but its chunks total {actual}")]
    FileSizeMismatch { declared: u64, actual: u64 },
    #[error("manifest plaintext is not canonically encoded")]
    NonCanonical,
}

fn validate_uuid(field: &'static str, value: Uuid) -> Result<(), ManifestError> {
    if value.is_nil() {
        return Err(ManifestError::NilIdentifier { field });
    }
    Ok(())
}

fn decode_manifest_uuid(field: &'static str, bytes: &[u8]) -> Result<Uuid, ManifestError> {
    let value: [u8; 16] = bytes
        .try_into()
        .map_err(|_| ManifestError::InvalidIdentifierLength {
            field,
            expected: 16,
            actual: bytes.len(),
        })?;
    let value = Uuid::from_bytes(value);
    validate_uuid(field, value)?;
    Ok(value)
}

fn decode_manifest_content_id(
    field: &'static str,
    bytes: &[u8],
) -> Result<ContentId, ManifestError> {
    let value = bytes
        .try_into()
        .map_err(|_| ManifestError::InvalidIdentifierLength {
            field,
            expected: 32,
            actual: bytes.len(),
        })?;
    Ok(ContentId::from_bytes(value))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedObjectRequest {
    request_id: Uuid,
    content_ids: Vec<ContentId>,
}

impl ValidatedObjectRequest {
    #[must_use]
    pub const fn request_id(&self) -> Uuid {
        self.request_id
    }

    #[must_use]
    pub fn content_ids(&self) -> &[ContentId] {
        &self.content_ids
    }
}

pub fn build_object_request<I>(
    request_id: Uuid,
    content_ids: I,
    limits: ProtocolLimits,
) -> Result<wire::ObjectRequest, ProtocolError>
where
    I: IntoIterator<Item = ContentId>,
{
    let request = wire::ObjectRequest {
        request_id: request_id.as_bytes().to_vec(),
        content_ids: content_ids
            .into_iter()
            .map(|content_id| content_id.as_bytes().to_vec())
            .collect(),
    };
    validate_object_request(&request, limits)?;
    Ok(request)
}

pub fn validate_object_request(
    request: &wire::ObjectRequest,
    limits: ProtocolLimits,
) -> Result<ValidatedObjectRequest, ProtocolError> {
    let request_id = parse_uuid("request_id", &request.request_id)?;
    if request.content_ids.is_empty() {
        return Err(ProtocolError::EmptyObjectRequest);
    }
    if request.content_ids.len() > limits.maximum_content_ids_per_request {
        return Err(ProtocolError::TooManyContentIds {
            actual: request.content_ids.len(),
            maximum: limits.maximum_content_ids_per_request,
        });
    }

    let mut seen = HashSet::with_capacity(request.content_ids.len());
    let mut content_ids = Vec::with_capacity(request.content_ids.len());
    for (index, bytes) in request.content_ids.iter().enumerate() {
        let content_id = parse_content_id("object_request.content_ids", index, bytes)?;
        if !seen.insert(content_id) {
            return Err(ProtocolError::DuplicateContentId(content_id));
        }
        content_ids.push(content_id);
    }

    Ok(ValidatedObjectRequest {
        request_id,
        content_ids,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedObjectRangeRequest {
    pub request_id: Uuid,
    pub content_id: ContentId,
    pub start_offset: u64,
}

pub fn build_object_range_request(
    request_id: Uuid,
    content_id: ContentId,
    start_offset: u64,
    limits: ProtocolLimits,
) -> Result<wire::ObjectRangeRequest, ProtocolError> {
    let request = wire::ObjectRangeRequest {
        request_id: request_id.as_bytes().to_vec(),
        content_id: content_id.as_bytes().to_vec(),
        start_offset,
    };
    validate_object_range_request(&request, limits)?;
    Ok(request)
}

pub fn validate_object_range_request(
    request: &wire::ObjectRangeRequest,
    limits: ProtocolLimits,
) -> Result<ValidatedObjectRangeRequest, ProtocolError> {
    let request_id = parse_uuid("object_range_request.request_id", &request.request_id)?;
    let content_id = parse_content_id("object_range_request.content_id", 0, &request.content_id)?;
    if request.start_offset >= limits.maximum_encrypted_object_bytes {
        return Err(ProtocolError::ObjectRangeOffsetTooLarge {
            actual: request.start_offset,
            maximum: limits.maximum_encrypted_object_bytes,
        });
    }
    Ok(ValidatedObjectRangeRequest {
        request_id,
        content_id,
        start_offset: request.start_offset,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedObjectTransfer {
    pub request_id: Uuid,
    pub content_id: ContentId,
    pub encrypted_size: u64,
    pub start_offset: u64,
}

pub fn build_object_offer(
    request: ValidatedObjectRangeRequest,
    encrypted_size: u64,
    limits: ProtocolLimits,
) -> Result<wire::ObjectOffer, ProtocolError> {
    let offer = wire::ObjectOffer {
        request_id: request.request_id.as_bytes().to_vec(),
        content_id: request.content_id.as_bytes().to_vec(),
        encrypted_size,
        start_offset: request.start_offset,
    };
    validate_object_offer(&offer, limits)?;
    Ok(offer)
}

pub fn validate_object_offer(
    offer: &wire::ObjectOffer,
    limits: ProtocolLimits,
) -> Result<ValidatedObjectTransfer, ProtocolError> {
    validate_object_transfer_metadata(
        "object_offer",
        &offer.request_id,
        &offer.content_id,
        offer.encrypted_size,
        offer.start_offset,
        limits,
    )
}

pub fn validate_object_offer_for_request(
    offer: &wire::ObjectOffer,
    request: ValidatedObjectRangeRequest,
    limits: ProtocolLimits,
) -> Result<ValidatedObjectTransfer, ProtocolError> {
    let transfer = validate_object_offer(offer, limits)?;
    if transfer.request_id != request.request_id
        || transfer.content_id != request.content_id
        || transfer.start_offset != request.start_offset
    {
        return Err(ProtocolError::ObjectTransferRequestMismatch);
    }
    Ok(transfer)
}

#[must_use]
pub fn build_object_stream_header(transfer: ValidatedObjectTransfer) -> wire::ObjectStreamHeader {
    wire::ObjectStreamHeader {
        request_id: transfer.request_id.as_bytes().to_vec(),
        content_id: transfer.content_id.as_bytes().to_vec(),
        encrypted_size: transfer.encrypted_size,
        start_offset: transfer.start_offset,
    }
}

pub fn validate_object_stream_header(
    header: &wire::ObjectStreamHeader,
    limits: ProtocolLimits,
) -> Result<ValidatedObjectTransfer, ProtocolError> {
    validate_object_transfer_metadata(
        "object_stream_header",
        &header.request_id,
        &header.content_id,
        header.encrypted_size,
        header.start_offset,
        limits,
    )
}

pub fn validate_object_stream_header_for_offer(
    header: &wire::ObjectStreamHeader,
    offer: ValidatedObjectTransfer,
    limits: ProtocolLimits,
) -> Result<ValidatedObjectTransfer, ProtocolError> {
    let transfer = validate_object_stream_header(header, limits)?;
    if transfer != offer {
        return Err(ProtocolError::ObjectTransferMetadataMismatch);
    }
    Ok(transfer)
}

fn validate_object_transfer_metadata(
    field: &'static str,
    request_id: &[u8],
    content_id: &[u8],
    encrypted_size: u64,
    start_offset: u64,
    limits: ProtocolLimits,
) -> Result<ValidatedObjectTransfer, ProtocolError> {
    let request_id = parse_uuid(field, request_id)?;
    let content_id = parse_content_id(field, 0, content_id)?;
    if encrypted_size < MINIMUM_ENCRYPTED_OBJECT_BYTES
        || encrypted_size > limits.maximum_encrypted_object_bytes
    {
        return Err(ProtocolError::InvalidObjectTransferSize {
            actual: encrypted_size,
            minimum: MINIMUM_ENCRYPTED_OBJECT_BYTES,
            maximum: limits.maximum_encrypted_object_bytes,
        });
    }
    if start_offset >= encrypted_size {
        return Err(ProtocolError::InvalidObjectTransferRange {
            start_offset,
            encrypted_size,
        });
    }
    Ok(ValidatedObjectTransfer {
        request_id,
        content_id,
        encrypted_size,
        start_offset,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedEncryptedChange {
    pub sequence: u64,
    pub revision_id: RevisionId,
    pub content_id: ContentId,
    pub authorization: ChangeAuthorization,
    pub encrypted_record: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedChangeBatch {
    pub records: Vec<ValidatedEncryptedChange>,
    pub high_watermark: u64,
    pub has_more: bool,
}

pub fn validate_change_batch(
    batch: &wire::ChangeBatch,
    limits: ProtocolLimits,
) -> Result<ValidatedChangeBatch, ProtocolError> {
    if batch.records.len() > limits.maximum_change_records_per_batch {
        return Err(ProtocolError::TooManyChangeRecords {
            actual: batch.records.len(),
            maximum: limits.maximum_change_records_per_batch,
        });
    }

    let mut previous_sequence = 0_u64;
    let mut validated = Vec::with_capacity(batch.records.len());
    for (index, record) in batch.records.iter().enumerate() {
        if record.sequence == 0 || record.sequence <= previous_sequence {
            return Err(ProtocolError::InvalidChangeSequence {
                index,
                previous: previous_sequence,
                actual: record.sequence,
            });
        }
        previous_sequence = record.sequence;
        let revision_id =
            RevisionId::from_uuid(parse_uuid("change.revision_id", &record.revision_id)?);
        let content_id = parse_content_id("change.content_id", index, &record.content_id)?;
        let author_device_id = DeviceId::from_uuid(parse_uuid(
            "change.author_device_id",
            &record.author_device_id,
        )?);
        let signature: [u8; CHANGE_SIGNATURE_SIZE] =
            record.signature.as_slice().try_into().map_err(|_| {
                ProtocolError::InvalidChangeSignatureLength {
                    index,
                    actual: record.signature.len(),
                }
            })?;

        let encrypted_size = u64::try_from(record.encrypted_record.len()).map_err(|_| {
            ProtocolError::EncryptedObjectTooLarge {
                index,
                actual: u64::MAX,
                maximum: limits.maximum_encrypted_object_bytes,
            }
        })?;
        if encrypted_size > limits.maximum_encrypted_object_bytes {
            return Err(ProtocolError::EncryptedObjectTooLarge {
                index,
                actual: encrypted_size,
                maximum: limits.maximum_encrypted_object_bytes,
            });
        }

        let object = EncryptedObject::from_bytes(&record.encrypted_record)
            .map_err(|source| ProtocolError::InvalidEncryptedObject { index, source })?;
        if object.kind() != ObjectKind::Manifest {
            return Err(ProtocolError::UnexpectedChangeObjectKind {
                index,
                actual: object.kind(),
            });
        }
        if object.content_id() != content_id {
            return Err(ProtocolError::ChangeContentIdMismatch { index });
        }
        validated.push(ValidatedEncryptedChange {
            sequence: record.sequence,
            revision_id,
            content_id,
            authorization: ChangeAuthorization {
                author_device_id,
                signature: ChangeSignature::from_bytes(signature),
            },
            encrypted_record: record.encrypted_record.clone(),
        });
    }

    if previous_sequence > batch.high_watermark {
        return Err(ProtocolError::InvalidHighWatermark {
            last_sequence: previous_sequence,
            high_watermark: batch.high_watermark,
        });
    }

    Ok(ValidatedChangeBatch {
        records: validated,
        high_watermark: batch.high_watermark,
        has_more: batch.has_more,
    })
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("operating system randomness is unavailable")]
    Randomness,
    #[error("device identity verification failed: {0}")]
    Identity(#[from] IdentityError),
    #[error("protocol limit {name}={value} is outside {minimum}..={maximum}")]
    InvalidLimit {
        name: &'static str,
        value: u64,
        minimum: u64,
        maximum: u64,
    },
    #[error("invalid protocol version range {minimum}..={maximum}")]
    InvalidVersionRange { minimum: u32, maximum: u32 },
    #[error(
        "protocol version {local} is outside the remote range {remote_minimum}..={remote_maximum}"
    )]
    IncompatibleProtocolVersion {
        local: u16,
        remote_minimum: u32,
        remote_maximum: u32,
    },
    #[error("identifier {field} has {actual} bytes, expected 16")]
    InvalidIdentifierLength { field: &'static str, actual: usize },
    #[error("identifier {field} is not a valid UUID")]
    InvalidIdentifier {
        field: &'static str,
        #[source]
        source: uuid::Error,
    },
    #[error("identifier {field} must not be nil")]
    NilIdentifier { field: &'static str },
    #[error("handshake is for group {actual}, expected {expected}")]
    GroupMismatch { expected: GroupId, actual: GroupId },
    #[error("peer is missing required capability {0:?}")]
    MissingRequiredCapability(Capability),
    #[error("session message is missing {0}")]
    MissingSessionField(&'static str),
    #[error("{field} has {actual} bytes, expected 32")]
    InvalidSessionNonceLength { field: &'static str, actual: usize },
    #[error("session nonce must not be all zero")]
    ZeroSessionNonce,
    #[error("session transport binding has {actual} bytes, expected 32")]
    InvalidSessionTransportBindingLength { actual: usize },
    #[error("session transport binding must not be all zero")]
    ZeroSessionTransportBinding,
    #[error("session transport binding does not match the encrypted connection")]
    SessionTransportBindingMismatch,
    #[error("peer enrollment public key has {actual} bytes, expected 32")]
    InvalidEnrollmentPublicKeyLength { actual: usize },
    #[error("peer enrollment listening port {0} is invalid")]
    InvalidEnrollmentListenPort(u32),
    #[error("peer enrollment proof does not match this workspace")]
    InvalidEnrollmentProof,
    #[error("{field} has {actual} bytes, expected 64")]
    InvalidSessionSignatureLength { field: &'static str, actual: usize },
    #[error("cannot establish a peer session with local device {device_id}")]
    SelfConnection { device_id: DeviceId },
    #[error("local session handshake does not match the supplied identity")]
    LocalIdentityMismatch,
    #[error("peer claimed {claimed}, but membership key identifies {authenticated}")]
    PeerIdentityMismatch {
        claimed: DeviceId,
        authenticated: DeviceId,
    },
    #[error("signed handshake acknowledgement does not match negotiated parameters")]
    HandshakeAcknowledgementMismatch,
    #[error("peer advertises {name}={value}, below the minimum {minimum}")]
    AdvertisedLimitTooSmall {
        name: &'static str,
        value: u64,
        minimum: u64,
    },
    #[error("control frame header has {actual} bytes, expected at least 4")]
    ControlFrameHeaderTooShort { actual: usize },
    #[error("control frame has {actual} payload bytes, maximum is {maximum}")]
    ControlFrameTooLarge { actual: usize, maximum: usize },
    #[error("control frame length mismatch: declared {declared}, actual {actual}")]
    ControlFrameLengthMismatch { declared: usize, actual: usize },
    #[error("control frame length cannot be represented")]
    FrameLengthOverflow,
    #[error("failed to encode control message")]
    Encode(#[from] prost::EncodeError),
    #[error("failed to decode control message")]
    Decode(#[from] prost::DecodeError),
    #[error("object request must contain at least one content ID")]
    EmptyObjectRequest,
    #[error("object request has {actual} content IDs, maximum is {maximum}")]
    TooManyContentIds { actual: usize, maximum: usize },
    #[error("{field}[{index}] has {actual} bytes, expected 32")]
    InvalidContentIdLength {
        field: &'static str,
        index: usize,
        actual: usize,
    },
    #[error("object request repeats content ID {0:?}")]
    DuplicateContentId(ContentId),
    #[error("object range offset {actual} must be below negotiated maximum {maximum}")]
    ObjectRangeOffsetTooLarge { actual: u64, maximum: u64 },
    #[error("encrypted object transfer has size {actual}, expected {minimum}..={maximum}")]
    InvalidObjectTransferSize {
        actual: u64,
        minimum: u64,
        maximum: u64,
    },
    #[error("encrypted object transfer starts at {start_offset}, size is {encrypted_size}")]
    InvalidObjectTransferRange {
        start_offset: u64,
        encrypted_size: u64,
    },
    #[error("object offer does not match its range request")]
    ObjectTransferRequestMismatch,
    #[error("object stream header does not match its accepted offer")]
    ObjectTransferMetadataMismatch,
    #[error("change batch has {actual} records, maximum is {maximum}")]
    TooManyChangeRecords { actual: usize, maximum: usize },
    #[error("change record {index} has non-increasing sequence {actual} after {previous}")]
    InvalidChangeSequence {
        index: usize,
        previous: u64,
        actual: u64,
    },
    #[error("encrypted object {index} has {actual} bytes, maximum is {maximum}")]
    EncryptedObjectTooLarge {
        index: usize,
        actual: u64,
        maximum: u64,
    },
    #[error("change record {index} contains an invalid encrypted object")]
    InvalidEncryptedObject {
        index: usize,
        #[source]
        source: EnvelopeError,
    },
    #[error("change record {index} contains {actual:?}, expected a manifest object")]
    UnexpectedChangeObjectKind { index: usize, actual: ObjectKind },
    #[error("change record {index} content ID does not match its encrypted object")]
    ChangeContentIdMismatch { index: usize },
    #[error("change record {index} signature has {actual} bytes, expected 64")]
    InvalidChangeSignatureLength { index: usize, actual: usize },
    #[error(
        "change batch high watermark {high_watermark} is below its last sequence {last_sequence}"
    )]
    InvalidHighWatermark {
        last_sequence: u64,
        high_watermark: u64,
    },
}

fn parse_uuid(field: &'static str, bytes: &[u8]) -> Result<Uuid, ProtocolError> {
    if bytes.len() != 16 {
        return Err(ProtocolError::InvalidIdentifierLength {
            field,
            actual: bytes.len(),
        });
    }
    let value = Uuid::from_slice(bytes)
        .map_err(|source| ProtocolError::InvalidIdentifier { field, source })?;
    if value.is_nil() {
        return Err(ProtocolError::NilIdentifier { field });
    }
    Ok(value)
}

fn parse_content_id(
    field: &'static str,
    index: usize,
    bytes: &[u8],
) -> Result<ContentId, ProtocolError> {
    let value = <[u8; 32]>::try_from(bytes).map_err(|_| ProtocolError::InvalidContentIdLength {
        field,
        index,
        actual: bytes.len(),
    })?;
    Ok(ContentId::from_bytes(value))
}

fn validate_usize_limit(
    name: &'static str,
    value: usize,
    minimum: usize,
    maximum: usize,
) -> Result<(), ProtocolError> {
    if !(minimum..=maximum).contains(&value) {
        return Err(ProtocolError::InvalidLimit {
            name,
            value: u64::try_from(value).unwrap_or(u64::MAX),
            minimum: u64::try_from(minimum).expect("protocol limits fit in u64"),
            maximum: u64::try_from(maximum).expect("protocol limits fit in u64"),
        });
    }
    Ok(())
}

fn validate_u64_limit(
    name: &'static str,
    value: u64,
    minimum: u64,
    maximum: u64,
) -> Result<(), ProtocolError> {
    if !(minimum..=maximum).contains(&value) {
        return Err(ProtocolError::InvalidLimit {
            name,
            value,
            minimum,
            maximum,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use orbit_core::RevisionId;
    use orbit_crypto::{DeviceIdentity, GroupKeys, GroupSecret};

    use super::*;

    fn device(value: u128) -> DeviceId {
        DeviceId::from_uuid(Uuid::from_u128(value))
    }

    fn group(value: u128) -> GroupId {
        GroupId::from_uuid(Uuid::from_u128(value))
    }

    fn keys(group_id: GroupId) -> GroupKeys {
        GroupSecret::from_bytes([53; 32])
            .derive_keys(group_id)
            .unwrap()
    }

    fn file_change() -> ChangeRecord {
        ChangeRecord::File(FileManifest {
            file_id: FileId::from_uuid(Uuid::from_u128(10)),
            revision_id: RevisionId::from_uuid(Uuid::from_u128(11)),
            relative_path: RelativePath::new("docs/report.txt").unwrap(),
            size: 5,
            modified_at_unix_ms: 1_700_000_000_123,
            version: VersionVector::from_entries([(device(2), 3), (device(1), 1)]).unwrap(),
            chunks: vec![
                ChunkRef {
                    content_id: ContentId::from_bytes([1; 32]),
                    plaintext_size: 3,
                },
                ChunkRef {
                    content_id: ContentId::from_bytes([2; 32]),
                    plaintext_size: 2,
                },
            ],
        })
    }

    #[test]
    fn compatible_peers_negotiate_the_same_limits() {
        let group_id = group(1);
        let first_limits = ProtocolLimits::default();
        let second_limits = ProtocolLimits::new(64 * 1024, 2 * 1024 * 1024, 64, 32).unwrap();
        let first = current_handshake(device(1), group_id, first_limits);
        let second = current_handshake(device(2), group_id, second_limits);

        let first_session = negotiate_handshake(&second, group_id, first_limits).unwrap();
        let second_session = negotiate_handshake(&first, group_id, second_limits).unwrap();

        assert_eq!(first_session.protocol_version(), PROTOCOL_VERSION);
        assert_eq!(
            first_session.maximum_control_frame_bytes(),
            second_session.maximum_control_frame_bytes()
        );
        assert_eq!(
            first_session.maximum_encrypted_object_bytes(),
            second_session.maximum_encrypted_object_bytes()
        );
        assert_eq!(first_session.capabilities(), second_session.capabilities());
    }

    #[test]
    fn authenticated_sessions_mutually_prove_membership_keys() {
        let group_id = group(1);
        let group_keys = keys(group_id);
        let initiator = DeviceIdentity::from_secret_bytes([1; 32]);
        let responder = DeviceIdentity::from_secret_bytes([2; 32]);
        let transport_binding =
            SessionTransportBinding::from_bytes([12; SESSION_TRANSPORT_BINDING_SIZE]).unwrap();
        let initiator_limits = ProtocolLimits::default();
        let responder_limits = ProtocolLimits::new(64 * 1024, 2 * 1024 * 1024, 64, 32).unwrap();
        let hello = build_session_hello(
            &initiator,
            &group_keys,
            initiator_limits,
            SessionNonce::from_bytes([3; SESSION_NONCE_SIZE]).unwrap(),
            transport_binding,
            48_177,
        );
        let enrollment = verify_peer_enrollment(&hello, &group_keys, transport_binding).unwrap();
        let (responder_session, challenge) = accept_session_hello(
            &hello,
            &responder,
            SessionNonce::from_bytes([4; SESSION_NONCE_SIZE]).unwrap(),
            transport_binding,
            group_id,
            responder_limits,
        )
        .unwrap();
        let (initiator_session, proof) = answer_session_challenge(
            &hello,
            &challenge,
            &initiator,
            responder.public_key(),
            transport_binding,
            group_id,
            initiator_limits,
        )
        .unwrap();
        let verified = verify_session_proof(
            &hello,
            &challenge,
            &proof,
            &responder,
            initiator.public_key(),
            transport_binding,
            group_id,
            responder_limits,
        )
        .unwrap();

        assert_eq!(initiator_session.remote_device_id(), responder.device_id());
        assert_eq!(enrollment.public_key, initiator.public_key());
        assert_eq!(enrollment.listen_port, Some(48_177));
        assert_eq!(responder_session.remote_device_id(), initiator.device_id());
        assert_eq!(verified, responder_session);
        assert_eq!(
            initiator_session.maximum_control_frame_bytes(),
            responder_session.maximum_control_frame_bytes()
        );
    }

    #[test]
    fn authenticated_sessions_reject_tampering_wrong_keys_and_replayed_proofs() {
        let group_id = group(1);
        let group_keys = keys(group_id);
        let initiator = DeviceIdentity::from_secret_bytes([5; 32]);
        let responder = DeviceIdentity::from_secret_bytes([6; 32]);
        let limits = ProtocolLimits::default();
        let transport_binding =
            SessionTransportBinding::from_bytes([13; SESSION_TRANSPORT_BINDING_SIZE]).unwrap();
        let hello = build_session_hello(
            &initiator,
            &group_keys,
            limits,
            SessionNonce::from_bytes([7; SESSION_NONCE_SIZE]).unwrap(),
            transport_binding,
            48_177,
        );
        let wrong_group_keys = GroupSecret::from_bytes([54; 32])
            .derive_keys(group_id)
            .unwrap();
        assert!(matches!(
            verify_peer_enrollment(&hello, &wrong_group_keys, transport_binding),
            Err(ProtocolError::InvalidEnrollmentProof)
        ));
        let (_, challenge) = accept_session_hello(
            &hello,
            &responder,
            SessionNonce::from_bytes([8; SESSION_NONCE_SIZE]).unwrap(),
            transport_binding,
            group_id,
            limits,
        )
        .unwrap();
        let (_, proof) = answer_session_challenge(
            &hello,
            &challenge,
            &initiator,
            responder.public_key(),
            transport_binding,
            group_id,
            limits,
        )
        .unwrap();

        let wrong_responder = DeviceIdentity::from_secret_bytes([9; 32]);
        assert!(matches!(
            answer_session_challenge(
                &hello,
                &challenge,
                &initiator,
                wrong_responder.public_key(),
                transport_binding,
                group_id,
                limits,
            ),
            Err(ProtocolError::PeerIdentityMismatch { .. })
        ));

        let mut downgraded = challenge.clone();
        downgraded
            .acknowledgement
            .as_mut()
            .unwrap()
            .maximum_object_bytes -= 1;
        assert!(matches!(
            answer_session_challenge(
                &hello,
                &downgraded,
                &initiator,
                responder.public_key(),
                transport_binding,
                group_id,
                limits,
            ),
            Err(ProtocolError::HandshakeAcknowledgementMismatch)
        ));

        let (_, second_challenge) = accept_session_hello(
            &hello,
            &responder,
            SessionNonce::from_bytes([10; SESSION_NONCE_SIZE]).unwrap(),
            transport_binding,
            group_id,
            limits,
        )
        .unwrap();
        assert!(matches!(
            verify_session_proof(
                &hello,
                &second_challenge,
                &proof,
                &responder,
                initiator.public_key(),
                transport_binding,
                group_id,
                limits,
            ),
            Err(ProtocolError::Identity(IdentityError::InvalidSignature))
        ));

        let mut invalid_hello = hello;
        invalid_hello.nonce.fill(0);
        assert!(matches!(
            accept_session_hello(
                &invalid_hello,
                &responder,
                SessionNonce::from_bytes([11; SESSION_NONCE_SIZE]).unwrap(),
                transport_binding,
                group_id,
                limits,
            ),
            Err(ProtocolError::ZeroSessionNonce)
        ));

        let different_binding =
            SessionTransportBinding::from_bytes([14; SESSION_TRANSPORT_BINDING_SIZE]).unwrap();
        assert!(matches!(
            answer_session_challenge(
                &invalid_hello,
                &challenge,
                &initiator,
                responder.public_key(),
                different_binding,
                group_id,
                limits,
            ),
            Err(ProtocolError::SessionTransportBindingMismatch)
        ));
    }

    #[test]
    fn incompatible_versions_and_groups_are_rejected() {
        let group_id = group(1);
        let mut handshake = current_handshake(device(1), group_id, ProtocolLimits::default());
        handshake.minimum_protocol_version = u32::from(PROTOCOL_VERSION) + 1;
        handshake.maximum_protocol_version = handshake.minimum_protocol_version;
        assert!(matches!(
            negotiate_handshake(&handshake, group_id, ProtocolLimits::default()),
            Err(ProtocolError::IncompatibleProtocolVersion { .. })
        ));

        let handshake = current_handshake(device(1), group(2), ProtocolLimits::default());
        assert!(matches!(
            negotiate_handshake(&handshake, group_id, ProtocolLimits::default()),
            Err(ProtocolError::GroupMismatch { .. })
        ));
    }

    #[test]
    fn missing_required_capability_is_rejected_but_unknown_values_are_ignored() {
        let group_id = group(1);
        let mut handshake = current_handshake(device(1), group_id, ProtocolLimits::default());
        handshake
            .capabilities
            .retain(|value| *value != Capability::Tombstones as i32);
        assert!(matches!(
            negotiate_handshake(&handshake, group_id, ProtocolLimits::default()),
            Err(ProtocolError::MissingRequiredCapability(
                Capability::Tombstones
            ))
        ));

        handshake.capabilities.push(Capability::Tombstones as i32);
        handshake.capabilities.push(999);
        negotiate_handshake(&handshake, group_id, ProtocolLimits::default()).unwrap();
    }

    #[test]
    fn control_frames_accept_unknown_protobuf_fields() {
        let handshake = current_handshake(device(1), group(1), ProtocolLimits::default());
        let mut payload = handshake.encode_to_vec();
        payload.extend_from_slice(&[0xa0, 0x06, 0x07]);
        let mut frame = Vec::new();
        frame.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
        frame.extend_from_slice(&payload);

        let decoded: wire::Handshake =
            decode_control_frame(&frame, ProtocolLimits::default()).unwrap();
        assert_eq!(decoded.device_id, handshake.device_id);
        assert_eq!(decoded.group_id, handshake.group_id);
        assert_eq!(decoded.capabilities, handshake.capabilities);
    }

    #[test]
    fn malformed_and_oversized_control_frames_are_rejected() {
        let limits = ProtocolLimits::new(1024, 1024, 4, 4).unwrap();
        let oversized = wire::Handshake {
            device_id: vec![0; 2048],
            ..Default::default()
        };
        assert!(matches!(
            encode_control_frame(&oversized, limits),
            Err(ProtocolError::ControlFrameTooLarge { .. })
        ));

        let truncated = [0, 0, 0, 5, 1, 2];
        assert!(matches!(
            decode_control_frame::<wire::Handshake>(&truncated, limits),
            Err(ProtocolError::ControlFrameLengthMismatch { .. })
        ));
    }

    #[test]
    fn object_requests_are_typed_bounded_and_deduplicated() {
        let limits = ProtocolLimits::new(1024, 1024, 2, 4).unwrap();
        let first = ContentId::from_bytes([1; 32]);
        let second = ContentId::from_bytes([2; 32]);
        let request_id = Uuid::from_u128(7);
        let request = build_object_request(request_id, [first, second], limits).unwrap();
        let validated = validate_object_request(&request, limits).unwrap();
        assert_eq!(validated.request_id(), request_id);
        assert_eq!(validated.content_ids(), &[first, second]);

        assert!(matches!(
            build_object_request(request_id, [first, first], limits),
            Err(ProtocolError::DuplicateContentId(value)) if value == first
        ));
        assert!(matches!(
            build_object_request(request_id, [first, second, first], limits),
            Err(ProtocolError::TooManyContentIds { .. })
        ));
    }

    #[test]
    fn object_ranges_are_bounded_and_correlated_across_control_and_streams() {
        let limits = ProtocolLimits::new(1024, 1024, 2, 4).unwrap();
        let content_id = ContentId::from_bytes([3; 32]);
        let request =
            build_object_range_request(Uuid::from_u128(8), content_id, 128, limits).unwrap();
        let request = validate_object_range_request(&request, limits).unwrap();
        let offer = build_object_offer(request, 800, limits).unwrap();
        let offer = validate_object_offer_for_request(&offer, request, limits).unwrap();
        let header = build_object_stream_header(offer);
        assert_eq!(
            validate_object_stream_header_for_offer(&header, offer, limits).unwrap(),
            offer
        );

        assert!(matches!(
            build_object_range_request(Uuid::from_u128(8), content_id, 1024, limits),
            Err(ProtocolError::ObjectRangeOffsetTooLarge { .. })
        ));
        assert!(matches!(
            build_object_offer(request, 128, limits),
            Err(ProtocolError::InvalidObjectTransferRange { .. })
        ));
        assert!(matches!(
            build_object_offer(request, 1025, limits),
            Err(ProtocolError::InvalidObjectTransferSize { .. })
        ));

        let mut mismatched_header = header;
        mismatched_header.start_offset += 1;
        assert!(matches!(
            validate_object_stream_header_for_offer(&mismatched_header, offer, limits),
            Err(ProtocolError::ObjectTransferMetadataMismatch)
        ));
    }

    #[test]
    fn encrypted_change_records_are_checked_before_acceptance() {
        let group_id = group(1);
        let keys = keys(group_id);
        let identity = DeviceIdentity::from_secret_bytes([71; 32]);
        let object = keys.seal_manifest(b"opaque manifest").unwrap();
        let content_id = object.content_id();
        let revision_id = RevisionId::new();
        let authorization = identity.authorize_change(group_id, revision_id, content_id);
        let record = wire::EncryptedChange {
            sequence: 1,
            revision_id: revision_id.as_uuid().as_bytes().to_vec(),
            content_id: content_id.as_bytes().to_vec(),
            encrypted_record: object.to_bytes().unwrap(),
            author_device_id: authorization.author_device_id.as_uuid().as_bytes().to_vec(),
            signature: authorization.signature.as_bytes().to_vec(),
        };
        let batch = wire::ChangeBatch {
            records: vec![record],
            high_watermark: 1,
            has_more: false,
        };
        let validated = validate_change_batch(&batch, ProtocolLimits::default()).unwrap();
        assert_eq!(
            validated.records,
            vec![ValidatedEncryptedChange {
                sequence: 1,
                revision_id,
                content_id,
                authorization,
                encrypted_record: batch.records[0].encrypted_record.clone(),
            }]
        );

        let mut mismatched = batch.clone();
        mismatched.records[0].content_id = [0x5a; 32].to_vec();
        assert!(matches!(
            validate_change_batch(&mismatched, ProtocolLimits::default()),
            Err(ProtocolError::ChangeContentIdMismatch { index: 0 })
        ));

        let mut missing_signature = batch.clone();
        missing_signature.records[0].signature.clear();
        assert!(matches!(
            validate_change_batch(&missing_signature, ProtocolLimits::default()),
            Err(ProtocolError::InvalidChangeSignatureLength {
                index: 0,
                actual: 0,
            })
        ));
    }

    #[test]
    fn canonical_change_records_round_trip() {
        let file = file_change();
        let encoded = encode_change_record(&file).unwrap();
        assert_eq!(decode_change_record(&encoded).unwrap(), file);

        let tombstone = ChangeRecord::Tombstone(Tombstone {
            file_id: FileId::from_uuid(Uuid::from_u128(10)),
            revision_id: RevisionId::from_uuid(Uuid::from_u128(12)),
            relative_path: RelativePath::new("docs/report.txt").unwrap(),
            deleted_at_unix_ms: 1_700_000_000_456,
            version: VersionVector::from_entries([(device(1), 2), (device(2), 3)]).unwrap(),
        });
        let encoded = encode_change_record(&tombstone).unwrap();
        assert_eq!(decode_change_record(&encoded).unwrap(), tombstone);
    }

    #[test]
    fn manifest_codec_rejects_invalid_and_noncanonical_records() {
        let file = file_change();
        let mut mismatched = match file.clone() {
            ChangeRecord::File(manifest) => manifest,
            ChangeRecord::Tombstone(_) => unreachable!(),
        };
        mismatched.size += 1;
        assert!(matches!(
            encode_change_record(&ChangeRecord::File(mismatched)),
            Err(ManifestError::FileSizeMismatch { .. })
        ));

        let encoded = encode_change_record(&file).unwrap();
        let mut envelope = wire::ManifestEnvelope::decode(encoded.as_slice()).unwrap();
        let wire::manifest_envelope::Record::File(wire_file) = envelope.record.as_mut().unwrap()
        else {
            unreachable!();
        };
        wire_file.version.reverse();
        assert!(matches!(
            decode_change_record(&envelope.encode_to_vec()),
            Err(ManifestError::VersionEntriesNotStrictlySorted { index: 1 })
        ));

        let mut with_unknown_field = encoded;
        with_unknown_field.extend_from_slice(&[0xa0, 0x06, 0x01]);
        assert!(matches!(
            decode_change_record(&with_unknown_field),
            Err(ManifestError::NonCanonical)
        ));
    }

    #[test]
    fn tombstone_manifest_has_stable_golden_bytes_and_content_id() {
        let record = ChangeRecord::Tombstone(Tombstone {
            file_id: FileId::from_uuid(Uuid::from_u128(1)),
            revision_id: RevisionId::from_uuid(Uuid::from_u128(2)),
            relative_path: RelativePath::new("a.txt").unwrap(),
            deleted_at_unix_ms: 3,
            version: VersionVector::from_entries([(device(4), 1)]).unwrap(),
        });
        let encoded = encode_change_record(&record).unwrap();
        let expected = [
            0x08, 0x01, 0x1a, 0x43, 0x0a, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x12, 0x10, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x1a, 0x05,
            b'a', b'.', b't', b'x', b't', 0x20, 0x06, 0x2a, 0x14, 0x0a, 0x10, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x10,
            0x01,
        ];

        assert_eq!(encoded, expected);
        assert_eq!(
            keys(group(1)).identify_manifest(&encoded),
            ContentId::from_bytes([
                42, 162, 202, 71, 186, 63, 69, 251, 88, 183, 63, 88, 250, 60, 155, 210, 234, 81,
                127, 194, 22, 105, 5, 197, 94, 216, 66, 129, 8, 224, 98, 215,
            ])
        );
    }
}
