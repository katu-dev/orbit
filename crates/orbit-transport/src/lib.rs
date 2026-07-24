#![forbid(unsafe_code)]

use std::{io, net::SocketAddr, sync::Arc};

use orbit_core::{ContentId, DeviceId, GroupId};
use orbit_crypto::{DeviceIdentity, DevicePublicKey, GroupKeys};
use orbit_engine::{
    ChangeBatchAdmissionError, ChangeBatchBuildError, admit_change_batch, build_change_batch,
};
use orbit_protocol::{
    NegotiatedSession, ProtocolError, ProtocolLimits, SESSION_TRANSPORT_BINDING_SIZE, SessionNonce,
    SessionTransportBinding, accept_session_hello, answer_session_challenge, build_object_offer,
    build_object_range_request, build_object_stream_header, build_session_hello,
    decode_control_frame, encode_control_frame, validate_object_offer,
    validate_object_offer_for_request, validate_object_range_request,
    validate_object_stream_header_for_offer, verify_peer_enrollment, verify_session_proof, wire,
};
use orbit_store::{
    Admission, MemberRole, MemberStatus, ObjectTransferAdmission, Store, StoreError,
};
use prost::Message;
use quinn::{Connection, Endpoint, RecvStream, SendStream};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
};
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

const TLS_SERVER_NAME: &str = "orbit.invalid";
const SESSION_EXPORTER_LABEL: &[u8] = b"EXPORTER-ORBIT-SESSION-v1";
const OBJECT_TRANSFER_BUFFER_SIZE: usize = 64 * 1024;

pub struct QuicEndpoint {
    endpoint: Endpoint,
}

impl QuicEndpoint {
    pub fn bind(address: SocketAddr) -> Result<Self, TransportError> {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec![TLS_SERVER_NAME.to_owned()])?;
        let certificate = cert.der().clone();
        let private_key = PrivatePkcs8KeyDer::from(key_pair.serialize_der());
        let server_config =
            quinn::ServerConfig::with_single_cert(vec![certificate], private_key.into())?;
        let mut endpoint = Endpoint::server(server_config, address)?;
        endpoint.set_default_client_config(insecure_client_config()?);
        Ok(Self { endpoint })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        Ok(self.endpoint.local_addr()?)
    }

    pub async fn connect(&self, address: SocketAddr) -> Result<Connection, TransportError> {
        Ok(self.endpoint.connect(address, TLS_SERVER_NAME)?.await?)
    }

    pub async fn accept(&self) -> Result<Connection, TransportError> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or(TransportError::EndpointClosed)?;
        Ok(incoming.await?)
    }

    pub fn close(&self) {
        self.endpoint.close(0_u32.into(), b"shutdown");
    }
}

pub struct AuthenticatedPeer {
    connection: Connection,
    send: SendStream,
    receive: RecvStream,
    session: NegotiatedSession,
    limits: ProtocolLimits,
    remote_public_key: DevicePublicKey,
    advertised_listen_port: Option<u16>,
}

impl AuthenticatedPeer {
    #[must_use]
    pub fn remote_device_id(&self) -> DeviceId {
        self.session.remote_device_id()
    }

    #[must_use]
    pub fn group_id(&self) -> GroupId {
        self.session.group_id()
    }

    #[must_use]
    pub const fn remote_public_key(&self) -> DevicePublicKey {
        self.remote_public_key
    }

    #[must_use]
    pub const fn advertised_listen_port(&self) -> Option<u16> {
        self.advertised_listen_port
    }

    #[must_use]
    pub const fn negotiated_session(&self) -> &NegotiatedSession {
        &self.session
    }

    #[must_use]
    pub const fn connection(&self) -> &Connection {
        &self.connection
    }

    pub async fn send_control<M: Message>(&mut self, message: &M) -> Result<(), TransportError> {
        write_control(&mut self.send, message, self.limits).await
    }

    pub async fn receive_control<M: Message + Default>(&mut self) -> Result<M, TransportError> {
        read_control(&mut self.receive, self.limits).await
    }

    pub async fn receive_optional_control<M: Message + Default>(
        &mut self,
    ) -> Result<Option<M>, TransportError> {
        read_optional_control(&mut self.receive, self.limits).await
    }

    pub fn finish_control(&mut self) -> Result<(), TransportError> {
        Ok(self.send.finish()?)
    }
}

pub async fn authenticate_outgoing(
    connection: Connection,
    identity: &DeviceIdentity,
    expected_peer_device_id: DeviceId,
    keys: &GroupKeys,
    store: &mut Store,
    limits: ProtocolLimits,
    local_listen_port: u16,
) -> Result<AuthenticatedPeer, TransportError> {
    require_local_identity(store, keys.group_id(), identity)?;
    let peer_public_key = require_active_member(store, keys.group_id(), expected_peer_device_id)?;
    let binding = connection_transport_binding(&connection)?;
    let (mut send, mut receive) = connection.open_bi().await?;
    let hello = build_session_hello(
        identity,
        keys,
        limits,
        SessionNonce::generate()?,
        binding,
        local_listen_port,
    );
    write_control(&mut send, &hello, limits).await?;
    let challenge: wire::SessionChallenge = read_control(&mut receive, limits).await?;
    let (session, proof) = answer_session_challenge(
        &hello,
        &challenge,
        identity,
        peer_public_key,
        binding,
        keys.group_id(),
        limits,
    )?;
    if session.remote_device_id() != expected_peer_device_id {
        return Err(TransportError::UnexpectedPeer {
            expected: expected_peer_device_id,
            actual: session.remote_device_id(),
        });
    }
    write_control(&mut send, &proof, limits).await?;
    let limits = negotiated_protocol_limits(limits, &session)?;
    Ok(AuthenticatedPeer {
        connection,
        send,
        receive,
        session,
        limits,
        remote_public_key: peer_public_key,
        advertised_listen_port: None,
    })
}

pub async fn authenticate_incoming(
    connection: Connection,
    identity: &DeviceIdentity,
    keys: &GroupKeys,
    store: &mut Store,
    limits: ProtocolLimits,
) -> Result<AuthenticatedPeer, TransportError> {
    require_local_identity(store, keys.group_id(), identity)?;
    let binding = connection_transport_binding(&connection)?;
    let (mut send, mut receive) = connection.accept_bi().await?;
    let hello: wire::SessionHello = read_control(&mut receive, limits).await?;
    let (pending_session, challenge) = accept_session_hello(
        &hello,
        identity,
        SessionNonce::generate()?,
        binding,
        keys.group_id(),
        limits,
    )?;
    let enrollment = verify_peer_enrollment(&hello, keys, binding)?;
    let peer_public_key = match store
        .group_member(keys.group_id(), pending_session.remote_device_id())?
    {
        Some(_) => {
            require_active_member(store, keys.group_id(), pending_session.remote_device_id())?
        }
        None => {
            store.add_group_member(keys.group_id(), enrollment.public_key, MemberRole::Member)?;
            enrollment.public_key
        }
    };
    write_control(&mut send, &challenge, limits).await?;
    let proof: wire::SessionProof = read_control(&mut receive, limits).await?;
    let session = verify_session_proof(
        &hello,
        &challenge,
        &proof,
        identity,
        peer_public_key,
        binding,
        keys.group_id(),
        limits,
    )?;
    let limits = negotiated_protocol_limits(limits, &session)?;
    Ok(AuthenticatedPeer {
        connection,
        send,
        receive,
        session,
        limits,
        remote_public_key: peer_public_key,
        advertised_listen_port: enrollment.listen_port,
    })
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PullReport {
    pub pages_received: usize,
    pub records_committed: usize,
    pub records_replayed: usize,
    pub objects_requested: usize,
    pub objects_stored: usize,
    pub objects_reused: usize,
    pub encrypted_bytes_received: u64,
    pub peer_high_watermark: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ServeReport {
    pub pages_sent: usize,
    pub objects_sent: usize,
    pub encrypted_bytes_sent: u64,
    pub acknowledgements_received: usize,
}

pub async fn pull_changes(
    mut peer: AuthenticatedPeer,
    keys: &GroupKeys,
    store: &mut Store,
    maximum_records_per_page: usize,
) -> Result<PullReport, TransportError> {
    validate_session_group(&peer, keys)?;
    validate_page_size(maximum_records_per_page, peer.limits)?;
    let peer_device_id = peer.remote_device_id();
    let group_id = keys.group_id();
    let mut after_sequence = store.peer_high_watermark(group_id, peer_device_id)?;
    let mut report = PullReport {
        peer_high_watermark: after_sequence,
        ..PullReport::default()
    };

    loop {
        let maximum_records = u32::try_from(maximum_records_per_page).map_err(|_| {
            TransportError::InvalidPageSize {
                actual: maximum_records_per_page,
                maximum: peer.limits.maximum_change_records_per_batch(),
            }
        })?;
        peer.send_control(&control_envelope(
            wire::control_envelope::Message::ChangeLogRequest(wire::ChangeLogRequest {
                after_sequence,
                maximum_records,
            }),
        ))
        .await?;

        let envelope: wire::ControlEnvelope = peer.receive_control().await?;
        let batch = match require_control_message(envelope)? {
            wire::control_envelope::Message::ChangeBatch(batch) => batch,
            message => {
                return Err(unexpected_control_message("change_batch", &message));
            }
        };
        report.pages_received += 1;

        let admission = admit_change_batch(peer_device_id, &batch, keys, store, peer.limits)?;
        report.records_committed += admission.records_committed;
        report.records_replayed += admission.records_replayed;
        let missing_content_ids = admission.missing_content_ids;
        let mut page_high_watermark = admission.peer_high_watermark;

        for content_id in missing_content_ids.iter().copied() {
            if store.has_object(group_id, content_id)? {
                report.objects_reused += 1;
                continue;
            }
            let object = pull_object(&mut peer, keys, store, content_id).await?;
            report.objects_requested += 1;
            report.encrypted_bytes_received += object.encrypted_bytes_received;
            match object.admission {
                Admission::Stored => report.objects_stored += 1,
                Admission::AlreadyPresent => report.objects_reused += 1,
            }
        }

        if !missing_content_ids.is_empty() {
            let retry = admit_change_batch(peer_device_id, &batch, keys, store, peer.limits)?;
            if !retry.missing_content_ids.is_empty() {
                return Err(TransportError::ObjectsStillMissing {
                    count: retry.missing_content_ids.len(),
                });
            }
            report.records_committed += retry.records_committed;
            page_high_watermark = retry.peer_high_watermark;
        }
        report.peer_high_watermark = page_high_watermark;

        if !batch.has_more {
            break;
        }
        if page_high_watermark <= after_sequence {
            return Err(TransportError::ChangePageMadeNoProgress {
                after_sequence,
                high_watermark: page_high_watermark,
            });
        }
        after_sequence = page_high_watermark;
    }

    peer.finish_control()?;
    if let Some(envelope) = peer
        .receive_optional_control::<wire::ControlEnvelope>()
        .await?
    {
        let message = require_control_message(envelope)?;
        return Err(unexpected_control_message(
            "control stream completion",
            &message,
        ));
    }
    Ok(report)
}

pub async fn serve_changes(
    mut peer: AuthenticatedPeer,
    keys: &GroupKeys,
    store: &mut Store,
) -> Result<ServeReport, TransportError> {
    validate_session_group(&peer, keys)?;
    let mut report = ServeReport::default();
    let mut pending_acknowledgement = None;

    while let Some(envelope) = peer
        .receive_optional_control::<wire::ControlEnvelope>()
        .await?
    {
        let message = require_control_message(envelope)?;
        if let Some((request_id, content_id)) = pending_acknowledgement {
            let acknowledgement = match message {
                wire::control_envelope::Message::ObjectAcknowledgement(acknowledgement) => {
                    acknowledgement
                }
                message => {
                    return Err(unexpected_control_message(
                        "object_acknowledgement",
                        &message,
                    ));
                }
            };
            validate_object_acknowledgement(&acknowledgement, request_id, content_id)?;
            pending_acknowledgement = None;
            report.acknowledgements_received += 1;
            continue;
        }

        match message {
            wire::control_envelope::Message::ChangeLogRequest(request) => {
                let maximum_records = usize::try_from(request.maximum_records).map_err(|_| {
                    TransportError::InvalidPageSize {
                        actual: usize::MAX,
                        maximum: peer.limits.maximum_change_records_per_batch(),
                    }
                })?;
                validate_page_size(maximum_records, peer.limits)?;
                let batch =
                    build_change_batch(keys, store, request.after_sequence, maximum_records)?;
                peer.send_control(&control_envelope(
                    wire::control_envelope::Message::ChangeBatch(batch),
                ))
                .await?;
                report.pages_sent += 1;
            }
            wire::control_envelope::Message::ObjectRangeRequest(request) => {
                let request = validate_object_range_request(&request, peer.limits)?;
                let range =
                    store.load_object_range(keys, request.content_id, request.start_offset)?;
                let offer = build_object_offer(request, range.encrypted_size, peer.limits)?;
                let transfer = validate_object_offer(&offer, peer.limits)?;
                peer.send_control(&control_envelope(
                    wire::control_envelope::Message::ObjectOffer(offer),
                ))
                .await?;
                send_object_stream(
                    peer.connection(),
                    transfer,
                    &range.encrypted_bytes,
                    peer.limits,
                )
                .await?;
                pending_acknowledgement = Some((request.request_id, request.content_id));
                report.objects_sent += 1;
                report.encrypted_bytes_sent +=
                    u64::try_from(range.encrypted_bytes.len()).unwrap_or(u64::MAX);
            }
            message => {
                return Err(unexpected_control_message(
                    "change_log_request or object_range_request",
                    &message,
                ));
            }
        }
    }

    if pending_acknowledgement.is_some() {
        return Err(TransportError::MissingObjectAcknowledgement);
    }
    peer.finish_control()?;
    if let Some(error_code) = peer.send.stopped().await? {
        return Err(TransportError::ControlStreamStopped { error_code });
    }
    Ok(report)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PulledObject {
    admission: Admission,
    encrypted_bytes_received: u64,
}

async fn pull_object(
    peer: &mut AuthenticatedPeer,
    keys: &GroupKeys,
    store: &mut Store,
    content_id: ContentId,
) -> Result<PulledObject, TransportError> {
    let group_id = keys.group_id();
    let peer_device_id = peer.remote_device_id();
    let existing = store.incoming_object_transfer(group_id, peer_device_id, content_id)?;
    if let Some(existing) = existing {
        if existing.received_size == existing.encrypted_size {
            return Ok(PulledObject {
                admission: store.complete_object_transfer(keys, peer_device_id, content_id)?,
                encrypted_bytes_received: 0,
            });
        }
    }
    let start_offset = existing.map_or(0, |transfer| transfer.received_size);
    let request_id = Uuid::new_v4();
    let request = build_object_range_request(request_id, content_id, start_offset, peer.limits)?;
    let validated_request = validate_object_range_request(&request, peer.limits)?;
    store.mark_object_request_attempt(group_id, peer_device_id, content_id)?;
    peer.send_control(&control_envelope(
        wire::control_envelope::Message::ObjectRangeRequest(request),
    ))
    .await?;

    let envelope: wire::ControlEnvelope = peer.receive_control().await?;
    let offer = match require_control_message(envelope)? {
        wire::control_envelope::Message::ObjectOffer(offer) => offer,
        message => return Err(unexpected_control_message("object_offer", &message)),
    };
    let transfer = validate_object_offer_for_request(&offer, validated_request, peer.limits)?;
    let transfer_admission = store.begin_object_transfer(
        group_id,
        peer_device_id,
        transfer.request_id,
        transfer.content_id,
        transfer.encrypted_size,
    )?;
    match transfer_admission {
        ObjectTransferAdmission::Started if transfer.start_offset != 0 => {
            return Err(TransportError::TransferResumeOffsetMismatch {
                requested: transfer.start_offset,
                durable: 0,
            });
        }
        ObjectTransferAdmission::Resuming { received_size }
            if received_size != transfer.start_offset =>
        {
            return Err(TransportError::TransferResumeOffsetMismatch {
                requested: transfer.start_offset,
                durable: received_size,
            });
        }
        _ => {}
    }

    let persist = transfer_admission != ObjectTransferAdmission::AlreadyPresent;
    let encrypted_bytes_received = receive_object_stream(peer, store, transfer, persist).await?;
    let (admission, status) = if persist {
        (
            store.complete_object_transfer(keys, peer_device_id, content_id)?,
            wire::object_acknowledgement::Status::Verified,
        )
    } else {
        (
            Admission::AlreadyPresent,
            wire::object_acknowledgement::Status::AlreadyPresent,
        )
    };
    peer.send_control(&control_envelope(
        wire::control_envelope::Message::ObjectAcknowledgement(wire::ObjectAcknowledgement {
            request_id: transfer.request_id.as_bytes().to_vec(),
            content_id: transfer.content_id.as_bytes().to_vec(),
            status: status as i32,
        }),
    ))
    .await?;
    Ok(PulledObject {
        admission,
        encrypted_bytes_received,
    })
}

async fn send_object_stream(
    connection: &Connection,
    transfer: orbit_protocol::ValidatedObjectTransfer,
    encrypted_bytes: &[u8],
    limits: ProtocolLimits,
) -> Result<(), TransportError> {
    let mut stream = connection.open_uni().await?;
    write_control(&mut stream, &build_object_stream_header(transfer), limits).await?;
    stream.write_all(encrypted_bytes).await?;
    stream.finish()?;
    Ok(())
}

async fn receive_object_stream(
    peer: &AuthenticatedPeer,
    store: &mut Store,
    offer: orbit_protocol::ValidatedObjectTransfer,
    persist: bool,
) -> Result<u64, TransportError> {
    let mut stream = peer.connection.accept_uni().await?;
    let header: wire::ObjectStreamHeader = read_control(&mut stream, peer.limits).await?;
    let transfer = validate_object_stream_header_for_offer(&header, offer, peer.limits)?;
    let mut offset = transfer.start_offset;
    let mut buffer = vec![0_u8; OBJECT_TRANSFER_BUFFER_SIZE];
    while offset < transfer.encrypted_size {
        let remaining = transfer.encrypted_size - offset;
        let maximum = usize::try_from(remaining)
            .unwrap_or(usize::MAX)
            .min(buffer.len());
        let Some(received) = stream.read(&mut buffer[..maximum]).await? else {
            return Err(TransportError::ObjectStreamFinishedEarly {
                expected: transfer.encrypted_size,
                actual: offset,
            });
        };
        if persist {
            store.append_object_transfer(
                peer.group_id(),
                peer.remote_device_id(),
                transfer.content_id,
                offset,
                &buffer[..received],
            )?;
        }
        offset += u64::try_from(received).expect("buffer length fits in u64");
    }
    let mut trailing = [0_u8; 1];
    if stream.read(&mut trailing).await?.is_some() {
        return Err(TransportError::ObjectStreamHasTrailingBytes);
    }
    Ok(offset - transfer.start_offset)
}

fn control_envelope(message: wire::control_envelope::Message) -> wire::ControlEnvelope {
    wire::ControlEnvelope {
        message: Some(message),
    }
}

fn require_control_message(
    envelope: wire::ControlEnvelope,
) -> Result<wire::control_envelope::Message, TransportError> {
    envelope
        .message
        .ok_or(TransportError::MissingControlMessage)
}

fn unexpected_control_message(
    expected: &'static str,
    actual: &wire::control_envelope::Message,
) -> TransportError {
    TransportError::UnexpectedControlMessage {
        expected,
        actual: control_message_name(actual),
    }
}

fn control_message_name(message: &wire::control_envelope::Message) -> &'static str {
    match message {
        wire::control_envelope::Message::ChangeLogRequest(_) => "change_log_request",
        wire::control_envelope::Message::ChangeBatch(_) => "change_batch",
        wire::control_envelope::Message::ObjectRangeRequest(_) => "object_range_request",
        wire::control_envelope::Message::ObjectOffer(_) => "object_offer",
        wire::control_envelope::Message::ObjectAcknowledgement(_) => "object_acknowledgement",
    }
}

fn validate_page_size(
    maximum_records: usize,
    limits: ProtocolLimits,
) -> Result<(), TransportError> {
    if maximum_records == 0 || maximum_records > limits.maximum_change_records_per_batch() {
        return Err(TransportError::InvalidPageSize {
            actual: maximum_records,
            maximum: limits.maximum_change_records_per_batch(),
        });
    }
    Ok(())
}

fn validate_session_group(
    peer: &AuthenticatedPeer,
    keys: &GroupKeys,
) -> Result<(), TransportError> {
    if peer.group_id() != keys.group_id() {
        return Err(TransportError::SessionGroupMismatch {
            session: peer.group_id(),
            keys: keys.group_id(),
        });
    }
    Ok(())
}

fn validate_object_acknowledgement(
    acknowledgement: &wire::ObjectAcknowledgement,
    request_id: Uuid,
    content_id: ContentId,
) -> Result<(), TransportError> {
    if acknowledgement.request_id.as_slice() != request_id.as_bytes()
        || acknowledgement.content_id.as_slice() != content_id.as_bytes()
    {
        return Err(TransportError::ObjectAcknowledgementMismatch);
    }
    let status =
        wire::object_acknowledgement::Status::try_from(acknowledgement.status).map_err(|_| {
            TransportError::InvalidObjectAcknowledgementStatus {
                actual: acknowledgement.status,
            }
        })?;
    if status == wire::object_acknowledgement::Status::Unspecified {
        return Err(TransportError::InvalidObjectAcknowledgementStatus {
            actual: acknowledgement.status,
        });
    }
    Ok(())
}

fn negotiated_protocol_limits(
    local: ProtocolLimits,
    session: &NegotiatedSession,
) -> Result<ProtocolLimits, ProtocolError> {
    ProtocolLimits::new(
        session.maximum_control_frame_bytes(),
        session.maximum_encrypted_object_bytes(),
        local.maximum_content_ids_per_request(),
        local.maximum_change_records_per_batch(),
    )
}

fn require_local_identity(
    store: &Store,
    group_id: GroupId,
    identity: &DeviceIdentity,
) -> Result<(), TransportError> {
    let public_key = require_active_member(store, group_id, identity.device_id())?;
    if public_key != identity.public_key() {
        return Err(StoreError::MemberKeyMismatch {
            device_id: identity.device_id(),
        }
        .into());
    }
    Ok(())
}

fn require_active_member(
    store: &Store,
    group_id: GroupId,
    device_id: DeviceId,
) -> Result<DevicePublicKey, TransportError> {
    let member = store
        .group_member(group_id, device_id)?
        .ok_or(StoreError::UnknownGroupMember { device_id })?;
    if member.status != MemberStatus::Active {
        return Err(StoreError::MemberRevoked { device_id }.into());
    }
    Ok(member.public_key)
}

fn connection_transport_binding(
    connection: &Connection,
) -> Result<SessionTransportBinding, TransportError> {
    let mut binding = [0_u8; SESSION_TRANSPORT_BINDING_SIZE];
    connection
        .export_keying_material(&mut binding, SESSION_EXPORTER_LABEL, b"")
        .map_err(|_| TransportError::KeyExporter)?;
    Ok(SessionTransportBinding::from_bytes(binding)?)
}

async fn write_control<M: Message>(
    send: &mut SendStream,
    message: &M,
    limits: ProtocolLimits,
) -> Result<(), TransportError> {
    let frame = encode_control_frame(message, limits)?;
    send.write_all(&frame).await?;
    send.flush().await?;
    Ok(())
}

async fn read_control<M: Message + Default>(
    receive: &mut RecvStream,
    limits: ProtocolLimits,
) -> Result<M, TransportError> {
    read_optional_control(receive, limits)
        .await?
        .ok_or(TransportError::ControlStreamFinished)
}

async fn read_optional_control<M: Message + Default>(
    receive: &mut RecvStream,
    limits: ProtocolLimits,
) -> Result<Option<M>, TransportError> {
    let mut header = [0_u8; 4];
    match receive.read_exact(&mut header).await {
        Ok(()) => {}
        Err(quinn::ReadExactError::FinishedEarly(0)) => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    let payload_length = usize::try_from(u32::from_be_bytes(header))
        .map_err(|_| ProtocolError::FrameLengthOverflow)?;
    if payload_length > limits.maximum_control_frame_bytes() {
        return Err(ProtocolError::ControlFrameTooLarge {
            actual: payload_length,
            maximum: limits.maximum_control_frame_bytes(),
        }
        .into());
    }
    let mut frame = Vec::with_capacity(4 + payload_length);
    frame.extend_from_slice(&header);
    frame.resize(4 + payload_length, 0);
    receive.read_exact(&mut frame[4..]).await?;
    Ok(Some(decode_control_frame(&frame, limits)?))
}

fn insecure_client_config() -> Result<quinn::ClientConfig, TransportError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let crypto = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .map_err(|error| TransportError::Configuration(error.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCertificate(provider)))
        .with_no_client_auth();
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
        .map_err(|error| TransportError::Configuration(error.to_string()))?;
    Ok(quinn::ClientConfig::new(Arc::new(crypto)))
}

#[derive(Debug)]
struct AcceptAnyServerCertificate(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for AcceptAnyServerCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            certificate,
            signature,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            certificate,
            signature,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("QUIC endpoint I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("TLS certificate generation failed: {0}")]
    Certificate(#[from] rcgen::Error),
    #[error("TLS configuration failed: {0}")]
    Tls(#[from] rustls::Error),
    #[error("QUIC configuration failed: {0}")]
    Configuration(String),
    #[error("QUIC connection setup failed: {0}")]
    Connect(#[from] quinn::ConnectError),
    #[error("QUIC connection failed: {0}")]
    Connection(#[from] quinn::ConnectionError),
    #[error("QUIC stream write failed: {0}")]
    Write(#[from] quinn::WriteError),
    #[error("QUIC stream read failed: {0}")]
    Read(#[from] quinn::ReadExactError),
    #[error("QUIC object stream read failed: {0}")]
    StreamRead(#[from] quinn::ReadError),
    #[error("QUIC stream is already closed")]
    ClosedStream(#[from] quinn::ClosedStream),
    #[error("waiting for QUIC stream completion failed: {0}")]
    Stopped(#[from] quinn::StoppedError),
    #[error("Orbit protocol failed: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("Orbit store failed: {0}")]
    Store(#[from] StoreError),
    #[error("failed to build a signed change batch: {0}")]
    ChangeBatchBuild(#[from] ChangeBatchBuildError),
    #[error("failed to admit a signed change batch: {0}")]
    ChangeBatchAdmission(#[from] ChangeBatchAdmissionError),
    #[error("TLS exporter failed")]
    KeyExporter,
    #[error("authenticated peer is {actual}, expected {expected}")]
    UnexpectedPeer {
        expected: DeviceId,
        actual: DeviceId,
    },
    #[error("control stream finished before the expected message")]
    ControlStreamFinished,
    #[error("peer stopped the control stream with error {error_code}")]
    ControlStreamStopped { error_code: quinn::VarInt },
    #[error("control envelope has no message")]
    MissingControlMessage,
    #[error("expected {expected} control message, received {actual}")]
    UnexpectedControlMessage {
        expected: &'static str,
        actual: &'static str,
    },
    #[error("change page size {actual} is outside 1..={maximum}")]
    InvalidPageSize { actual: usize, maximum: usize },
    #[error("change page made no progress after {after_sequence} (watermark {high_watermark})")]
    ChangePageMadeNoProgress {
        after_sequence: u64,
        high_watermark: u64,
    },
    #[error("{count} objects are still missing after transfer")]
    ObjectsStillMissing { count: usize },
    #[error("object transfer requested offset {requested}, durable offset is {durable}")]
    TransferResumeOffsetMismatch { requested: u64, durable: u64 },
    #[error("object stream finished at {actual} bytes, expected {expected}")]
    ObjectStreamFinishedEarly { expected: u64, actual: u64 },
    #[error("object stream contains bytes after its declared encrypted size")]
    ObjectStreamHasTrailingBytes,
    #[error("object acknowledgement does not match the preceding offer")]
    ObjectAcknowledgementMismatch,
    #[error("object acknowledgement has invalid status {actual}")]
    InvalidObjectAcknowledgementStatus { actual: i32 },
    #[error("control stream finished before the pending object acknowledgement")]
    MissingObjectAcknowledgement,
    #[error("session group {session} does not match key group {keys}")]
    SessionGroupMismatch { session: GroupId, keys: GroupId },
    #[error("QUIC endpoint is closed")]
    EndpointClosed,
}

#[cfg(test)]
mod tests {
    use std::{fs, time::Duration};

    use orbit_core::GroupId;
    use orbit_crypto::GroupSecret;
    use orbit_engine::FullScanner;
    use orbit_store::MemberRole;

    use super::*;

    fn group(value: u128) -> GroupId {
        format!("{value:032x}").parse().unwrap()
    }

    fn keys() -> GroupKeys {
        GroupSecret::from_bytes([81; 32])
            .derive_keys(group(1))
            .unwrap()
    }

    fn register_pair(store: &mut Store, keys: &GroupKeys, identities: [&DeviceIdentity; 2]) {
        for identity in identities {
            store
                .add_group_member(keys.group_id(), identity.public_key(), MemberRole::Member)
                .unwrap();
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn loopback_quic_enrolls_workspace_member_before_control_exchange() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let temporary_directory = tempfile::tempdir().unwrap();
            let keys = keys();
            let initiator = DeviceIdentity::from_secret_bytes([1; 32]);
            let responder = DeviceIdentity::from_secret_bytes([2; 32]);
            let mut initiator_store =
                Store::open(temporary_directory.path().join("initiator")).unwrap();
            let mut responder_store =
                Store::open(temporary_directory.path().join("responder")).unwrap();
            register_pair(&mut initiator_store, &keys, [&initiator, &responder]);
            responder_store
                .add_group_member(keys.group_id(), responder.public_key(), MemberRole::Owner)
                .unwrap();

            let initiator_endpoint = QuicEndpoint::bind("127.0.0.1:0".parse().unwrap()).unwrap();
            let responder_endpoint = QuicEndpoint::bind("127.0.0.1:0".parse().unwrap()).unwrap();
            let responder_address = responder_endpoint.local_addr().unwrap();
            let limits = ProtocolLimits::default();

            let incoming = async {
                let connection = responder_endpoint.accept().await.unwrap();
                authenticate_incoming(connection, &responder, &keys, &mut responder_store, limits)
                    .await
                    .unwrap()
            };
            let outgoing = async {
                let connection = initiator_endpoint.connect(responder_address).await.unwrap();
                authenticate_outgoing(
                    connection,
                    &initiator,
                    responder.device_id(),
                    &keys,
                    &mut initiator_store,
                    limits,
                    48_177,
                )
                .await
                .unwrap()
            };
            let (mut incoming, mut outgoing) = tokio::join!(incoming, outgoing);

            assert_eq!(incoming.remote_device_id(), initiator.device_id());
            assert_eq!(incoming.advertised_listen_port(), Some(48_177));
            assert_eq!(outgoing.remote_device_id(), responder.device_id());
            assert_eq!(
                responder_store
                    .group_member(keys.group_id(), initiator.device_id())
                    .unwrap()
                    .unwrap()
                    .status,
                MemberStatus::Active
            );
            let request = wire::ControlEnvelope {
                message: Some(wire::control_envelope::Message::ChangeLogRequest(
                    wire::ChangeLogRequest {
                        after_sequence: 7,
                        maximum_records: 32,
                    },
                )),
            };
            outgoing.send_control(&request).await.unwrap();
            let received: wire::ControlEnvelope = incoming.receive_control().await.unwrap();
            assert_eq!(received, request);

            initiator_endpoint.close();
            responder_endpoint.close();
        })
        .await
        .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn loopback_pull_admits_objects_and_reconnects_without_duplicate_changes() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let temporary_directory = tempfile::tempdir().unwrap();
            let source_root = temporary_directory.path().join("source-sync");
            fs::create_dir_all(&source_root).unwrap();
            fs::write(
                source_root.join("payload.bin"),
                (0..256 * 1024)
                    .map(|index| ((index * 31) % 251) as u8)
                    .collect::<Vec<_>>(),
            )
            .unwrap();
            let keys = keys();
            let receiver = DeviceIdentity::from_secret_bytes([11; 32]);
            let source = DeviceIdentity::from_secret_bytes([12; 32]);
            let mut receiver_store =
                Store::open(temporary_directory.path().join("receiver-store")).unwrap();
            let mut source_store =
                Store::open(temporary_directory.path().join("source-store")).unwrap();
            register_pair(&mut receiver_store, &keys, [&receiver, &source]);
            register_pair(&mut source_store, &keys, [&receiver, &source]);
            let scan = FullScanner::default()
                .scan(&source_root, &source, &keys, &mut source_store)
                .unwrap();
            assert_eq!(scan.file_changes, 1);
            assert!(scan.chunks_stored > 0);
            let source_high_watermark = source_store
                .changes_after(keys.group_id(), 0, 10)
                .unwrap()
                .high_watermark;

            let receiver_endpoint = QuicEndpoint::bind("127.0.0.1:0".parse().unwrap()).unwrap();
            let source_endpoint = QuicEndpoint::bind("127.0.0.1:0".parse().unwrap()).unwrap();
            let source_address = source_endpoint.local_addr().unwrap();
            let limits = ProtocolLimits::default();

            let serve = async {
                let connection = source_endpoint.accept().await.unwrap();
                let peer =
                    authenticate_incoming(connection, &source, &keys, &mut source_store, limits)
                        .await
                        .unwrap();
                serve_changes(peer, &keys, &mut source_store).await.unwrap()
            };
            let pull = async {
                let connection = receiver_endpoint.connect(source_address).await.unwrap();
                let peer = authenticate_outgoing(
                    connection,
                    &receiver,
                    source.device_id(),
                    &keys,
                    &mut receiver_store,
                    limits,
                    48_177,
                )
                .await
                .unwrap();
                pull_changes(peer, &keys, &mut receiver_store, 1)
                    .await
                    .unwrap()
            };
            let (served, pulled) = tokio::join!(serve, pull);

            assert_eq!(served.pages_sent, 1);
            assert!(served.objects_sent > 0);
            assert_eq!(served.objects_sent, served.acknowledgements_received);
            assert_eq!(pulled.pages_received, 1);
            assert_eq!(pulled.records_committed, 1);
            assert!(pulled.objects_stored > 0);
            assert_eq!(pulled.peer_high_watermark, source_high_watermark);
            assert_eq!(
                receiver_store
                    .changes_after(keys.group_id(), 0, 10)
                    .unwrap()
                    .records
                    .len(),
                1
            );

            let serve = async {
                let connection = source_endpoint.accept().await.unwrap();
                let peer =
                    authenticate_incoming(connection, &source, &keys, &mut source_store, limits)
                        .await
                        .unwrap();
                serve_changes(peer, &keys, &mut source_store).await.unwrap()
            };
            let pull = async {
                let connection = receiver_endpoint.connect(source_address).await.unwrap();
                let peer = authenticate_outgoing(
                    connection,
                    &receiver,
                    source.device_id(),
                    &keys,
                    &mut receiver_store,
                    limits,
                    48_177,
                )
                .await
                .unwrap();
                pull_changes(peer, &keys, &mut receiver_store, 1)
                    .await
                    .unwrap()
            };
            let (served_again, pulled_again) = tokio::join!(serve, pull);

            assert_eq!(served_again.objects_sent, 0);
            assert_eq!(pulled_again.objects_requested, 0);
            assert_eq!(pulled_again.records_committed, 0);
            assert_eq!(pulled_again.records_replayed, 0);
            assert_eq!(pulled_again.peer_high_watermark, source_high_watermark);
            assert_eq!(
                receiver_store
                    .changes_after(keys.group_id(), 0, 10)
                    .unwrap()
                    .records
                    .len(),
                1
            );

            receiver_endpoint.close();
            source_endpoint.close();
        })
        .await
        .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn interrupted_object_stream_resumes_from_exact_durable_offset() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let temporary_directory = tempfile::tempdir().unwrap();
            let source_root = temporary_directory.path().join("source-sync");
            fs::create_dir_all(&source_root).unwrap();
            fs::write(source_root.join("payload.bin"), b"resumable peer payload").unwrap();
            let keys = keys();
            let receiver = DeviceIdentity::from_secret_bytes([21; 32]);
            let source = DeviceIdentity::from_secret_bytes([22; 32]);
            let mut receiver_store =
                Store::open(temporary_directory.path().join("receiver-store")).unwrap();
            let mut source_store =
                Store::open(temporary_directory.path().join("source-store")).unwrap();
            register_pair(&mut receiver_store, &keys, [&receiver, &source]);
            register_pair(&mut source_store, &keys, [&receiver, &source]);
            FullScanner::default()
                .scan(&source_root, &source, &keys, &mut source_store)
                .unwrap();
            let source_high_watermark = source_store
                .changes_after(keys.group_id(), 0, 10)
                .unwrap()
                .high_watermark;

            let receiver_endpoint = QuicEndpoint::bind("127.0.0.1:0".parse().unwrap()).unwrap();
            let source_endpoint = QuicEndpoint::bind("127.0.0.1:0".parse().unwrap()).unwrap();
            let source_address = source_endpoint.local_addr().unwrap();
            let limits = ProtocolLimits::default();

            let interrupt = async {
                let connection = source_endpoint.accept().await.unwrap();
                let mut peer =
                    authenticate_incoming(connection, &source, &keys, &mut source_store, limits)
                        .await
                        .unwrap();
                let envelope: wire::ControlEnvelope = peer.receive_control().await.unwrap();
                let request = match require_control_message(envelope).unwrap() {
                    wire::control_envelope::Message::ChangeLogRequest(request) => request,
                    message => panic!("unexpected {}", control_message_name(&message)),
                };
                let batch = build_change_batch(
                    &keys,
                    &mut source_store,
                    request.after_sequence,
                    request.maximum_records as usize,
                )
                .unwrap();
                peer.send_control(&control_envelope(
                    wire::control_envelope::Message::ChangeBatch(batch),
                ))
                .await
                .unwrap();

                let envelope: wire::ControlEnvelope = peer.receive_control().await.unwrap();
                let request = match require_control_message(envelope).unwrap() {
                    wire::control_envelope::Message::ObjectRangeRequest(request) => {
                        validate_object_range_request(&request, peer.limits).unwrap()
                    }
                    message => panic!("unexpected {}", control_message_name(&message)),
                };
                assert_eq!(request.start_offset, 0);
                let range = source_store
                    .load_object_range(&keys, request.content_id, request.start_offset)
                    .unwrap();
                let offer = build_object_offer(request, range.encrypted_size, peer.limits).unwrap();
                let transfer = validate_object_offer(&offer, peer.limits).unwrap();
                peer.send_control(&control_envelope(
                    wire::control_envelope::Message::ObjectOffer(offer),
                ))
                .await
                .unwrap();
                let split = range.encrypted_bytes.len() / 2;
                assert!(split > 0);
                let mut stream = peer.connection.open_uni().await.unwrap();
                write_control(
                    &mut stream,
                    &build_object_stream_header(transfer),
                    peer.limits,
                )
                .await
                .unwrap();
                stream
                    .write_all(&range.encrypted_bytes[..split])
                    .await
                    .unwrap();
                stream.finish().unwrap();
                assert_eq!(stream.stopped().await.unwrap(), None);
                (request.content_id, range.encrypted_size, split as u64)
            };
            let pull = async {
                let connection = receiver_endpoint.connect(source_address).await.unwrap();
                let peer = authenticate_outgoing(
                    connection,
                    &receiver,
                    source.device_id(),
                    &keys,
                    &mut receiver_store,
                    limits,
                    48_177,
                )
                .await
                .unwrap();
                pull_changes(peer, &keys, &mut receiver_store, 10).await
            };
            let ((content_id, encrypted_size, split), interrupted) = tokio::join!(interrupt, pull);

            assert!(matches!(
                interrupted,
                Err(TransportError::ObjectStreamFinishedEarly {
                    expected,
                    actual,
                }) if expected == encrypted_size && actual == split
            ));
            let durable = receiver_store
                .incoming_object_transfer(keys.group_id(), source.device_id(), content_id)
                .unwrap()
                .unwrap();
            assert_eq!(durable.encrypted_size, encrypted_size);
            assert_eq!(durable.received_size, split);
            assert_eq!(
                receiver_store
                    .peer_high_watermark(keys.group_id(), source.device_id())
                    .unwrap(),
                0
            );

            let serve = async {
                let connection = source_endpoint.accept().await.unwrap();
                let peer =
                    authenticate_incoming(connection, &source, &keys, &mut source_store, limits)
                        .await
                        .unwrap();
                serve_changes(peer, &keys, &mut source_store).await.unwrap()
            };
            let resume = async {
                let connection = receiver_endpoint.connect(source_address).await.unwrap();
                let peer = authenticate_outgoing(
                    connection,
                    &receiver,
                    source.device_id(),
                    &keys,
                    &mut receiver_store,
                    limits,
                    48_177,
                )
                .await
                .unwrap();
                pull_changes(peer, &keys, &mut receiver_store, 10)
                    .await
                    .unwrap()
            };
            let (served, resumed) = tokio::join!(serve, resume);

            assert_eq!(served.objects_sent, 1);
            assert_eq!(served.encrypted_bytes_sent, encrypted_size - split);
            assert_eq!(resumed.encrypted_bytes_received, encrypted_size - split);
            assert_eq!(resumed.records_committed, 1);
            assert_eq!(resumed.peer_high_watermark, source_high_watermark);
            assert!(
                receiver_store
                    .incoming_object_transfer(keys.group_id(), source.device_id(), content_id)
                    .unwrap()
                    .is_none()
            );
            assert_eq!(
                receiver_store
                    .changes_after(keys.group_id(), 0, 10)
                    .unwrap()
                    .records
                    .len(),
                1
            );

            receiver_endpoint.close();
            source_endpoint.close();
        })
        .await
        .unwrap();
    }
}
