use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use orbit_core::GroupId;
use orbit_daemon::{
    CycleReport, DaemonConfig, InitializationOptions, PeerConfig, Runtime, RuntimeStatus,
    initialize, run_cycle, run_daemon_until,
};
use orbit_store::Store;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, State};
use tokio::{sync::oneshot, task::JoinHandle};

const INVITE_PREFIX: &str = "orbit1_";
const GROUP_SECRET_SIZE: usize = 32;

pub struct ClientState {
    config_path: PathBuf,
    default_sync_root: PathBuf,
    service: tokio::sync::Mutex<Option<ServiceTask>>,
}

impl ClientState {
    pub fn new(config_path: PathBuf, default_sync_root: PathBuf) -> Self {
        Self {
            config_path,
            default_sync_root,
            service: tokio::sync::Mutex::new(None),
        }
    }
}

struct ServiceTask {
    shutdown: Option<oneshot::Sender<()>>,
    join: JoinHandle<Result<(), orbit_daemon::DaemonError>>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BootstrapResponse {
    initialized: bool,
    platform: &'static str,
    mobile: bool,
    default_sync_root: String,
    snapshot: Option<ClientSnapshot>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientSnapshot {
    device_id: String,
    group_id: String,
    public_key: String,
    sync_root: String,
    store_root: String,
    listen_address: String,
    scan_interval_seconds: u64,
    sync_interval_seconds: u64,
    maximum_records_per_page: usize,
    local_change_count: u64,
    service_running: bool,
    peers: Vec<ClientPeer>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientPeer {
    device_id: String,
    public_key: String,
    address: String,
    high_watermark: u64,
    pending_objects: usize,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializeRequest {
    sync_root: Option<String>,
    listen_address: String,
    invite_code: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerRequest {
    address: String,
    public_key: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsRequest {
    listen_address: String,
    scan_interval_seconds: u64,
    sync_interval_seconds: u64,
    maximum_records_per_page: usize,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncResult {
    local_changes: usize,
    files_discovered: usize,
    peers_synchronized: usize,
    peers_failed: usize,
    peer_errors: Vec<String>,
    records_committed: usize,
    objects_stored: usize,
    encrypted_bytes_received: u64,
    remote_records_applied: usize,
    conflicts_kept_both: usize,
    completed_at_unix_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct InvitePayload {
    version: u8,
    group_id: String,
    group_secret: String,
    peer_address: String,
    peer_public_key: String,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ServiceEvent {
    running: bool,
}

#[tauri::command]
pub async fn bootstrap(state: State<'_, ClientState>) -> Result<BootstrapResponse, String> {
    let initialized = state.config_path.is_file();
    let snapshot = if initialized {
        Some(snapshot_for(&state).await?)
    } else {
        None
    };
    Ok(BootstrapResponse {
        initialized,
        platform: platform_name(),
        mobile: is_mobile(),
        default_sync_root: display_path(&state.default_sync_root),
        snapshot,
    })
}

#[tauri::command]
pub async fn load_snapshot(state: State<'_, ClientState>) -> Result<ClientSnapshot, String> {
    snapshot_for(&state).await
}

#[tauri::command]
pub async fn initialize_node(
    request: InitializeRequest,
    state: State<'_, ClientState>,
) -> Result<ClientSnapshot, String> {
    if state.config_path.exists() {
        return Err("This device is already initialized.".to_owned());
    }
    let listen_address: SocketAddr = request
        .listen_address
        .parse()
        .map_err(|error| format!("Invalid listen address: {error}"))?;
    let sync_root = request
        .sync_root
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| state.default_sync_root.clone());
    let config_directory = state
        .config_path
        .parent()
        .ok_or_else(|| "Configuration path has no parent directory.".to_owned())?;
    fs::create_dir_all(config_directory).map_err(command_error)?;

    let mut imported_group_secret = None;
    let mut inviter = None;
    let (group_id, group_secret_file) = if let Some(code) = request.invite_code {
        let invite = decode_invite(&code)?;
        let group_id = invite
            .group_id
            .parse()
            .map_err(|error| format!("Invitation group ID is invalid: {error}"))?;
        validate_public_key(&invite.peer_public_key)?;
        let address: SocketAddr = invite
            .peer_address
            .parse()
            .map_err(|error| format!("Invitation peer address is invalid: {error}"))?;
        let secret = decode_group_secret(&invite.group_secret)?;
        let secret_path = config_directory.join("orbit.group.key");
        write_secret_file(&secret_path, &secret)?;
        imported_group_secret = Some(secret_path.clone());
        inviter = Some(PeerConfig {
            address,
            public_key: invite.peer_public_key,
            synchronize: true,
        });
        (Some(group_id), Some(secret_path))
    } else {
        (None, None)
    };

    let initialized = initialize(&InitializationOptions {
        config_path: state.config_path.clone(),
        sync_root,
        store_root: config_directory.join("state"),
        listen_address,
        group_id,
        group_secret_file,
    });
    if let Err(error) = initialized {
        if let Some(path) = imported_group_secret {
            let _ = fs::remove_file(path);
        }
        return Err(error.to_string());
    }
    if let Some(peer) = inviter {
        update_config(&state.config_path, |config| config.peers.push(peer))?;
    }
    snapshot_for(&state).await
}

#[tauri::command]
pub async fn start_service(
    app: AppHandle,
    state: State<'_, ClientState>,
) -> Result<ClientSnapshot, String> {
    start_service_internal(&app, &state).await?;
    snapshot_for(&state).await
}

#[tauri::command]
pub async fn stop_service(
    app: AppHandle,
    state: State<'_, ClientState>,
) -> Result<ClientSnapshot, String> {
    stop_service_internal(&app, &state).await?;
    snapshot_for(&state).await
}

#[tauri::command]
pub async fn sync_now(app: AppHandle, state: State<'_, ClientState>) -> Result<SyncResult, String> {
    let restart = stop_service_internal(&app, &state).await?;
    let runtime = Arc::new(Runtime::load(&state.config_path).map_err(command_error)?);
    let cycle = run_cycle(runtime).await.map_err(command_error);
    let restart_result = if restart {
        start_service_internal(&app, &state).await
    } else {
        Ok(false)
    };
    restart_result?;
    cycle.map(sync_result)
}

#[tauri::command]
pub async fn add_peer(
    app: AppHandle,
    request: PeerRequest,
    state: State<'_, ClientState>,
) -> Result<ClientSnapshot, String> {
    let address: SocketAddr = request
        .address
        .parse()
        .map_err(|error| format!("Invalid peer address: {error}"))?;
    validate_public_key(&request.public_key)?;
    add_peer_config(
        &app,
        PeerConfig {
            address,
            public_key: request.public_key,
            synchronize: true,
        },
        &state,
    )
    .await
}

#[tauri::command]
pub async fn add_peer_from_invite(
    app: AppHandle,
    invite_code: String,
    state: State<'_, ClientState>,
) -> Result<ClientSnapshot, String> {
    let runtime = Runtime::load(&state.config_path).map_err(command_error)?;
    let status = runtime.status().map_err(command_error)?;
    let group_secret = fs::read(&runtime.config().group_secret_file).map_err(command_error)?;
    let peer = invite_peer_config(
        decode_invite(&invite_code)?,
        &status.group_id.to_string(),
        &group_secret,
    )?;
    add_peer_config(&app, peer, &state).await
}

#[tauri::command]
pub async fn switch_workspace_from_invite(
    app: AppHandle,
    invite_code: String,
    state: State<'_, ClientState>,
) -> Result<ClientSnapshot, String> {
    let runtime = Runtime::load(&state.config_path).map_err(command_error)?;
    let current_group_id = runtime.group_id();
    let (group_id, group_secret, peer) = invite_workspace(decode_invite(&invite_code)?)?;
    if group_id == current_group_id {
        return Err("This device already belongs to the invitation workspace.".to_owned());
    }

    let config_directory = state
        .config_path
        .parent()
        .ok_or_else(|| "Configuration path has no parent directory.".to_owned())?;
    let secret_name = format!("orbit.group.{group_id}.key");
    let secret_path = config_directory.join(&secret_name);
    let original_config = fs::read(&state.config_path).map_err(command_error)?;
    let restart = stop_service_internal(&app, &state).await?;
    let secret_created = match ensure_secret_file(&secret_path, &group_secret) {
        Ok(created) => created,
        Err(error) => {
            if restart {
                start_service_internal(&app, &state).await?;
            }
            return Err(error);
        }
    };
    let update = update_config(&state.config_path, |config| {
        config.group_id = group_id;
        config.group_secret_file = PathBuf::from(secret_name);
        config.peers = vec![peer];
    });
    if let Err(error) = update {
        if secret_created {
            let _ = fs::remove_file(secret_path);
        }
        if restart {
            start_service_internal(&app, &state).await?;
        }
        return Err(error);
    }
    if restart {
        if let Err(error) = start_service_internal(&app, &state).await {
            fs::write(&state.config_path, original_config).map_err(command_error)?;
            if secret_created {
                let _ = fs::remove_file(secret_path);
            }
            start_service_internal(&app, &state).await.map_err(|rollback| {
                format!(
                    "Could not start the invited workspace: {error}. The previous workspace was restored but its service could not restart: {rollback}"
                )
            })?;
            return Err(format!(
                "Could not start the invited workspace: {error}. The previous workspace was restored."
            ));
        }
    }
    snapshot_for(&state).await
}

async fn add_peer_config(
    app: &AppHandle,
    peer: PeerConfig,
    state: &ClientState,
) -> Result<ClientSnapshot, String> {
    let restart = stop_service_internal(app, state).await?;
    let update = update_config(&state.config_path, |config| {
        if let Some(existing) = config
            .peers
            .iter_mut()
            .find(|existing| existing.public_key.eq_ignore_ascii_case(&peer.public_key))
        {
            *existing = peer;
        } else {
            config.peers.push(peer);
        }
    });
    let restart_result = if restart {
        start_service_internal(app, state).await
    } else {
        Ok(false)
    };
    update?;
    restart_result?;
    snapshot_for(state).await
}

#[tauri::command]
pub async fn revoke_peer(
    app: AppHandle,
    device_id: String,
    state: State<'_, ClientState>,
) -> Result<ClientSnapshot, String> {
    let restart = stop_service_internal(&app, &state).await?;
    let update = (|| {
        let runtime = Runtime::load(&state.config_path).map_err(command_error)?;
        let status = runtime.status().map_err(command_error)?;
        let peer = status
            .peers
            .iter()
            .find(|peer| peer.device_id.to_string() == device_id)
            .ok_or_else(|| format!("Peer {device_id} is not configured."))?;
        let original = fs::read_to_string(&state.config_path).map_err(command_error)?;
        let mut config: DaemonConfig = toml::from_str(&original).map_err(command_error)?;
        config
            .peers
            .retain(|configured| configured.public_key != peer.public_key);
        write_config(&state.config_path, &config)?;
        let store = Store::open(&status.store_root).map_err(command_error)?;
        if !store
            .revoke_group_member(status.group_id, peer.device_id)
            .map_err(command_error)?
        {
            fs::write(&state.config_path, original).map_err(command_error)?;
            return Err(format!("Peer {device_id} was not active."));
        }
        Ok(())
    })();
    let restart_result = if restart {
        start_service_internal(&app, &state).await
    } else {
        Ok(false)
    };
    update?;
    restart_result?;
    snapshot_for(&state).await
}

#[tauri::command]
pub async fn save_settings(
    app: AppHandle,
    request: SettingsRequest,
    state: State<'_, ClientState>,
) -> Result<ClientSnapshot, String> {
    let restart = stop_service_internal(&app, &state).await?;
    let listen_address: SocketAddr = request
        .listen_address
        .parse()
        .map_err(|error| format!("Invalid listen address: {error}"))?;
    let update = update_config(&state.config_path, |config| {
        config.listen_address = listen_address;
        config.scan_interval_seconds = request.scan_interval_seconds;
        config.sync_interval_seconds = request.sync_interval_seconds;
        config.maximum_records_per_page = request.maximum_records_per_page;
    });
    let restart_result = if restart {
        start_service_internal(&app, &state).await
    } else {
        Ok(false)
    };
    update?;
    restart_result?;
    snapshot_for(&state).await
}

#[tauri::command]
pub fn create_invite(
    reachable_address: String,
    state: State<'_, ClientState>,
) -> Result<String, String> {
    let address: SocketAddr = reachable_address
        .parse()
        .map_err(|error| format!("Invalid reachable address: {error}"))?;
    if address.ip().is_unspecified() {
        return Err("Use an address another device can reach, not 0.0.0.0 or [::].".to_owned());
    }
    let runtime = Runtime::load(&state.config_path).map_err(command_error)?;
    let status = runtime.status().map_err(command_error)?;
    let secret = fs::read(&runtime.config().group_secret_file).map_err(command_error)?;
    if secret.len() != GROUP_SECRET_SIZE {
        return Err("The group secret file must contain exactly 32 bytes.".to_owned());
    }
    let payload = InvitePayload {
        version: 1,
        group_id: status.group_id.to_string(),
        group_secret: hex::encode(secret),
        peer_address: address.to_string(),
        peer_public_key: status.public_key,
    };
    let encoded = serde_json::to_vec(&payload).map_err(command_error)?;
    Ok(format!("{INVITE_PREFIX}{}", hex::encode(encoded)))
}

async fn snapshot_for(state: &ClientState) -> Result<ClientSnapshot, String> {
    let runtime = Runtime::load(&state.config_path).map_err(command_error)?;
    let status = runtime.status().map_err(command_error)?;
    Ok(client_snapshot(status, service_is_running(state).await))
}

fn client_snapshot(status: RuntimeStatus, service_running: bool) -> ClientSnapshot {
    ClientSnapshot {
        device_id: status.device_id.to_string(),
        group_id: status.group_id.to_string(),
        public_key: status.public_key,
        sync_root: display_path(&status.sync_root),
        store_root: display_path(&status.store_root),
        listen_address: status.listen_address.to_string(),
        scan_interval_seconds: status.scan_interval_seconds,
        sync_interval_seconds: status.sync_interval_seconds,
        maximum_records_per_page: status.maximum_records_per_page,
        local_change_count: status.local_change_count,
        service_running,
        peers: status
            .peers
            .into_iter()
            .map(|peer| ClientPeer {
                device_id: peer.device_id.to_string(),
                public_key: peer.public_key,
                address: peer.address.to_string(),
                high_watermark: peer.high_watermark,
                pending_objects: peer.pending_objects,
            })
            .collect(),
    }
}

async fn service_is_running(state: &ClientState) -> bool {
    state
        .service
        .lock()
        .await
        .as_ref()
        .is_some_and(|task| !task.join.is_finished())
}

async fn start_service_internal(app: &AppHandle, state: &ClientState) -> Result<bool, String> {
    let mut service = state.service.lock().await;
    if service
        .as_ref()
        .is_some_and(|task| !task.join.is_finished())
    {
        return Ok(false);
    }
    if let Some(previous) = service.take() {
        drop(service);
        let _ = previous.join.await;
        service = state.service.lock().await;
    }
    let runtime = Arc::new(Runtime::load(&state.config_path).map_err(command_error)?);
    let (shutdown, receiver) = oneshot::channel();
    let app_handle = app.clone();
    let join = tokio::spawn(async move {
        let result = run_daemon_until(runtime, async move {
            let _ = receiver.await;
            Ok(())
        })
        .await;
        let _ = app_handle.emit("orbit://service-state", ServiceEvent { running: false });
        result
    });
    *service = Some(ServiceTask {
        shutdown: Some(shutdown),
        join,
    });
    drop(service);
    tokio::task::yield_now().await;
    if !service_is_running(state).await {
        stop_service_internal(app, state).await?;
        return Err("The synchronization service could not start.".to_owned());
    }
    app.emit("orbit://service-state", ServiceEvent { running: true })
        .map_err(command_error)?;
    Ok(true)
}

async fn stop_service_internal(app: &AppHandle, state: &ClientState) -> Result<bool, String> {
    let Some(mut task) = state.service.lock().await.take() else {
        return Ok(false);
    };
    let was_running = !task.join.is_finished();
    if let Some(shutdown) = task.shutdown.take() {
        let _ = shutdown.send(());
    }
    task.join
        .await
        .map_err(command_error)?
        .map_err(command_error)?;
    app.emit("orbit://service-state", ServiceEvent { running: false })
        .map_err(command_error)?;
    Ok(was_running)
}

fn update_config(config_path: &Path, update: impl FnOnce(&mut DaemonConfig)) -> Result<(), String> {
    let original = fs::read_to_string(config_path).map_err(command_error)?;
    let mut config: DaemonConfig = toml::from_str(&original).map_err(command_error)?;
    update(&mut config);
    write_config(config_path, &config)?;
    if let Err(error) = Runtime::load(config_path) {
        fs::write(config_path, original).map_err(command_error)?;
        return Err(error.to_string());
    }
    Ok(())
}

fn write_config(path: &Path, config: &DaemonConfig) -> Result<(), String> {
    let encoded = toml::to_string_pretty(config).map_err(command_error)?;
    let mut file = File::create(path).map_err(command_error)?;
    file.write_all(encoded.as_bytes()).map_err(command_error)?;
    file.sync_all().map_err(command_error)
}

fn decode_invite(code: &str) -> Result<InvitePayload, String> {
    let encoded = code
        .trim()
        .strip_prefix(INVITE_PREFIX)
        .ok_or_else(|| "Invitation code must start with orbit1_.".to_owned())?;
    let bytes = hex::decode(encoded).map_err(|error| format!("Invitation is invalid: {error}"))?;
    let invite: InvitePayload = serde_json::from_slice(&bytes)
        .map_err(|error| format!("Invitation payload is invalid: {error}"))?;
    if invite.version != 1 {
        return Err(format!(
            "Invitation version {} is not supported.",
            invite.version
        ));
    }
    Ok(invite)
}

fn invite_peer_config(
    invite: InvitePayload,
    expected_group_id: &str,
    expected_group_secret: &[u8],
) -> Result<PeerConfig, String> {
    if invite.group_id != expected_group_id {
        return Err("Invitation belongs to a different Orbit workspace.".to_owned());
    }
    let invited_group_secret = decode_group_secret(&invite.group_secret)?;
    if expected_group_secret != invited_group_secret {
        return Err("Invitation group secret does not match this workspace.".to_owned());
    }
    validate_public_key(&invite.peer_public_key)?;
    let address = invite
        .peer_address
        .parse()
        .map_err(|error| format!("Invitation peer address is invalid: {error}"))?;
    Ok(PeerConfig {
        address,
        public_key: invite.peer_public_key,
        synchronize: true,
    })
}

fn invite_workspace(invite: InvitePayload) -> Result<(GroupId, [u8; 32], PeerConfig), String> {
    let group_id = invite
        .group_id
        .parse()
        .map_err(|error| format!("Invitation group ID is invalid: {error}"))?;
    let group_secret = decode_group_secret(&invite.group_secret)?;
    validate_public_key(&invite.peer_public_key)?;
    let address = invite
        .peer_address
        .parse()
        .map_err(|error| format!("Invitation peer address is invalid: {error}"))?;
    Ok((
        group_id,
        group_secret,
        PeerConfig {
            address,
            public_key: invite.peer_public_key,
            synchronize: true,
        },
    ))
}

fn decode_group_secret(encoded: &str) -> Result<[u8; GROUP_SECRET_SIZE], String> {
    let mut secret = [0_u8; GROUP_SECRET_SIZE];
    hex::decode_to_slice(encoded, &mut secret)
        .map_err(|error| format!("Invitation group secret is invalid: {error}"))?;
    Ok(secret)
}

fn validate_public_key(encoded: &str) -> Result<(), String> {
    let mut bytes = [0_u8; 32];
    hex::decode_to_slice(encoded, &mut bytes)
        .map_err(|error| format!("Device public key is invalid: {error}"))
}

fn write_secret_file(path: &Path, secret: &[u8; GROUP_SECRET_SIZE]) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path).map_err(command_error)?;
    file.write_all(secret).map_err(command_error)?;
    file.sync_all().map_err(command_error)
}

fn ensure_secret_file(path: &Path, secret: &[u8; GROUP_SECRET_SIZE]) -> Result<bool, String> {
    if path.exists() {
        let existing = fs::read(path).map_err(command_error)?;
        if existing != secret {
            return Err(
                "A different secret already exists for the invitation workspace.".to_owned(),
            );
        }
        return Ok(false);
    }
    write_secret_file(path, secret)?;
    Ok(true)
}

fn sync_result(report: CycleReport) -> SyncResult {
    SyncResult {
        local_changes: report.maintenance.scan.changes_committed(),
        files_discovered: report.maintenance.scan.files_discovered,
        peers_synchronized: report.synchronization.peers_synchronized,
        peers_failed: report.synchronization.peers_failed,
        peer_errors: report.synchronization.peer_errors,
        records_committed: report.synchronization.records_committed,
        objects_stored: report.synchronization.objects_stored,
        encrypted_bytes_received: report.synchronization.encrypted_bytes_received,
        remote_records_applied: report.synchronization.materialization.records_applied,
        conflicts_kept_both: report.synchronization.materialization.conflicts_kept_both,
        completed_at_unix_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX),
    }
}

fn display_path(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn command_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}

const fn is_mobile() -> bool {
    cfg!(any(target_os = "android", target_os = "ios"))
}

const fn platform_name() -> &'static str {
    if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "android") {
        "android"
    } else if cfg!(target_os = "ios") {
        "ios"
    } else {
        "unknown"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invite_round_trips_and_rejects_unknown_versions() {
        let invite = InvitePayload {
            version: 1,
            group_id: "00000000-0000-4000-8000-000000000001".to_owned(),
            group_secret: "11".repeat(32),
            peer_address: "127.0.0.1:48177".to_owned(),
            peer_public_key: "22".repeat(32),
        };
        let code = format!(
            "{INVITE_PREFIX}{}",
            hex::encode(serde_json::to_vec(&invite).unwrap())
        );
        assert_eq!(decode_invite(&code).unwrap().group_id, invite.group_id);

        let mut unsupported = invite;
        unsupported.version = 2;
        let code = format!(
            "{INVITE_PREFIX}{}",
            hex::encode(serde_json::to_vec(&unsupported).unwrap())
        );
        assert!(decode_invite(&code).is_err());
    }

    #[test]
    fn invitation_peer_must_match_the_current_workspace() {
        let invite = InvitePayload {
            version: 1,
            group_id: "00000000-0000-4000-8000-000000000001".to_owned(),
            group_secret: "11".repeat(32),
            peer_address: "192.0.2.10:48177".to_owned(),
            peer_public_key: "22".repeat(32),
        };
        let peer = invite_peer_config(
            invite.clone(),
            "00000000-0000-4000-8000-000000000001",
            &[0x11; 32],
        )
        .unwrap();
        assert_eq!(peer.address.to_string(), "192.0.2.10:48177");
        assert_eq!(peer.public_key, "22".repeat(32));

        assert_eq!(
            invite_peer_config(
                invite.clone(),
                "00000000-0000-4000-8000-000000000002",
                &[0x11; 32],
            )
            .unwrap_err(),
            "Invitation belongs to a different Orbit workspace."
        );
        assert_eq!(
            invite_peer_config(invite, "00000000-0000-4000-8000-000000000001", &[0x33; 32],)
                .unwrap_err(),
            "Invitation group secret does not match this workspace."
        );
    }

    #[test]
    fn invitation_workspace_extracts_switch_configuration() {
        let invite = InvitePayload {
            version: 1,
            group_id: "e7e92e24-62ea-485a-a2f9-20e9a44bd0ef".to_owned(),
            group_secret: "66".repeat(32),
            peer_address: "192.168.1.10:48177".to_owned(),
            peer_public_key: "fa".repeat(32),
        };
        let (group_id, secret, peer) = invite_workspace(invite).unwrap();
        assert_eq!(group_id.to_string(), "e7e92e24-62ea-485a-a2f9-20e9a44bd0ef");
        assert_eq!(secret, [0x66; 32]);
        assert_eq!(peer.address.to_string(), "192.168.1.10:48177");
        assert_eq!(peer.public_key, "fa".repeat(32));
    }
}
