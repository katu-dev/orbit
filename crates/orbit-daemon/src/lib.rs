#![forbid(unsafe_code)]

use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    future::Future,
    io::{self, Read, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use orbit_core::{DeviceId, GroupId};
use orbit_crypto::{
    CryptoError, DeviceIdentity, DevicePublicKey, GroupKeys, GroupSecret, IdentityError,
};
use orbit_engine::{
    ApplyError, ApplyOutcome, FullScanner, IncomingApplier, MaterializationRecoveryReport,
    ScanError, ScanReport,
};
use orbit_protocol::ProtocolLimits;
use orbit_store::{MemberRole, Store, StoreError};
use orbit_transport::{
    PullReport, QuicEndpoint, ServeReport, TransportError, authenticate_incoming,
    authenticate_outgoing, pull_changes, serve_changes,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{
    sync::Mutex,
    task::JoinError,
    time::{Instant, MissedTickBehavior, interval_at},
};
use zeroize::Zeroizing;

const SECRET_SIZE: usize = 32;
const MATERIALIZATION_PAGE_SIZE: usize = 256;
const DEFAULT_SCAN_INTERVAL_SECONDS: u64 = 5;
const DEFAULT_SYNC_INTERVAL_SECONDS: u64 = 15;
const DEFAULT_MAXIMUM_RECORDS_PER_PAGE: usize = 64;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonConfig {
    pub group_id: GroupId,
    pub sync_root: PathBuf,
    pub store_root: PathBuf,
    pub listen_address: SocketAddr,
    pub device_secret_file: PathBuf,
    pub group_secret_file: PathBuf,
    #[serde(default = "default_scan_interval_seconds")]
    pub scan_interval_seconds: u64,
    #[serde(default = "default_sync_interval_seconds")]
    pub sync_interval_seconds: u64,
    #[serde(default = "default_maximum_records_per_page")]
    pub maximum_records_per_page: usize,
    #[serde(default)]
    pub peers: Vec<PeerConfig>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PeerConfig {
    pub address: SocketAddr,
    pub public_key: String,
    #[serde(default = "default_true")]
    pub synchronize: bool,
}

#[derive(Clone, Debug)]
pub struct InitializationOptions {
    pub config_path: PathBuf,
    pub sync_root: PathBuf,
    pub store_root: PathBuf,
    pub listen_address: SocketAddr,
    pub group_id: Option<GroupId>,
    pub group_secret_file: Option<PathBuf>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitializedIdentity {
    pub config_path: PathBuf,
    pub group_id: GroupId,
    pub device_id: DeviceId,
    pub public_key_hex: String,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MaterializationReport {
    pub recovered: usize,
    pub records_examined: usize,
    pub records_applied: usize,
    pub records_unchanged: usize,
    pub records_kept_local: usize,
    pub conflicts_kept_both: usize,
    pub unsigned_records_skipped: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MaintenanceReport {
    pub materialization: MaterializationReport,
    pub scan: ScanReport,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SynchronizationReport {
    pub peers_synchronized: usize,
    pub peers_failed: usize,
    pub peer_errors: Vec<String>,
    pub pages_received: usize,
    pub records_committed: usize,
    pub objects_stored: usize,
    pub encrypted_bytes_received: u64,
    pub materialization: MaterializationReport,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CycleReport {
    pub maintenance: MaintenanceReport,
    pub synchronization: SynchronizationReport,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RuntimeStatus {
    pub device_id: DeviceId,
    pub group_id: GroupId,
    pub public_key: String,
    pub sync_root: PathBuf,
    pub store_root: PathBuf,
    pub listen_address: SocketAddr,
    pub scan_interval_seconds: u64,
    pub sync_interval_seconds: u64,
    pub maximum_records_per_page: usize,
    pub local_change_count: u64,
    pub peers: Vec<RuntimePeerStatus>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RuntimePeerStatus {
    pub device_id: DeviceId,
    pub public_key: String,
    pub address: SocketAddr,
    pub high_watermark: u64,
    pub pending_objects: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RuntimePeer {
    address: SocketAddr,
    public_key: DevicePublicKey,
    synchronize: bool,
}

pub struct Runtime {
    config_path: PathBuf,
    config_write: Mutex<()>,
    config: DaemonConfig,
    identity: DeviceIdentity,
    keys: GroupKeys,
    peers: Vec<RuntimePeer>,
}

impl Runtime {
    pub fn load(config_path: impl AsRef<Path>) -> Result<Self, DaemonError> {
        let config_path = config_path.as_ref();
        let mut config: DaemonConfig = toml::from_str(&fs::read_to_string(config_path)?)?;
        let config_directory = config_path.parent().unwrap_or_else(|| Path::new("."));
        config.sync_root = resolve_path(config_directory, &config.sync_root);
        config.store_root = resolve_path(config_directory, &config.store_root);
        config.device_secret_file = resolve_path(config_directory, &config.device_secret_file);
        config.group_secret_file = resolve_path(config_directory, &config.group_secret_file);
        validate_config(&config)?;

        fs::create_dir_all(&config.sync_root)?;
        let device_secret = read_secret(&config.device_secret_file)?;
        let group_secret = read_secret(&config.group_secret_file)?;
        let identity = DeviceIdentity::from_secret_bytes(*device_secret);
        let keys = GroupSecret::from_bytes(*group_secret).derive_keys(config.group_id)?;
        let mut peer_ids = BTreeSet::new();
        let mut peers = Vec::with_capacity(config.peers.len());
        for configured in &config.peers {
            let public_key = decode_public_key(&configured.public_key)?;
            let device_id = public_key.device_id();
            if device_id == identity.device_id() {
                return Err(DaemonError::LocalDeviceConfiguredAsPeer { device_id });
            }
            if !peer_ids.insert(device_id) {
                return Err(DaemonError::DuplicatePeer { device_id });
            }
            peers.push(RuntimePeer {
                address: configured.address,
                public_key,
                synchronize: configured.synchronize,
            });
        }

        let runtime = Self {
            config_path: config_path.to_path_buf(),
            config_write: Mutex::new(()),
            config,
            identity,
            keys,
            peers,
        };
        runtime.configured_store()?;
        Ok(runtime)
    }

    #[must_use]
    pub fn device_id(&self) -> DeviceId {
        self.identity.device_id()
    }

    #[must_use]
    pub fn group_id(&self) -> GroupId {
        self.keys.group_id()
    }

    #[must_use]
    pub const fn listen_address(&self) -> SocketAddr {
        self.config.listen_address
    }

    #[must_use]
    pub const fn config(&self) -> &DaemonConfig {
        &self.config
    }

    async fn remember_discovered_peer(
        &self,
        public_key: DevicePublicKey,
        address: SocketAddr,
    ) -> Result<bool, DaemonError> {
        if self
            .peers
            .iter()
            .any(|peer| peer.public_key.device_id() == public_key.device_id())
        {
            return Ok(false);
        }
        let _guard = self.config_write.lock().await;
        let original = fs::read_to_string(&self.config_path)?;
        let mut config: DaemonConfig = toml::from_str(&original)?;
        if config.peers.iter().any(|peer| {
            decode_public_key(&peer.public_key)
                .is_ok_and(|existing| existing.device_id() == public_key.device_id())
        }) {
            return Ok(false);
        }
        config.peers.push(PeerConfig {
            address,
            public_key: hex::encode(public_key.as_bytes()),
            synchronize: false,
        });
        write_existing_file(
            &self.config_path,
            toml::to_string_pretty(&config)?.as_bytes(),
        )?;
        Ok(true)
    }

    pub fn status(&self) -> Result<RuntimeStatus, DaemonError> {
        let store = self.configured_store()?;
        let local_change_count = store
            .changes_after(self.keys.group_id(), 0, 0)?
            .high_watermark;
        let mut peers = Vec::with_capacity(self.peers.len());
        for peer in &self.peers {
            let device_id = peer.public_key.device_id();
            peers.push(RuntimePeerStatus {
                device_id,
                public_key: hex::encode(peer.public_key.as_bytes()),
                address: peer.address,
                high_watermark: store.peer_high_watermark(self.keys.group_id(), device_id)?,
                pending_objects: store
                    .pending_object_requests(self.keys.group_id(), device_id, usize::MAX)?
                    .len(),
            });
        }
        Ok(RuntimeStatus {
            device_id: self.identity.device_id(),
            group_id: self.keys.group_id(),
            public_key: hex::encode(self.identity.public_key().as_bytes()),
            sync_root: self.config.sync_root.clone(),
            store_root: self.config.store_root.clone(),
            listen_address: self.config.listen_address,
            scan_interval_seconds: self.config.scan_interval_seconds,
            sync_interval_seconds: self.config.sync_interval_seconds,
            maximum_records_per_page: self.config.maximum_records_per_page,
            local_change_count,
            peers,
        })
    }

    fn configured_store(&self) -> Result<Store, DaemonError> {
        let mut store = Store::open(&self.config.store_root)?;
        store.add_group_member(
            self.keys.group_id(),
            self.identity.public_key(),
            MemberRole::Owner,
        )?;
        for peer in &self.peers {
            store.add_group_member(self.keys.group_id(), peer.public_key, MemberRole::Member)?;
        }
        Ok(store)
    }

    fn materialize_catalog(&self) -> Result<MaterializationReport, DaemonError> {
        let mut store = self.configured_store()?;
        let applier = IncomingApplier;
        let recovery = applier.recover_pending_materializations(
            &self.config.sync_root,
            &self.keys,
            &mut store,
        )?;
        ensure_recovery_unblocked(&recovery)?;
        let mut report = MaterializationReport {
            recovered: recovery.completed,
            ..MaterializationReport::default()
        };
        let mut after_sequence = 0;

        loop {
            let page = store.changes_after(
                self.keys.group_id(),
                after_sequence,
                MATERIALIZATION_PAGE_SIZE,
            )?;
            if page.records.is_empty() {
                break;
            }
            for record in &page.records {
                report.records_examined += 1;
                let Some(authentication) =
                    store.change_authentication(self.keys.group_id(), record.revision_id)?
                else {
                    report.unsigned_records_skipped += 1;
                    continue;
                };
                if authentication.authorization.author_device_id == self.identity.device_id() {
                    continue;
                }
                match applier.apply(
                    &self.config.sync_root,
                    record.content_id,
                    authentication.authorization,
                    &self.keys,
                    &mut store,
                )? {
                    ApplyOutcome::Applied { .. } => report.records_applied += 1,
                    ApplyOutcome::NoChange => report.records_unchanged += 1,
                    ApplyOutcome::KeptLocal { .. } => report.records_kept_local += 1,
                    ApplyOutcome::KeptBoth { .. } => report.conflicts_kept_both += 1,
                    ApplyOutcome::MissingObjects { content_ids } => {
                        return Err(DaemonError::AdmittedChangeMissingObjects {
                            count: content_ids.len(),
                        });
                    }
                }
            }
            let next_sequence = page
                .records
                .last()
                .expect("nonempty page has a final record")
                .sequence;
            if next_sequence <= after_sequence {
                return Err(DaemonError::MaterializationMadeNoProgress {
                    sequence: after_sequence,
                });
            }
            after_sequence = next_sequence;
            if after_sequence >= page.high_watermark {
                break;
            }
        }
        Ok(report)
    }

    fn maintain_local_folder(&self) -> Result<MaintenanceReport, DaemonError> {
        let materialization = self.materialize_catalog()?;
        let mut store = self.configured_store()?;
        let scan = FullScanner::default().scan(
            &self.config.sync_root,
            &self.identity,
            &self.keys,
            &mut store,
        )?;
        Ok(MaintenanceReport {
            materialization,
            scan,
        })
    }
}

pub fn initialize(options: &InitializationOptions) -> Result<InitializedIdentity, DaemonError> {
    if options.group_id.is_some() != options.group_secret_file.is_some() {
        return Err(DaemonError::IncompleteGroupJoin);
    }
    if options.config_path.exists() {
        return Err(DaemonError::PathAlreadyExists {
            path: options.config_path.clone(),
        });
    }

    let config_directory = options
        .config_path
        .parent()
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(config_directory)?;
    let sync_root = resolve_path(config_directory, &options.sync_root);
    let store_root = resolve_path(config_directory, &options.store_root);
    validate_roots(&sync_root, &store_root)?;
    fs::create_dir_all(sync_root)?;
    let stem = options
        .config_path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("orbit");
    let device_secret_name = format!("{stem}.device.key");
    let device_secret_path = config_directory.join(&device_secret_name);
    if device_secret_path.exists() {
        return Err(DaemonError::PathAlreadyExists {
            path: device_secret_path,
        });
    }

    let mut device_secret = Zeroizing::new([0_u8; SECRET_SIZE]);
    getrandom::fill(&mut device_secret[..]).map_err(|_| DaemonError::Randomness)?;
    write_secret(&device_secret_path, &device_secret)?;
    let identity = DeviceIdentity::from_secret_bytes(*device_secret);

    let (group_id, group_secret_file, generated_group_secret_path) =
        if let (Some(group_id), Some(group_secret_file)) =
            (options.group_id, options.group_secret_file.as_ref())
        {
            let group_secret_file = fs::canonicalize(group_secret_file)?;
            read_secret(&group_secret_file)?;
            (group_id, group_secret_file, None)
        } else {
            let group_id = GroupId::new();
            let group_secret_name = format!("{stem}.group.key");
            let group_secret_path = config_directory.join(&group_secret_name);
            if group_secret_path.exists() {
                let _ = fs::remove_file(&device_secret_path);
                return Err(DaemonError::PathAlreadyExists {
                    path: group_secret_path,
                });
            }
            let mut group_secret = Zeroizing::new([0_u8; SECRET_SIZE]);
            getrandom::fill(&mut group_secret[..]).map_err(|_| DaemonError::Randomness)?;
            write_secret(&group_secret_path, &group_secret)?;
            (
                group_id,
                PathBuf::from(group_secret_name),
                Some(group_secret_path),
            )
        };

    let config = DaemonConfig {
        group_id,
        sync_root: options.sync_root.clone(),
        store_root: options.store_root.clone(),
        listen_address: options.listen_address,
        device_secret_file: PathBuf::from(device_secret_name),
        group_secret_file,
        scan_interval_seconds: DEFAULT_SCAN_INTERVAL_SECONDS,
        sync_interval_seconds: DEFAULT_SYNC_INTERVAL_SECONDS,
        maximum_records_per_page: DEFAULT_MAXIMUM_RECORDS_PER_PAGE,
        peers: Vec::new(),
    };
    let encoded = toml::to_string_pretty(&config)?;
    if let Err(error) = write_new_file(&options.config_path, encoded.as_bytes()) {
        let _ = fs::remove_file(&device_secret_path);
        if let Some(path) = generated_group_secret_path {
            let _ = fs::remove_file(path);
        }
        return Err(error.into());
    }

    Ok(InitializedIdentity {
        config_path: options.config_path.clone(),
        group_id,
        device_id: identity.device_id(),
        public_key_hex: hex::encode(identity.public_key().as_bytes()),
    })
}

pub async fn run_once(runtime: Arc<Runtime>) -> Result<(), DaemonError> {
    let report = run_cycle(runtime).await?;
    print_maintenance_report(&report.maintenance);
    print_synchronization_report(&report.synchronization);
    if report.synchronization.peers_failed != 0 {
        return Err(DaemonError::PeerSynchronizationsFailed {
            count: report.synchronization.peers_failed,
        });
    }
    Ok(())
}

pub async fn run_cycle(runtime: Arc<Runtime>) -> Result<CycleReport, DaemonError> {
    let bind_address = SocketAddr::new(runtime.listen_address().ip(), 0);
    let endpoint = QuicEndpoint::bind(bind_address)?;
    let maintenance = run_maintenance(Arc::clone(&runtime)).await?;
    let synchronization = synchronize_peers(&endpoint, Arc::clone(&runtime)).await?;
    endpoint.close();
    Ok(CycleReport {
        maintenance,
        synchronization,
    })
}

pub async fn run_daemon(runtime: Arc<Runtime>) -> Result<(), DaemonError> {
    run_daemon_until(runtime, async {
        tokio::signal::ctrl_c().await?;
        Ok(())
    })
    .await
}

pub async fn run_daemon_until<F>(runtime: Arc<Runtime>, shutdown: F) -> Result<(), DaemonError>
where
    F: Future<Output = Result<(), DaemonError>>,
{
    let endpoint = Arc::new(QuicEndpoint::bind(runtime.listen_address())?);
    println!(
        "Orbit device {} listening on {} for group {}",
        runtime.device_id(),
        endpoint.local_addr()?,
        runtime.group_id()
    );

    let accept_task = tokio::spawn(accept_loop(Arc::clone(&endpoint), Arc::clone(&runtime)));
    match run_maintenance(Arc::clone(&runtime)).await {
        Ok(report) => print_maintenance_report(&report),
        Err(error) => eprintln!("initial maintenance failed: {error}"),
    }
    match synchronize_peers(&endpoint, Arc::clone(&runtime)).await {
        Ok(report) => print_synchronization_report(&report),
        Err(error) => eprintln!("initial synchronization failed: {error}"),
    }

    let now = Instant::now();
    let mut scan_interval = interval_at(
        now + Duration::from_secs(runtime.config.scan_interval_seconds),
        Duration::from_secs(runtime.config.scan_interval_seconds),
    );
    scan_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut sync_interval = interval_at(
        now + Duration::from_secs(runtime.config.sync_interval_seconds),
        Duration::from_secs(runtime.config.sync_interval_seconds),
    );
    sync_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            result = &mut shutdown => {
                result?;
                break;
            }
            _ = scan_interval.tick() => {
                match run_maintenance(Arc::clone(&runtime)).await {
                    Ok(report) => print_maintenance_report(&report),
                    Err(error) => eprintln!("folder maintenance failed: {error}"),
                }
            }
            _ = sync_interval.tick() => {
                match synchronize_peers(&endpoint, Arc::clone(&runtime)).await {
                    Ok(report) => print_synchronization_report(&report),
                    Err(error) => eprintln!("peer synchronization failed: {error}"),
                }
            }
        }
    }

    endpoint.close();
    accept_task.abort();
    let _ = accept_task.await;
    Ok(())
}

async fn accept_loop(
    endpoint: Arc<QuicEndpoint>,
    runtime: Arc<Runtime>,
) -> Result<(), DaemonError> {
    loop {
        let connection = endpoint.accept().await?;
        let runtime = Arc::clone(&runtime);
        tokio::spawn(async move {
            match serve_connection(connection, &runtime).await {
                Ok(report) => print_serve_report(&report),
                Err(error) => eprintln!("incoming peer session failed: {error}"),
            }
        });
    }
}

async fn serve_connection(
    connection: quinn::Connection,
    runtime: &Runtime,
) -> Result<ServeReport, DaemonError> {
    let observed_address = connection.remote_address();
    let reverse_connection = connection.clone();
    let mut store = runtime.configured_store()?;
    let peer = authenticate_incoming(
        connection,
        &runtime.identity,
        &runtime.keys,
        &mut store,
        ProtocolLimits::default(),
    )
    .await?;
    let peer_device_id = peer.remote_device_id();
    if let Some(port) = peer.advertised_listen_port() {
        runtime
            .remember_discovered_peer(
                peer.remote_public_key(),
                SocketAddr::new(observed_address.ip(), port),
            )
            .await?;
    }
    let report = serve_changes(peer, &runtime.keys, &mut store).await?;
    let reverse_peer = authenticate_outgoing(
        reverse_connection,
        &runtime.identity,
        peer_device_id,
        &runtime.keys,
        &mut store,
        ProtocolLimits::default(),
        runtime.listen_address().port(),
    )
    .await?;
    pull_changes(
        reverse_peer,
        &runtime.keys,
        &mut store,
        runtime.config.maximum_records_per_page,
    )
    .await?;
    runtime.materialize_catalog()?;
    Ok(report)
}

async fn synchronize_peers(
    endpoint: &QuicEndpoint,
    runtime: Arc<Runtime>,
) -> Result<SynchronizationReport, DaemonError> {
    let mut report = SynchronizationReport::default();
    for peer in &runtime.peers {
        if !peer.synchronize {
            continue;
        }
        match synchronize_peer(endpoint, &runtime, *peer).await {
            Ok(pull) => {
                report.peers_synchronized += 1;
                report.pages_received += pull.pages_received;
                report.records_committed += pull.records_committed;
                report.objects_stored += pull.objects_stored;
                report.encrypted_bytes_received += pull.encrypted_bytes_received;
            }
            Err(error) => {
                report.peers_failed += 1;
                report.peer_errors.push(format!(
                    "Peer {} at {}: {error}",
                    peer.public_key.device_id(),
                    peer.address
                ));
                eprintln!(
                    "peer {} at {} failed: {error}",
                    peer.public_key.device_id(),
                    peer.address
                );
            }
        }
    }
    report.materialization = run_materialization(runtime).await?;
    Ok(report)
}

async fn synchronize_peer(
    endpoint: &QuicEndpoint,
    runtime: &Runtime,
    configured_peer: RuntimePeer,
) -> Result<PullReport, DaemonError> {
    let mut store = runtime.configured_store()?;
    let connection = endpoint.connect(configured_peer.address).await?;
    let reverse_connection = connection.clone();
    let peer = authenticate_outgoing(
        connection,
        &runtime.identity,
        configured_peer.public_key.device_id(),
        &runtime.keys,
        &mut store,
        ProtocolLimits::default(),
        runtime.listen_address().port(),
    )
    .await?;
    let report = pull_changes(
        peer,
        &runtime.keys,
        &mut store,
        runtime.config.maximum_records_per_page,
    )
    .await?;
    let reverse_peer = authenticate_incoming(
        reverse_connection,
        &runtime.identity,
        &runtime.keys,
        &mut store,
        ProtocolLimits::default(),
    )
    .await?;
    serve_changes(reverse_peer, &runtime.keys, &mut store).await?;
    Ok(report)
}

async fn run_maintenance(runtime: Arc<Runtime>) -> Result<MaintenanceReport, DaemonError> {
    tokio::task::spawn_blocking(move || runtime.maintain_local_folder()).await?
}

async fn run_materialization(runtime: Arc<Runtime>) -> Result<MaterializationReport, DaemonError> {
    tokio::task::spawn_blocking(move || runtime.materialize_catalog()).await?
}

fn ensure_recovery_unblocked(recovery: &MaterializationRecoveryReport) -> Result<(), DaemonError> {
    if recovery.blocked.is_empty() {
        return Ok(());
    }
    Err(DaemonError::BlockedMaterializations {
        count: recovery.blocked.len(),
    })
}

fn validate_config(config: &DaemonConfig) -> Result<(), DaemonError> {
    if config.scan_interval_seconds == 0 {
        return Err(DaemonError::ZeroInterval {
            field: "scan_interval_seconds",
        });
    }
    if config.sync_interval_seconds == 0 {
        return Err(DaemonError::ZeroInterval {
            field: "sync_interval_seconds",
        });
    }
    let limits = ProtocolLimits::default();
    if config.maximum_records_per_page == 0
        || config.maximum_records_per_page > limits.maximum_change_records_per_batch()
    {
        return Err(DaemonError::InvalidPageSize {
            actual: config.maximum_records_per_page,
            maximum: limits.maximum_change_records_per_batch(),
        });
    }
    validate_roots(&config.sync_root, &config.store_root)
}

fn validate_roots(sync_root: &Path, store_root: &Path) -> Result<(), DaemonError> {
    if sync_root == store_root
        || store_root.starts_with(sync_root)
        || sync_root.starts_with(store_root)
    {
        return Err(DaemonError::OverlappingRoots {
            sync_root: sync_root.to_path_buf(),
            store_root: store_root.to_path_buf(),
        });
    }
    Ok(())
}

fn resolve_path(config_directory: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        config_directory.join(path)
    }
}

fn decode_public_key(encoded: &str) -> Result<DevicePublicKey, DaemonError> {
    let mut bytes = [0_u8; SECRET_SIZE];
    hex::decode_to_slice(encoded, &mut bytes)?;
    Ok(DevicePublicKey::from_bytes(bytes)?)
}

fn read_secret(path: &Path) -> Result<Zeroizing<[u8; SECRET_SIZE]>, DaemonError> {
    let mut file = File::open(path)?;
    let mut bytes = Zeroizing::new([0_u8; SECRET_SIZE]);
    file.read_exact(&mut bytes[..])?;
    let mut trailing = [0_u8; 1];
    if file.read(&mut trailing)? != 0 {
        return Err(DaemonError::InvalidSecretLength {
            path: path.to_path_buf(),
        });
    }
    Ok(bytes)
}

fn write_secret(path: &Path, bytes: &[u8; SECRET_SIZE]) -> Result<(), DaemonError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn write_new_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn write_existing_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).truncate(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn print_maintenance_report(report: &MaintenanceReport) {
    if report.scan.changes_committed() != 0
        || report.materialization.records_applied != 0
        || report.materialization.conflicts_kept_both != 0
    {
        println!(
            "maintenance: {} local changes, {} remote changes applied, {} conflicts kept",
            report.scan.changes_committed(),
            report.materialization.records_applied,
            report.materialization.conflicts_kept_both
        );
    }
}

fn print_synchronization_report(report: &SynchronizationReport) {
    if report.peers_synchronized != 0 || report.peers_failed != 0 {
        println!(
            "synchronization: {} peers complete, {} failed, {} records and {} objects admitted",
            report.peers_synchronized,
            report.peers_failed,
            report.records_committed,
            report.objects_stored
        );
    }
}

fn print_serve_report(report: &ServeReport) {
    println!(
        "served peer: {} pages and {} objects ({} encrypted bytes)",
        report.pages_sent, report.objects_sent, report.encrypted_bytes_sent
    );
}

const fn default_scan_interval_seconds() -> u64 {
    DEFAULT_SCAN_INTERVAL_SECONDS
}

const fn default_sync_interval_seconds() -> u64 {
    DEFAULT_SYNC_INTERVAL_SECONDS
}

const fn default_maximum_records_per_page() -> usize {
    DEFAULT_MAXIMUM_RECORDS_PER_PAGE
}

const fn default_true() -> bool {
    true
}

#[derive(Debug, Error)]
pub enum DaemonError {
    #[error("daemon I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("configuration TOML is invalid: {0}")]
    ConfigDecode(#[from] toml::de::Error),
    #[error("configuration TOML could not be encoded: {0}")]
    ConfigEncode(#[from] toml::ser::Error),
    #[error("hexadecimal public key is invalid: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("cryptographic operation failed: {0}")]
    Crypto(#[from] CryptoError),
    #[error("device identity is invalid: {0}")]
    Identity(#[from] IdentityError),
    #[error("store operation failed: {0}")]
    Store(#[from] StoreError),
    #[error("folder scan failed: {0}")]
    Scan(#[from] ScanError),
    #[error("incoming materialization failed: {0}")]
    Apply(#[from] ApplyError),
    #[error("peer transport failed: {0}")]
    Transport(#[from] TransportError),
    #[error("background task failed: {0}")]
    Join(#[from] JoinError),
    #[error("operating system randomness is unavailable")]
    Randomness,
    #[error("both --group-id and --group-secret-file are required when joining a group")]
    IncompleteGroupJoin,
    #[error("refusing to overwrite existing path {path}")]
    PathAlreadyExists { path: PathBuf },
    #[error("secret file {path} must contain exactly 32 bytes")]
    InvalidSecretLength { path: PathBuf },
    #[error("device {device_id} is configured as its own peer")]
    LocalDeviceConfiguredAsPeer { device_id: DeviceId },
    #[error("peer {device_id} appears more than once")]
    DuplicatePeer { device_id: DeviceId },
    #[error("{field} must be greater than zero")]
    ZeroInterval { field: &'static str },
    #[error("maximum_records_per_page {actual} is outside 1..={maximum}")]
    InvalidPageSize { actual: usize, maximum: usize },
    #[error("sync root {sync_root:?} and store root {store_root:?} must not overlap")]
    OverlappingRoots {
        sync_root: PathBuf,
        store_root: PathBuf,
    },
    #[error("{count} pending materializations remain blocked")]
    BlockedMaterializations { count: usize },
    #[error("admitted change still references {count} missing objects")]
    AdmittedChangeMissingObjects { count: usize },
    #[error("materialization catalog made no progress after sequence {sequence}")]
    MaterializationMadeNoProgress { sequence: u64 },
    #[error("{count} peer synchronizations failed")]
    PeerSynchronizationsFailed { count: usize },
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn update_peers(config_path: &Path, peers: Vec<PeerConfig>) {
        let mut config: DaemonConfig =
            toml::from_str(&fs::read_to_string(config_path).unwrap()).unwrap();
        config.peers = peers;
        fs::write(config_path, toml::to_string_pretty(&config).unwrap()).unwrap();
    }

    #[test]
    fn initialization_round_trips_relative_paths_and_identity() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let config_path = temporary_directory.path().join("node/orbit.toml");
        let initialized = initialize(&InitializationOptions {
            config_path: config_path.clone(),
            sync_root: PathBuf::from("sync"),
            store_root: PathBuf::from("state"),
            listen_address: "127.0.0.1:0".parse().unwrap(),
            group_id: None,
            group_secret_file: None,
        })
        .unwrap();
        let runtime = Runtime::load(&config_path).unwrap();
        assert_eq!(runtime.group_id(), initialized.group_id);
        assert_eq!(runtime.device_id(), initialized.device_id);
        assert_eq!(initialized.public_key_hex.len(), 64);
        assert!(temporary_directory.path().join("node/sync").is_dir());
        assert_eq!(
            runtime
                .configured_store()
                .unwrap()
                .group_member(runtime.group_id(), runtime.device_id())
                .unwrap()
                .unwrap()
                .public_key,
            runtime.identity.public_key()
        );
    }

    #[test]
    fn initialization_requires_complete_existing_group_coordinates() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let result = initialize(&InitializationOptions {
            config_path: temporary_directory.path().join("orbit.toml"),
            sync_root: PathBuf::from("sync"),
            store_root: PathBuf::from("state"),
            listen_address: "127.0.0.1:0".parse().unwrap(),
            group_id: Some(GroupId::new()),
            group_secret_file: None,
        });

        assert!(matches!(result, Err(DaemonError::IncompleteGroupJoin)));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn initialized_nodes_scan_pull_and_materialize_over_loopback() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let temporary_directory = tempfile::tempdir().unwrap();
            let source_config_path = temporary_directory.path().join("source/source.toml");
            let source = initialize(&InitializationOptions {
                config_path: source_config_path.clone(),
                sync_root: PathBuf::from("sync"),
                store_root: PathBuf::from("state"),
                listen_address: "127.0.0.1:0".parse().unwrap(),
                group_id: None,
                group_secret_file: None,
            })
            .unwrap();
            let source_group_secret = temporary_directory.path().join("source/source.group.key");
            let receiver_config_path = temporary_directory.path().join("receiver/receiver.toml");
            let receiver = initialize(&InitializationOptions {
                config_path: receiver_config_path.clone(),
                sync_root: PathBuf::from("sync"),
                store_root: PathBuf::from("state"),
                listen_address: "127.0.0.1:0".parse().unwrap(),
                group_id: Some(source.group_id),
                group_secret_file: Some(source_group_secret),
            })
            .unwrap();
            fs::write(
                temporary_directory.path().join("source/sync/report.txt"),
                b"materialized through the daemon",
            )
            .unwrap();

            let source_endpoint =
                Arc::new(QuicEndpoint::bind("127.0.0.1:0".parse().unwrap()).unwrap());
            let receiver_endpoint = QuicEndpoint::bind("127.0.0.1:0".parse().unwrap()).unwrap();
            update_peers(
                &source_config_path,
                vec![PeerConfig {
                    address: "127.0.0.1:1".parse().unwrap(),
                    public_key: receiver.public_key_hex,
                    synchronize: true,
                }],
            );
            update_peers(
                &receiver_config_path,
                vec![PeerConfig {
                    address: source_endpoint.local_addr().unwrap(),
                    public_key: source.public_key_hex,
                    synchronize: true,
                }],
            );
            let source_runtime = Arc::new(Runtime::load(&source_config_path).unwrap());
            let receiver_runtime = Arc::new(Runtime::load(&receiver_config_path).unwrap());
            let maintenance = source_runtime.maintain_local_folder().unwrap();
            assert_eq!(maintenance.scan.file_changes, 1);

            let serve = async {
                let connection = source_endpoint.accept().await.unwrap();
                serve_connection(connection, &source_runtime).await.unwrap()
            };
            let synchronize = synchronize_peers(&receiver_endpoint, Arc::clone(&receiver_runtime));
            let (served, synchronized) = tokio::join!(serve, synchronize);
            let synchronized = synchronized.unwrap();

            assert_eq!(served.pages_sent, 1);
            assert_eq!(synchronized.peers_synchronized, 1);
            assert_eq!(synchronized.peers_failed, 0);
            assert_eq!(synchronized.records_committed, 1);
            assert_eq!(synchronized.materialization.records_applied, 1);
            assert_eq!(
                fs::read(temporary_directory.path().join("receiver/sync/report.txt")).unwrap(),
                b"materialized through the daemon"
            );

            source_endpoint.close();
            receiver_endpoint.close();
        })
        .await
        .unwrap();
    }
}
