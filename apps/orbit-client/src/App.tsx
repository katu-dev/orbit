import { useEffect, useState } from "react";
import type { FormEvent } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { open } from "@tauri-apps/plugin-dialog";
import {
  Activity,
  AlertCircle,
  ArrowRight,
  Check,
  CheckCircle2,
  Clock3,
  Copy,
  FolderOpen,
  FolderSync,
  HardDrive,
  KeyRound,
  LayoutDashboard,
  LoaderCircle,
  Monitor,
  Orbit as OrbitIcon,
  Play,
  Plus,
  RadioTower,
  RefreshCw,
  Settings2,
  ShieldAlert,
  ShieldCheck,
  Smartphone,
  Square,
  Trash2,
  UserPlus,
  UsersRound,
  Wifi,
  X,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import "./App.css";

type ViewName = "overview" | "peers" | "settings";
type OnboardingMode = "create" | "join";
type PeerEntryMode = "invite" | "manual";
type CopyTarget = "invite" | "public-key" | null;

interface ClientPeer {
  deviceId: string;
  publicKey: string;
  address: string;
  highWatermark: number;
  pendingObjects: number;
}

interface ClientSnapshot {
  deviceId: string;
  groupId: string;
  publicKey: string;
  syncRoot: string;
  storeRoot: string;
  listenAddress: string;
  scanIntervalSeconds: number;
  syncIntervalSeconds: number;
  maximumRecordsPerPage: number;
  localChangeCount: number;
  serviceRunning: boolean;
  peers: ClientPeer[];
}

interface BootstrapResponse {
  initialized: boolean;
  platform: string;
  mobile: boolean;
  defaultSyncRoot: string;
  snapshot: ClientSnapshot | null;
}

interface SyncResult {
  localChanges: number;
  filesDiscovered: number;
  peersSynchronized: number;
  peersFailed: number;
  peerErrors: string[];
  recordsCommitted: number;
  objectsStored: number;
  encryptedBytesReceived: number;
  remoteRecordsApplied: number;
  conflictsKeptBoth: number;
  completedAtUnixMs: number;
}

interface ActivityEntry {
  id: number;
  title: string;
  detail: string;
  time: string;
  tone: "neutral" | "success" | "warning";
}

interface SettingsDraft {
  listenAddress: string;
  scanIntervalSeconds: string;
  syncIntervalSeconds: string;
  maximumRecordsPerPage: string;
}

interface ServiceEvent {
  running: boolean;
}

const NAVIGATION: Array<{
  id: ViewName;
  label: string;
  icon: LucideIcon;
}> = [
  { id: "overview", label: "Overview", icon: LayoutDashboard },
  { id: "peers", label: "Peers", icon: UsersRound },
  { id: "settings", label: "Settings", icon: Settings2 },
];

const VIEW_TITLES: Record<ViewName, string> = {
  overview: "Overview",
  peers: "Connected devices",
  settings: "Settings",
};

const DEFAULT_SETTINGS: SettingsDraft = {
  listenAddress: "0.0.0.0:48177",
  scanIntervalSeconds: "5",
  syncIntervalSeconds: "15",
  maximumRecordsPerPage: "64",
};

function settingsFromSnapshot(snapshot: ClientSnapshot): SettingsDraft {
  return {
    listenAddress: snapshot.listenAddress,
    scanIntervalSeconds: String(snapshot.scanIntervalSeconds),
    syncIntervalSeconds: String(snapshot.syncIntervalSeconds),
    maximumRecordsPerPage: String(snapshot.maximumRecordsPerPage),
  };
}

function shortId(value: string, start = 8): string {
  if (value.length <= start + 5) return value;
  return `${value.slice(0, start)}...${value.slice(-4)}`;
}

function formatCount(value: number): string {
  return new Intl.NumberFormat().format(value);
}

function formatBytes(value: number): string {
  if (value < 1024) return `${value} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let size = value / 1024;
  let unit = units[0];
  for (let index = 1; index < units.length && size >= 1024; index += 1) {
    size /= 1024;
    unit = units[index];
  }
  return `${size >= 10 ? size.toFixed(0) : size.toFixed(1)} ${unit}`;
}

function errorMessage(error: unknown): string {
  if (typeof error === "string") return error;
  if (error instanceof Error) return error.message;
  return "Orbit could not complete that action.";
}

function Brand({ compact = false }: { compact?: boolean }) {
  return (
    <div className={`brand${compact ? " brand-compact" : ""}`}>
      <span className="brand-mark" aria-hidden="true">
        <OrbitIcon size={compact ? 22 : 25} strokeWidth={2.2} />
      </span>
      <span>Orbit</span>
    </div>
  );
}

function App() {
  const [bootstrap, setBootstrap] = useState<BootstrapResponse | null>(null);
  const [snapshot, setSnapshot] = useState<ClientSnapshot | null>(null);
  const [view, setView] = useState<ViewName>("overview");
  const [busy, setBusy] = useState<string | null>("boot");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [onboardingMode, setOnboardingMode] =
    useState<OnboardingMode>("create");
  const [initializeForm, setInitializeForm] = useState({
    syncRoot: "",
    listenAddress: "0.0.0.0:48177",
    inviteCode: "",
  });
  const [settingsForm, setSettingsForm] =
    useState<SettingsDraft>(DEFAULT_SETTINGS);
  const [peerEntryMode, setPeerEntryMode] =
    useState<PeerEntryMode>("invite");
  const [peerForm, setPeerForm] = useState({
    inviteCode: "",
    address: "",
    publicKey: "",
  });
  const [peerPanelOpen, setPeerPanelOpen] = useState(false);
  const [inviteOpen, setInviteOpen] = useState(false);
  const [inviteAddress, setInviteAddress] = useState("");
  const [inviteCode, setInviteCode] = useState<string | null>(null);
  const [copied, setCopied] = useState<CopyTarget>(null);
  const [syncResult, setSyncResult] = useState<SyncResult | null>(null);
  const [activityEntries, setActivityEntries] = useState<ActivityEntry[]>([]);

  function applySnapshot(next: ClientSnapshot) {
    setSnapshot(next);
    setSettingsForm(settingsFromSnapshot(next));
  }

  function addActivity(
    title: string,
    detail: string,
    tone: ActivityEntry["tone"] = "neutral",
  ) {
    const entry: ActivityEntry = {
      id: Date.now() + Math.random(),
      title,
      detail,
      time: new Intl.DateTimeFormat(undefined, {
        hour: "numeric",
        minute: "2-digit",
      }).format(new Date()),
      tone,
    };
    setActivityEntries((current) => [entry, ...current].slice(0, 6));
  }

  useEffect(() => {
    let mounted = true;

    async function loadClient() {
      try {
        const response = await invoke<BootstrapResponse>("bootstrap");
        if (!mounted) return;
        setBootstrap(response);
        setInitializeForm((current) => ({
          ...current,
          syncRoot: response.defaultSyncRoot,
        }));
        if (response.snapshot) {
          applySnapshot(response.snapshot);
          if (!response.snapshot.serviceRunning) {
            try {
              const started = await invoke<ClientSnapshot>("start_service");
              if (!mounted) return;
              applySnapshot(started);
              addActivity(
                "Service started",
                `Listening on ${started.listenAddress}`,
                "success",
              );
            } catch (startError) {
              if (mounted) setError(errorMessage(startError));
            }
          }
        }
      } catch (loadError) {
        if (mounted) setError(errorMessage(loadError));
      } finally {
        if (mounted) setBusy(null);
      }
    }

    void loadClient();
    const unlisten = listen<ServiceEvent>(
      "orbit://service-state",
      ({ payload }) => {
        if (!mounted) return;
        setSnapshot((current) =>
          current ? { ...current, serviceRunning: payload.running } : current,
        );
      },
    );

    return () => {
      mounted = false;
      void unlisten.then((stopListening) => stopListening());
    };
  }, []);

  useEffect(() => {
    if (!notice) return;
    const timeout = window.setTimeout(() => setNotice(null), 3200);
    return () => window.clearTimeout(timeout);
  }, [notice]);

  useEffect(() => {
    if (!bootstrap?.initialized) return;
    let active = true;
    const interval = window.setInterval(() => {
      void invoke<ClientSnapshot>("load_snapshot")
        .then((next) => {
          if (active) setSnapshot(next);
        })
        .catch(() => {
          // Foreground actions surface errors; background refresh keeps the last snapshot.
        });
    }, 5000);
    return () => {
      active = false;
      window.clearInterval(interval);
    };
  }, [bootstrap?.initialized]);

  async function chooseSyncRoot() {
    try {
      const selected = await open({
        directory: true,
        multiple: false,
        title: "Choose an Orbit folder",
      });
      if (typeof selected === "string") {
        setInitializeForm((current) => ({ ...current, syncRoot: selected }));
      }
    } catch (dialogError) {
      setError(errorMessage(dialogError));
    }
  }

  async function initializeNode(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!bootstrap) return;
    setBusy("initialize");
    setError(null);
    try {
      const created = await invoke<ClientSnapshot>("initialize_node", {
        request: {
          syncRoot: initializeForm.syncRoot.trim() || null,
          listenAddress: initializeForm.listenAddress.trim(),
          inviteCode:
            onboardingMode === "join"
              ? initializeForm.inviteCode.trim()
              : null,
        },
      });
      applySnapshot(created);
      setBootstrap({ ...bootstrap, initialized: true, snapshot: created });
      addActivity(
        onboardingMode === "join" ? "Workspace joined" : "Workspace created",
        `Syncing ${created.syncRoot}`,
        "success",
      );
      try {
        const started = await invoke<ClientSnapshot>("start_service");
        applySnapshot(started);
      } catch (startError) {
        setError(`Device initialized. ${errorMessage(startError)}`);
      }
    } catch (initializeError) {
      setError(errorMessage(initializeError));
    } finally {
      setBusy(null);
    }
  }

  async function toggleService() {
    if (!snapshot) return;
    const command = snapshot.serviceRunning ? "stop_service" : "start_service";
    setBusy("service");
    setError(null);
    try {
      const next = await invoke<ClientSnapshot>(command);
      applySnapshot(next);
      addActivity(
        next.serviceRunning ? "Service started" : "Service paused",
        next.serviceRunning
          ? `Listening on ${next.listenAddress}`
          : "Network listener stopped",
        next.serviceRunning ? "success" : "warning",
      );
    } catch (serviceError) {
      setError(errorMessage(serviceError));
    } finally {
      setBusy(null);
    }
  }

  async function synchronizeNow() {
    if (!snapshot) return;
    setBusy("sync");
    setError(null);
    try {
      const result = await invoke<SyncResult>("sync_now");
      setSyncResult(result);
      const refreshed = await invoke<ClientSnapshot>("load_snapshot");
      applySnapshot(refreshed);
      addActivity(
        result.peersFailed > 0 ? "Sync completed with errors" : "Sync complete",
        `${formatCount(result.localChanges)} local, ${formatCount(result.recordsCommitted)} received`,
        result.peersFailed > 0 ? "warning" : "success",
      );
    } catch (syncError) {
      setError(errorMessage(syncError));
      try {
        applySnapshot(await invoke<ClientSnapshot>("load_snapshot"));
      } catch {
        // Keep the last known state when a failed cycle also prevents refresh.
      }
    } finally {
      setBusy(null);
    }
  }

  async function addPeer(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const fromInvitation = peerEntryMode === "invite";
    setBusy("add-peer");
    setError(null);
    try {
      const next = await invoke<ClientSnapshot>(
        fromInvitation ? "add_peer_from_invite" : "add_peer",
        fromInvitation
          ? { inviteCode: peerForm.inviteCode.trim() }
          : {
              request: {
                address: peerForm.address.trim(),
                publicKey: peerForm.publicKey.trim(),
              },
            },
      );
      applySnapshot(next);
      setPeerForm({ inviteCode: "", address: "", publicKey: "" });
      setPeerPanelOpen(false);
      addActivity(
        "Peer added",
        fromInvitation
          ? "Invitation accepted"
          : `Connecting to ${peerForm.address.trim()}`,
        "success",
      );
      setNotice("Peer added");
    } catch (peerError) {
      const message = errorMessage(peerError);
      if (
        fromInvitation &&
        message === "Invitation belongs to a different Orbit workspace."
      ) {
        const confirmed = window.confirm(
          "This invitation belongs to another workspace. Switch this device to that workspace?\n\nYour device identity and files stay in place. Existing files in the sync folder will be synchronized with the invited workspace. Previous workspace metadata remains stored locally.",
        );
        if (confirmed) {
          setBusy("switch-workspace");
          try {
            const next = await invoke<ClientSnapshot>(
              "switch_workspace_from_invite",
              { inviteCode: peerForm.inviteCode.trim() },
            );
            applySnapshot(next);
            setPeerForm({ inviteCode: "", address: "", publicKey: "" });
            setPeerPanelOpen(false);
            setSyncResult(null);
            addActivity(
              "Workspace joined",
              `Group ${shortId(next.groupId, 12)}`,
              "success",
            );
            setNotice("Workspace switched");
          } catch (switchError) {
            setError(errorMessage(switchError));
          }
        }
      } else {
        setError(message);
      }
    } finally {
      setBusy(null);
    }
  }

  async function revokePeer(peer: ClientPeer) {
    const confirmed = window.confirm(
      `Revoke ${shortId(peer.deviceId)}? New changes from this device will be rejected.`,
    );
    if (!confirmed) return;
    setBusy(`revoke-${peer.deviceId}`);
    setError(null);
    try {
      const next = await invoke<ClientSnapshot>("revoke_peer", {
        deviceId: peer.deviceId,
      });
      applySnapshot(next);
      addActivity("Peer revoked", peer.address, "warning");
      setNotice("Peer revoked");
    } catch (revokeError) {
      setError(errorMessage(revokeError));
    } finally {
      setBusy(null);
    }
  }

  async function saveSettings(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy("settings");
    setError(null);
    try {
      const next = await invoke<ClientSnapshot>("save_settings", {
        request: {
          listenAddress: settingsForm.listenAddress.trim(),
          scanIntervalSeconds: Number(settingsForm.scanIntervalSeconds),
          syncIntervalSeconds: Number(settingsForm.syncIntervalSeconds),
          maximumRecordsPerPage: Number(settingsForm.maximumRecordsPerPage),
        },
      });
      applySnapshot(next);
      addActivity("Settings updated", `Listening on ${next.listenAddress}`);
      setNotice("Settings saved");
    } catch (settingsError) {
      setError(errorMessage(settingsError));
    } finally {
      setBusy(null);
    }
  }

  function showInvite() {
    if (!snapshot) return;
    const separator = snapshot.listenAddress.lastIndexOf(":");
    const host = snapshot.listenAddress.slice(0, separator);
    setInviteAddress(
      host === "0.0.0.0" || host === "[::]" ? "" : snapshot.listenAddress,
    );
    setInviteCode(null);
    setCopied(null);
    setInviteOpen(true);
  }

  async function createInvite(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy("invite");
    setError(null);
    try {
      const code = await invoke<string>("create_invite", {
        reachableAddress: inviteAddress.trim(),
      });
      setInviteCode(code);
    } catch (inviteError) {
      setError(errorMessage(inviteError));
    } finally {
      setBusy(null);
    }
  }

  async function copyValue(value: string, target: Exclude<CopyTarget, null>) {
    try {
      await writeText(value);
      setCopied(target);
      window.setTimeout(
        () => setCopied((current) => (current === target ? null : current)),
        1800,
      );
    } catch (copyError) {
      setError(errorMessage(copyError));
    }
  }

  if (!bootstrap) {
    return (
      <main className="boot-screen">
        <div className="boot-mark">
          <OrbitIcon size={34} />
        </div>
        <span>Starting Orbit</span>
        <LoaderCircle className="spin" size={18} aria-hidden="true" />
        {error && <p className="boot-error">{error}</p>}
      </main>
    );
  }

  if (!snapshot) {
    return (
      <main className="onboarding">
        <section className="onboarding-brand">
          <Brand />
          <div className="orbit-graphic" aria-hidden="true">
            <span className="orbit-ring orbit-ring-one" />
            <span className="orbit-ring orbit-ring-two" />
            <span className="orbit-core"><OrbitIcon size={52} /></span>
          </div>
          <div className="onboarding-statement">
            <span className="eyebrow eyebrow-light">Private file synchronization</span>
            <h1>Your files,<br />in your orbit.</h1>
          </div>
          <div className="security-note">
            <ShieldCheck size={18} />
            <span>Encrypted peer to peer</span>
          </div>
        </section>

        <section className="onboarding-form-wrap">
          <div className="mobile-onboarding-brand"><Brand compact /></div>
          <div className="onboarding-form-inner">
            <span className="step-label">Set up this device</span>
            <h2>{onboardingMode === "create" ? "Create a workspace" : "Join a workspace"}</h2>
            <div className="segmented" aria-label="Workspace setup mode">
              <button
                className={onboardingMode === "create" ? "active" : ""}
                type="button"
                onClick={() => setOnboardingMode("create")}
              >
                Create new
              </button>
              <button
                className={onboardingMode === "join" ? "active" : ""}
                type="button"
                onClick={() => setOnboardingMode("join")}
              >
                Join with code
              </button>
            </div>

            <form className="onboarding-form" onSubmit={initializeNode}>
              {onboardingMode === "join" && (
                <label className="field field-full">
                  <span>Invitation code</span>
                  <textarea
                    value={initializeForm.inviteCode}
                    onChange={(event) =>
                      setInitializeForm((current) => ({
                        ...current,
                        inviteCode: event.target.value,
                      }))
                    }
                    placeholder="orbit1_..."
                    rows={4}
                    required
                    spellCheck={false}
                  />
                </label>
              )}

              <label className="field field-full">
                <span>Sync folder</span>
                <span className="input-with-action">
                  <input
                    value={initializeForm.syncRoot}
                    onChange={(event) =>
                      setInitializeForm((current) => ({
                        ...current,
                        syncRoot: event.target.value,
                      }))
                    }
                    placeholder={bootstrap.defaultSyncRoot}
                    required
                  />
                  {!bootstrap.mobile && (
                    <button
                      className="field-icon-button"
                      type="button"
                      title="Choose folder"
                      aria-label="Choose folder"
                      onClick={() => void chooseSyncRoot()}
                    >
                      <FolderOpen size={19} />
                    </button>
                  )}
                </span>
              </label>

              <label className="field field-full">
                <span>Listen address</span>
                <input
                  value={initializeForm.listenAddress}
                  onChange={(event) =>
                    setInitializeForm((current) => ({
                      ...current,
                      listenAddress: event.target.value,
                    }))
                  }
                  placeholder="0.0.0.0:48177"
                  required
                  spellCheck={false}
                />
              </label>

              <button
                className="primary-button onboarding-submit"
                type="submit"
                disabled={busy === "initialize"}
              >
                {busy === "initialize" ? <LoaderCircle className="spin" size={18} /> : <KeyRound size={18} />}
                {onboardingMode === "create" ? "Create workspace" : "Join workspace"}
                {busy !== "initialize" && <ArrowRight size={18} />}
              </button>
            </form>
            <div className="platform-note">
              {bootstrap.mobile ? <Smartphone size={15} /> : <Monitor size={15} />}
              <span>{bootstrap.platform}</span>
            </div>
          </div>
        </section>
        {error && (
          <div className="toast toast-error" role="alert">
            <AlertCircle size={18} />
            <span>{error}</span>
            <button type="button" aria-label="Dismiss error" onClick={() => setError(null)}><X size={17} /></button>
          </div>
        )}
      </main>
    );
  }

  const pendingObjects = snapshot.peers.reduce(
    (total, peer) => total + peer.pendingObjects,
    0,
  );

  const overview = (
    <>
      <section className={`service-band${snapshot.serviceRunning ? " is-active" : ""}`}>
        <div className="service-copy">
          <span className="service-icon"><RadioTower size={21} /></span>
          <div>
            <span className="eyebrow">Synchronization service</span>
            <h2>{snapshot.serviceRunning ? "Active and listening" : "Paused on this device"}</h2>
            <p>{snapshot.listenAddress}</p>
          </div>
        </div>
        <button
          className="secondary-button service-toggle"
          type="button"
          onClick={() => void toggleService()}
          disabled={busy === "service"}
        >
          {busy === "service" ? <LoaderCircle className="spin" size={17} /> : snapshot.serviceRunning ? <Square size={15} fill="currentColor" /> : <Play size={17} fill="currentColor" />}
          {snapshot.serviceRunning ? "Pause" : "Start"}
        </button>
      </section>

      <section className="metrics" aria-label="Synchronization summary">
        <div className="metric">
          <span>Local changes</span>
          <strong>{formatCount(snapshot.localChangeCount)}</strong>
          <small><HardDrive size={14} /> indexed</small>
        </div>
        <div className="metric">
          <span>Peers</span>
          <strong>{snapshot.peers.length}</strong>
          <small><Wifi size={14} /> configured</small>
        </div>
        <div className="metric">
          <span>Pending chunks</span>
          <strong>{formatCount(pendingObjects)}</strong>
          <small><Activity size={14} /> queued</small>
        </div>
        <div className="metric">
          <span>Last sync</span>
          <strong className="metric-time">
            {syncResult
              ? new Intl.DateTimeFormat(undefined, { hour: "numeric", minute: "2-digit" }).format(syncResult.completedAtUnixMs)
              : "Not yet"}
          </strong>
          <small><Clock3 size={14} /> this session</small>
        </div>
      </section>

      <section className="root-strip">
        <div className="root-path">
          <FolderSync size={21} />
          <div><span>Sync root</span><strong>{snapshot.syncRoot}</strong></div>
        </div>
        <button
          className="primary-button"
          type="button"
          onClick={() => void synchronizeNow()}
          disabled={busy === "sync"}
        >
          <RefreshCw className={busy === "sync" ? "spin" : ""} size={18} />
          {busy === "sync" ? "Syncing" : "Sync now"}
        </button>
      </section>

      {syncResult && (
        <section className={`sync-result${syncResult.peersFailed > 0 ? " has-warning" : ""}`}>
          {syncResult.peersFailed > 0 ? <ShieldAlert size={20} /> : <CheckCircle2 size={20} />}
          <div>
            <strong>{syncResult.peersFailed > 0 ? "Sync completed with peer errors" : "Everything is up to date"}</strong>
            <span>
              {formatCount(syncResult.filesDiscovered)} files scanned · {formatCount(syncResult.objectsStored)} chunks received · {formatBytes(syncResult.encryptedBytesReceived)} transferred
            </span>
            {syncResult.peerErrors[0] && (
              <span className="peer-error">{syncResult.peerErrors[0]}</span>
            )}
          </div>
          {syncResult.conflictsKeptBoth > 0 && <span className="conflict-chip">{syncResult.conflictsKeptBoth} conflicts kept</span>}
        </section>
      )}

      <div className="overview-grid">
        <section className="content-section">
          <div className="section-heading">
            <div><span className="eyebrow">Network</span><h3>Peers</h3></div>
            <button className="text-button" type="button" onClick={() => setView("peers")}>Manage <ArrowRight size={15} /></button>
          </div>
          {snapshot.peers.length === 0 ? (
            <div className="empty-inline">
              <UsersRound size={21} />
              <div><strong>No peers configured</strong><span>Add a device to begin exchanging changes.</span></div>
            </div>
          ) : (
            <div className="compact-peer-list">
              {snapshot.peers.slice(0, 3).map((peer) => (
                <div className="compact-peer" key={peer.deviceId}>
                  <span className={`peer-presence${peer.pendingObjects > 0 ? " is-busy" : ""}`} />
                  <div><strong>{shortId(peer.deviceId)}</strong><span>{peer.address}</span></div>
                  <small>{peer.pendingObjects > 0 ? `${peer.pendingObjects} pending` : "Ready"}</small>
                </div>
              ))}
            </div>
          )}
        </section>

        <section className="content-section activity-section">
          <div className="section-heading"><div><span className="eyebrow">This session</span><h3>Activity</h3></div></div>
          {activityEntries.length === 0 ? (
            <div className="empty-inline"><Clock3 size={21} /><div><strong>No activity yet</strong><span>Service events will appear here.</span></div></div>
          ) : (
            <div className="activity-list">
              {activityEntries.map((entry) => (
                <div className="activity-row" key={entry.id}>
                  <span className={`activity-dot ${entry.tone}`} />
                  <div><strong>{entry.title}</strong><span>{entry.detail}</span></div>
                  <time>{entry.time}</time>
                </div>
              ))}
            </div>
          )}
        </section>
      </div>
    </>
  );

  const peers = (
    <>
      <section className="page-intro">
        <div>
          <span className="eyebrow">Trusted network</span>
          <h2>{snapshot.peers.length} {snapshot.peers.length === 1 ? "peer" : "peers"}</h2>
          <p>Group {shortId(snapshot.groupId, 12)}</p>
        </div>
        <div className="intro-actions">
          <button className="secondary-button" type="button" onClick={() => setPeerPanelOpen((open) => !open)}>
            {peerPanelOpen ? <X size={17} /> : <Plus size={17} />}
            {peerPanelOpen ? "Cancel" : "Add peer"}
          </button>
          <button className="primary-button" type="button" onClick={showInvite}><UserPlus size={17} /> Create invite</button>
        </div>
      </section>

      <section className="identity-strip">
        <span className="identity-icon"><ShieldCheck size={20} /></span>
        <div><span>This device</span><strong>{shortId(snapshot.deviceId, 12)}</strong><code>{snapshot.publicKey}</code></div>
        <button className="icon-button" type="button" title="Copy public key" aria-label="Copy public key" onClick={() => void copyValue(snapshot.publicKey, "public-key")}>
          {copied === "public-key" ? <Check size={18} /> : <Copy size={18} />}
        </button>
      </section>

      {peerPanelOpen && (
        <form className="inline-form peer-form" onSubmit={addPeer}>
          <div className="inline-form-heading"><UserPlus size={20} /><div><strong>Add a peer</strong><span>Use an invitation or enter the connection details.</span></div></div>
          <div className="segmented peer-entry-mode" aria-label="Peer entry mode">
            <button className={peerEntryMode === "invite" ? "active" : ""} type="button" onClick={() => setPeerEntryMode("invite")}>Invitation</button>
            <button className={peerEntryMode === "manual" ? "active" : ""} type="button" onClick={() => setPeerEntryMode("manual")}>Manual</button>
          </div>
          {peerEntryMode === "invite" ? (
            <label className="field peer-invite-field"><span>Invitation code</span><textarea className="peer-invite-code" value={peerForm.inviteCode} onChange={(event) => setPeerForm((current) => ({ ...current, inviteCode: event.target.value }))} placeholder="orbit1_..." rows={3} required spellCheck={false} /></label>
          ) : (
            <>
              <label className="field"><span>Address</span><input value={peerForm.address} onChange={(event) => setPeerForm((current) => ({ ...current, address: event.target.value }))} placeholder="192.168.1.12:48177" required spellCheck={false} /></label>
              <label className="field field-key"><span>Public key</span><input value={peerForm.publicKey} onChange={(event) => setPeerForm((current) => ({ ...current, publicKey: event.target.value }))} placeholder="64 hexadecimal characters" required minLength={64} maxLength={64} spellCheck={false} /></label>
            </>
          )}
          <button className="primary-button" type="submit" disabled={busy === "add-peer" || busy === "switch-workspace"}>{busy === "add-peer" || busy === "switch-workspace" ? <LoaderCircle className="spin" size={17} /> : <Plus size={17} />}{peerEntryMode === "invite" ? "Join workspace" : "Add peer"}</button>
        </form>
      )}

      <section className="peer-directory">
        <div className="section-heading"><div><span className="eyebrow">Directory</span><h3>Remote devices</h3></div></div>
        {snapshot.peers.length === 0 ? (
          <div className="empty-state">
            <span><UsersRound size={27} /></span>
            <h3>No remote devices</h3>
            <p>Create an invitation or add a peer directly.</p>
          </div>
        ) : (
          <div className="peer-list">
            {snapshot.peers.map((peer) => (
              <article className="peer-row" key={peer.deviceId}>
                <span className="device-avatar"><Monitor size={20} /></span>
                <div className="peer-main"><strong>{shortId(peer.deviceId, 12)}</strong><span>{peer.address}</span><code>{shortId(peer.publicKey, 14)}</code></div>
                <div className="peer-stat"><span>Watermark</span><strong>{formatCount(peer.highWatermark)}</strong></div>
                <div className="peer-stat"><span>Pending</span><strong>{formatCount(peer.pendingObjects)}</strong></div>
                <span className={`peer-state${peer.pendingObjects > 0 ? " is-busy" : ""}`}><span />{peer.pendingObjects > 0 ? "Receiving" : "Ready"}</span>
                <button className="icon-button danger-button" type="button" title="Revoke peer" aria-label={`Revoke peer ${shortId(peer.deviceId)}`} onClick={() => void revokePeer(peer)} disabled={busy === `revoke-${peer.deviceId}`}>
                  {busy === `revoke-${peer.deviceId}` ? <LoaderCircle className="spin" size={17} /> : <Trash2 size={17} />}
                </button>
              </article>
            ))}
          </div>
        )}
      </section>
    </>
  );

  const settings = (
    <form className="settings-page" onSubmit={saveSettings}>
      <section className="page-intro settings-intro">
        <div><span className="eyebrow">Device configuration</span><h2>Sync behavior</h2><p>Changes restart the local service.</p></div>
        <button className="primary-button" type="submit" disabled={busy === "settings"}>{busy === "settings" ? <LoaderCircle className="spin" size={17} /> : <Check size={17} />} Save changes</button>
      </section>

      <section className="settings-section">
        <div className="settings-heading"><span><RadioTower size={20} /></span><div><h3>Network</h3><p>Inbound QUIC listener</p></div></div>
        <div className="settings-fields">
          <label className="field field-wide"><span>Listen address</span><input value={settingsForm.listenAddress} onChange={(event) => setSettingsForm((current) => ({ ...current, listenAddress: event.target.value }))} required spellCheck={false} /></label>
        </div>
      </section>

      <section className="settings-section">
        <div className="settings-heading"><span><Clock3 size={20} /></span><div><h3>Schedule</h3><p>Polling and synchronization intervals</p></div></div>
        <div className="settings-fields settings-grid">
          <label className="field"><span>Scan every</span><span className="input-suffix"><input type="number" min="1" value={settingsForm.scanIntervalSeconds} onChange={(event) => setSettingsForm((current) => ({ ...current, scanIntervalSeconds: event.target.value }))} required /><small>sec</small></span></label>
          <label className="field"><span>Sync every</span><span className="input-suffix"><input type="number" min="1" value={settingsForm.syncIntervalSeconds} onChange={(event) => setSettingsForm((current) => ({ ...current, syncIntervalSeconds: event.target.value }))} required /><small>sec</small></span></label>
          <label className="field"><span>Records per page</span><input type="number" min="1" value={settingsForm.maximumRecordsPerPage} onChange={(event) => setSettingsForm((current) => ({ ...current, maximumRecordsPerPage: event.target.value }))} required /></label>
        </div>
      </section>

      <section className="settings-section">
        <div className="settings-heading"><span><FolderSync size={20} /></span><div><h3>Storage</h3><p>Local filesystem locations</p></div></div>
        <div className="readonly-list">
          <div><span>Sync root</span><strong>{snapshot.syncRoot}</strong></div>
          <div><span>Orbit state</span><strong>{snapshot.storeRoot}</strong></div>
        </div>
      </section>

      <section className="settings-section">
        <div className="settings-heading"><span><KeyRound size={20} /></span><div><h3>Identity</h3><p>Device and workspace identifiers</p></div></div>
        <div className="readonly-list mono-list">
          <div><span>Device ID</span><strong>{snapshot.deviceId}</strong></div>
          <div><span>Group ID</span><strong>{snapshot.groupId}</strong></div>
          <div><span>Public key</span><strong>{snapshot.publicKey}</strong><button className="icon-button" type="button" title="Copy public key" aria-label="Copy public key" onClick={() => void copyValue(snapshot.publicKey, "public-key")}>{copied === "public-key" ? <Check size={17} /> : <Copy size={17} />}</button></div>
        </div>
      </section>
    </form>
  );

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <Brand />
        <nav className="side-nav" aria-label="Main navigation">
          {NAVIGATION.map((item) => {
            const Icon = item.icon;
            return <button className={view === item.id ? "active" : ""} type="button" key={item.id} onClick={() => setView(item.id)}><Icon size={19} /><span>{item.label}</span>{item.id === "peers" && snapshot.peers.length > 0 && <small>{snapshot.peers.length}</small>}</button>;
          })}
        </nav>
        <div className="sidebar-footer">
          <div className="sidebar-service"><span className={snapshot.serviceRunning ? "online" : ""} /><div><strong>{snapshot.serviceRunning ? "Service active" : "Service paused"}</strong><small>{shortId(snapshot.deviceId)}</small></div></div>
        </div>
      </aside>

      <header className="mobile-header">
        <Brand compact />
        <button className="icon-button" type="button" title="Sync now" aria-label="Sync now" onClick={() => void synchronizeNow()} disabled={busy === "sync"}><RefreshCw className={busy === "sync" ? "spin" : ""} size={19} /></button>
      </header>

      <main className="workspace">
        <header className="topbar">
          <div><span className="eyebrow">Orbit workspace</span><h1>{VIEW_TITLES[view]}</h1></div>
          <div className="topbar-actions">
            <span className={`service-pill${snapshot.serviceRunning ? " online" : ""}`}><span />{snapshot.serviceRunning ? "Active" : "Paused"}</span>
            <span className="platform-pill">{bootstrap.mobile ? <Smartphone size={15} /> : <Monitor size={15} />}{bootstrap.platform}</span>
            {view !== "overview" && <button className="primary-button top-sync" type="button" onClick={() => void synchronizeNow()} disabled={busy === "sync"}><RefreshCw className={busy === "sync" ? "spin" : ""} size={17} /> Sync now</button>}
          </div>
        </header>
        <div className="workspace-scroll">
          <div className="workspace-content">
            {view === "overview" && overview}
            {view === "peers" && peers}
            {view === "settings" && settings}
          </div>
        </div>
      </main>

      <nav className="bottom-nav" aria-label="Main navigation">
        {NAVIGATION.map((item) => {
          const Icon = item.icon;
          return <button className={view === item.id ? "active" : ""} type="button" key={item.id} onClick={() => setView(item.id)}><Icon size={20} /><span>{item.label}</span></button>;
        })}
      </nav>

      {inviteOpen && (
        <div className="modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) setInviteOpen(false); }}>
          <section className="modal" role="dialog" aria-modal="true" aria-labelledby="invite-title">
            <header><div><span className="eyebrow">Peer enrollment</span><h2 id="invite-title">Create invitation</h2></div><button className="icon-button" type="button" title="Close" aria-label="Close invitation" onClick={() => setInviteOpen(false)}><X size={19} /></button></header>
            {!inviteCode ? (
              <form onSubmit={createInvite}>
                <label className="field field-full"><span>Reachable address</span><input value={inviteAddress} onChange={(event) => setInviteAddress(event.target.value)} placeholder="192.168.1.10:48177" required spellCheck={false} /></label>
                <div className="modal-actions"><button className="secondary-button" type="button" onClick={() => setInviteOpen(false)}>Cancel</button><button className="primary-button" type="submit" disabled={busy === "invite"}>{busy === "invite" ? <LoaderCircle className="spin" size={17} /> : <KeyRound size={17} />} Generate code</button></div>
              </form>
            ) : (
              <div className="invite-result">
                <div className="sensitive-warning"><ShieldAlert size={20} /><div><strong>Contains the group encryption key</strong><span>Send it through a trusted private channel.</span></div></div>
                <label className="field"><span>Invitation code</span><textarea className="invite-code" value={inviteCode} readOnly rows={8} spellCheck={false} /></label>
                <div className="modal-actions"><button className="secondary-button" type="button" onClick={() => { setInviteCode(null); setCopied(null); }}>New code</button><button className="primary-button" type="button" onClick={() => void copyValue(inviteCode, "invite")}>{copied === "invite" ? <Check size={17} /> : <Copy size={17} />}{copied === "invite" ? "Copied" : "Copy invitation"}</button></div>
              </div>
            )}
          </section>
        </div>
      )}

      {error && <div className="toast toast-error" role="alert"><AlertCircle size={18} /><span>{error}</span><button type="button" aria-label="Dismiss error" onClick={() => setError(null)}><X size={17} /></button></div>}
      {notice && !error && <div className="toast toast-success" role="status"><CheckCircle2 size={18} /><span>{notice}</span></div>}
    </div>
  );
}

export default App;
