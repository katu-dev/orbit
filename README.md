# Orbit

Orbit is a cross-platform, peer-to-peer file synchronization system under active development. It chunks changed files with FastCDC, encrypts content before transfer, signs replicated changes with per-device Ed25519 identities, resumes interrupted object streams from durable offsets, and keeps concurrent edits under deterministic conflict-copy names.

The `orbit-daemon` executable runs the synchronization loop on Windows, macOS, and Linux. The Tauri client in `apps/orbit-client` embeds that same daemon in a native Windows, macOS, Linux, Android, or iOS application with first-run setup, peer invitations, status, manual sync, and settings.

## Prerequisites

- [Rustup](https://rustup.rs/)
- Rust 1.87 or newer
- A native C/C++ build toolchain for your platform
- Node.js 22 and npm for the graphical client

On Windows, the normal Rust MSVC toolchain requires Visual Studio Build Tools with the **Desktop development with C++** workload. The verified npm launcher can instead use the GNU setup documented below and does not require `link.exe`. SQLite and Protobuf tooling are bundled by the Rust dependencies, so separate SQLite and `protoc` installations are not required.

Install the pinned minimum Rust toolchain and its development components:

```powershell
rustup toolchain install 1.87.0
rustup component add rustfmt clippy --toolchain 1.87.0
```

## Build And Test

Run these commands from the repository root:

```powershell
cargo +1.87.0 build --workspace
cargo +1.87.0 test --workspace
```

Build and inspect the daemon CLI:

```powershell
cargo +1.87.0 build --release -p orbit-daemon
cargo +1.87.0 run -p orbit-daemon -- --help
```

Run a single crate's tests while developing a specific layer:

```powershell
cargo +1.87.0 test -p orbit-store
cargo +1.87.0 test -p orbit-engine
```

## Continuous Integration And Releases

GitHub Actions validates Rust formatting, synchronization crate tests, and the frontend production build on pushes to `main` and pull requests. A manual **Build and release** run builds downloadable Windows, Linux, macOS, and Android artifacts without publishing a release.

Push a version tag matching the Tauri/package version to publish a GitHub Release automatically:

```powershell
git tag v0.1.0
git push origin v0.1.0
```

Tagged builds attach native desktop bundles and an ARM64 Android debug APK to one release. Production Android signing is intentionally not stored in the repository; configure a keystore through GitHub secrets before distributing a release-signed APK through an app store.

Available crates:

| Crate | Purpose |
| --- | --- |
| `orbit-core` | Domain identifiers, manifests, paths, version vectors, and conflict resolution |
| `orbit-crypto` | Key derivation, device identities, change signatures, and authenticated object encryption |
| `orbit-content` | FastCDC chunking and delta transfer planning |
| `orbit-daemon` | Configuration, recovery, polling, peer scheduling, and the runnable CLI |
| `orbit-engine` | Deterministic scans, encrypted ingestion, reconciliation, and crash-safe filesystem materialization |
| `orbit-protocol` | Versioned Protobuf messages, framing, and semantic validation |
| `orbit-store` | SQLite catalog, membership, signed provenance, encrypted object storage, recovery, and resumable request state |
| `orbit-transport` | Exporter-bound mutual authentication, QUIC control sessions, and resumable object streams |

## Desktop And Mobile App

Install the frontend dependencies and launch the native desktop client:

```powershell
cd apps/orbit-client
npm ci
npm run tauri dev
```

The first screen can create a new workspace or join one with an invitation code. Choose a local sync folder and a UDP listen address. Orbit starts its synchronization service while the application process is running. Use **Create invite** from the Peers view and enter an IP address and port that the joining device can reach. Invitation codes include the group encryption key, so send them only through a trusted private channel.

Build an installer or application bundle for the current desktop platform:

```powershell
npm run tauri build
```

Desktop builds require the platform dependencies listed by [Tauri](https://v2.tauri.app/start/prerequisites/). On the verified Windows setup, the npm launcher selects Rust 1.87 GNU and the portable MinGW tools documented below, so Visual Studio's `link.exe` is not required; WebView2 is still required. macOS application bundles must be built on macOS, and Linux packages must be built on Linux.

For Android, install Android Studio, SDK Platform 36, Platform Tools, Build Tools, and a compatible NDK. On Windows, the client launcher discovers Android Studio's JDK and the SDK automatically, prefers NDK 29, and supports stable NDK 28.2. Initialize the platform project once and run it on an emulator or connected device:

```powershell
cd apps/orbit-client
npm run android:init
npm run android:dev
```

Create Android release packages with `npm run android:build`. Build an x86_64 debug APK for an emulator with `npm run android:build:emulator`. For iOS, use a macOS host with Xcode and run `npm run tauri ios init`, followed by `npm run tauri ios dev` or `npm run tauri ios build`.

Android and iOS can suspend an application that is not in the foreground. The current mobile client synchronizes while its app process remains active; it does not yet install an Android foreground service or iOS background-processing task. See `apps/orbit-client/README.md` for the complete client setup and troubleshooting guide.

## Two-Device Quick Start

Initialize the first device. Paths in the generated TOML are resolved relative to the configuration file:

```powershell
cargo +1.87.0 run -p orbit-daemon -- init `
	--config node-a/orbit.toml `
	--sync-root sync `
	--store-root state `
	--listen 0.0.0.0:48177
```

The command prints the group ID, device ID, and public key. It also creates `node-a/orbit.device.key` and `node-a/orbit.group.key` without overwriting existing files.

Securely copy only the group key to the second device, then join the same group. Each device must have its own generated device key:

```powershell
cargo +1.87.0 run -p orbit-daemon -- init `
	--config node-b/orbit.toml `
	--sync-root sync `
	--store-root state `
	--listen 0.0.0.0:48177 `
	--group-id <GROUP_ID_FROM_NODE_A> `
	--group-secret-file node-b/shared.group.key
```

Add the other device to each configuration using the public keys printed by `init`. Node A needs Node B's reachable address and public key:

```toml
[[peers]]
address = "192.0.2.11:48177"
public_key = "<NODE_B_PUBLIC_KEY>"
```

Node B needs the corresponding Node A entry:

```toml
[[peers]]
address = "192.0.2.10:48177"
public_key = "<NODE_A_PUBLIC_KEY>"
```

Allow inbound UDP on the configured port, then run both nodes:

```powershell
cargo +1.87.0 run --release -p orbit-daemon -- run --config node-a/orbit.toml
cargo +1.87.0 run --release -p orbit-daemon -- run --config node-b/orbit.toml
```

Use separate terminals or machines. Stop a foreground daemon with Ctrl-C. The `once` command performs recovery, materialization, one local scan, and one pull from every configured peer before exiting:

```powershell
cargo +1.87.0 run -p orbit-daemon -- once --config node-b/orbit.toml
```

`once` does not remain available to serve another peer, so at least the source node must be running while a one-shot pull executes.

The generated configuration includes these tunable values:

```toml
scan_interval_seconds = 5
sync_interval_seconds = 15
maximum_records_per_page = 64
```

Secret files contain exactly 32 raw bytes. `init` creates them with mode `0600` on Unix; Windows uses the parent directory's inherited ACL. Keep the configuration and secret files in an OS-protected location, never commit them, and do not reuse a device key on multiple devices. Orbit does not yet integrate with an operating-system credential vault.

## Device Identity And Membership

Every device uses an Ed25519 `orbit_crypto::DeviceIdentity`. Its `DeviceId` is derived from its public key, and every replicated change is signed over the group ID, author device ID, revision ID, and encrypted manifest content ID.

Membership is currently administered locally through `orbit_store::Store`:

```rust
let identity = DeviceIdentity::from_secret_bytes(device_secret);
store.add_group_member(
	keys.group_id(),
	identity.public_key(),
	MemberRole::Member,
)?;
scanner.scan(sync_root, &identity, &keys, &mut store)?;
```

The daemon provisions a stable 32-byte device secret during `init`. Applications embedding the libraries can provision identities themselves. Use `Store::revoke_group_member` to block new changes from a device. An exact change authenticated before revocation remains valid for idempotent commit and crash recovery.

The SQLite catalog is schema version 7. Version 7 adds the durable incoming-transfer journal; a version-6 catalog migrates in place without losing queued object requests. Migrating a version-5 catalog creates an empty member registry, so devices must be enrolled before scanning or applying new changes. Legacy unsigned log entries remain readable locally, but `orbit_engine::build_change_batch` refuses to send them.

## Current Ingestion Behavior

`orbit-engine::FullScanner` can ingest one filesystem root per sync group for an active registered device. A successful scan:

- validates all discovered paths before inferring deletions;
- skips symbolic links and rejects non-portable or colliding paths;
- streams files through FastCDC without loading whole files into memory;
- encrypts and stores only chunks that are not already present;
- signs canonical encrypted manifests and commits provenance through compare-and-swap local heads;
- emits tombstones for files removed since the previous complete scan; and
- makes an unchanged repeat scan a no-op.

The daemon runs the scanner on the configured polling interval. `orbit-engine::FullScanner` also remains available as a library API.

## Current Incoming Apply Behavior

`orbit-engine::IncomingApplier` applies an encrypted manifest already admitted to `orbit-store`. It:

- verifies the claimed author is an active member and validates the Ed25519 change signature before filesystem mutation;
- authenticates, decrypts, and canonically decodes the manifest;
- authenticates every referenced chunk before filesystem mutation and reports missing chunk IDs;
- reconciles the incoming record against the current local head using version vectors;
- preserves both concurrent file edits under a deterministic conflict-copy path;
- writes files through a random journaled stage, syncs them, atomically replaces the destination, and restores the manifest modification time;
- applies tombstones as idempotent file deletions; and
- commits signed provenance and the local head through compare-and-swap before clearing the durable materialization journal.

The initial deterministic conflict copy is a local-only tracked head rather than a newly replicated revision. This prevents different peers from assigning incompatible authors to the same derived revision. If a user edits that copy, the scanner emits the edit as a normal signed change.

Call `IncomingApplier::recover_pending_materializations` after opening the store and before starting a full scan. `FullScanner` refuses to scan while journal entries remain, preventing a partial stage from being interpreted as user content after a process crash.

`orbit_engine::build_change_batch` constructs paginated outbound Protobuf records from the durable change log. It includes stored author signatures, verifies each encrypted manifest while loading it, and fails closed if any selected revision lacks signed provenance.

The daemon recovers pending materializations before scanning and reapplies admitted remote history idempotently after each pull. This closes the crash window between durable network admission and filesystem replacement.

## Authenticated Network Behavior

Orbit uses QUIC for encrypted transport. The current TLS certificate is ephemeral and is not the peer identity authority. Before accepting any synchronization message, both devices sign a three-message Orbit handshake containing fresh nonces, the exact negotiated protocol acknowledgement, and a 32-byte TLS exporter binding. The claimed device must match an active locally configured membership public key, which prevents replay and cross-connection relay.

Change pages include encrypted manifests and stored author signatures. A receiver does not advance a peer watermark while referenced chunks are missing. Each encrypted chunk uses its own QUIC stream with a validated request, offer, and stream header. Received bytes are fsynced before the SQLite offset advances; reconnects request only the suffix after that durable offset. The final object is authenticated and decrypted before the signed change can commit.

## Current Limits

- Peer addresses are explicit IP socket addresses; DNS discovery, LAN discovery, relays, and NAT traversal are not implemented.
- Folder changes are found by polling rather than native filesystem notifications.
- Membership remains local. The native client can exchange direct invitation codes, but there is no centralized invitation, discovery, revocation broadcast, or key-rotation service.
- The standalone daemon runs in the foreground and does not install itself as a Windows service, launchd agent, or systemd unit. The native client runs the daemon only for the lifetime permitted to the application by the operating system.
- Secret files are not stored in an operating-system credential vault.

## Formatting And Linting

```powershell
cargo +1.87.0 fmt --all -- --check
cargo +1.87.0 clippy --workspace --all-targets -- -D warnings
```

To apply Rust formatting instead of only checking it:

```powershell
cargo +1.87.0 fmt --all
```

## Verified Windows GNU Setup

If the MSVC build tools are unavailable, this repository has also been tested with Rust 1.87 GNU and a portable MinGW installation at `%USERPROFILE%\.orbit-tools\mingw-binutils\mingw64`:

```powershell
rustup toolchain install 1.87.0-x86_64-pc-windows-gnu
rustup component add rustfmt clippy --toolchain 1.87.0-x86_64-pc-windows-gnu

$gnuTools = Join-Path $env:USERPROFILE '.rustup\toolchains\1.87.0-x86_64-pc-windows-gnu\lib\rustlib\x86_64-pc-windows-gnu\bin\self-contained'
$mingwBin = Join-Path $env:USERPROFILE '.orbit-tools\mingw-binutils\mingw64\bin'
$env:PATH = "$mingwBin;$gnuTools;$env:PATH"
$env:CC_x86_64_pc_windows_gnu = Join-Path $mingwBin 'gcc.exe'
$env:CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER = Join-Path $gnuTools 'x86_64-w64-mingw32-gcc.exe'

cargo +1.87.0-x86_64-pc-windows-gnu test --workspace
```

The portable MinGW directory is a local development convention and is not installed by this repository.