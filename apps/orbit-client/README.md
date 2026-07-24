# Orbit Client

Orbit Client is the native desktop and mobile interface for the Orbit peer-to-peer synchronization engine. One React interface and one Rust command layer target Windows, macOS, Linux, Android, and iOS through Tauri 2. The Rust shell calls `orbit-daemon` directly; synchronization logic is not reimplemented in TypeScript.

## Features

- Create a new encrypted workspace or join one with an invitation code.
- Choose a sync root, start or pause the embedded daemon, and run an immediate cycle.
- Inspect peer watermarks, pending chunks, local change counts, and session activity.
- Add peers directly, create sensitive invitation codes, and revoke devices.
- Configure listen, scan, sync, and pagination settings.
- Use a desktop sidebar or phone-sized bottom navigation from the same codebase.

## Desktop Development

Prerequisites:

- Node.js 22 and npm
- Rust 1.87 or newer
- The [Tauri platform prerequisites](https://v2.tauri.app/start/prerequisites/) for the host OS

From this directory:

```powershell
npm ci
npm run tauri dev
```

`tauri dev` starts Vite at `http://localhost:1420` and opens the native window. The page is not a standalone web client: it requires Tauri IPC for filesystem, clipboard, and Orbit daemon operations.

Build a release bundle for the current host platform:

```powershell
npm run tauri build
```

On this Windows development environment, the npm launcher automatically selects the installed Rust 1.87 GNU toolchain and portable MinGW compiler, so this command does not require `link.exe`. The result is written below the repository-level `target/release/bundle` directory (or `target/<triple>/release/bundle` when an explicit Rust target is selected). Cross-platform desktop bundles are not cross-compiled: build Windows on Windows, macOS on macOS, and Linux on Linux.

Run the frontend-only type check and bundle:

```powershell
npm run build
```

Run the native command-layer check from the repository root:

```powershell
cargo +1.87.0 check -p orbit-client
```

## Android

Install Android Studio and use its SDK Manager to install:

- Android SDK Platform 36 and Platform Tools
- Android SDK Build Tools 35 or newer
- Android NDK 29 or stable NDK 28.2
- Android Studio's bundled JDK

Configure `JAVA_HOME`, `ANDROID_HOME`, and `NDK_HOME` as described in the Tauri prerequisites. Add an emulator or connect a device with USB debugging enabled, then run:

```powershell
npm run android:init
npm run android:dev
```

On Windows, these scripts discover Android Studio's JDK and the SDK under `%LOCALAPPDATA%\Android\Sdk`. They prefer NDK 29 when available and support the installed stable NDK 28.2 fallback. The first initialization installs any missing Rust targets and may ask you to accept Google's Android SDK license if no compatible NDK is installed.

Build an x86_64 debug APK for the Android emulator with:

```powershell
npm run android:build:emulator
```

The Android emulator cannot reliably receive Orbit's QUIC/UDP traffic through `adb emu redir`. Run Orbit on Windows at `0.0.0.0:48177`, then add Windows to the emulator as a manual peer using `10.0.2.2:48177` and the Windows device's public key. The emulator initiates one connection and Orbit synchronizes in both directions over it. Windows retains the discovered Android identity as an inbound-only peer, so it remains visible without retrying the emulator's unroutable source address. A physical Android device should instead use actual Wi-Fi addresses, with both devices on a network that permits UDP traffic.

Build release APK/AAB artifacts with:

```powershell
npm run android:build
```

The generated Android project lives under `src-tauri/gen/android` and should be regenerated only when Tauri configuration requires it. Debug APKs are written under `src-tauri/gen/android/app/build/outputs/apk`.

## iOS

iOS development requires macOS, Xcode, CocoaPods, and an Apple development team for device signing:

```bash
npm run tauri ios init
npm run tauri ios dev
npm run tauri ios build
```

The generated Xcode project lives under `src-tauri/gen/apple`. It cannot be initialized or validated on Windows.

## First Run

1. Select **Create new** on the first device, choose the sync root, and set the listen address. `0.0.0.0:48177` accepts traffic on every local interface.
2. Open **Peers**, select **Create invite**, and enter the first device's actual address as seen by the second device, such as `192.168.1.42:48177` on a LAN. For the Android emulator, use the manual peer setup described above instead.
3. Transfer the invitation through a trusted private channel. It contains the group encryption key.
4. Select **Join with code** on the second device, paste the invitation, and choose its local sync root.
5. Allow inbound UDP for the selected port and keep at least one source device running while another pulls changes.

If the second device is already initialized, open **Peers**, select **Add peer**, choose **Invitation**, and paste the complete `orbit1_` code. Re-pasting an invitation updates a stale peer address. An invitation for the current workspace adds its peer directly. For a different workspace, Orbit asks for confirmation before switching groups; the device identity and sync files stay in place, and existing files in that folder will synchronize with the invited workspace. On first contact, the inviter securely enrolls the joining device and records its observed address automatically.

Direct peer entry requires the other device's reachable socket address and 64-character Ed25519 public key. Revocation blocks newly authenticated changes from that device in the local store; Orbit does not yet broadcast revocations or rotate the shared group key.

## Mobile Lifecycle

The embedded service is cancellable and runs while the Orbit application process is active. Android and iOS may suspend or terminate ordinary applications in the background, so this release does not promise continuous synchronization after the app leaves the foreground. A production always-on mobile mode requires an Android foreground service and an iOS background-processing design with platform-specific scheduling constraints.

The default mobile sync root is the app's Orbit document directory. Mobile operating systems may restrict arbitrary shared-folder access. Keep configuration, device keys, and group keys inside the application data directory; invitation codes should be treated as secrets.

## Troubleshooting

- **Desktop GNU tool missing on Windows:** install the Rust 1.87 GNU and portable MinGW setup from the root README. The npm launcher does not use Visual Studio's `link.exe`; WebView2 is still required.
- **Android command cannot find the SDK/NDK:** launch Android Studio once, install the packages above, and verify `ANDROID_HOME` and `NDK_HOME`.
- **Peers cannot connect:** use reachable IP addresses, allow inbound UDP, and check the concrete peer error shown after **Sync now**. Android emulators must initiate toward Windows at `10.0.2.2`; the emulator's `10.0.2.15` address is not directly reachable from the Windows host.
- **The Vite page reports missing Tauri internals:** launch with `npm run tauri dev`; `npm run dev` alone does not provide native IPC.
