import { spawnSync } from "node:child_process";
import { existsSync, readdirSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const clientRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const tauriCli = join(
  clientRoot,
  "node_modules",
  "@tauri-apps",
  "cli",
  "tauri.js",
);
const args = process.argv.slice(2);
const command = args[0];
const env = { ...process.env };
const pathKey =
  Object.keys(env).find((key) => key.toLowerCase() === "path") ?? "PATH";

function prependPath(...directories) {
  env[pathKey] = `${directories.join(";")};${env[pathKey] ?? ""}`;
}

function findAndroidNdk(androidSdk) {
  const ndkRoot = join(androidSdk, "ndk");
  const preferredVersions = ["29.0.13846066", "28.2.13676358"];
  const installedVersions = existsSync(ndkRoot)
    ? readdirSync(ndkRoot, { withFileTypes: true })
        .filter((entry) => entry.isDirectory())
        .map((entry) => entry.name)
        .sort((left, right) =>
          right.localeCompare(left, undefined, { numeric: true }),
        )
    : [];

  return [...new Set([...preferredVersions, ...installedVersions])]
    .map((version) => join(ndkRoot, version))
    .find(
      (directory) =>
        existsSync(join(directory, "source.properties")) &&
        existsSync(
          join(
            directory,
            "toolchains",
            "llvm",
            "prebuilt",
            "windows-x86_64",
            "bin",
          ),
        ),
    );
}

if (process.platform === "win32" && command === "android") {
  const androidSdk =
    env.ANDROID_HOME ??
    env.ANDROID_SDK_ROOT ??
    join(env.LOCALAPPDATA ?? join(homedir(), "AppData", "Local"), "Android", "Sdk");
  const javaHome = join(
    env.ProgramFiles ?? "C:\\Program Files",
    "Android",
    "Android Studio",
    "jbr",
  );
  const ndkHome = findAndroidNdk(androidSdk);

  for (const [label, required] of [
    ["Android SDK", androidSdk],
    ["Android Studio JDK", javaHome],
  ]) {
    if (!existsSync(required)) {
      console.error(`${label} was not found at: ${required}`);
      console.error("Install it through Android Studio before running this command.");
      process.exit(1);
    }
  }

  env.RUSTUP_TOOLCHAIN = "1.87.0-x86_64-pc-windows-gnu";
  env.ANDROID_HOME = androidSdk;
  env.ANDROID_SDK_ROOT = androidSdk;
  env.JAVA_HOME = javaHome;
  const selfContained = join(
    homedir(),
    ".rustup",
    "toolchains",
    env.RUSTUP_TOOLCHAIN,
    "lib",
    "rustlib",
    "x86_64-pc-windows-gnu",
    "bin",
    "self-contained",
  );
  const mingwBin = join(
    homedir(),
    ".orbit-tools",
    "mingw-binutils",
    "mingw64",
    "bin",
  );
  const compiler = join(mingwBin, "gcc.exe");
  const dllTool = join(mingwBin, "dlltool.exe");
  const linker = join(
    selfContained,
    "x86_64-w64-mingw32-gcc.exe",
  );

  for (const required of [compiler, dllTool, linker]) {
    if (!existsSync(required)) {
      console.error(`Orbit's Windows GNU tool is missing: ${required}`);
      console.error(
        "Install the verified GNU toolchain described in the root README before building for Android.",
      );
      process.exit(1);
    }
  }

  env.CC_x86_64_pc_windows_gnu = compiler;
  env.CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER = linker;
  prependPath(
    mingwBin,
    selfContained,
    join(javaHome, "bin"),
    join(androidSdk, "platform-tools"),
  );

  if (ndkHome) {
    env.NDK_HOME = ndkHome;
    env.ANDROID_NDK_HOME = ndkHome;
  }
}

if (
  process.platform === "win32" &&
  (command === "build" || command === "dev")
) {
  const toolchain = "1.87.0-x86_64-pc-windows-gnu";
  const selfContained = join(
    homedir(),
    ".rustup",
    "toolchains",
    toolchain,
    "lib",
    "rustlib",
    "x86_64-pc-windows-gnu",
    "bin",
    "self-contained",
  );
  const mingwBin = join(
    homedir(),
    ".orbit-tools",
    "mingw-binutils",
    "mingw64",
    "bin",
  );
  const compiler = join(mingwBin, "gcc.exe");
  const linker = join(selfContained, "x86_64-w64-mingw32-gcc.exe");

  for (const required of [compiler, linker]) {
    if (!existsSync(required)) {
      console.error(`Orbit's Windows GNU tool is missing: ${required}`);
      console.error(
        "Install the verified GNU toolchain described in the root README, or install Visual Studio Build Tools and invoke Tauri directly.",
      );
      process.exit(1);
    }
  }

  env.RUSTUP_TOOLCHAIN = toolchain;
  env.CC_x86_64_pc_windows_gnu = compiler;
  env.CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER = linker;
  prependPath(mingwBin, selfContained);

  const hasTarget = args.some(
    (arg) => arg === "--target" || arg.startsWith("--target="),
  );
  if (!hasTarget) {
    args.push("--target", "x86_64-pc-windows-gnu");
  }
}

const result = spawnSync(process.execPath, [tauriCli, ...args], {
  cwd: clientRoot,
  env,
  stdio: "inherit",
});

if (result.error) {
  console.error(result.error.message);
  process.exit(1);
}

process.exit(result.status ?? 1);