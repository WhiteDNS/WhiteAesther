/**
 * Builds the Psiphon console client and stages it as a Tauri sidecar, with the
 * bootstrap server list it needs to reach anything the first time.
 *
 * Unlike mihomo, this one cannot be downloaded. Psiphon publishes three library
 * archives and no console executable -- `Psiphon-Client-Library.zip` holds
 * c-shared `.dll`/`.so`/`.dylib` builds, which would mean FFI and a Go runtime
 * inside the Tauri process instead of a supervised child, and which in any case
 * ship no Windows arm64 or Apple Silicon build. So the binary is built here from
 * a pinned source revision.
 *
 * That changes what "pinned" can mean. A Go build is not bit-identical across
 * toolchain versions, so a digest of the output cannot be the gate the way it is
 * for mihomo. What is pinned is the *revision*; what is checked is the server
 * list, which is a downloaded artifact and does have a stable digest.
 */
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { access, chmod, mkdir, rename, rm, stat, writeFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { pipeline } from "node:stream/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const appRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const option = (name) => {
  const index = process.argv.indexOf(name);
  return index === -1 ? undefined : process.argv[index + 1];
};

/** Pinned to a tag, not a branch. Bump deliberately. */
const REVISION = "v2.0.41";
const REPOSITORY = "https://github.com/Psiphon-Labs/psiphon-tunnel-core.git";

/**
 * The bootstrap list: one hex-encoded server entry per line, which is what
 * tunnel-core takes as `-serverList`.
 *
 * A third-party mirror rather than Psiphon, who publish it only inside their own
 * clients. That is acceptable here and would not be for a binary: every entry is
 * signed and verified by tunnel-core itself, so a substituted file costs a slow
 * first connect rather than trust. Psiphon replaces the list from inside the
 * tunnel once a connection is up, so it goes stale the way a phone book does
 * rather than the way a key does.
 */
const SERVER_LIST = {
  repository: "mbm110/MSN-GUARD",
  revision: "a6379f5d060bc7ca48a4c4ee015648afc8c07a05",
  path: "app/src/main/assets/server_entries.txt",
  sha256: "6d6d10c4ef8eaf656cb9614513568f40d5590477fc25215507517d51fc6a293e",
};

/** Rust target triple to the GOOS/GOARCH pair that produces it. */
const GO_TARGETS = {
  "x86_64-pc-windows-msvc": { GOOS: "windows", GOARCH: "amd64" },
  "aarch64-pc-windows-msvc": { GOOS: "windows", GOARCH: "arm64" },
  "x86_64-apple-darwin": { GOOS: "darwin", GOARCH: "amd64" },
  "aarch64-apple-darwin": { GOOS: "darwin", GOARCH: "arm64" },
  "x86_64-unknown-linux-gnu": { GOOS: "linux", GOARCH: "amd64" },
  "aarch64-unknown-linux-gnu": { GOOS: "linux", GOARCH: "arm64" },
};

const target = option("--target") ?? process.env.CARGO_BUILD_TARGET ?? rustHost();
const goTarget = GO_TARGETS[target];
if (!goTarget) {
  throw new Error(`No Go target is mapped for ${target}. Add it to GO_TARGETS.`);
}

const extension = target.includes("windows") ? ".exe" : "";
const binariesDir = join(appRoot, "src-tauri", "binaries");
const destination = join(binariesDir, `psiphon-tunnel-core-${target}${extension}`);
const serverListDestination = join(binariesDir, "psiphon_server_entries.txt");
await mkdir(binariesDir, { recursive: true });

// The checkout lives beside the app rather than inside it: it is large, it is
// not ours, and it is regenerable -- the same three reasons the Aether fork sits
// where it does.
const checkout = option("--source") ?? process.env.PSIPHON_SOURCE ?? join(appRoot, "..", "psiphon-tunnel-core");

if (await isBuilt(destination)) {
  console.log(`Psiphon ${REVISION} already staged for ${target}`);
} else {
  await ensureCheckout(checkout);
  console.log(`Building the console client for ${target} (${goTarget.GOOS}/${goTarget.GOARCH})`);
  const scratch = `${destination}.build`;
  execFileSync(
    "go",
    ["build", "-trimpath", "-ldflags=-s -w", "-o", scratch, "./ConsoleClient"],
    {
      cwd: checkout,
      stdio: "inherit",
      env: {
        ...process.env,
        ...goTarget,
        // No cgo, so every target cross-compiles from any host with nothing but
        // the Go toolchain. It is also what keeps the binary static, which
        // matters for a sidecar that has to run on whatever the user has.
        CGO_ENABLED: "0",
      },
    },
  );
  await rm(destination, { force: true });
  await rename(scratch, destination);
  if (!target.includes("windows")) await chmod(destination, 0o755);
}

await stageServerList();

const size = (await stat(destination)).size;
console.log(`Staged Psiphon ${REVISION} for ${target}`);
console.log(`  ${destination}`);
console.log(`  ${(size / 1048576).toFixed(1)} MB  sha256:${(await sha256(destination)).slice(0, 16)}…`);
console.log(`  ${serverListDestination}`);

/**
 * Fetches the bootstrap list and checks it before it is put anywhere.
 *
 * Two checks, not one. The digest catches a substituted or truncated file; the
 * hex check catches the case the digest cannot explain -- an HTML error page
 * served with a 200, which tunnel-core would reject as a whole without saying
 * which line lost it.
 */
async function stageServerList() {
  if (await matches(serverListDestination, SERVER_LIST.sha256)) {
    console.log("server list already present and matches the pin");
    return;
  }
  const url = `https://raw.githubusercontent.com/${SERVER_LIST.repository}/${SERVER_LIST.revision}/${SERVER_LIST.path}`;
  console.log("Fetching the Psiphon server list");
  const response = await fetch(url);
  if (!response.ok) throw new Error(`${url} returned ${response.status}`);
  const body = Buffer.from(await response.arrayBuffer());

  const actual = createHash("sha256").update(body).digest("hex");
  if (actual !== SERVER_LIST.sha256) {
    throw new Error(
      `The Psiphon server list does not match its pinned digest.\n` +
        `  expected ${SERVER_LIST.sha256}\n` +
        `  actual   ${actual}`,
    );
  }
  const lines = body.toString("utf8").split(/\r?\n/).filter((line) => line.trim());
  const bad = lines.findIndex((line) => !/^[0-9a-fA-F]+$/.test(line));
  if (bad !== -1) {
    throw new Error(`The Psiphon server list is not hex at line ${bad + 1}`);
  }
  await writeFile(serverListDestination, body);
  console.log(`  ${lines.length} server entries`);
}

async function ensureCheckout(path) {
  try {
    await access(join(path, "ConsoleClient"));
  } catch {
    console.log(`Cloning psiphon-tunnel-core ${REVISION} into ${path}`);
    execFileSync(
      "git",
      ["clone", "--depth", "1", "--branch", REVISION, REPOSITORY, path],
      { stdio: "inherit" },
    );
    return;
  }
  // A checkout that is present but on the wrong revision is the trap the Aether
  // fork already fell into once: it silently staged an older engine. Refuse
  // rather than build whatever is sitting there.
  const described = execFileSync("git", ["describe", "--tags", "--always"], {
    cwd: path,
    encoding: "utf8",
  }).trim();
  if (described !== REVISION) {
    throw new Error(
      `${path} is at ${described}, not ${REVISION}. ` +
        `Check it out at the pinned revision, or delete it and let this script clone it.`,
    );
  }
}

async function isBuilt(path) {
  try {
    return (await stat(path)).size > 1_000_000;
  } catch {
    return false;
  }
}

async function matches(path, digest) {
  try {
    await access(path);
  } catch {
    return false;
  }
  return (await sha256(path)) === digest;
}

async function sha256(path) {
  const hash = createHash("sha256");
  await pipeline(createReadStream(path), hash);
  return hash.digest("hex");
}

function rustHost() {
  const output = execFileSync("rustc", ["-vV"], { encoding: "utf8", windowsHide: true });
  const host = output.match(/^host:\s*(.+)$/m)?.[1]?.trim();
  if (!host) throw new Error("Could not determine the Rust host target");
  return host;
}
