/**
 * Builds Xray-core for the Cloudflare Worker carrier and stages it as a Tauri
 * sidecar, with a manifest the app checks before it runs the binary.
 *
 * The revision is the one the Android client ships (native/xray/go.mod, locked
 * by go.sum), so both clients speak to a Worker with the same engine. Only one
 * file changes: the Browser Dialer's loopback page. Upstream serves its token
 * with wildcard CORS and accepts a WebSocket from any origin, so any web page
 * open on the machine could join the bridge. The overlay restricts both to the
 * page's own origin, after checking the exact source it replaces.
 *
 * A Go build is not bit-identical across toolchains, so the digest is taken of
 * what this build produced and written to xray-manifest.json, which the app
 * reads to refuse a binary that was swapped or corrupted after packaging.
 */
import { createHash } from "node:crypto";
import { chmod, cp, mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const appRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const moduleDir = join(appRoot, "native", "xray");
const option = (name) => {
  const index = process.argv.indexOf(name);
  return index === -1 ? undefined : process.argv[index + 1];
};

const MODULE = "github.com/xtls/xray-core";
/** Read from go.mod so the pin has one home. */
const REVISION = (await readFile(join(moduleDir, "go.mod"), "utf8")).match(/github\.com\/xtls\/xray-core (v\S+)/)?.[1];
if (!REVISION) throw new Error("native/xray/go.mod does not pin xray-core");
/** What `xray version` prints for that revision. Checked here and at runtime. */
export const XRAY_VERSION = "26.10.31";

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
if (!goTarget) throw new Error(`No Go target is mapped for ${target}. Add it to GO_TARGETS.`);
const extension = target.includes("windows") ? ".exe" : "";
const binariesDir = join(appRoot, "src-tauri", "binaries");
const destination = join(binariesDir, `xray-${target}${extension}`);
const manifestPath = join(binariesDir, "xray-manifest.json");
await mkdir(binariesDir, { recursive: true });

const hostEnv = { ...process.env, GOTOOLCHAIN: process.env.GOTOOLCHAIN ?? "auto" };
delete hostEnv.GOOS;
delete hostEnv.GOARCH;
// Fetches the module and checks it against go.sum's h1: hash -- the source pin.
const downloaded = JSON.parse(
  execFileSync("go", ["mod", "download", "-json", `${MODULE}@${REVISION}`], { cwd: moduleDir, encoding: "utf8", env: hostEnv }),
);
if (!downloaded.Dir) throw new Error(`Could not resolve ${MODULE}@${REVISION}`);

const relative = join("transport", "internet", "browser_dialer", "dialer.go");
const original = join(downloaded.Dir, relative);
const source = await readFile(original, "utf8");
const origin = "CheckOrigin: func(r *http.Request) bool {\n\t\treturn true";
const cors = 'w.Header().Set("Access-Control-Allow-Origin", "*")';
if (!source.includes(origin) || !source.includes(cors)) {
  throw new Error("The pinned Browser Dialer source changed; review the origin adaptation");
}
const adapted = source
  .replace(origin, 'CheckOrigin: func(r *http.Request) bool {\n\t\treturn r.Header.Get("Origin") == "http://"+r.Host')
  .replace(cors, 'w.Header().Set("Access-Control-Allow-Origin", "http://"+r.Host)');

// Go refuses overlays inside the module cache, so the verified source is copied
// out and the build points at the copy through a generated modfile. The repo's
// go.mod stays the plain pin.
const scratch = join(moduleDir, "build");
const staged = join(scratch, "source");
await rm(staged, { recursive: true, force: true });
await cp(downloaded.Dir, staged, { recursive: true });
const replacement = join(staged, relative);
await chmod(replacement, 0o644);
await writeFile(replacement, adapted);
const modfile = join(scratch, "go.mod");
await writeFile(modfile, `${await readFile(join(moduleDir, "go.mod"), "utf8")}
replace ${MODULE} => ./source
`);
await cp(join(moduleDir, "go.sum"), join(scratch, "go.sum"));

console.log(`Building Xray ${REVISION} for ${target} (${goTarget.GOOS}/${goTarget.GOARCH})`);
const output = `${destination}.build`;
execFileSync(
  "go",
  ["build", "-mod=readonly", `-modfile=${modfile}`, "-trimpath", "-ldflags=-s -w -buildid=", "-o", output, `${MODULE}/main`],
  // No cgo, so every target cross-compiles from any host with the Go toolchain alone.
  { cwd: scratch, stdio: "inherit", env: { ...hostEnv, ...goTarget, CGO_ENABLED: "0" } },
);
await rm(destination, { force: true });
await rename(output, destination);
if (!extension) await chmod(destination, 0o755);

if (rustHost() === target) {
  const printed = execFileSync(destination, ["version"], { encoding: "utf8" });
  if (!printed.startsWith(`Xray ${XRAY_VERSION} `)) throw new Error(`Built Xray reports ${printed.split("\n")[0]}`);
}
const sha256 = createHash("sha256").update(await readFile(destination)).digest("hex");
await writeFile(manifestPath, `${JSON.stringify({ version: XRAY_VERSION, revision: REVISION, sha256 }, null, 2)}\n`);
console.log(`Staged Xray ${XRAY_VERSION} for ${target}`);
console.log(`  ${destination}`);
console.log(`  sha256:${sha256}`);

function rustHost() {
  const out = execFileSync("rustc", ["-vV"], { encoding: "utf8", windowsHide: true });
  const host = out.match(/^host:\s*(.+)$/m)?.[1]?.trim();
  if (!host) throw new Error("Could not determine the Rust host target");
  return host;
}
