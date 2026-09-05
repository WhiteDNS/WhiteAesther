/**
 * Fetches the mihomo binary and stages it as a Tauri sidecar.
 *
 * The chain engine is a released binary rather than something we build, so
 * unlike the Aether core there is no source tree to compile -- but it still has
 * to arrive under the target-triple name Tauri expects, and it still has to be
 * pinned, or a release would silently pick up whatever upstream published that
 * morning.
 */
import { createHash } from "node:crypto";
import { createWriteStream } from "node:fs";
import { chmod, mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { createGunzip } from "node:zlib";
import { pipeline } from "node:stream/promises";
import { Readable } from "node:stream";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createReadStream } from "node:fs";

const appRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const option = (name) => {
  const index = process.argv.indexOf(name);
  return index === -1 ? undefined : process.argv[index + 1];
};

/** Pinned so a build is reproducible. Bump deliberately. */
const VERSION = "v1.19.30";

/**
 * SHA-256 of the *extracted* binary for each target, as staged.
 *
 * A pinned version alone is a promise the release host makes and can retract:
 * a tag can be moved and an asset can be replaced, and neither leaves a trace
 * in a build that only asks for the name. The digest is the part upstream
 * cannot change under us.
 *
 * Used on both paths, which is the point -- verifying only the download would
 * leave a binary that is already on disk trusted forever, and a cached artifact
 * is exactly what an attacker who got one bad build through would rely on.
 *
 * Regenerate every entry when VERSION moves; a stale digest fails the build
 * rather than silently passing, which is the direction to fail in.
 */
const DIGESTS = {
  "x86_64-pc-windows-msvc": "6ac25fcb26afe8e1bea24b6e6e80805bf884a33232d12e2d78dfa0b6c529ac14",
  "aarch64-pc-windows-msvc": "27a3132a81a53d41a027b2844b994f3f8eb08f9435e9b339c5507b37b5c548df",
  "x86_64-apple-darwin": "30895e01ba17cc4293f9fa192c0601e91fcb812acb72a03a0286b8ffef72dadc",
  "aarch64-apple-darwin": "e80c6334b4e3aae53dfbc86cddd4434cec1565a61d4483931fac2ae12fec6d30",
  "x86_64-unknown-linux-gnu": "8ad44e28fe72be4640254b96741b677f4074991b99186cc4486a1c28ded02b1a",
  "aarch64-unknown-linux-gnu": "b9456718a8955364b9a77c80f74dca49ded10f071c1c6b4513a0ea68a3d87a50",
};

/**
 * The "compatible" builds avoid newer CPU instructions, which is the right
 * default for a client that has to run on whatever machine a user has.
 */
const ASSETS = {
  "x86_64-pc-windows-msvc": `mihomo-windows-amd64-compatible-${VERSION}.zip`,
  "aarch64-pc-windows-msvc": `mihomo-windows-arm64-${VERSION}.zip`,
  "x86_64-apple-darwin": `mihomo-darwin-amd64-compatible-${VERSION}.gz`,
  "aarch64-apple-darwin": `mihomo-darwin-arm64-${VERSION}.gz`,
  "x86_64-unknown-linux-gnu": `mihomo-linux-amd64-compatible-${VERSION}.gz`,
  "aarch64-unknown-linux-gnu": `mihomo-linux-arm64-${VERSION}.gz`,
};

const target = option("--target") ?? process.env.CARGO_BUILD_TARGET ?? rustHost();
const asset = ASSETS[target];
if (!asset) {
  throw new Error(
    `No mihomo build is mapped for ${target}. Add it to ASSETS, or the chain will be missing.`,
  );
}
const expected = DIGESTS[target];
if (!expected) {
  // Refused rather than staged unverified. A target that downloads whatever
  // upstream is serving today is the exact thing the pin exists to prevent, and
  // making it opt-in by omission would mean the weakest path is the quiet one.
  throw new Error(
    `No pinned digest for ${target}. Add its SHA-256 to DIGESTS before staging that target.`,
  );
}

const extension = target.includes("windows") ? ".exe" : "";
const destination = join(appRoot, "src-tauri", "binaries", `mihomo-${target}${extension}`);
await mkdir(dirname(destination), { recursive: true });

if (await isStaged(destination, expected)) {
  console.log(`mihomo ${VERSION} already staged for ${target}`);
} else {
  const url = `https://github.com/MetaCubeX/mihomo/releases/download/${VERSION}/${asset}`;
  console.log(`Fetching ${asset}`);
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`${url} returned ${response.status}`);
  }

  const scratch = `${destination}.download`;
  if (asset.endsWith(".gz")) {
    await pipeline(Readable.fromWeb(response.body), createGunzip(), createWriteStream(scratch));
  } else {
    // Node has no zip reader, and adding a dependency to unpack one file is a
    // poor trade. The platforms that ship zips all have a system unzip.
    const archive = `${destination}.zip`;
    await writeFile(archive, Buffer.from(await response.arrayBuffer()));
    unzipSingle(archive, scratch);
    await rm(archive, { force: true });
  }

  // Checked before it is put anywhere the build will find it, and the scratch
  // copy is removed on failure -- so a bad download cannot be left behind to be
  // picked up by the next run, which would turn one bad fetch into a permanent
  // one.
  const actual = await sha256(scratch);
  if (actual !== expected) {
    await rm(scratch, { force: true });
    throw new Error(
      `${asset} does not match its pinned digest.\n` +
        `  expected ${expected}\n` +
        `  actual   ${actual}\n` +
        `Upstream may have replaced the asset. Verify what changed before updating DIGESTS.`,
    );
  }

  await rm(destination, { force: true });
  await writeFile(destination, await readFile(scratch));
  await rm(scratch, { force: true });
  if (!target.includes("windows")) await chmod(destination, 0o755);
}

const size = (await stat(destination)).size;
console.log(`Staged mihomo ${VERSION} for ${target}`);
console.log(`  ${destination}`);
console.log(`  ${(size / 1048576).toFixed(1)} MB  sha256:${expected.slice(0, 16)}… verified`);

/**
 * Whether the binary already on disk is the one we pinned.
 *
 * This used to ask only whether the file was over a megabyte, which accepted
 * anything at all -- a truncated download, a half-written file from an
 * interrupted run, or a binary someone swapped in. It is also the path taken on
 * every build after the first, so it was the check that mattered most and did
 * the least.
 */
async function isStaged(path, digest) {
  try {
    if ((await stat(path)).size < 1_000_000) return false;
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

function unzipSingle(archive, into) {
  const script =
    `$e=[IO.Compression.ZipFile]::OpenRead('${archive}');` +
    `$f=$e.Entries|Where-Object{$_.Name -like '*.exe'}|Select-Object -First 1;` +
    `[IO.Compression.ZipFileExtensions]::ExtractToFile($f,'${into}',$true);$e.Dispose()`;
  execFileSync(
    "powershell",
    ["-NoProfile", "-Command", `Add-Type -AssemblyName System.IO.Compression.FileSystem; ${script}`],
    { stdio: "inherit" },
  );
}

function rustHost() {
  const output = execFileSync("rustc", ["-vV"], { encoding: "utf8", windowsHide: true });
  const host = output.match(/^host:\s*(.+)$/m)?.[1]?.trim();
  if (!host) throw new Error("Could not determine the Rust host target");
  return host;
}
