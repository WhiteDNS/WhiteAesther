/**
 * Fetches the Tor Expert Bundle and stages what the Tor carrier needs.
 *
 * Unlike Psiphon this one is downloadable: Tor Project publishes the expert
 * bundle for every desktop target, already carrying `tor`, the pluggable
 * transports, and the geoip data. And unlike mihomo it publishes a *signed*
 * digest manifest alongside it, so the pins below are Tor's own numbers rather
 * than ones we computed from bytes we happened to receive.
 *
 * Four files come out of it:
 *
 * - `tor` itself,
 * - `lyrebird`, which provides obfs4, webtunnel, meek_lite and snowflake — one
 *   binary for every transport we would offer,
 * - `geoip` and `geoip6`, which tor wants for country data, and
 * - `pt_config.json`, which carries **Tor's own built-in bridge lists**.
 *
 * That last one is the answer to a trap the Android client hit: a bridge list
 * written by hand rots, and two of the three it first shipped were already
 * unreachable. Reading the list out of the pinned bundle means it can only go
 * stale when the bundle does, and bumping the bundle bumps both together.
 */
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { access, copyFile, chmod, mkdir, rm, stat, writeFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { pipeline } from "node:stream/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const appRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const option = (name) => {
  const index = process.argv.indexOf(name);
  return index === -1 ? undefined : process.argv[index + 1];
};

/** Pinned so a build is reproducible. Bump deliberately, digests and all. */
const VERSION = "15.0.21";

/**
 * Rust target triple to the bundle that serves it, with the SHA-256 Tor
 * published for it.
 *
 * Taken from `sha256sums-signed-build.txt` at this version, not computed from a
 * download — which is the difference between checking that a file arrived
 * intact and checking that it is the file Tor built. Their `.asc` alongside it
 * signs the manifest; verifying that signature needs a key and a GPG dependency
 * this script does not have, so the manifest is trusted at the same level as
 * the TLS connection that fetched it. Better than nothing and honestly less
 * than a signature check; a build server with gpg should do the stronger thing.
 *
 * Two desktop targets are missing on purpose: Tor publishes no
 * `windows-aarch64` or `linux-aarch64` expert bundle at this version. They are
 * absent rather than mapped to a near-miss, and staging skips them with a
 * warning rather than failing -- see below for why the whole build should not
 * stop over one carrier.
 */
const BUNDLES = {
  "x86_64-pc-windows-msvc": {
    asset: `tor-expert-bundle-windows-x86_64-${VERSION}.tar.gz`,
    sha256: "f22b8b17cb18c9fa775dfcf68acf6a2fe788336535fe94645204ca85158aa490",
  },
  "x86_64-apple-darwin": {
    asset: `tor-expert-bundle-macos-x86_64-${VERSION}.tar.gz`,
    sha256: "7e21f5dab4c627e2ff8e894b2039fa49bdd78d12b025f96893d4d6238c6577e4",
  },
  "aarch64-apple-darwin": {
    asset: `tor-expert-bundle-macos-aarch64-${VERSION}.tar.gz`,
    sha256: "83dec16412c1d97b91af603229481dd29f578e1485620ecffd9ac4aabcf6fb46",
  },
  "x86_64-unknown-linux-gnu": {
    asset: `tor-expert-bundle-linux-x86_64-${VERSION}.tar.gz`,
    sha256: "40ef58c536d7077543a25707be5ba467f4b6bcdbafdc015daa25bcf9cb1edc11",
  },
};

const target = option("--target") ?? process.env.CARGO_BUILD_TARGET ?? rustHost();
const bundle = BUNDLES[target];
if (!bundle) {
  // Skipped, not fatal. Refusing the whole build because one of three carriers
  // is unavailable would mean never shipping for arm64 Windows or Linux at all,
  // where Aether and Psiphon both work perfectly well. The app asks which
  // carriers are actually present (`carriers_available`) and offers only those,
  // so a build without Tor is honest about it rather than showing a control
  // that cannot start.
  console.warn(
    `Tor publishes no expert bundle for ${target} at ${VERSION}; ` +
      `building without the Tor carrier. Aether and Psiphon are unaffected.`,
  );
  // The bundle configuration globs this directory, and a glob that matches
  // nothing is a packaging error on some targets. A note is written instead of
  // a placeholder binary: an empty file named `tor` would be found by the very
  // lookup that decides whether this carrier can run.
  const supportDir = join(appRoot, "src-tauri", "binaries", "tor");
  await mkdir(supportDir, { recursive: true });
  await writeFile(
    join(supportDir, "UNAVAILABLE.txt"),
    `The Tor carrier is not part of this build.\n\n` +
      `Tor publishes no expert bundle for ${target} at ${VERSION}, so there is no tor binary\n` +
      `to ship. The application asks which carriers are present and offers only those, so\n` +
      `Tor does not appear as a choice on this build. Aether and Psiphon are unaffected.\n`,
  );
  process.exit(0);
}

const extension = target.includes("windows") ? ".exe" : "";
const binariesDir = join(appRoot, "src-tauri", "binaries");
// Everything travels in one resource directory rather than as a target-triple
// sidecar. Tor is not shipped for every target -- there is no linux-aarch64
// expert bundle -- and a declared sidecar that is missing fails the whole
// bundle, which would mean no arm64 Linux build at all rather than one without
// this one carrier. It also keeps tor next to the transports it launches and
// the geoip data it reads.
const supportDir = join(binariesDir, "tor");
const destination = join(supportDir, `tor${extension}`);
await mkdir(supportDir, { recursive: true });

const staged = [
  destination,
  join(supportDir, `lyrebird${extension}`),
  join(supportDir, "geoip"),
  join(supportDir, "geoip6"),
  join(supportDir, "pt_config.json"),
];

if (await allPresent(staged)) {
  console.log(`Tor ${VERSION} already staged for ${target}`);
} else {
  const url = `https://dist.torproject.org/torbrowser/${VERSION}/${bundle.asset}`;
  console.log(`Fetching ${bundle.asset}`);
  const response = await fetch(url);
  if (!response.ok) throw new Error(`${url} returned ${response.status}`);
  const archive = join(binariesDir, `${bundle.asset}.download`);
  await writeFile(archive, Buffer.from(await response.arrayBuffer()));

  // Checked before a single file is unpacked. The alternative -- extract, then
  // verify what came out -- has already run an archive of unknown provenance
  // through a decompressor by the time it decides whether to trust it.
  const actual = await sha256(archive);
  if (actual !== bundle.sha256) {
    await rm(archive, { force: true });
    throw new Error(
      `${bundle.asset} does not match the digest Tor published for it.\n` +
        `  expected ${bundle.sha256}\n` +
        `  actual   ${actual}`,
    );
  }

  const scratch = join(binariesDir, "tor-unpack");
  await rm(scratch, { recursive: true, force: true });
  await mkdir(scratch, { recursive: true });
  // bsdtar ships with Windows 10 and later, and tar is everywhere else.
  //
  // Relative names, with the directory passed as `cwd`: an absolute Windows
  // path contains a drive colon, and every tar reads `E:\...` as `host:path`
  // and tries to fetch it over rsh. The failure is an unrecoverable status 128
  // that says nothing about why.
  execFileSync("tar", ["-xzf", `${bundle.asset}.download`, "-C", "tor-unpack"], {
    cwd: binariesDir,
    stdio: "inherit",
  });

  await rm(destination, { force: true });
  await copyFile(join(scratch, "tor", `tor${extension}`), destination);
  await copyFile(
    join(scratch, "tor", "pluggable_transports", `lyrebird${extension}`),
    join(supportDir, `lyrebird${extension}`),
  );
  for (const name of ["geoip", "geoip6"]) {
    await copyFile(join(scratch, "data", name), join(supportDir, name));
  }
  // Tor's own bridge lists travel with the binary they are meant to work with.
  await copyFile(
    join(scratch, "tor", "pluggable_transports", "pt_config.json"),
    join(supportDir, "pt_config.json"),
  );

  // The licences come out of the same pinned archive as the binaries they
  // cover, rather than being fetched separately: a licence file that can drift
  // from the build it describes is worse than none, because it reads as a
  // statement about what we shipped.
  const licences = join(appRoot, "licenses");
  await mkdir(licences, { recursive: true });
  for (const [from, to] of [
    ["tor.txt", "tor-BSD-3-Clause.txt"],
    ["lyrebird.txt", "lyrebird-BSD-3-Clause.txt"],
  ]) {
    await copyFile(join(scratch, "docs", from), join(licences, to));
  }

  if (!target.includes("windows")) {
    await chmod(destination, 0o755);
    await chmod(join(supportDir, "lyrebird"), 0o755);
  }
  await rm(scratch, { recursive: true, force: true });
  await rm(archive, { force: true });
}

const bridges = await countBridges(join(supportDir, "pt_config.json"));
console.log(`Staged Tor ${VERSION} for ${target}`);
console.log(`  ${destination}  (${((await stat(destination)).size / 1048576).toFixed(1)} MB)`);
console.log(`  ${supportDir}`);
console.log(`  built-in bridges: ${bridges}`);

/**
 * How many bridges Tor's own list carries, by transport.
 *
 * Printed rather than checked: a bundle that shipped an empty list would be a
 * surprise worth seeing at build time rather than discovering when someone in a
 * censored country taps the one control that was supposed to help them.
 */
async function countBridges(path) {
  try {
    const config = JSON.parse(await (await import("node:fs/promises")).readFile(path, "utf8"));
    return Object.entries(config.bridges ?? {})
      .map(([transport, list]) => `${transport} ${list.length}`)
      .join(", ") || "none — the bundle shipped no list";
  } catch (error) {
    return `unreadable (${error.message})`;
  }
}

async function allPresent(paths) {
  for (const path of paths) {
    try {
      await access(path);
    } catch {
      return false;
    }
  }
  return true;
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
