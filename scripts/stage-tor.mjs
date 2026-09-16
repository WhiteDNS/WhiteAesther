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

/**
 * Pinned so a build is reproducible. Bump deliberately, digests and all.
 *
 * This one expires, unlike the others. `dist.torproject.org/torbrowser/` keeps
 * only the current release -- 15.0.21 was pinned here and staging began failing
 * with a plain 404 the day 15.0.22 replaced it, and then 15.0.22 went the same
 * way. A pin protects against the asset changing under us; it cannot keep the
 * asset alive. Expect to bump this on roughly Tor Browser's release cadence,
 * and note that a green build says nothing about tomorrow.
 *
 * The digests below did not change between 15.0.22 and 15.0.23: the expert
 * bundle is byte-identical across those two, so only the version in the URL
 * moved. Worth checking rather than assuming on the next bump -- if the sums
 * *do* change, that is the pin doing its job and the new ones have to come from
 * Tor's manifest, never from whatever arrived.
 */
const VERSION = "15.0.23";

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
    sha256: "231dad6b9cb401a54c260db7046965ef04e4f72ff071b140d423fb5da281ab1e",
  },
  "x86_64-apple-darwin": {
    asset: `tor-expert-bundle-macos-x86_64-${VERSION}.tar.gz`,
    sha256: "be1be1cb13cd093713f02a0beade0d2471b61119011bfeb0efc08353eadf2e4e",
  },
  "aarch64-apple-darwin": {
    asset: `tor-expert-bundle-macos-aarch64-${VERSION}.tar.gz`,
    sha256: "e8ea3f667c83309abad34280f0f9e1cfae52843da6b8db111ca15d6221051db5",
  },
  "x86_64-unknown-linux-gnu": {
    asset: `tor-expert-bundle-linux-x86_64-${VERSION}.tar.gz`,
    sha256: "08d49de27f542b8f73e2014e064d8320562b5d20019c03d4725c5a5249d97985",
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

let stagedVersion = VERSION;

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
  // What is actually being fetched, which is the pin until the pin is gone.
  let { version, asset, sha256: expected } = { version: VERSION, ...bundle };

  let url = `https://dist.torproject.org/torbrowser/${version}/${asset}`;
  console.log(`Fetching ${asset}`);
  let response = await fetch(url);

  // A 404 is not the pin failing. It is the pinned release having been deleted,
  // which `dist.torproject.org` does to every version the moment the next one
  // lands -- so this happens on their schedule, not ours, and it has broken the
  // build twice now with a bare status code and no hint of what to do.
  //
  // The distinction below is the whole design, and it must not blur: a bundle
  // whose *digest* does not match is the pin catching something and always
  // fails, no matter what. Only a bundle that is *not there at all* is followed
  // forward, and then only to a newer version, verified against the digest Tor
  // publishes for that version.
  //
  // That is a real if narrow loss: the pinned digest was read by a person from
  // Tor's manifest and committed, and a followed one is whatever the manifest
  // says today. It is the same manifest over the same TLS the tarball comes
  // over, so it is not a new trust root -- but it is one fewer pair of eyes.
  // Hence the warning, and hence it prints the lines to paste: the point is to
  // get the pin back at the next commit, not to live without one.
  if (response.status === 404) {
    const current = await currentVersion();
    if (!current || compareVersions(current, version) <= 0) {
      throw new Error(
        `${url} returned 404 and no newer release was found to follow.\n` +
          `Check https://dist.torproject.org/torbrowser/ by hand.`,
      );
    }
    const published = await publishedDigest(current, asset.replace(version, current));
    if (!published) {
      throw new Error(
        `${url} returned 404, and ${current} publishes no ${asset.replace(version, current)}.\n` +
          `Tor may have stopped building this target; check by hand.`,
      );
    }
    console.warn(
      `\n  !! Tor ${version} has been removed from dist.torproject.org.\n` +
        `  !! Following to ${current} and verifying against the digest it publishes.\n` +
        `  !! Re-pin this in scripts/stage-tor.mjs -- the pin is a person having\n` +
        `  !! read the manifest, and following it forward skips that:\n` +
        `  !!     const VERSION = "${current}";\n` +
        `  !!     ${target} sha256: "${published}"\n`,
    );
    version = current;
    asset = asset.replace(VERSION, current);
    expected = published;
    url = `https://dist.torproject.org/torbrowser/${version}/${asset}`;
    response = await fetch(url);
  }

  // After the 404 branch, so it reports what was staged rather than what was
  // asked for -- the two differ exactly when a release has been deleted, which
  // is the moment somebody most needs to be told which one they actually got.
  stagedVersion = version;

  if (!response.ok) throw new Error(`${url} returned ${response.status}`);
  const archive = join(binariesDir, `${asset}.download`);
  await writeFile(archive, Buffer.from(await response.arrayBuffer()));

  // Checked before a single file is unpacked. The alternative -- extract, then
  // verify what came out -- has already run an archive of unknown provenance
  // through a decompressor by the time it decides whether to trust it.
  const actual = await sha256(archive);
  if (actual !== expected) {
    await rm(archive, { force: true });
    throw new Error(
      `${asset} does not match the digest Tor published for it.\n` +
        `  expected ${expected}\n` +
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
  execFileSync("tar", ["-xzf", `${asset}.download`, "-C", "tor-unpack"], {
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
console.log(`Staged Tor ${stagedVersion} for ${target}`);
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

/**
 * The newest release `dist.torproject.org` is currently serving.
 *
 * Read from the directory index, because there is no API and the index is what
 * the 404 is telling us about. Returns null rather than throwing: a lookup that
 * fails leaves the caller to report the original 404, which is the more useful
 * of the two errors.
 */
async function currentVersion() {
  try {
    const response = await fetch("https://dist.torproject.org/torbrowser/");
    if (!response.ok) return null;
    const body = await response.text();
    const versions = [...body.matchAll(/href="(\d+\.\d+\.\d+)\//g)].map((match) => match[1]);
    if (versions.length === 0) return null;
    return versions.sort(compareVersions).at(-1);
  } catch {
    return null;
  }
}

/**
 * The SHA-256 Tor published for one asset, from that release's own manifest.
 *
 * `sha256sums-signed-build.txt` is the same file the pinned digests were copied
 * out of by hand. There is an `.asc` beside it that signs it, and checking that
 * signature needs a key and a GPG dependency this script does not have -- so
 * this is trusted at the level of the TLS connection that fetched it, exactly
 * as the tarball is. Said plainly rather than implied: it is weaker than a
 * signature check, and it is why following a version forward prints a warning.
 */
async function publishedDigest(version, asset) {
  try {
    const response = await fetch(
      `https://dist.torproject.org/torbrowser/${version}/sha256sums-signed-build.txt`,
    );
    if (!response.ok) return null;
    const line = (await response.text())
      .split(/\r?\n/)
      .find((row) => row.trim().endsWith(` ${asset}`));
    return line ? line.trim().split(/\s+/)[0] : null;
  } catch {
    return null;
  }
}

/** Numeric, so 15.0.9 sorts below 15.0.23 rather than above it. */
function compareVersions(left, right) {
  const a = left.split(".").map(Number);
  const b = right.split(".").map(Number);
  for (let i = 0; i < Math.max(a.length, b.length); i += 1) {
    const difference = (a[i] ?? 0) - (b[i] ?? 0);
    if (difference !== 0) return difference;
  }
  return 0;
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
