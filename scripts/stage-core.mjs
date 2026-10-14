import { constants } from "node:fs";
import { access, chmod, copyFile, mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { validateCoreContract, binaryArchitecture, checkWindowsRuntime } from "./core-contract.mjs";

const appRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const option = (name) => {
  const index = process.argv.indexOf(name);
  return index === -1 ? undefined : process.argv[index + 1];
};

const target = option("--target") ?? process.env.CARGO_BUILD_TARGET ?? rustHost();
const extension = target.includes("windows") ? ".exe" : "";
const source = await findCore(extension);
const expected = JSON.parse(await readFile(join(appRoot, "core-source.json"), "utf8"));
const destination = join(appRoot, "src-tauri", "binaries", `aether-${target}${extension}`);
const version = execFileSync(source, ["--version"], {
  encoding: "utf8",
  timeout: 10_000,
  windowsHide: true,
}).trim();

const run = (args) => execFileSync(source, args, { encoding: "utf8", timeout: 10_000, windowsHide: true,
  env: Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("AETHER_"))),
});
if (version !== `aether ${expected.version}`) throw new Error(`Expected Aether ${expected.version}, got ${version}`);
const capabilities = JSON.parse(run(["--desktop-capabilities"]));
validateCoreContract(version, capabilities, expected);
const bytes = await readFile(source);
const architecture = binaryArchitecture(bytes);
if (target.includes("windows")) checkWindowsRuntime(bytes);
const wanted = target.startsWith("aarch64-") ? "arm64" : target.startsWith("x86_64-") ? "x86_64" : null;
if (!wanted || architecture !== wanted) throw new Error(`Core architecture ${architecture} does not match ${target}`);
const help = run(["--help"]);
for (const command of capabilities.commands) {
  if (!help.includes(`--${command}`)) throw new Error(`Core help is missing --${command}`);
}
const scratch = await mkdtemp(join(tmpdir(), "whiteaesther-core-check-"));
try {
  const config = join(scratch, "missing-identity.toml");
  const checked = JSON.parse(run(["--check-options", "--tls-groups", "X25519:P-256:P-384", "--tls-ciphers", "ECDHE-RSA-AES128-GCM-SHA256"]));
  if (checked.ok !== true) throw new Error("Core rejected valid TLS settings");
  const invalid = JSON.parse(run(["--check-options", "--tls-ciphers", "INVALID-WHITEAESTHER-CIPHER"]));
  if (invalid.ok !== false) throw new Error("Core silently accepted an invalid TLS cipher");
  const backup = JSON.parse(run(["--export-identity", "--config", config]));
  if (backup.ok !== false || !/no identity/.test(backup.error)) throw new Error("Core backup contract failed for a missing identity");
  try { await access(config); throw new Error("Backup created an identity"); }
  catch (error) { if (error.code !== "ENOENT") throw error; }
} finally { await rm(scratch, { recursive: true, force: true }); }

await mkdir(dirname(destination), { recursive: true });
if (resolve(source) !== resolve(destination)) await copyFile(source, destination);
if (!target.includes("windows")) await chmod(destination, 0o755);
console.log(`Staged ${version} for ${target}`);

function rustHost() {
  const output = execFileSync("rustc", ["-vV"], { encoding: "utf8", windowsHide: true });
  const host = output.match(/^host:\s*(.+)$/m)?.[1]?.trim();
  if (!host) throw new Error("Could not determine the Rust host target");
  return host;
}

async function findCore(binaryExtension) {
  const requested = option("--source") ?? process.env.AETHER_CORE_SOURCE ?? process.env.WHITEAESTHER_CORE_PATH;
  const candidates = [
    requested,
    // The fork first: it is the one with the scanner's reporting modes.
    join(appRoot, "..", "Aether-whiteaesther", "aether", "target", "release", `aether${binaryExtension}`),
    join(appRoot, "..", "Aether-whiteaesther", "aether", "target", "debug", `aether${binaryExtension}`),
    join(appRoot, "..", "Aether", "aether", "target", "release", `aether${binaryExtension}`),
    join(appRoot, "..", "Aether", "aether", "target", "debug", `aether${binaryExtension}`),
  ].filter(Boolean);

  if (requested) {
    await access(requested, constants.X_OK);
    return resolve(requested);
  }

  for (const candidate of candidates) {
    try {
      await access(candidate, constants.X_OK);
      return resolve(candidate);
    } catch {
      // Try the next explicit or conventional location.
    }
  }
  throw new Error("Aether core not found. Set AETHER_CORE_SOURCE or pass --source <path>.");
}
