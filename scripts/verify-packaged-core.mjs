// Extract our build artifacts and execute the core inside each package.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { access, mkdtemp, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { binaryArchitecture, validateCoreContract, checkWindowsRuntime } from "./core-contract.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const expected = JSON.parse(await readFile(join(root, "core-source.json"), "utf8"));
const option = (flag) => { const at = process.argv.indexOf(flag); return at < 0 ? undefined : process.argv[at + 1]; };
const packageRoot = option("--packages");
if (!packageRoot) throw new Error("Pass --packages <bundle directory>");
const extensions = process.platform === "win32" ? [".msi", ".exe"] : process.platform === "darwin" ? [".dmg"] : [".deb", ".rpm", ".AppImage"];
const files = await walk(resolve(packageRoot));
const packages = files.filter((path) => /^whiteaesther[_-]/i.test(basename(path)) && extensions.some((ext) => path.endsWith(ext)));
if (!packages.length) throw new Error("No packages were found");
const results = [];
for (const artifact of packages) {
  const scratch = await mkdtemp(join(tmpdir(), "whiteaesther-package-check-"));
  let mounted = false;
  try {
    if (artifact.endsWith(".msi")) {
      run("msiexec.exe", ["/a", artifact, "/qn", "/norestart", `TARGETDIR=${scratch}`]);
    } else if (artifact.endsWith(".exe")) {
      run(join(process.env.ProgramFiles || "C:\\Program Files", "7-Zip", "7z.exe"), ["x", "-y", `-o${scratch}`, artifact]);
    } else if (artifact.endsWith(".dmg")) {
      run("hdiutil", ["attach", "-readonly", "-nobrowse", "-mountpoint", scratch, artifact]);
      mounted = true;
    } else if (artifact.endsWith(".deb")) {
      run("dpkg-deb", ["-x", artifact, scratch]);
    } else if (artifact.endsWith(".rpm")) {
      const archive = execFileSync("rpm2cpio", [artifact], { maxBuffer: 256 * 1024 * 1024 });
      execFileSync("cpio", ["-idm", "--no-absolute-filenames"], { cwd: scratch, input: archive, stdio: ["pipe", "ignore", "pipe"] });
    } else {
      run(artifact, ["--appimage-extract"], { cwd: scratch });
    }
    const binaries = (await walk(scratch)).filter((path) => ["aether", "aether.exe"].includes(basename(path)));
    if (binaries.length !== 1) throw new Error(`${basename(artifact)} contains ${binaries.length} Aether cores, expected one`);
    const core = binaries[0];
    const version = run(core, ["--version"]).trim();
    const capabilities = JSON.parse(run(core, ["--desktop-capabilities"]));
    validateCoreContract(version, capabilities, expected);
    const coreBytes = await readFile(core);
    const architecture = binaryArchitecture(coreBytes);
    const nativeImports = process.platform === "win32" ? checkWindowsRuntime(coreBytes) : undefined;
    const wanted = process.arch === "arm64" ? "arm64" : "x86_64";
    if (architecture !== wanted) throw new Error(`Packaged core architecture ${architecture} does not match ${wanted}`);
    const checked = JSON.parse(run(core, ["--check-options", "--tls-groups", "X25519:P-256:P-384"]));
    if (checked.ok !== true) throw new Error("Packaged core cannot validate TLS options");
    const config = join(scratch, "missing-identity.toml");
    const backup = JSON.parse(run(core, ["--export-identity", "--config", config]));
    if (backup.ok !== false || !/no identity/.test(backup.error)) throw new Error("Packaged core backup contract failed");
    const restore = JSON.parse(run(core, ["--import-identity", join(scratch, "absent-backup.json"), "--config", config]));
    if (restore.ok !== false || !/cannot read/.test(restore.error)) throw new Error("Packaged core import contract failed");
    for (const args of [["--scan-only", "--scan-limit", "64"], ["--test-endpoint", "127.0.0.1:1"]]) {
      // Invalid TLS is rejected before any DNS, identity registration or dialing.
      const report = JSON.parse(run(core, [...args, "--masque", "--config", config, "--tls-ciphers", "INVALID-WHITEAESTHER-CIPHER"]));
      if (report.ok !== false || typeof report.error !== "string") throw new Error("Packaged scanner error contract failed");
    }
    try { await access(config); throw new Error("Offline checks created an identity"); }
    catch (error) { if (error.code !== "ENOENT") throw error; }
    results.push({ package: basename(artifact), sha256: createHash("sha256").update(await readFile(artifact)).digest("hex"), version, revision: capabilities.revision, architecture, nativeImports, offlineCommands: "passed" });
    console.log(`Verified ${basename(artifact)}: ${version}, ${architecture}, ${capabilities.revision}`);
  } finally {
    if (mounted) run("hdiutil", ["detach", scratch]);
    await rm(scratch, { recursive: true, force: true });
  }
}
const report = resolve(option("--report") || "package-verification.json");
await mkdir(dirname(report), { recursive: true });
await writeFile(report, JSON.stringify(results, null, 2) + "\n");

function run(file, args, options = {}) {
  return execFileSync(file, args, { encoding: "utf8", timeout: 120_000, maxBuffer: 8 * 1024 * 1024, windowsHide: true,
    env: Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("AETHER_"))), ...options });
}
async function walk(directory) {
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) files.push(...await walk(path));
    else if (entry.isFile()) files.push(path);
  }
  return files;
}
