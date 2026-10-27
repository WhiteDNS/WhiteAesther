import { execFileSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const option = (name) => { const index = process.argv.indexOf(name); return index < 0 ? undefined : process.argv[index + 1]; };
const checkout = resolve(option("--checkout") ?? "aether-source");
const destination = resolve(option("--destination") ?? "aether-core");
const manifest = JSON.parse(readFileSync(join(root, "core-source.json"), "utf8"));
if (existsSync(destination)) throw new Error("Core destination already exists; choose a new empty destination.");
const git = (args) => execFileSync("git", args, { cwd: checkout, windowsHide: true, maxBuffer: 128 * 1024 * 1024 });
if (git(["rev-parse", "HEAD"]).toString().trim() !== manifest.revision) throw new Error("Core checkout does not match the pinned Android revision.");
const paths = [manifest.sourceDirectory, ...manifest.overlays.map(item => item.source)];
for (const path of paths) if (!path || isAbsolute(path) || path.split(/[\\/]/).includes("..")) throw new Error("Invalid core source path.");
const scratchRoot = resolve(tmpdir());
const scratch = mkdtempSync(join(scratchRoot, "aether-source-"));
try {
  const archive = join(scratch, "source.tar");
  writeFileSync(archive, git(["archive", "--format=tar", manifest.revision, "--", ...paths]));
  execFileSync("tar", ["-xf", archive, "-C", scratch], { windowsHide: true });
  mkdirSync(destination, { recursive: true });
  cpSync(join(scratch, manifest.sourceDirectory), destination, { recursive: true });
  for (const overlay of manifest.overlays) {
    if (isAbsolute(overlay.destination) || overlay.destination.split(/[\\/]/).includes("..")) throw new Error("Invalid overlay destination.");
    cpSync(join(scratch, overlay.source), join(destination, overlay.destination), { recursive: true });
  }
  writeFileSync(join(destination, ".core-source.json"), JSON.stringify({ repository: manifest.repository, revision: manifest.revision }) + "\n");
  execFileSync(process.execPath, [join(root, "scripts/apply-core-patches.mjs"), destination], { stdio: "inherit", windowsHide: true });
  console.log(`Prepared shared Android Aether ${manifest.version} at ${destination}`);
} finally {
  if (dirname(resolve(scratch)) !== scratchRoot || !basename(scratch).startsWith("aether-source-")) throw new Error("Unexpected temporary source directory");
  rmSync(scratch, { recursive: true, force: true });
}
