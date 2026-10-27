import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const appRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const core = resolve(process.argv[2] ?? "aether-core");
const manifest = JSON.parse(readFileSync(resolve(appRoot, "core-source.json"), "utf8"));
const prepared = JSON.parse(readFileSync(resolve(core, ".core-source.json"), "utf8"));
if (prepared.revision !== manifest.revision || prepared.repository !== manifest.repository) throw new Error("Prepared core does not match the pinned source");
const git = args => execFileSync("git", ["apply", "--no-index", ...args], {
  cwd: core, encoding: "utf8", windowsHide: true,
  env: { ...process.env, GIT_CEILING_DIRECTORIES: dirname(core) },
});
for (const patch of manifest.patches) {
  const path = resolve(appRoot, patch.path);
  const digest = createHash("sha256").update(readFileSync(path)).digest("hex");
  if (digest !== patch.sha256) throw new Error(`Core patch checksum mismatch: ${patch.path}`);
  git(["--check", path]);
  git([path]);
  console.log(`Applied ${patch.path} (${digest})`);
}
