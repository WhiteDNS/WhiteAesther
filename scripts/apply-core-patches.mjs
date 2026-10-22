import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const appRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const core = resolve(process.argv[2] ?? "aether-core");
const manifest = JSON.parse(readFileSync(resolve(appRoot, "core-source.json"), "utf8"));
const git = args => execFileSync("git", ["-C", core, ...args], { encoding: "utf8", windowsHide: true });
if (git(["rev-parse", "HEAD"]).trim() !== manifest.revision) throw new Error("Core checkout does not match the pinned revision");
if (git(["status", "--porcelain"]).trim()) throw new Error("Core checkout must be clean before applying patches");
for (const patch of manifest.patches) {
  const path = resolve(appRoot, patch.path);
  const digest = createHash("sha256").update(readFileSync(path)).digest("hex");
  if (digest !== patch.sha256) throw new Error(`Core patch checksum mismatch: ${patch.path}`);
  git(["apply", "--check", path]);
  git(["apply", path]);
  console.log(`Applied ${patch.path} (${digest})`);
}
