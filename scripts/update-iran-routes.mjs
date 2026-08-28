/**
 * Refreshes the bundled Iran routing lists from Chocolate4U/Iran-clash-rules.
 *
 * These are compiled into the binary with `include_str!` (see
 * src-tauri/src/iran_routes.rs), not fetched at runtime: fetching them would
 * need a working connection to GitHub, which is exactly what a filtered
 * network does not have -- the same chicken-and-egg problem `GEOIP` databases
 * have. A snapshot is committed instead, and this script is how it moves
 * forward. Not run automatically; run it by hand before a release when the
 * upstream lists are worth pulling in again.
 */
import { readFile, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const appRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SOURCE = "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release";

const FILES = [
  {
    upstream: "ircidr.txt",
    local: "routing/iran-ip-ranges.txt",
    kind: "IP ranges",
  },
  {
    upstream: "ir-lite.txt",
    local: "routing/iran-domains.txt",
    kind: "non-.ir domains hosted in Iran",
  },
];

const today = new Date().toISOString().slice(0, 10);

for (const file of FILES) {
  const url = `${SOURCE}/${file.upstream}`;
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`${url} responded ${response.status}`);
  }
  const body = await response.text();
  const header =
    `# WhiteAesther: bundled ${file.kind} used to let Iranian sites bypass the tunnel.\n` +
    `# Source: https://github.com/Chocolate4U/Iran-clash-rules (release/${file.upstream})\n` +
    `# License: GPL-3.0 -- see THIRD_PARTY_NOTICES.md\n` +
    `# Snapshot taken: ${today}. Refresh with scripts/update-iran-routes.mjs.\n`;

  const path = join(appRoot, file.local);
  const previous = await readFile(path, "utf8").catch(() => "");
  const previousBody = previous.split("\n").slice(4).join("\n");
  const nextBody = body;
  if (previousBody.trim() === nextBody.trim()) {
    console.log(`${file.local}: unchanged upstream`);
    continue;
  }

  await writeFile(path, header + body);
  console.log(`${file.local}: updated (${(body.length / 1024).toFixed(0)} KB)`);
}
