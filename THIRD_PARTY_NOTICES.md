# Third-party notices

WhiteAesther is distributed with, and builds on, the software below. Each remains under its own
licence, and those licences are not superseded by WhiteAesther's.

## Aether

The connection engine. WhiteAesther ships the `aether` executable inside its installers and runs it
to connect, and in a reporting mode to populate the endpoint picker.

- Upstream: <https://github.com/CluvexStudio/Aether> — version 1.8.0
- The build used here: <https://github.com/WhiteDNS/Aether> at tag `v1.8.0-whiteaesther.1` — a fork
  adding the two reporting modes the endpoint picker needs, with upstream history preserved and
  every change reviewable as a diff against it
- Licence: GNU Affero General Public License v3.0 — see `LICENSE`, also installed as
  `licenses/whiteaesther-AGPL-3.0.txt`
- Copyright: the Aether authors

Because WhiteAesther is built around Aether and distributes it, WhiteAesther is treated as a
derivative work and is licensed AGPL-3.0. Its complete source is public at <https://github.com/WhiteDNS/WhiteAesther>.

### Trademark

"Aether", the Aether logo and its branding are trademarks of CluvexStudio and the Aether project,
and are **not** covered by the AGPL-3.0 grant. Use of the name in the WhiteDNS fork is by written
permission from the Aether maintainers, conditional on that repository remaining public. See
`TRADEMARK.md` in the Aether repository.

WhiteAesther is not an official Aether product and is not endorsed by the Aether project. Problems
with WhiteAesther should be reported to WhiteDNS, not to the Aether maintainers.

## mihomo

The second hop behind the Exit chain feature. WhiteAesther ships the `mihomo` executable inside its
installers and drives it over its local control API; the two are separate programs communicating
over documented interfaces, and no mihomo code is linked into WhiteAesther.

- Upstream: <https://github.com/MetaCubeX/mihomo>
- The build shipped here: release `v1.19.30`, downloaded unmodified by `scripts/stage-chain.mjs`
- Corresponding source: <https://github.com/MetaCubeX/mihomo/tree/v1.19.30>
- Licence: GNU General Public License v3.0 — the full text is in `licenses/mihomo-GPL-3.0.txt`,
  copied verbatim from that tag and installed alongside the binary
- Copyright: the mihomo authors

**Read the licence from the tag, not from the repository's front page.** The default branch of
`MetaCubeX/mihomo` is `main`, which carries an unrelated project under an MIT licence
("Copyright 2023 KT") — and GitHub's licence API reports *that* file, so the repository shows as
MIT at a glance. The proxy core lives on the `Meta` branch and its releases, and `LICENSE` at
`v1.19.30` is the GNU GPL v3. The build we distribute is GPL-3.0.

Because mihomo is conveyed as a separate executable rather than linked, its licence does not extend
to WhiteAesther's own source, which remains AGPL-3.0. GPL-3.0 still obliges us to pass the licence
on with the binary and to say where its source is; both are above.

## Iran routing lists

The lists behind "Iranian sites bypass the tunnel": the IP ranges allocated to Iran, and the
non-`.ir` domains hosted inside it. Compiled into the binary as plain text (see
`routing/` and `src-tauri/src/iran_routes.rs`) rather than fetched at runtime, because
fetching them would need the working connection they exist to make unnecessary.

- Upstream: <https://github.com/Chocolate4U/Iran-clash-rules>
- The snapshot shipped here: `ircidr.txt` and `ir-lite.txt` from the `release` branch, taken
  unmodified apart from a four-line provenance header, and refreshed by
  `scripts/update-iran-routes.mjs`
- Licence: GNU General Public License v3.0
- Copyright: the Iran-clash-rules contributors

These are data rather than code, and they are conveyed verbatim. WhiteAesther is AGPL-3.0, which
carries the same obligations GPL-3.0 asks of us here: the source of the lists is named above and
the app's own source stays public.

## Cloudflare WARP

WhiteAesther connects to Cloudflare's WARP and MASQUE infrastructure using the protocols Aether
implements. It is not affiliated with, endorsed by, or sponsored by Cloudflare, Inc. "Cloudflare"
and "WARP" are trademarks of Cloudflare, Inc.

## Bundled fonts

- **Inter** — SIL Open Font License 1.1, © The Inter Project Authors
- **IBM Plex Mono** — SIL Open Font License 1.1, © IBM Corp.

## Application dependencies

The Rust and JavaScript dependencies are recorded in `src-tauri/Cargo.lock` and `pnpm-lock.yaml`,
each under its own licence — predominantly MIT and Apache-2.0. Notable components include Tauri
(MIT/Apache-2.0), React (MIT), Radix UI (MIT), Tailwind CSS (MIT), shadcn/ui (MIT) and Lucide
(ISC).
