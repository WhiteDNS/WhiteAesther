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
- The build shipped here: release `v1.19.30`, downloaded unmodified by `scripts/stage-chain.mjs`,
  which refuses to stage an asset whose SHA-256 is not the one pinned in that script — so
  "unmodified" is checked at build time rather than asserted here. The Windows x86-64 binary we
  ship is `6ac25fcb26afe8e1bea24b6e6e80805bf884a33232d12e2d78dfa0b6c529ac14`; the digests for the
  other five targets are in `DIGESTS` in the same script.
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

## psiphon-tunnel-core

The Psiphon carrier. WhiteAesther ships the `psiphon-tunnel-core` console client inside its
installers and drives it as a child process, reading its JSON notice stream and routing traffic
into the SOCKS5 listener it produces. The two are separate programs communicating over documented
interfaces, and no Psiphon code is linked into WhiteAesther.

- Upstream: <https://github.com/Psiphon-Labs/psiphon-tunnel-core>
- The build shipped here: **built from source**, not downloaded. Psiphon publishes no console-client
  executable — its releases carry only `Psiphon-Android-Library.zip`, `Psiphon-Client-Library.zip`
  and `Psiphon-iOS-Library.zip` — so `scripts/stage-psiphon.mjs` compiles `./ConsoleClient` from the
  pinned revision `v2.0.41` with `CGO_ENABLED=0 go build -trimpath`.
- Corresponding source: <https://github.com/Psiphon-Labs/psiphon-tunnel-core/tree/v2.0.41>
- Licence: GNU General Public License v3.0 — the full text is in
  `licenses/psiphon-tunnel-core-GPL-3.0.txt`, copied verbatim from that tag and installed alongside
  the binary
- Copyright: Psiphon Inc.

Because we build and distribute this binary rather than merely fetching one, GPL-3.0's source
obligation is ours to meet: the revision above is the exact source of what we ship, and the build
command is recorded here and in the staging script so anyone can reproduce it.

`PropagationChannelId` and `SponsorId` are set to the all-Fs and all-1s placeholders that appear in
tunnel-core's own tests and in open-source clients that have not been issued their own. They are not
credentials and authenticate nothing; they identify who distributed a client so Psiphon can plan
capacity. Ours are therefore indistinguishable from every other unattributed client.

### The bootstrap server list

`psiphon_server_entries.txt` is the embedded list tunnel-core bootstraps from — one hex-encoded
server entry per line. Psiphon publishes it only inside their own clients, so it is fetched from a
third-party mirror (`mbm110/MSN-GUARD`) pinned to a revision and verified against a SHA-256 before
it is staged. That is safe in a way it would not be for a binary: every entry is signed and verified
by tunnel-core itself, so a substituted file costs a slow first connect rather than trust. Psiphon
replaces the list from inside the tunnel once a connection is up.

## Tor, and the lyrebird pluggable transport

The Tor carrier. WhiteAesther ships `tor` and `lyrebird` inside its installers and drives `tor` as a
child process over its loopback control port, routing traffic into the SOCKS5 listener it produces.
`tor` launches `lyrebird` itself when bridges are turned on. All are separate programs communicating
over documented interfaces, and none of their code is linked into WhiteAesther.

- Upstream: <https://gitlab.torproject.org/tpo/core/tor> and
  <https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird>
- The build shipped here: the **Tor Expert Bundle** `15.0.21`, downloaded unmodified by
  `scripts/stage-tor.mjs` and verified against the SHA-256 Tor publishes for it in
  `sha256sums-signed-build.txt` — so the check is against Tor's own number, not one we computed from
  bytes we happened to receive. The Windows x86-64 bundle we ship is
  `f22b8b17cb18c9fa775dfcf68acf6a2fe788336535fe94645204ca85158aa490`; the digests for the other
  targets are in `BUNDLES` in that script.
- Corresponding source: <https://dist.torproject.org/torbrowser/15.0.21/>
- Licence: BSD 3-Clause. The full texts are in `licenses/tor-BSD-3-Clause.txt` and
  `licenses/lyrebird-BSD-3-Clause.txt`, copied out of that same archive rather than fetched
  separately — a licence file that can drift from the build it describes is worse than none.
- Copyright: The Tor Project, Inc., and contributors

The bundle also supplies `geoip`, `geoip6`, and `pt_config.json`. That last file carries **Tor's own
built-in bridge lists**, which is why WhiteAesther maintains none of its own: a hand-written list
rots between releases, and this one can only go stale when the bundle does.

Tor publishes no expert bundle for `windows-aarch64` or `linux-aarch64`. Builds for those targets
ship without the Tor carrier, and the application offers only the carriers it actually has.

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
