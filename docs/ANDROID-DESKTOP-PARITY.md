# Android and desktop connection parity

Reference: WhiteAestherMobile v1.16.0, commit
`6e2ade9e86c5f66194c66e6be1e23b40677c2db2`.

This change ports the Android connection policy and its complete Aether 2.4
network core to the desktop. Android framework services, socket protection and
VPN permissions map to the desktop supervisor, carrier processes and TUN
integration. Existing desktop profiles and identities must remain readable.

## Source and build

Desktop 1.10.4 builds the complete committed Android `native/aether` tree,
including its quiche tree, plus `native/third-party/boring-sys-5.3`. It no longer
builds the older desktop 2.3 core with selected 2.4 backports.
`core-source.json` pins the revision, overlay, desktop adapter patch checksum,
and runtime capability contract. `scripts/prepare-core.mjs` archives the pinned
commit rather than copying a possibly modified checkout. Both local builds and
the release workflow use this preparation path.

The adapter patch preserves desktop reporting, identity backups, process locks,
8 MiB engine stacks, continuously owned listeners, network-scoped last-connection
history and strict upstream routing. Android protocol and cryptographic
implementations remain in the shared source, including Boring/tokio-boring 5.3,
the Android BoringSSL patches and post-quantum groups.

## Connection parity matrix

| Android connection behavior | Desktop implementation and coverage |
| --- | --- |
| H2/H3 quick attempts, TLS records, TCP fragmentation, H2/H3 ECH, compact ClientHello, IPv6-only, WOM, deeper H2 and MIM | `src-tauri/src/recovery.rs` supplies the recipe list to `race.rs`, `scanner.rs` and supervisor retries. Tests require every method to remain reachable and preserve explicit ECH-off/require and IPv4-only policy. |
| Separate connection workers for Aether, Psiphon and Tor | `race.rs` runs one sequential recipe worker per carrier. This avoids concurrent Aether processes competing over one identity. A proven engine route delays alternate carriers; an independently verified alternate gets a short engine grace period. |
| Native TLS settings | `tls_options.rs`, `CoreProfile`, `src/types.ts` and `Advanced.tsx` cover MASQUE SNI, API Host/SNI, TLS 1.2/1.3 ciphers, groups/key shares, signature algorithms, certificate compression, ALPS, trust anchors, server padding, GREASE/signature/ECH GREASE, OCSP, SCT, session tickets and extension permutation. Existing ECH DNS/domain, enrollment address, fragmentation size/delay and SNI splitting remain available. Persistence, CLI validation and UI round-trip tests cover the new fields. |
| Successful settings survive selection and reconnect | `RaceWinner.recipe`, `profileForWinner` and backend winner application carry the full recipe, including empty/null fields that clear an older tactic. Original user policy is stored separately so a winning automatic ECH attempt does not become a permanent ECH requirement. Tests cover IPv6, stale ECH and record-shaping winners. |
| Network-scoped proven-route memory | `route_memory.rs` stores the full recipe, TLS/policy context hash and Tor settings. Changed settings invalidate proof. Secrets are hashed rather than written into route memory. Legacy entries remain readable. |
| Endpoint discovery across multiple profiles | `scanner.rs` provisions once, tests cached hints again, scans quick and deeper profiles, attempts two independent real TLS traffic confirmations, and ranks confirmations/jitter. Every returned candidate needs at least one successful confirmation, including when the budget expires. Diagnostics survive recoverable failures; conclusive identity holds stop Aether attempts. |
| Bounded search, cancellation and network change | Recipes have explicit budgets; native scan commands use `--scan-budget-ms`. Search and discovery check cancellation/network changes, terminate child processes, and discard stale results. Workers finish before a winning carrier starts its real session. UI cancellation cannot fall through into `startCore`. |
| Registration, enrollment, activation and Retry-After | Shared Android `account.rs`/`api.rs` implement persisted pending keys, registration budgets and resumable activation. Desktop backup compatibility is retained. Ambiguous non-idempotent API mutations are not replayed after server errors. Core tests cover these transactions and holds. |
| Tor custom bridges, Snowflake, obfs4 and direct fallback | `race.rs` tries these in order with per-mode budgets and carries the successful Tor settings to the real session. `tor.rs` includes startup/control/bootstrap time in its budget. |
| Psiphon stays alive for the search lifetime | `psiphon.rs` accepts a search-specific budget and adjusts its internal establishment timeout; it is not stopped at the earlier fixed search limit. |
| Reconnect after Aether or carrier failure | `core_supervisor.rs` re-enters Automatic search after failure when enabled, including a dead Tor/Psiphon process. Manual chains retain their configured chain. Generation checks cancel obsolete recovery work; a held kill-switch proxy stays held during replacement. |
| Retry pacing | Fast search rounds have Android's one-minute floor, doubling up to eight minutes. Per-session restarts have bounded attempts and cancellable backoff. |
| Out-of-band lane in API setup (1.16) | Shared core `oob.rs`, `fragment.rs`, `https.rs` and `apifront.rs` arrive with the pinned revision; the adapter patch is unchanged apart from context. The lane starts three seconds after the others and its handshake is certificate-verified like every lane. `oob::tests` and `apifront::tests::every_out_of_band_method_completes_a_verified_handshake` run in CI on each platform. |
| Password on the Worker's local listener (1.16) | `worker.rs` renders Xray's inbound with a random 32-character username and password per session. `http_bridge.rs` keeps them in memory by listener address and `socks5_connect` answers with RFC 1929, so the carrier probe, latency probe, LAN share and HTTP bridge all authenticate; `chain.rs` writes them on mihomo's socks5 proxy. The Xray config and mihomo's `config.yaml` are deleted when their session stops. `scripts/test-worker-engine.py` runs real Xray and checks no-auth `05ff`, a wrong password `01ff` and the session's own `0100`. |
| IPv6 only (1.16) | `endpointError` and `CoreProfile::validate` refuse a pinned endpoint outside the chosen family when Aether is in the connection; `has_global_ipv6` asks the routing table for a global source address to warn under the option; a change while connected reconnects. |
| Settings the connection does not use (1.16) | `engineSettingsApply` in `src/types.ts` (automatic routing, or Aether in either hop) decides both what Advanced shows and which connect checks run. Choosing Fragment or Browser in the Worker form turns ECH off. |
| Imported rule lists (1.16) | `rule_lists.rs` parses, stores (app data directory, index plus one file per list), caps, matches and translates to mihomo. Engine rules travel in a content-named routes file rather than on the command line, which on Windows is capped at 32,767 characters. |
| Framing order (1.16) | `recovery::recipes` puts the quick H3 recipe ahead of H2 only when H3 is what last carried traffic on this network; otherwise H2 goes first. A framing won on another network is not evidence here. |
| Correct packaged/runtime core | `tls_options.rs` rejects an incompatible selected core at runtime. Staging and package extraction verify version, pinned revision, patchset, required features, architecture and Windows CRT imports. The required contract is shared with `core-source.json`. |

## Platform mapping

Android `VpnService`, socket protection, network callbacks and foreground-service
lifetime map to the desktop supervisor, native TUN integration, route checks,
owned carrier processes and tray lifecycle. They are platform APIs rather than
portable engine code. Android's notification, tile and widget map to the existing
desktop window/tray controls.

On Windows, whole-device routing uses **Full tunnel** and requires Administrator
permission to create/configure the adapter. System proxy mode covers applications
that honor the proxy. This is a real routing difference from Android's VPN mode;
the app keeps the routing choice and its permission request explicit. Existing
profiles, saved identities and explicit manual settings are retained.

## Validation and limits

Local Windows verification on 2026-10-27:

- Shared adapted Aether core: **523 passed**, 5 live-network tests ignored.
- Windows backend: **228 passed**, 4 environment/live tests ignored, including
  budget expiry before any endpoint traffic confirmation.
- Frontend unit tests: **72 passed**; TypeScript check and production build passed.
- Browser suite: **15 passed**, including new TLS fields, persistence, cancelled
  Automatic search and the small-window scrolling layouts.
- Fresh preparation of the pinned source and adapter patch is compared against
  the tested source tree, normalizing only CRLF/LF in text files. Evidence is in
  `artifacts/diagnostics/desktop-mobile-2026-10-27/core-reconstruction.json`.
- Windows backend results, build logs and extracted installer checks are kept in
  the same diagnostics directory. Package verification exercises only offline
  commands and must not create an identity or register a device.
- Both Windows 1.10.4 EXE/MSI installers were built and extracted successfully.
  Their cores match the staged binary byte for byte and pass the full runtime
  contract, architecture, CRT-import and offline command checks. Local installers
  and SHA-256 sums are in `artifacts/releases/v1.10.4/windows`; the consolidated
  record is `artifacts/diagnostics/desktop-mobile-2026-10-27/implementation-verification.json`.
  No public release was published by this change.

These checks establish implementation and local build behavior. They do not
establish connectivity on a physical Android device, a user's restricted network,
or macOS/Linux. M01's externally supplied partial configuration is deferred; its
actual byte-sending implementation was not provided and it is not part of the
Android v1.15 parity reference.
