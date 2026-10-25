# Aether 2.4 networking backports

The desktop core remains based on WhiteDNS/Aether 2.3.0 at
`9d91b294f613d2e6961f04f3a1d5a01e3353615b`. Patchset
`restricted-networks-v2` incorporates selected networking changes from upstream
2.4.0 (`d58f9d568083129ce2c767c85054021eb3ee6a38`). `core-source.json`
records the base, backport provenance, required features and cumulative patch
checksum. This is not a wholesale replacement with the upstream release binary.

## API bootstrap and identities

- Default WARP API names are `api.devices.cloudflare.com`, followed by
  `api.cloudflareclient.com`. Authenticated TLS handshakes compete with a
  200 ms lead for the preferred name. An answering API name is preferred for
  subsequent calls in that run.
- The existing bounded direct, fragmented and ECH bootstrap lanes remain.
  The two additional upstream API edge candidates are included in their pool.
  Losing handshakes are cancelled before an HTTP mutation is sent.
- An explicit 403/404 gateway page can fall back to the other API name.
  Ambiguous transport failures, malformed successful responses and mutation
  5xx/408 replies are not replayed. Gateway pages do not revoke saved identities.
- `--api-address`, `--api-host` and `--api-sni` are supported. The desktop's
  existing enrollment-address setting now emits `--api-address`, while retaining
  its saved profile key. `--enroll-address` remains a compatibility override
  using the previous API name. New environment variables are cleared when the
  desktop starts a child, alongside the old TLS and enrollment variables.
- Fresh WG and MASQUE registrations persist `warp_activation_pending` before
  further network work. Activation sets `warp_enabled` and clears the pending
  marker only after the API acknowledges it. Cancellation resumes the same
  registration. MASQUE enrollment still persists and reuses its pending key.
- Old stores default the new marker to false. Existing identities continue to
  work without adding an activation API dependency at every startup.
- Activation stays inside the provisioning and OS store locks. The nested
  WG-over-MASQUE activation path also holds the OS store lock.
- Full Retry-After durations and persisted registration budgets remain in use.
  Safe reads no longer sleep for Retry-After after the final attempt.

## Listener, reconnect and gateway behavior

The CLI owns its SOCKS and optional HTTP listener continuously from before
provisioning until exit. Each tunnel receives a duplicate socket. This retains
the port and queued clients between tunnels without sharing ownership with an
independent embedded session. Desktop readiness still depends on the existing
post-validation serving event, rather than a new early-listener log event.

Two successive MASQUE tunnels shorter than five minutes cause an automatically
selected gateway IP to rest for five minutes and be excluded from scans.
Manually pinned peers remain selected. A tunnel lasting at least five minutes
resets the failure count for MASQUE, WireGuard and both nested modes.

The scan includes upstream's 297 recent IPv4 gateways on the configured MASQUE
ports and adds the 199/103 IPv4/IPv6 gateway knowledge. Assigned endpoints,
custom peers, network-scoped history, fair port/family scheduling and wider
fallback ranges are retained. Reachability still requires authenticated and
data-plane verification; the upstream candidate list alone is not proof that an
address works on the user's operator.

Invalid upstream proxy settings fail option validation before provisioning.
The additional upstream MASQUE certificate pin is installed while preserving
the fork's existing pin policy and CA/hostname checks for API and DoH HTTPS.

## Preserved and separate work

The desktop JSON scanner, offline option check, identity backup/import format,
WG-over-MASQUE flag, classic gool profile mapping, scoped upstream routing,
8 MiB engine stacks and cancellation behavior remain intact.

BoringSSL/boring 5.3 and upstream's expanded TLS fingerprint controls are not
included in this backport. The existing 5.2 dependency set remains locked.
Upstream's built-in Tor/Psiphon lifecycle, exit-country policy, statistics and
Android API-level change are also outside this desktop patch. Desktop carrier
sidecars retain their separate implementation and build configuration.

## Reproduction and verification

Use the pinned base and `node scripts/apply-core-patches.mjs <core-checkout>`,
then the existing core tests, formatting, Clippy and staging commands. Windows
builds must retain `-C target-feature=+crt-static` and set
`AETHER_BUILD_REVISION` to the pinned base revision. Staging requires patchset v2
and all five new capability labels, so the previously staged unpatched local
2.3 executable is rejected.

Focused regression fixtures cover API-name fallback without duplicate
registration, ambiguous replies, invalid names, interrupted/resumed activation,
legacy identities, persistent SOCKS/HTTP port ownership, isolated embedded
sessions and gateway strike/reset/expiry rules. Public Cloudflare registration
and real operator connectivity are not exercised by these local tests.

Local Windows validation on October 25, 2026:

- Core: 492 passed, 5 live-network tests ignored.
- Desktop backend: 226 passed, 4 integration tests ignored.
- Frontend: 71 passed; TypeScript check passed.
- Core formatting passed; Clippy completed with the existing warnings.
- The cumulative patch applied to 21 files reconstructed from the pinned Git
  revision, and every resulting file matched the tested working source.
- Windows executable architecture, static-runtime imports and real offline
  API-option parsing passed. Staging and package verification share those API
  checks, including legacy address compatibility and malformed upstream rejection.

The first full core run hit the pre-existing 10-second fragmentation-fixture
timeout while release compilation was active. Its isolated rerun passed, and
the final complete core suite passed without changing that fixture or its timeout.
Local Windows NSIS and MSI installers were subsequently built on October 25,
2026. Both extracted cores passed the offline package checks and their SHA-256
matched the verified staged core. The packages and verification reports are in
`artifacts/restricted-networks/local-windows-1.10.1-aether-v2-20261025/`.
The local build did not publish a release or exercise real-operator connectivity.
