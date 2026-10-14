# WhiteAesther

Cross-platform desktop control surface for the Aether connection core.

## Working features

- Starts, monitors and stops a real Aether process from the Tauri backend
- Verifies the core executable and reports its exact version before connecting
- Exposes MASQUE H2, MASQUE H3, WireGuard and WARP-in-WARP profile controls
- Maps discovery, validation, fragmentation, reconnect, DNS, routing and Zero Trust settings to validated core arguments
- Streams real process logs and derives connection state, edge and latency from core events
- Retries a failed core on a widening delay, up to eight attempts, and reports which attempt it is on
- Alternates MASQUE H2 and H3 across those retries, so a network that blocks UDP does not fail eight times over QUIC
- Pins a specific endpoint with a choice of falling back to discovery when it fails, or reporting the failure rather than silently substituting
- Builds a reviewable diagnostics report that redacts addresses by default and carries no Zero Trust credentials
- Persists profiles locally while keeping Access secrets and tokens memory-only
- Ranks reachable gateways by round-trip time without connecting, sweeping the other transport when one finds nothing, and pins the one you choose
- Bundles a target-specific Aether sidecar in Windows, macOS and Linux packages

- Points the operating system's proxy at the SOCKS5 listener while connected, restores it on disconnect, and repairs it on the next launch if the app was killed

A full-device tunnel remains a roadmap item and is labeled as such in the UI.

## Development

Requirements: Node.js 24+, pnpm 10+, Rust 1.88 and the platform-specific Tauri prerequisites. The unit tests are TypeScript run directly on Node's test runner, which needs 22.18 or newer for type stripping; 24 is what CI uses.

The endpoint scanner needs the reporting modes added in [WhiteDNS/Aether](https://github.com/WhiteDNS/Aether), so builds use that fork rather than upstream. Clone it beside this repository as `Aether-whiteaesther`, or set `AETHER_CORE_SOURCE` to an executable built from it. Then run:

```text
pnpm install
pnpm desktop:dev
```

The staging command verifies the executable with `aether --version` and copies it to Tauri's target-triple sidecar name. To create an installer:

```text
pnpm desktop:build
```

The desktop packaging workflow builds Aether and WhiteAesther together on Windows, macOS and Linux. Release builds are pinned to a reviewed Aether commit rather than a moving branch.

## Validation

```text
pnpm build
pnpm test
cargo test --manifest-path src-tauri/Cargo.toml --locked
```

`pnpm test` runs the frontend unit tests on Node's own test runner, with no test framework installed. It covers the diagnostics report, including that redaction removes every address form the core actually logs and leaves timestamps alone.

The Windows end-to-end smoke test also verifies core discovery, live state events, SOCKS5 exposure, a proxied request and clean shutdown.

## Licence

WhiteAesther is licensed under the **GNU Affero General Public License v3.0** — see `LICENSE`. It
builds on the Aether connection engine, which is AGPL-3.0, so this client is a derivative work and
its source stays public.

Aether is a trademark of CluvexStudio and the Aether project, used here by written permission. See
`THIRD_PARTY_NOTICES.md`. WhiteAesther is not an official Aether product.

## Aether 2.3 desktop integration

See [the Persian settings and upgrade guide](docs/AETHER-2.3.fa.md), [v1.10.0 release notes](docs/releases/v1.10.0.md), and [verification evidence](docs/AETHER-2.3-VALIDATION.md).
