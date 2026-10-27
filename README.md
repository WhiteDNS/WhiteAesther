# WhiteAesther

Cross-platform desktop control surface for the Aether connection core.

## Aether credits and support

The [Aether connection core](https://github.com/CluvexStudio/Aether) was created by
[CluvexStudio](https://github.com/CluvexStudio). Credit for the original core and its networking
work belongs to CluvexStudio and the Aether contributors. WhiteAesther provides the desktop
interface and integration around the [shared Android Aether core](https://github.com/WhiteDNS/WhiteAestherMobile/tree/v1.15.0/native/aether).

Please visit [CluvexStudio's Telegram channel](https://t.me/CluvexStudio) for updates and information
on supporting the original developer's work. Thank you to CluvexStudio for developing Aether.

## Working features

- Starts, monitors and stops a real Aether process from the Tauri backend
- Verifies the core executable and reports its exact version before connecting
- Exposes MASQUE H2, MASQUE H3, WireGuard and WARP-in-WARP profile controls
- Maps discovery, validation, fragmentation, reconnect, DNS, routing and Zero Trust settings to validated core arguments
- Streams real process logs and derives connection state, edge and latency from core events
- Retries failed connections on a widening delay, up to twelve attempts, and reports the current attempt
- Shares Android's H2/H3, record shaping, ECH, IPv6, WOM and MIM recovery recipes across discovery and reconnects; Automatic also rechecks alternate carriers
- Pins a specific endpoint with a choice of falling back to discovery when it fails, or reporting the failure rather than silently substituting
- Builds a reviewable diagnostics report that redacts addresses by default and carries no Zero Trust credentials
- Persists profiles locally while keeping Access secrets and tokens memory-only
- Ranks reachable gateways by round-trip time without connecting, sweeping the other transport when one finds nothing, and pins the one you choose
- Bundles a target-specific Aether sidecar in Windows, macOS and Linux packages

- Points the operating system's proxy at the SOCKS5 listener while connected, restores it on disconnect, and repairs it on the next launch if the app was killed

A full-device tunnel remains a roadmap item and is labeled as such in the UI.

## Development

Requirements: Node.js 24+, pnpm 10+, Rust 1.88 and the platform-specific Tauri prerequisites. The unit tests are TypeScript run directly on Node's test runner, which needs 22.18 or newer for type stripping; 24 is what CI uses.

Builds use the pinned Android Aether 2.4 source with desktop adapters, including BoringSSL 5.3. Prepare and compile the shared core first:

```sh
git clone https://github.com/WhiteDNS/WhiteAestherMobile.git aether-source
git -C aether-source checkout --detach 2409297365e23e3fd320a87c0da73d0656bee67c
node scripts/prepare-core.mjs --checkout aether-source --destination aether-core
cargo build --release --locked --manifest-path aether-core/aether/Cargo.toml
```

The staging script checks the exact revision, patchset, required capabilities and executable architecture. Windows core builds need the static CRT (`-C target-feature=+crt-static`). Then run:

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

## Android and desktop connection parity

See [the parity matrix and validation](docs/ANDROID-DESKTOP-PARITY.md). Earlier integration history remains in [the Persian guide](docs/AETHER-2.3.fa.md), [the selected 2.4 backports](docs/AETHER-2.4-BACKPORTS.md) and [the earlier verification evidence](docs/AETHER-2.3-VALIDATION.md).
