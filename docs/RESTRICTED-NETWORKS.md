# Restricted-network bootstrap and native stacks

The desktop supervises Aether as a sidecar; it does not embed Android's JNI
bridge. The changes are maintained in `patches/aether/restricted-networks.patch`
on top of the exact `core-source.json` revision. CI verifies the patch SHA-256,
applies it before building, and executes the core extracted from each installer.
Staging and package verification require the new patchset and capabilities, so
an older Aether 2.3 binary cannot accidentally be shipped under the same version.

For a local engine build, clone `WhiteDNS/Aether` into `aether-core`, check out
the revision in `core-source.json`, run `node scripts/apply-core-patches.mjs`,
then build its `aether/Cargo.toml` with Cargo. Windows release builds must use
`CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS=-C target-feature=+crt-static`,
as CI does. The staging script finds this workspace build before sibling repos.

Android references:

- Initial bootstrap and stack fix: [fbbe8346](https://github.com/WhiteDNS/WhiteAestherMobile/commit/fbbe8346a883af63efe57f73416abbbdcf0a95a8).
- Enrollment and endpoint recovery: [ca457726](https://github.com/WhiteDNS/WhiteAestherMobile/commit/ca457726f9f0be8ed58c25b0efe7d3d0a0f620ad), as included in [v1.14.0](https://github.com/WhiteDNS/WhiteAestherMobile/tree/388e48311de386e8b321632bb48c1dc90dc35c70).

## Connection behavior

On an unproven network, MASQUE H2 gets a three-second lead over the other engine
trials. A verified route recalled for that same network receives the lead
instead. H3, nested MASQUE and the other carriers remain available. The MASQUE
SNI is `www.cloudflare.com`; the existing certificate pin verification remains
in place. API and resolver HTTPS retain CA and hostname verification.

Default enrollment probes a bounded, diverse Cloudflare IP pool, including
`188.114.97.6`, with 1.2-second TCP probes. A TCP answer only admits an IP to
authenticated TLS trials. Direct TLS, split ClientHello (including the previous
TLS 1.2 fingerprint), and ECH compete before any HTTP mutation is sent. ECH
lookup stays inside its lane; the winning handshake cancels all losing futures
and sends the single request. A dropped exchange, malformed success, or 5xx/408
after a mutation is returned without replaying that mutation on another route.

An explicit ECH policy or enrollment address disables adaptive enrollment.
`off` is passed explicitly. A manual ECH list is validated, and `auto` cannot
silently fall back to clear SNI. Resolver URLs remain separate from Base64
ECHConfigList data. Lookup failures (`ECH_KEY_FETCH_FAILED`), invalid lists
(`ECH_CONFIG_INVALID`), and server ECH rejection are distinguishable. A required
key that cannot be obtained or parsed stops automatic reconnect of that same
configuration, including while the kill switch holds traffic.

Registration is saved before certificate enrollment. Its pending certificate
and private key are saved before PATCH and reused after interruption. Enrollment
updates the interface addresses and assigned endpoint from Cloudflare's answer.
429 and the full Retry-After, including HTTP dates, are retained across restarts
for registration and enrollment. Desktop sidecars share an OS file lock around
Identity read/modify/provision sequences; killing a losing sidecar releases it.
Existing Identity and profile formats remain readable.

A successful trial returns its actual gateway to the final session as a
custom-first endpoint, together with its framing, fragmentation and ECH policy.
Endpoint caches are namespaced by desktop network identity. Unknown networks
use process-local cache names rather than inheriting another network's success.
The global legacy cache remains on disk. Every candidate is authenticated again,
and a trial wins only after verified TLS traffic passes through its SOCKS route.

## Stack and cancellation

The CLI entry point constructs and polls its root future on an 8 MiB engine
thread. Its Tokio workers also have 8 MiB stacks. The public prepare operation
dispatches construction and polling of its inner future onto an 8 MiB thread;
dropping its receiver cancels that operation and tears down its runtime. Large
HTTPS exchange futures and response buffers are heap allocated. This addresses
the calling thread that `#[tokio::main]`/`block_on` uses as well as worker stacks.

## Validation and field testing

CI runs the core library tests, formatting and Clippy, frontend tests/build,
release-mode Tauri tests, and installer extraction/architecture/offline-command
checks separately on Windows x86_64, macOS arm64/x86_64, and Linux arm64/x86_64.
The package verification JSON records the base revision, patchset, patch
checksum, native imports and each installer's SHA-256.

Focused tests cover authenticated handshake races with one HTTP registration,
untrusted certificates, stalled loser cancellation, incomplete mutation replies,
long Retry-After, pending-key reuse, enrollment metadata, file-lock cancellation,
H2/recalled-route priority and explicit ECH settings. A 256 KiB caller test
constructs and polls real prepare and checks stack-heavy root and worker work.
Prepare uses offline invalid-option rejection in this test to avoid provisioning
a public Cloudflare account. Live enrollment/operator tests remain opt-in.

Local tests or successful CI builds do not establish carrier connectivity in
Iran. Field tests should include MCI and Mokhaberat, both a new and an existing
Identity, cancellation during bootstrap, interruption after PATCH, ECH resolver
failure/rejection, a network switch, H3 recovery and actual browsing over the
resulting tunnel. Report platform, operator, framing, elapsed time and redacted
logs; do not include Identity backups or private keys.
