# Aether 2.3 validation — 2026-10-14

The initial delivery was local only, with desktop version 1.9.9. Its installers remain local
previews. The user subsequently authorized GitHub publication, merge and release of v1.10.0.
The release is an initial prerelease; native CI results are recorded in GitHub checks.
The original Android and sibling core checkouts were not changed. Existing desktop notes and
untracked user files are excluded from the implementation commit.

## Sources and reproducibility

- Desktop baseline: `611f9e0eab0c77d77ca0a64c4a8d194ff1421b24`.
- Android reference: `f15fc92d5eec14c35e3dbe4ca11d1a19dc0e9a4f`.
- Upstream Aether 2.3.0: `6175b67df370ab856bcee07fe85b524031903956`.
- Desktop core baseline: `d031a1f57357941f12f0a36a9d5e124914aae63a`.
- Final core: `9d91b294f613d2e6961f04f3a1d5a01e3353615b`, branch `codex/desktop-2.3`.
- Desktop branch: `codex/android-aether-2.3`.

`core-source.json` and the desktop workflow pin the final core. Staging checks its exact clean
revision, version, native architecture, required capabilities/help, real BoringSSL validation
and missing-identity export without provisioning. The core's `DESKTOP_2_3.md` describes merge
provenance and retained desktop behavior. Official boring-sys 5.2.0 is vendored with only a NASM
include-path quoting correction; Android NDK executable changes were excluded.

The core commit was published on `codex/desktop-2.3` in WhiteDNS/Aether for the native checks.
The five-platform matrix is now required before release. The local core Git bundle can also be imported into a checkout
containing the baseline without changing its working tree:

```powershell
git -C 'E:\projects\Aether-whiteaesther' fetch '<absolute path to aether-2.3-core.bundle>' 'codex/desktop-2.3:codex/desktop-2.3'
```

To build locally, build that core with its locked dependencies, then explicitly stage its binary:

```powershell
$env:CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS = '-C target-feature=+crt-static'
cargo build --release --locked --manifest-path '<core checkout>\aether\Cargo.toml'
```

Set this before building the Windows core and desktop. The official boring-sys build uses the
target feature to select CMake's static MSVC runtime. Then stage the built core and package:

```powershell
node scripts/stage-core.mjs --source '<absolute path to release\aether.exe>'
pnpm tauri build --verbose --bundles 'nsis,msi'
```

Existing chain/Psiphon/Tor staging remains required on a clean checkout. The conventional sibling
core search deliberately rejects the previous 2.0 binary instead of silently packaging it.

## Completed checks

| Check | Actual result |
|---|---|
| Core library, serial execution | 470 passed; 6 opt-in live tests ignored; final static-runtime release profile passed |
| Core formatting | Passed |
| Core all-target clippy | Completed with warnings; strict `-D warnings` is not clean |
| Windows core release | Built in `D:\codex-build\whiteaesther core23`, including a space; exact revision verified |
| Desktop backend library | 222 passed; 4 opt-in tests ignored; debug and static-runtime release profiles passed |
| Desktop backend clippy | Completed with existing style/dead-code warnings |
| New TLS validation module formatting | Passed; whole-backend formatting has pre-existing differences |
| Frontend/script tests | 69 passed |
| TypeScript | Passed |
| Production frontend build | Passed |
| Rendered UI with final release core | 7 passed |
| Windows x86_64 NSIS and MSI | Both built; both extracted cores passed exact revision, architecture, PE runtime and offline JSON command checks |
| Workflow YAML | Parsed locally; five native targets present; GitHub checks track release validation separately |

UI tests use the actual React application in Chromium with controlled Tauri IPC and fixture
storage. They cover character-by-character typing, clipboard paste, clear, late Save, queued
Saves, reload and invalid BoringSSL names followed by correction. Restoring the previous Save
handler reproduced the lost-edit failure in all five field scenarios; the fix passed them.
Reload verifies the fixture's saved state, not a native app restart or OS credential storage.
Existing Rust profile/identity tests cover the native contracts separately.

## Platform and network limits

Windows x86_64 is the locally buildable target. Package verification extracts each generated
installer and executes its embedded Aether, checking revision, architecture and offline commands.
The first build exposed `MSVCP140.dll`/`VCRUNTIME140.dll` imports in the core. Windows builds
now select `crt-static`; staging and extracted-package verification read PE imports and reject
unbundled VC runtime dependencies. The old dynamic build was correctly rejected by that guard.
Final extracted cores import only Windows system DLLs. Both installers successfully executed
capabilities, TLS validation, missing-identity export/import errors and scanner/test-endpoint
JSON errors forced by invalid TLS before any networking. `delivery/package-verification.json`
records their SHA-256 hashes and native imports. MSI bundling completed with four WiX ICE warnings
from the generated installer template; these are not a fresh-machine installation result.
This does not replace installation on a fresh Windows machine without developer dependencies.
macOS arm64/x86_64 and Linux arm64/x86_64 have not been built or executed here; their native CI
jobs include core/backend tests, locked builds and extracted-package execution.

Local TLS/ECH/DNS/task-cancellation fixtures do not prove live connectivity. No claim is made
about restrictive-network H2/H3 ECH, Automatic, WOM, real registration or reconnect. Those remain
live acceptance checks. Full tunnel/elevation/system-proxy crash recovery was not exercised on
the host during this work; its existing implementation and tests were preserved.

See [the Persian guide](AETHER-2.3.fa.md) for settings, defaults, compatibility and upgrade steps,
and [v1.10.0 release notes](releases/v1.10.0.md) for the user-facing changes.
