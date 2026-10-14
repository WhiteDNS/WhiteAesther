# Unreleased desktop: Aether 2.3

- Upgrade the desktop fork to Aether 2.3 networking while retaining scanner JSON, identity
  backup/restore, routing, the existing carriers and clean sidecar teardown.
- Add TLS 1.2 ciphers, colon-separated key groups, GREASE control, registration destination,
  ECH resolver/domain, H2/H3 ECH, Verified edges and WireGuard over MASQUE.
- Add an H2+ECH Automatic trial and retain the actual winning tactic in network route memory.
  Keep the core’s eight validated gateway records as a separate layer; save CLI history on readiness.
- Preserve new edits when an earlier Save completes; serialize profile writes. Invalid settings
  keep their text and report the engine’s validation error.
- Stage only the pinned core revision with the required desktop commands and matching native architecture.

Defaults: new text fields empty, GREASE enabled, ECH off unless selected or tried by Automatic.
Empty ECH resolver on an active ECH attempt uses authenticated DoH at https://1.1.1.1/dns-query.
Old profiles and identity backups remain compatible. No app version bump or public release is implied.

See [the Persian guide](AETHER-2.3.fa.md) and [implementation/verification notes](AETHER-2.3-VALIDATION.md).
Fixture and UI tests do not establish connectivity on restrictive networks; live acceptance remains separate.
