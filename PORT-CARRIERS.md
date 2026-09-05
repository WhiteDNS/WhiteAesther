# Adding Psiphon and Tor as carriers

A brief for whoever picks this up, written straight after building the same thing
in the Android client at `E:\projects\whiteAesther android`. Read
`native/psiphon/README.md` and `native/tor/README.md` there first: they record what
was measured, and most of it transfers.

Start by reading `src-tauri/src/core_supervisor.rs` and `src-tauri/src/chain.rs`
and saying back how the core is supervised and how the chain config is rendered,
**before changing anything**.

## The design, and why this repo is already most of the way there

A *carrier* is whatever gets us out of the network. Each one ends in a SOCKS5
listener on loopback. mihomo owns the interface and routes everything into
whichever carrier is running.

This app already works exactly that way and does not know it. `core_supervisor.rs`
runs the Aether core as a child process and exposes `connected_socks()`;
`chain.rs` declares that listener to mihomo as the proxy named `aether` and puts
every node behind it with `dialer-proxy`. A carrier is one more child process that
ends in a SOCKS listener, and `TUNNEL_PROXY` becoming a parameter rather than the
constant `"aether"`.

So the shape of the work is: a second and third supervisor beside
`core_supervisor.rs`, and one string in `chain.rs` that stops being a constant.

## What is different from Android, and it makes this much easier

- Everything here is already a child process, so there is no "one Go runtime per
  process" problem and no JNI. Psiphon's `ConsoleClient` and `tor.exe` are two more
  supervised children, configured by a file and read on stdout — the same pattern
  `core_supervisor.rs` already implements.
- Windows and Linux have no restriction on executing shipped binaries, so nothing
  has to be disguised as a library the way Android forces.
- A normal `tor.exe` launches its own pluggable transports. Use
  `ClientTransportPlugin obfs4 exec <path>` and do **not** port the Android
  managed-proxy handshake — that existed only because Guardian Project's JNI build
  aborts on `exec`, which cost half a day to find.
- Psiphon is a Go program but nothing here needs to link it. Ship the console
  client binary; the app stays Rust.

## Traps, all found by measurement on Android

1. **tor reports its control port up before it has a circuit.** Poll
   `status/bootstrap-phase` and only report connected at `PROGRESS=100`. Skipping
   this ships a carrier that says connected and carries nothing — which is exactly
   how meek passed review and then failed for three minutes straight.
2. **Never measure the exit address from the process that runs the carrier.** On
   Android that process is excluded from the interface, so the answer was the
   user's own address under a label saying the opposite. Here the equivalent
   mistake is measuring before mihomo is in the path. Ask through the carrier's own
   SOCKS listener.
3. **Tor carries no UDP.** Declare `udp: false` on the proxy *and* put
   `NETWORK,udp,REJECT` above `MATCH`, or DNS and QUIC hang instead of falling
   back within a round trip.
4. **Built-in bridge lists rot.** The first list shipped on Android was written
   from memory and two of its three bridges were already unreachable from an
   uncensored network. Fetch from Tor's own service and health-check every address
   before shipping — port `native/tor/refresh-bridges.ps1`, which does both.
5. **Public bridges are blocked where they matter.** Implement the one-tap fetch
   from `bridges.torproject.org/moat/circumvention/settings`: ask about the
   *user's* country, not the exit's, and send the request through whichever carrier
   is already up, because that host is itself blocked in most of the places its
   answer is wanted. For Iran it currently answers `webtunnel`, and a circuit
   behind it built in seventeen seconds. On a desktop there is no SIM to read the
   country from — offer the field rather than guessing from the exit.
6. **Psiphon replays the server that worked**, so the exit address stops changing
   and users read it as being stuck on one server. Offer the exit country, and read
   the list from Psiphon's own available-regions notice rather than a hardcoded
   table — it reported 25 regions.
7. **Every string that names Cloudflare or assumes the engine has to be re-read.**
   The Android exit-chain screen said "Traffic leaves from Cloudflare" while
   Psiphon was carrying the session out of Singapore, and offered a switch the
   carrier path never reads. A control that saves and does nothing is worse than
   one that is absent.

## Order of work, each ending at a gate checked from outside the app

1. `TUNNEL_PROXY` becomes a parameter, and a carrier setting chooses which
   supervisor runs. **Gate:** the engine path behaves exactly as it does today.
2. Psiphon as a supervised child. **Gate:** a request through its own SOCKS returns
   an address that is not this machine's, and the whole desktop follows once mihomo
   is pointed at it.
3. Exit country. **Gate:** choosing a country moves the exit address.
4. Tor, direct. **Gate:** connected only at bootstrap 100, and an exit relay
   answers.
5. Bridges — built-in, pasted, fetched in one tap. **Gate:** all three reach a
   circuit, and a fetch asked as a censored country returns real lines.
6. Kill switch and leak matrix on both platforms this app ships to. A carrier that
   leaks on failure is worse than no carrier.

## Rules

- Keep mihomo's controller and DNS listener loopback-only.
- The scanner, the endpoint pinning and the discovery depth all describe a search
  for a Cloudflare gateway. Under a carrier they do nothing — say so on the screen
  rather than leaving controls that quietly have no effect.
- Do not claim any carrier works until traffic from another process has been
  observed leaving through it. Building is not evidence.
- Pin every downloaded binary by revision and checksum, the way
  `native/chain/setup.ps1` and `native/psiphon/setup.ps1` do on Android.
- `psiphon-tunnel-core` is GPL-3.0; tor, lyrebird and snowflake are BSD-3-Clause.
  This app is AGPL-3.0, and section 13 permits the combination — but the notice
  obligation is real. Record each one in `THIRD_PARTY_NOTICES.md` with the exact
  revision and where to get the source.
