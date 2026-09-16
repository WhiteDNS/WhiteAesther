# What to take from the Android client, after its 1.7.0

A brief for whoever picks this up, written straight after shipping the same
round of work in the Android client at `E:\projects\whiteAesther android`. Its
`docs/AETHER_2_0_MERGE.md` and the commit `Find the way out on networks that lie
about DNS` are the sources.

Read this before reaching for that repo, because the obvious assumption is
wrong: **on the two findings that mattered most over there, this repo was
already right and Android was behind.** Both were checked here rather than
assumed, and the evidence is below. Re-doing them would cost days and change
nothing.

Start by reading `src-tauri/src/carrier.rs`, `core_supervisor.rs` and
`http_bridge.rs` and saying back how a carrier is chosen today, **before
changing anything**.

## Two corrections, added 2026-09-15 after checking the brief against the code

**There is an automatic mode, and it shipped in 1.9.1.** Section 2 below says
this repo does not have one, on the strength of `grep automatic
src-tauri/src/carrier.rs`. That grep was in the wrong language: the feature is
`src/features/carrierSearch.ts` and `WayOutSearch` in `Advanced.tsx`. It tries
three single carriers and six pairs, with a per-carrier cap taken from the
deadline each already enforces on itself. So section 2 is not "build an
automatic mode", it is **"race what already runs in turn"** — a smaller change
than it reads, and the losing-attempt teardown it asks for is already there.

The lanes point in that section also answers a blocker this repo hit
independently: racing looked impossible here because `Psiphon::start` begins
with `self.stop()` and the supervisor holds one child. Android's answer is one
route at a time *per carrier* rather than per lane, which makes
`aether | psiphon | tor` raceable as they stand. Racing both MASQUE framings at
once turned out not to need the supervisor to hold more than one child either:
a trial engine is an ordinary process on a private port, owned by the race
rather than by the supervisor. **Done 2026-09-15** in `race.rs` — the singles
race, the pairs stay sequential because every pair uses two of the three
carriers and there is no fourth to run a second pair with.

**Section 2's point about deciding a winner landed on code that had just
shipped, and it was right.** 1.9.1's check was `probe_latency` — a byte back
from `1.1.1.1:80` over plain HTTP, which an interception answers too. Replaced
2026-09-15 by `carrier_probe.rs`: a verified TLS handshake to a name the carrier
resolves. The TLS-through-a-carrier machinery this needed already existed in
`moat.rs` and now lives in `tls.rs`, shared by both. **Done.**

## Already right here — do not port these

**Names go to the carrier, not to this machine's resolver.**
`http_bridge.rs:238` `socks5_connect` writes the SOCKS5 request by hand with
address type `0x03` and the hostname in it. That is exactly the thing Android
had to be rescued from: it used an HTTP client over a proxy, which resolves the
host locally first, so on a network whose resolver answers with the censor's
address it asked every carrier to reach the block page and threw away the ones
that could not. Android now has `core/CarriedSocket.kt` doing what this file
already did. Nothing to do here.

**A hop that cannot carry datagrams is declared that way.** `chain.rs` already
computes UDP capability per hop -- its tests say *the weakest hop decides* and
assert `udp: false` over a Psiphon hop. Android was declaring `udp: true` for
Psiphon, so mihomo handed it every datagram and it swallowed them, which a user
experiences as DNS and QUIC hanging while TCP works. Already correct here.

If you change either of those, you are walking into a bug this project has
already paid for once.

## Worth taking, in order

### 1. Aether 2.0.0, and MASQUE-in-MASQUE with it

The engine moved 1.8.0 -> 2.0.0. `docs/AETHER_2_0_MERGE.md` in the Android repo
records the whole merge: how it was done, the nine real conflicts, and every
decision. Most of that is about vendoring the source into an app that embeds it
by JNI. **This repo ships the core as a sidecar binary, so most of that
complexity does not apply here** -- what applies is which build you bundle.

What the bump brings that a user feels: bigger netstack and HTTP/2 windows, MTU
sized by framing so a tunnel over H2 gets 1500 instead of 1280, a QUIC v2
version-negotiation bait ahead of the handshake, smoltcp 0.14, and upstream's
own fix for the WARP-in-WARP teardown panic.

And the part that is this repo's alone:

- **MASQUE-in-MASQUE (`--mim`) is usable here today.** It is a fourth protocol,
  two nested MASQUE hops, for a network that has learnt to spot a single one.
  `run_mim` *is* the desktop path -- Android has to refuse it, because every
  protocol there needs an embedded variant that hands its stack to the app
  instead of binding listeners, and that does not exist yet. Here it is a
  profile control beside MASQUE H2/H3, WireGuard and WARP-in-WARP, plus
  `--mim-outer` / `--mim-inner` if someone wants to pin the hops.
- **`--mark` / the new `egress` module** sets `SO_MARK` on every outbound
  socket, so the core's own traffic can be routed around the tunnel it is
  building. It needs root or `CAP_NET_ADMIN`, which is why Android cannot use it
  at all and why this is a Linux feature that only exists for desktops.
- **Manual gool hops** (`--wiw-outer`, `--wiw-inner`, `--wiw-peers`) skip the
  endpoint scan for WARP-in-WARP when the addresses are already known.

Note that 2.0.0 requires **Rust 1.98**, and that upstream's `tor` feature stays
off in the Android vendoring for reasons that are Android's (one Go runtime per
process, transports shipped as Go binaries). Here, with tor already a supervised
child process in `tor.rs`, that reasoning does not transfer -- decide it on its
own merits rather than copying the conclusion.

### 2. Automatic: race the carriers instead of asking

This is the biggest thing this repo does not have. `grep automatic
src-tauri/src/carrier.rs` finds nothing: the user picks a carrier, and if it
cannot get out of their network they have to know that Psiphon and tor are in
there and go and choose one.

Android races them. From the moment the user taps: the engine in both MASQUE
framings, Psiphon, and tor's bridge modes, started together rather than in turn,
and the first route that carries real traffic wins. The reference is
`data/AutoRoute.kt` (the plan and the budgets) and `service/AetherVpnService.kt`
(`runAutoRace`, `raceLanes`, `tryRoute`).

Three things that cost Android a release to learn, and are worth having for free:

- **Deciding a winner is the hard part, not running the race.** A route that
  finishes its handshake is not a route that carries traffic. Android settles it
  with a TLS handshake through the carrier, verified against the hostname --
  `service/CarrierProbe.kt`. An HTTP status is not enough once the far end is
  doing the lookup, because an interception answers too; a certificate for the
  name asked for is something only the real host can present. `socks5_connect`
  already gives you the connection, so this is a TLS layer and a check, not a
  new client.
- **One route at a time per carrier, not per lane.** There is one core process
  and one tor. Android's lanes exist for exactly that, and the engine is raced
  as a SOCKS listener behind the race's interface rather than on the interface
  itself.
- **Everything the race starts must be stopped by the race**, including a losing
  engine still inside an endpoint scan. Android had to add a cancel path into
  the core for this (`nativeCancelPrepare`); here the equivalent is killing a
  child process, which this repo already does well.

### 3. Remember per network, and remember failures too

Android keys what worked on a hash of the network's gateway, resolvers and
search domain (`data/AutoRoute.kt`, `RouteMemory` and `NetworkKey`) rather than
globally. `grep` here finds only "remembered in the profile".

It matters less on a desktop than on a phone, but it is not nothing for a
laptop: the framing that worked on home wifi is a bad first guess on a tethered
phone, and starting a full endpoint search on that guess costs minutes before
anything else is tried.

The half that is easy to miss is the **negative** memory. Android's engine used
to go first whenever it had ever connected anywhere, on a flag that never
expired -- so a laptop that had connected at home spent two and a half minutes
on every session on a network that does not carry it. Recording *failure* per
network, with a short life because it is a negative, is what fixed it. It only
costs the engine the lead; it still races.

## Does not transfer

Listed so nobody goes looking: `VpnService.protect` and the socket protector,
`START_STICKY` and restoring the kill switch after a process death, split-tunnel
allow lists, `FileObserver`, and everything about Android's string resources.
The Android engine embeds by JNI; this one supervises a child. Where Android had
to add cancellation inside the core, here you kill a process.

## The one thing to take even if you take nothing else

The Android probe resolved its targets locally, and it decided which carrier
won. On a network with a hijacked resolver, that quietly discarded working
tunnels and reported that nothing worked. It was invisible for two releases
because every test passes on a network that answers DNS honestly.

`http_bridge.rs` is already immune. The lesson generalises past it: **anything
in this app that asks a question through a carrier must let the carrier resolve
the name, and must verify who answered.** Before adding any new check that goes
through a tunnel, that is the question to ask of it.
