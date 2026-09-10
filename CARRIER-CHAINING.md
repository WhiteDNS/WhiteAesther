# Chaining two carriers

A carrier is whatever gets us out of the network, and `PORT-CARRIERS.md` left the
app with three of them, one at a time. This is the design for running two in
sequence: the first leaves the local network, the second decides the exit
address, and the subscription node — if there is one — sits after both.

Everything below rests on measurement rather than reading. Every claim marked
**measured** was produced on 2026-09-10 against the shipped 1.8.0 binaries, and
the method is recorded so it can be repeated when a version moves.

## The shape

```
applications → mihomo → hop 1 → hop 2 → [exit node] → internet
                          ↑        ↑
              leaves this network  decides the exit address
```

mihomo already owns the interface and dials whatever carrier is running. It does
not need to know there are two: it dials **hop 2's** listener, and hop 2 has been
configured to make its own outbound connections through hop 1. Nothing in
`chain.rs` learns a new concept; it learns that some of its inputs are now
plural.

## How each carrier is told to use the one before it

Three mechanisms, one per carrier. Each covers two of the six orderings, which
is why three tests were enough.

| Carrier | Setting | Measured |
|---|---|---|
| Psiphon | `UpstreamProxyURL: "socks5://127.0.0.1:PORT"` | ✅ 15 connections arrived at a proxy under our control; tunnel established through it |
| Tor | `Socks5Proxy 127.0.0.1:PORT` in the torrc | ✅ 5 connections arrived; bootstrapped to 50% through it |
| Aether | `AETHER_UPSTREAM=socks5://127.0.0.1:PORT` (already a profile field) | ✅ with a precondition — see below |

**Method.** A SOCKS5 proxy under our own control, logging every request, placed
where the previous hop would be. This distinguishes *the option is accepted* from
*the option is used*: a carrier that ignores the setting connects anyway, and
from the outside the two look identical. That is the failure worth catching —
the user believes they have two hops and has one.

## The nine findings

### 1. Aether cannot register a new identity through a chain — measured

Confirmed three separate ways: through our own proxy, through a real Psiphon
tunnel, and through the proxy again with full SOCKS logging. Same failure each
time.

The cause is Aether's own anti-censorship design. In the proxy log, **the only
hostname connection was the test's own** — Aether never asks for
`api.cloudflareclient.com` by name. It dials raw Cloudflare edge addresses with
a spoofed SNI so that DNS cannot be poisoned or blocked, and through a SOCKS
proxy that fails: the direct route with a transport error, then the camouflaged
route with `cert verification failed — unable to get local issuer certificate`.

**With an existing identity it works completely.** The identity loads, the
upstream is used, the cached gateway is reused, and traffic exits at a Cloudflare
address while the proxy logs the connection to the MASQUE gateway.

So: `Psiphon → Aether` and `Tor → Aether` require Aether to have registered at
least once **directly**. The app must guarantee that before offering Aether as a
second hop, and say so plainly when it cannot — a fresh install whose first
action is `Psiphon → Aether` will otherwise fail with a message about
registration that names nothing the user can act on.

### 2. Any chain containing Psiphon or Tor is TCP-only — measured

Psiphon's SOCKS5 refuses `UDP ASSOCIATE` with `0x07 COMMAND NOT SUPPORTED`. Tor
carries no datagrams by design.

`carries_udp` and `carries_quic` stop being properties of *a* carrier and become
properties of *the chain*, computed as the AND across hops. Two consequences,
and both must reach the screen rather than being discovered:

- Aether in such a chain can only use **MASQUE H2**. H3 rides QUIC and WireGuard
  is UDP; both die at the TCP-only hop. Those options must be disabled, not
  merely annotated.
- The `udp: false` declaration and the `NETWORK,udp,REJECT` rule already written
  for Tor now apply to any chain with a TCP-only hop.

### 3. Psiphon does not leak when its upstream fails — measured

Pointed at a proxy that refused every connection, Psiphon made **1340 attempts
and never once connected directly**. `tunnels: (none)`.

This is what makes a chain trustworthy. Someone who picks `Aether → Psiphon` so
that the local network sees only Cloudflare gets that guarantee even when Aether
drops: Psiphon fails closed rather than revealing the thing it was hiding.

### 4. But it hammers while it fails — measured

Those 1340 attempts are the same finding read the other way. If hop 1 dies, hop 2
will pound the network indefinitely.

The watcher must therefore treat the chain as one unit: when **any** hop dies,
stop them all. Watching hops independently and restarting the dead one is wrong
here — hop 2 has no route while hop 1 is down, and letting it keep trying is both
noisy and, on a hostile network, the kind of traffic that gets an address
blocked.

### 5. Both hop processes must be exempted from the TUN device

Under full tunnel, `auto-route` sends the default route into the device, and a
carrier's own packets would be captured and handed back to the carrier that
produced them. The loop is silent and total — including the traffic that would
have explained why.

Strictly, only hop 1 reaches the physical network; hop 2 talks to hop 1 on
loopback, which `auto-route` does not capture. **Exempt both anyway.** The cost
is one rule; the risk otherwise is a hop that makes one unexpected direct
connection — a DNS query, an IPv6 attempt, a fallback — and takes the whole
connection down in a way that produces no diagnosis at all.

The address-based `IP-CIDR` exemption stays as a second line of defence and
applies to **hop 1 only**, since it is the only hop with a gateway on the real
internet, and only Aether has a single address worth naming.

### 6. Hop 1 must pass every port — measured

Psiphon dialled ports **22, 53, 443 and 554**; Tor dialled **993, 9100, 443 and
1080**. Both vary ports deliberately to avoid classification.

Aether and Psiphon pass arbitrary ports, so every ordering is fine today. But
this is a real property of a first hop and belongs in `CarrierKind` rather than
in someone's memory: a future carrier that only forwards 443 would silently
break every chain built on it.

### 7. Tor accepts bridges and an upstream proxy together — partly measured

`tor --verify-config` reports `Configuration was valid` with `Socks5Proxy`,
`ClientTransportPlugin` and `UseBridges` all present, and the pluggable-transport
specification carries `TOR_PT_PROXY` for exactly this case.

**Not verified at runtime.** Whether lyrebird honours the upstream when tor hands
it one has not been observed carrying traffic. Treat `X → Tor with bridges` as
unproven until it is, and gate it behind a real test rather than shipping it on
the strength of a config check.

### 8. `upstreamProxy` collides with the chain

The profile already exposes `upstreamProxy` for a proxy the user runs
themselves. A chain sets the same field programmatically.

**The user's own value wins.** A chain requested alongside a manual upstream
proxy is refused with a message naming the conflict, rather than one silently
overwriting the other. Quietly replacing a proxy someone configured deliberately
is the worse failure: their traffic goes somewhere they did not choose.

### 9. Two of the six orderings do not do what they look like

`Psiphon → Aether` and `Tor → Aether` end at Cloudflare, which egresses near the
user and does not change their country — the very thing carriers exist to
provide. They are being shipped because they were asked for, and because there
are networks where only Psiphon or Tor gets out at all and Aether's speed is
still wanted afterwards.

They must not be presented as ways to get a foreign exit. The screen states the
exit each ordering produces; `PORT-CARRIERS.md` already records what happens when
it does not — an Android screen that said traffic left from Cloudflare while
Psiphon carried it out of Singapore.

### 10. The last hop was standing in for the whole chain — measured

Written after the first end-to-end run of a real pair, which found seven faults
with one cause. Every question that is properly about *the chain* was being
asked of its **last hop**, because before chaining there was only ever one hop
and the two were the same thing.

| Asked of the last hop | What it broke |
| --- | --- |
| `current_carrier`, polled by the Aether hop | `Aether → X` never got past hop 1: the poll waited the full 30s hop timeout for the *second* hop's listener, which does not exist yet because it is started through the first. Two of six orderings, dead. |
| `has_something_to_do` | mihomo refused to start for `X → Aether` — "the chain has nothing to carry". Two more orderings, dead. |
| `engine_is_wanted` | Toggling the exit chain on a live `X → Aether` stopped the routing engine, and with it the only thing enforcing that the chain carries no datagrams. |
| `spawn_carrier_watch` | Returned outright when the last hop was Aether, so `X → Aether` had no watcher at all; in the others, hop 1 dying went unnoticed while the screen read connected. |
| `Running.carrier`, for the QUIC advice | `Psiphon → Aether` was told to "switch the protocol to WireGuard" — Aether's remedy for Aether's shortfall, useless against Psiphon refusing datagrams in front of it. |
| `carries_quic()` | Read the snapshot's `transport`, which holds a proxy name under a carrier and so matched neither MASQUE transport: **every** chain reported itself as carrying QUIC, including ones whose first hop refuses datagrams outright. |

Two further faults were teardown rather than capability:

- `stop_carriers` knows only the two carriers that are separate programs, so the
  error paths left a chained Aether running. Measured: after one failed
  `Psiphon → Aether`, the engine lost its upstream, began hunting for a
  Cloudflare gateway **directly**, and was still sweeping two minutes later with
  the screen reading Stopped. On a network that filters, that is the one thing
  this must never do.
- `carrier_died` stopped mihomo and the door but left the surviving hops up.

And one that was honest before chaining and is not now: the snapshot's
`socks_address` kept the last hop's own port while mihomo owned the route, so
"This app only" named a listener that bypasses mihomo — and with it the datagram
rejection and the Iranian-sites bypass that only mihomo applies.

The remedy is structural, not seven patches: the rules live on `RunningChain`,
which is the only type that can see every hop, and the call sites ask it rather
than re-deriving. `needs_routing_engine`, `carries_udp`, `carries_quic`,
`datagram_blocker` and `process_names` are that surface. Where a caller
genuinely means the engine and not the exit — the Aether hop's own readiness
poll — it says so by name: `aether_carrier`, never `current_carrier`.

## The types

```rust
/// An ordered pair. `first` leaves the local network; `second` decides the exit.
///
/// `second: None` is the single-carrier case, which is every session that exists
/// today — so a profile written before chaining reads as itself.
pub struct CarrierChain {
    pub first: CarrierKind,
    pub second: Option<CarrierKind>,
}

/// A chain that is up. Ordered as traffic travels: hop 1 first.
pub struct RunningChain {
    hops: Vec<Carrier>,        // one or two
}

impl RunningChain {
    /// What mihomo dials: the last hop.
    fn listener(&self) -> SocketAddr;
    /// Every process to keep out of the TUN device. All of them, see finding 5.
    fn process_names(&self) -> Vec<&'static str>;
    /// AND across hops, not the last hop's answer. See finding 2.
    fn carries_udp(&self) -> bool;
    fn carries_quic(&self) -> bool;
    /// Hop 1's gateway, when it has one. Only hop 1 touches the real network.
    fn endpoint(&self) -> Option<IpAddr>;
}
```

`ChainRequest.carrier: Option<Carrier>` becomes
`ChainRequest.carriers: Option<RunningChain>`. `render()` changes in four
places: the proxy declaration takes the last hop, the `PROCESS-NAME` rules
become one per hop, the `udp:` flag and the `NETWORK,udp,REJECT` rule read the
AND, and the `IP-CIDR` exemption reads hop 1.

## Startup and teardown

Sequential, and the order is not negotiable.

1. Hop 1 starts and must reach **carrying traffic** — not merely listening. Both
   existing gates apply: Psiphon's `Tunnels ≥ 1`, Tor's `PROGRESS=100`. Hop 2
   will use hop 1 immediately, and a listener with no tunnel behind it swallows
   its connections.
2. Hop 1's listener address is written into hop 2's upstream setting.
3. Hop 2 starts and must reach carrying traffic by its own gate.
4. mihomo starts, pointed at hop 2, with both process names exempted.
5. The system proxy and the shared door follow mihomo, exactly as now.

Teardown is the reverse, and **any** hop dying tears down the whole chain
(finding 4). Establish time is the sum of both hops: measured, Psiphon takes
30–60s and Tor 30–120s, so a chain can legitimately need three minutes. The
screen must show which hop is being worked on, or the wait is indistinguishable
from a hang.

## The "find one that works" button

Six orderings plus three single carriers is nine attempts, and at three minutes
each that is half an hour. That is not a button, it is abandoning the app.

- **Singles first, in order of measured speed:** Aether (~25s), Psiphon (~40s),
  Tor (~60s). On most networks the first one answers and the search ends.
- **Chains only after every single has failed**, which is the situation the
  search exists for.
- **A hard cap per attempt**, around 90 seconds — long enough for a legitimately
  slow Psiphon, short enough that nine of them stay bounded.
- **Skip what cannot work:** with no Aether identity, every `X → Aether` is
  skipped rather than attempted (finding 1). With a manual `upstreamProxy` set,
  chains are skipped (finding 8).
- **Report each attempt as it happens, and allow cancelling.** A silent
  multi-minute search is the same fault as a carrier that says connected and
  carries nothing.

The search must also say what it settled on. Ending on `Psiphon → Tor` without
saying so leaves someone believing they are on Aether.

## Order of work, each ending at a gate checked from outside the app

1. `CarrierChain` and `RunningChain`, with `render()` taking plural inputs.
   **Gate:** the single-carrier config renders byte-identically to 1.8.0 — the
   same assertion that guarded phase 1 of the carrier port.
2. Sequential startup and teardown for one hard-coded pair.
   **Gate:** `Aether → Psiphon` carries traffic, and the exit address is
   Psiphon's rather than Cloudflare's, measured from another process.
3. All six orderings selectable, with the impossible ones refused rather than
   attempted. **Gate:** each of the six either carries traffic or refuses with a
   message naming the actual reason.
4. Weakest-link UDP, and the transport controls disabled where they cannot work.
   **Gate:** with a TCP-only hop, the rendered config declares `udp: false`,
   carries `NETWORK,udp,REJECT`, and the screen offers no H3 or WireGuard.
5. The chain-wide watcher and kill switch.
   **Gate:** killing hop 1 stops hop 2 within seconds; with the kill switch on,
   traffic is held rather than sent in the clear.
6. The search button, and the honest exit labelling.
   **Gate:** on a network where only one ordering works, the search finds it and
   names it.

## What the gates actually returned

Steps 1-5 are closed, measured from outside the app on 2026-09-10.

- **Step 2 and 3.** Five of the six orderings were run and every one carried
  real traffic through mihomo: `Aether → Psiphon`, `Psiphon → Aether`,
  `Tor → Aether`, `Tor → Psiphon`, `Aether → Tor`. `Psiphon → Tor` has not
  been run. The exit belongs to the last hop, not the first: on
  `Aether → Tor`, `curl` through mihomo's port reached
  `check.torproject.org/api/ip`, which answered
  `{"IsTor":true,"IP":"203.55.81.2"}`.
- **Step 4.** `Aether → Tor` rendered
  `{name: tor, type: socks5, port: 45990, udp: false}` with
  `NETWORK,udp,REJECT` — Aether carries datagrams and Tor does not, and the
  chain declared the weaker of the two. The transport cards are absent from the
  screen for any chain.
- **Step 5.** Hop 1 killed at 13:22:52.186; `Aether, carrying Aether → Tor,
  stopped unexpectedly` logged at 13:22:52.809 — **623ms** — and five seconds
  later `tor`, `mihomo` and the engine were all gone. The kill-switch half is
  untested.

One thing measured and not yet explained: both orderings **ending** at Aether
come up, carry traffic, and then reset within seconds —
`h2 body: connection reset; reconnecting`, three times out of three, at 4s, 10s
and immediately. A lone Aether stays up for minutes, so this correlates with
the SOCKS upstream rather than with the chain wiring, which puts it in the
engine's upstream path. The engine recovers on its own and the app reports
`reconnecting` honestly, so it degrades rather than breaks — but it is why the
snapshot's advertised address had to stop following the engine's listener line
(finding 10): an internal reconnect is routine here, not rare.

## Rules

- Never present an ordering as giving a foreign exit when it ends at Aether.
- A hop that dies takes the chain with it. No independent restarts.
- Both hop processes stay out of the TUN device, whatever the reasoning says
  about which one strictly needs it.
- Do not claim any ordering works until traffic from another process has been
  observed leaving through it, and the exit address checked. Building is not
  evidence — three of the nine findings above contradict what the code looked
  like it would do.
- Finding 7 is unproven at runtime. Do not ship `X → Tor with bridges` on the
  strength of a config check.
