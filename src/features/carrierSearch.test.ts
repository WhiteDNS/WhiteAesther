import assert from "node:assert/strict";
import test from "node:test";

import { attemptCapMs, isImpossible, searchBudgetMs, searchOrder, verdictFor } from "./carrierSearch.ts";
import { carrierChainLabel, type CarrierKind } from "../types.ts";

const label = (chain: { first: CarrierKind; second: CarrierKind | null }) =>
  carrierChainLabel(chain, (kind) => kind);

test("every single is tried before any chain", () => {
  // A sweep where nothing answers runs for the better part of an hour, because
  // every carrier is given the time it actually needs -- so the cheap answer
  // has to come first. Chains exist for the network where no single answers at
  // all.
  const order = searchOrder(null);
  const firstChain = order.findIndex((chain) => chain.second !== null);
  const lastSingle = order.reduce((last, chain, index) => (chain.second === null ? index : last), -1);
  assert.ok(firstChain > lastSingle, order.map(label).join(" | "));
});

test("the singles come in measured order of how long they take", () => {
  const singles = searchOrder(null).filter((chain) => chain.second === null);
  assert.deepEqual(singles.map(label), ["aether", "psiphon", "tor"]);
});

test("all six orderings are offered, and none is a carrier chained to itself", () => {
  const pairs = searchOrder(null).filter((chain) => chain.second !== null);
  assert.equal(pairs.length, 6, pairs.map(label).join(" | "));
  assert.equal(new Set(pairs.map(label)).size, 6, "no ordering is offered twice");
  for (const chain of pairs) {
    assert.notEqual(chain.first, chain.second, label(chain));
  }
});

test("a carrier that is not installed is left out of both halves", () => {
  // Attempting it would spend an attempt on a certainty.
  const order = searchOrder(["aether", "psiphon"]);
  assert.ok(
    order.every((chain) => chain.first !== "tor" && chain.second !== "tor"),
    order.map(label).join(" | "),
  );
  // And what is left is still complete: two singles and both of their pairings.
  assert.deepEqual(order.map(label), ["aether", "psiphon", "aether → psiphon", "psiphon → aether"]);
});

test("one carrier on its own leaves exactly one attempt", () => {
  assert.deepEqual(searchOrder(["tor"]).map(label), ["tor"]);
});

test("nothing installed is an empty sweep rather than a wasted one", () => {
  assert.deepEqual(searchOrder([]), []);
});

test("the refusals that mean never are told apart from the ones that mean not now", () => {
  // The backend owns these rules; the search reads its words rather than
  // keeping a second copy that could drift from the one being enforced.
  assert.ok(
    isImpossible(
      "Aether has not registered a device yet, and it cannot register from inside another carrier.",
    ),
  );
  assert.ok(
    isImpossible("this profile already dials through a proxy of your own, so Aether cannot also"),
  );
  assert.ok(!isImpossible("Aether did not connect in 30s"));
  assert.ok(!isImpossible("Psiphon reported a listener and then stopped carrying"));
});

test("no attempt is cut before the carrier it is waiting for can answer", () => {
  // The deadlines each carrier already enforces on itself, in the backend.
  // A cap below any of these does not bound the search, it replaces that
  // deadline -- which is how a Psiphon that needed its first-run tactics fetch
  // could never be found by the feature that exists to find it.
  const profile = { scanMode: "balanced", startupSecs: 30 };
  const OWN_DEADLINE_MS: Record<CarrierKind, number> = {
    // The engine scans to prober.rs's own deadline (balanced: 120s + 20s
    // quiet) and only then starts the handshake --startup-secs bounds.
    aether: 140_000 + 30_000,
    psiphon: 315_000, // ESTABLISH_TIMEOUT, psiphon.rs
    tor: 180_000, // BOOTSTRAP_TIMEOUT, tor.rs
  };
  for (const chain of searchOrder(null)) {
    const needed = (OWN_DEADLINE_MS[chain.first] ?? 0)
      + (chain.second ? OWN_DEADLINE_MS[chain.second] : 0);
    assert.ok(attemptCapMs(chain, profile) >= needed, `${label(chain)} is cut short`);
  }
});

test("a chain waits for its hops added up, not for the longest of them", () => {
  // They start one after another: each has to be carrying traffic before the
  // next one begins.
  const tor = attemptCapMs({ first: "tor", second: null });
  const psiphon = attemptCapMs({ first: "psiphon", second: null });
  assert.equal(attemptCapMs({ first: "tor", second: "psiphon" }), tor + psiphon);
  assert.ok(attemptCapMs({ first: "tor", second: "psiphon" }) > Math.max(tor, psiphon));
});

test("the budget shown to the user is every attempt the sweep would make", () => {
  const order = searchOrder(null);
  assert.equal(
    searchBudgetMs(order),
    order.reduce((total, chain) => total + attemptCapMs(chain), 0),
  );
  // One carrier installed means one attempt, and the budget is that attempt.
  assert.equal(searchBudgetMs(searchOrder(["tor"])), attemptCapMs({ first: "tor", second: null }));
});

test("a process that has started is not a carrier that is carrying traffic", () => {
  // `start_core` returns the instant the engine is spawned, with the snapshot
  // reading "starting" and the search still ahead of it. Reading that as
  // success settled every sweep on Aether alone and never reached the chains.
  assert.equal(verdictFor("starting"), "waiting");
  assert.equal(verdictFor("scanning"), "waiting");
  assert.equal(verdictFor("connecting"), "waiting");
  // The engine between its own attempts is still trying, not yet an answer.
  assert.equal(verdictFor("reconnecting"), "waiting");

  assert.equal(verdictFor("connected"), "connected");
  assert.equal(verdictFor("error"), "failed");
  assert.equal(verdictFor("idle"), "failed");
});

test("how hard the engine was asked to look decides how long it is given", () => {
  // `thorough` scans for more than seven times as long as `turbo`. A cap that
  // ignores that fails the mode someone chose precisely because the network is
  // hard.
  const turbo = attemptCapMs({ first: "aether", second: null }, { scanMode: "turbo", startupSecs: 30 });
  const balanced = attemptCapMs({ first: "aether", second: null }, { scanMode: "balanced", startupSecs: 30 });
  const thorough = attemptCapMs({ first: "aether", second: null }, { scanMode: "thorough", startupSecs: 30 });
  assert.ok(turbo < balanced, `${turbo} < ${balanced}`);
  assert.ok(balanced < thorough, `${balanced} < ${thorough}`);

  // `--startup-secs` wraps the handshake *after* a gateway is chosen, so it
  // adds to the scan rather than containing it.
  const patient = attemptCapMs({ first: "aether", second: null }, { scanMode: "balanced", startupSecs: 120 });
  assert.equal(patient - balanced, 90_000);

  // A mode this build has not heard of gets the default window, not the
  // shortest one.
  assert.equal(
    attemptCapMs({ first: "aether", second: null }, { scanMode: "from-a-newer-build", startupSecs: 30 }),
    balanced,
  );
});

test("only the engine's share of a chain moves with the scan mode", () => {
  // Psiphon and Tor do not scan for a Cloudflare gateway, so their deadlines
  // are unaffected by how hard Aether was told to look.
  const turbo = { scanMode: "turbo", startupSecs: 30 };
  const thorough = { scanMode: "thorough", startupSecs: 30 };
  assert.equal(
    attemptCapMs({ first: "psiphon", second: null }, turbo),
    attemptCapMs({ first: "psiphon", second: null }, thorough),
  );
  assert.ok(
    attemptCapMs({ first: "psiphon", second: "aether" }, thorough)
      > attemptCapMs({ first: "psiphon", second: "aether" }, turbo),
  );
});
