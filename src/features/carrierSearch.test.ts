import assert from "node:assert/strict";
import test from "node:test";

import { isImpossible, searchOrder } from "./carrierSearch.ts";
import { carrierChainLabel, type CarrierKind } from "../types.ts";

const label = (chain: { first: CarrierKind; second: CarrierKind | null }) =>
  carrierChainLabel(chain, (kind) => kind);

test("every single is tried before any chain", () => {
  // Nine attempts at up to ninety seconds is a quarter of an hour, so the
  // cheap answer has to come first. Chains exist for the network where no
  // single answers at all.
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
