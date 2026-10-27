import assert from "node:assert/strict";
import { test } from "node:test";
import { DEFAULT_PROFILE } from "../types.ts";
import type { RaceWinner } from "./api.ts";
import { profileForWinner } from "./winner.ts";

test("the verified recipe clears stale tactics and retains the tested IP family", () => {
  const profile = { ...DEFAULT_PROFILE, ech: "require", helloShape: "compact" as const };
  const recipe = { protocol: "masque" as const, masqueTransport: "h2" as const,
    fragmentClientHello: true, helloShape: "records" as const, fragmentSize: "16-32",
    fragmentDelay: "2-10", fragmentSni: true, ech: null, ipFamily: "v6" as const, scanMode: "turbo" as const };
  const session = profileForWinner(profile, winner({ recipe, peer: "[2001:db8::1]:443" }));
  assert.equal(session.helloShape, "records");
  assert.equal(session.ech, null);
  assert.equal(session.ipFamily, "v6");
  assert.equal(session.peer, "[2001:db8::1]:443");
});

function winner(overrides: Partial<RaceWinner>): RaceWinner {
  return {
    carrier: "aether",
    masqueTransport: null,
    protocol: null,
    fragmentClientHello: null,
    ech: null,
    endpointMode: null,
    peer: null,
    seconds: 4,
    ...overrides,
  };
}

test("the final session reuses the gateway that carried verified trial traffic", () => {
  const session = profileForWinner(DEFAULT_PROFILE, winner({ peer: "188.114.97.6:443", endpointMode: "custom-first" }));
  assert.equal(session.peer, "188.114.97.6:443");
  assert.equal(session.endpointMode, "custom-first");
});

test("the session runs the tactic the winning lane ran, not the profile's", () => {
  const profile = { ...DEFAULT_PROFILE, fragmentClientHello: false, ech: null };
  const session = profileForWinner(
    profile,
    winner({ protocol: "masque", masqueTransport: "h2", fragmentClientHello: true }),
  );
  assert.equal(session.masqueTransport, "h2");
  assert.equal(session.fragmentClientHello, true);

  const withEch = profileForWinner(
    profile,
    winner({ protocol: "masque", masqueTransport: "h3", ech: "require" }),
  );
  assert.equal(withEch.ech, "require");
});

test("a pin without a fallback is given one for the session", () => {
  const profile = { ...DEFAULT_PROFILE, endpointMode: "custom-only" as const, peer: "162.159.198.1:443" };
  const session = profileForWinner(profile, winner({ endpointMode: "custom-first" }));
  assert.equal(session.endpointMode, "custom-first");
  assert.equal(session.peer, "162.159.198.1:443");
});

test("a carrier that is not the engine leaves the engine's settings alone", () => {
  const profile = { ...DEFAULT_PROFILE, fragmentClientHello: false };
  const session = profileForWinner(profile, winner({ carrier: "psiphon" }));
  assert.deepEqual(session.carriers, { first: "psiphon", second: null });
  assert.equal(session.fragmentClientHello, false);
  assert.equal(session.endpointMode, profile.endpointMode);
});
