import assert from "node:assert/strict";
import { test } from "node:test";
import { compareVersions, isDueForCheck, isNewer } from "./updates.ts";

test("versions are ordered by number, not by text", () => {
  assert.ok(compareVersions("1.5.5", "1.5.4") > 0);
  assert.ok(compareVersions("1.5.4", "1.5.5") < 0);
  assert.equal(compareVersions("1.5.4", "1.5.4"), 0);

  // The case string comparison gets wrong, and the one nobody is still testing
  // for by the time it arrives.
  assert.ok(compareVersions("1.10.0", "1.9.0") > 0);
  assert.ok(compareVersions("2.0.0", "1.99.99") > 0);
  assert.ok(compareVersions("1.5.10", "1.5.9") > 0);
});

test("a leading v and a missing segment are the same release, not an upgrade", () => {
  // Tags carry the v, package.json does not. Treating them as different would
  // offer an update to the version already running, forever.
  assert.equal(compareVersions("v1.5.4", "1.5.4"), 0);
  assert.equal(compareVersions("V1.5.4", "1.5.4"), 0);
  assert.equal(compareVersions("1.6", "1.6.0"), 0);
  assert.equal(compareVersions("1.6.0.0", "1.6"), 0);
});

test("a prerelease suffix is ignored rather than ranked", () => {
  // We do not publish them; inventing an order for something we never ship
  // would be a rule written from nothing.
  assert.equal(compareVersions("1.6.0-beta.1", "1.6.0"), 0);
});

test("only a genuinely newer build is worth telling someone about", () => {
  assert.ok(isNewer("1.5.5", "1.5.4"));
  assert.ok(!isNewer("1.5.4", "1.5.4"));
  assert.ok(!isNewer("1.5.3", "1.5.4"), "a downgrade is not an update");
});

test("a build with no recorded version never prompts", () => {
  // VITE_APP_VERSION falls back to "unknown" rather than a wrong number, and
  // comparing against that would tell every such build to upgrade every time.
  assert.ok(!isNewer("1.5.5", "unknown"));
  assert.ok(!isNewer("1.5.5", ""));
});

test("the check is throttled, and a clock that jumped does not park it forever", () => {
  const now = 1_000_000_000_000;
  const sixHours = 6 * 60 * 60 * 1000;

  assert.ok(isDueForCheck(now, null), "never asked is due");
  assert.ok(isDueForCheck(now, now - sixHours), "exactly the interval is due");
  assert.ok(isDueForCheck(now, now - sixHours - 1));
  assert.ok(!isDueForCheck(now, now - 60_000), "asked a minute ago is not due");

  // A last-check stamp in the future means the clock moved backwards. Waiting
  // for it to catch up would mean never asking again.
  assert.ok(isDueForCheck(now, now + sixHours));
});
