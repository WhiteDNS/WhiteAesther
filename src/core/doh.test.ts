import assert from "node:assert/strict";
import { test } from "node:test";
import { skippedByFullTunnel } from "./doh.ts";

test("a resolver with a DoH endpoint is not reported as skipped", () => {
  assert.deepEqual(skippedByFullTunnel(["1.1.1.1", "8.8.4.4", "[2620:fe::fe]", " 9.9.9.9 "]), []);
});

test("a resolver with none is, so the screen can say full tunnel ignores it", () => {
  assert.deepEqual(skippedByFullTunnel(["10.0.0.1", "1.1.1.1", "208.67.222.222"]), ["10.0.0.1", "208.67.222.222"]);
});
