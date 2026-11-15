import assert from "node:assert/strict";
import { test } from "node:test";
import { endpointError, normalizeEndpoint } from "./endpoint.ts";

test("accepts and canonicalises IPv4 endpoints", () => {
  assert.equal(normalizeEndpoint("162.159.192.18:443"), "162.159.192.18:443");
  assert.equal(normalizeEndpoint("  1.1.1.1:2408  "), "1.1.1.1:2408");
  assert.equal(normalizeEndpoint("0.0.0.0:1"), "0.0.0.0:1");
  assert.equal(normalizeEndpoint("255.255.255.255:65535"), "255.255.255.255:65535");
});

test("accepts bracketed IPv6 endpoints and compresses them", () => {
  assert.equal(normalizeEndpoint("[2606:4700:110:8a5f::1]:443"), "[2606:4700:110:8a5f::1]:443");
  // Leading zeroes dropped, longest zero run collapsed, upper case folded.
  assert.equal(
    normalizeEndpoint("[2606:4700:0110:8A5F:0000:0000:0000:0001]:443"),
    "[2606:4700:110:8a5f::1]:443",
  );
  assert.equal(normalizeEndpoint("[::1]:443"), "[::1]:443");
});

test("rejects everything the core cannot dial", () => {
  for (const value of [
    "",
    "   ",
    "cloudflare.example:443",       // a hostname cannot be resolved before the tunnel exists
    "162.159.192.18",               // no port
    "162.159.192.18:",
    "162.159.192.18:0",             // port 0 is not dialable
    "162.159.192.18:65536",
    "162.159.192.18:443:443",
    "256.1.1.1:443",
    "1.1.1:443",
    "1.1.1.1.1:443",
    "2606:4700:110:8a5f::1:443",    // bare IPv6: the port is indistinguishable
    "[2606:4700:110:8a5f::1]",      // bracketed but no port
    "[2606:4700::110::1]:443",      // two "::" runs is not a valid address
    "[not:hex:here]:443",
    "[]:443",
    "[::1]443",
  ]) {
    assert.equal(normalizeEndpoint(value), null, `accepted ${JSON.stringify(value)}`);
  }
});

test("nothing is required while the endpoint is automatic", () => {
  assert.equal(endpointError("automatic", ""), null);
  assert.equal(endpointError("automatic", "nonsense"), null);
});

test("a pinned endpoint reports why it is unusable", () => {
  for (const mode of ["custom-first", "custom-only"]) {
    assert.equal(endpointError(mode, ""), "Enter an endpoint to pin");
    assert.match(endpointError(mode, "cloudflare.example:443") ?? "", /numeric address/);
    assert.equal(endpointError(mode, "162.159.192.18:443"), null);
  }
});

test("a pin outside the chosen address family is refused", () => {
  const family = /address family/;
  assert.match(endpointError("custom-only", "162.159.192.18:443", "v6") ?? "", family);
  assert.match(endpointError("custom-only", "[2606:4700:d0::a29f:c001]:443", "v4") ?? "", family);
  assert.equal(endpointError("custom-only", "[2606:4700:d0::a29f:c001]:443", "v6"), null);
  assert.equal(endpointError("custom-first", "162.159.192.18:443", "v4"), null);
  assert.equal(endpointError("custom-first", "162.159.192.18:443", "both"), null);
});
