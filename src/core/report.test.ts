import assert from "node:assert/strict";
import { test } from "node:test";
import { DEFAULT_PROFILE, IDLE_SNAPSHOT, type CoreLogEvent } from "../types.ts";
import { REPORT_EVENT_LIMIT, buildReport, redactAddresses, reportFilename } from "./report.ts";

function event(message: string, timestamp = 0): CoreLogEvent {
  return { timestamp, stream: "stdout", level: "info", message };
}

function report(overrides: Partial<Parameters<typeof buildReport>[0]> = {}): string {
  return buildReport({
    appVersion: "1.0.0",
    engineVersion: "aether 1.8.0",
    system: "windows · x86_64",
    snapshot: IDLE_SNAPSHOT,
    profile: DEFAULT_PROFILE,
    logs: [],
    options: { includeSystem: true, includeSettings: true, includeEvents: true, redact: true },
    ...overrides,
  });
}

test("redaction removes every address the core actually logs", () => {
  const cases: Array<[string, string]> = [
    ["[+] selected MASQUE gateway 162.159.192.18:443 (rtt 84.5ms)", "162.159.192.18"],
    ["[+] socks5 server listening on 127.0.0.1:1819", "127.0.0.1"],
    ["custom endpoint 5.6.7.8:2408 failed MASQUE validation", "5.6.7.8"],
    ["connected via [2606:4700:110:8a5f::1]:443", "8a5f"],
    // Bare and fully expanded: the form the edge-assigned tunnel address takes,
    // which a bracketed-only pattern walks straight past.
    [
      "[+] identity ready: device=ab12 ipv4=172.16.0.2 ipv6=2606:4700:110:8a5f:c0c0:7d5c:9a0d:8ba7",
      "2606:4700:110:8a5f:c0c0:7d5c:9a0d:8ba7",
    ],
    ["edge assigned embedded TUN address 2606:4700:110:8a5f::1/128", "2606:4700:110:8a5f::1"],
    ["dns 2606:4700:4700::1111", "2606:4700:4700::1111"],
  ];
  for (const [line, secret] of cases) {
    assert.ok(!redactAddresses(line).includes(secret), `${secret} survived in ${line}`);
  }
});

test("redaction leaves lines that only look like addresses alone", () => {
  // Every digit in a clock time is also a hex digit, so a pattern that counted
  // colons rather than requiring "::" would eat the timestamp on every line.
  for (const line of [
    "12:04:31 WARN supervisor retry 2 of 8 on masque-h3 in 6s",
    "23:59:59 ERROR stderr could not bind",
    "session transport=masque-h2 scan=balanced peerPinned=true validateSecs=10",
    "[+] MASQUE transport: HTTP/2 (TCP)",
    "tunnel startup timed out after 30s",
    "[+] obfuscation profile: balanced",
  ]) {
    assert.equal(redactAddresses(line), line);
  }
});

test("the version header is never redacted", () => {
  const text = report({ appVersion: "1.0.0.0", engineVersion: "aether 1.8.0" });
  assert.ok(text.includes("app 1.0.0.0"), text);
  assert.ok(text.includes("engine aether 1.8.0"), text);
});

test("Zero Trust credentials and the pinned endpoint never reach the report", () => {
  const text = report({
    profile: {
      ...DEFAULT_PROFILE,
      team: "acme",
      accessClientId: "client-id-value",
      accessClientSecret: "super-secret",
      accessEmail: "someone@example.com",
      accessToken: "token-value",
      peer: "162.159.192.18:443",
    },
  });
  for (const secret of [
    "acme",
    "client-id-value",
    "super-secret",
    "someone@example.com",
    "token-value",
    "162.159.192.18",
  ]) {
    assert.ok(!text.includes(secret), `${secret} leaked into:\n${text}`);
  }
  assert.ok(text.includes("zeroTrust=true"), text);
  assert.ok(text.includes("peerPinned=true"), text);
});

test("each section can be left out", () => {
  const full = report();
  assert.ok(full.includes("system windows"));
  assert.ok(full.includes("settings profile="));

  const trimmed = report({
    logs: [event("[+] socks5 server listening on 127.0.0.1:1819")],
    options: { includeSystem: false, includeSettings: false, includeEvents: false, redact: true },
  });
  assert.ok(!trimmed.includes("system windows"));
  assert.ok(!trimmed.includes("settings profile="));
  assert.ok(!trimmed.includes("socks5"));
  // The header and the current state are what make a report readable at all.
  assert.ok(trimmed.includes("app 1.0.0"));
  assert.ok(trimmed.includes("state idle"));
});

test("verbatim mode keeps the addresses and says so", () => {
  const logs = [event("[+] selected MASQUE gateway 162.159.192.18:443")];
  const redacted = report({ logs });
  assert.ok(!redacted.includes("162.159.192.18"));
  assert.ok(redacted.includes("# IP addresses replaced"));

  const verbatim = report({
    logs,
    options: { includeSystem: true, includeSettings: true, includeEvents: true, redact: false },
  });
  assert.ok(verbatim.includes("162.159.192.18"));
  assert.ok(!verbatim.includes("# IP addresses replaced"));
});

test("only the most recent events are carried", () => {
  const logs = Array.from({ length: REPORT_EVENT_LIMIT + 50 }, (_, index) =>
    event(`line-${index}`, index));
  const text = report({ logs });
  assert.ok(!text.includes("line-0 "), "the oldest event should have been dropped");
  assert.ok(text.includes(`line-${REPORT_EVENT_LIMIT + 49}`), "the newest event should be kept");
});

test("the file name is a plain name the backend will accept", () => {
  const name = reportFilename(new Date(2026, 7, 12, 14, 3, 1));
  assert.equal(name, "whiteaesther-20260812-140301.txt");
  // Mirrors sanitize_report_name in core_supervisor.rs.
  assert.match(name, /^[A-Za-z0-9][A-Za-z0-9._-]*\.txt$/);
});
