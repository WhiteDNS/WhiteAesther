import type { ConnectionProfile, CoreLogEvent, CoreSnapshot } from "../types";

export interface ReportOptions {
  includeSystem: boolean;
  includeSettings: boolean;
  includeEvents: boolean;
  redact: boolean;
}

export interface ReportInput {
  appVersion: string;
  engineVersion: string | null;
  system: string;
  snapshot: CoreSnapshot;
  profile: ConnectionProfile;
  logs: CoreLogEvent[];
  options: ReportOptions;
}

/**
 * Enough recent history to show how a connection failed without turning the
 * report into something nobody reads.
 */
export const REPORT_EVENT_LIMIT = 200;

const IPV4 = /\b\d{1,3}(?:\.\d{1,3}){3}\b(?::\d+)?/g;
/** Socket addresses, which Rust always renders bracketed. */
const IPV6_BRACKETED = /\[[0-9a-fA-F:]+\](?::\d+)?/g;
/**
 * Bare, fully expanded — the form the edge-assigned tunnel address is logged
 * in, which a bracketed-only pattern walks straight past.
 */
const IPV6_FULL = /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b/g;
/**
 * Bare and compressed. The literal "::" is what keeps this off clock times:
 * every digit in 12:04:31 is also a hex digit, so the colon count alone is not
 * enough to tell an address from a timestamp.
 */
const IPV6_COMPRESSED = /\b[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})*::(?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})*)?/g;

/**
 * Replaces addresses with placeholders. Which edge was selected is usually not
 * what a report is read for, and the addresses are the part of it that says
 * something about the person who collected it.
 */
export function redactAddresses(line: string): string {
  return line
    .replace(IPV6_BRACKETED, "[ipv6]:port")
    .replace(IPV6_FULL, "[ipv6]")
    .replace(IPV6_COMPRESSED, "[ipv6]")
    .replace(IPV4, "0.0.0.0:port");
}

export function reportFilename(now: Date = new Date()): string {
  const pad = (value: number) => String(value).padStart(2, "0");
  const stamp = `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}`
    + `-${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}`;
  return `whiteaesther-${stamp}.txt`;
}

/**
 * Composes the report the user reviews before saving it.
 *
 * Zero Trust credentials are reduced to whether one is configured, and the
 * pinned peer to whether one is set, so the text can be handed over without the
 * user having to audit it line by line.
 */
export function buildReport(input: ReportInput): string {
  const { appVersion, engineVersion, system, snapshot, profile, logs, options } = input;
  // Version numbers are dotted quads often enough that running them through the
  // IPv4 pattern would redact them, so the header is composed separately and
  // never redacted. Everything below it can carry an address.
  const header = [`app ${appVersion}`, `engine ${engineVersion ?? "unavailable"}`];
  const body: string[] = [];

  if (options.includeSystem) body.push(`system ${system}`);

  body.push(
    `state ${snapshot.state}${snapshot.transport ? ` · ${snapshot.transport}` : ""}`
      + (snapshot.attempt > 0 ? ` · attempt ${snapshot.attempt} of ${snapshot.maxAttempts}` : ""),
  );

  // Redacted along with everything else: the line is address-free by
  // construction, but the profile name is free text the user chose.
  if (options.includeSettings) body.push(settingsLine(profile));

  if (options.includeEvents) {
    body.push("");
    for (const entry of logs.slice(-REPORT_EVENT_LIMIT)) {
      const time = new Date(entry.timestamp).toLocaleTimeString();
      body.push(`${time} ${entry.level.toUpperCase()} ${entry.stream} ${entry.message}`);
    }
  }

  const lines = [...header, ...(options.redact ? body.map(redactAddresses) : body)];
  if (options.redact) lines.push("", "# IP addresses replaced");

  return `${lines.join("\n")}\n`;
}

function settingsLine(profile: ConnectionProfile): string {
  const values: Array<[string, string | number | boolean]> = [
    ["profile", profile.name],
    ["protocol", profile.protocol],
    ["transport", profile.masqueTransport],
    ["scan", profile.scanMode],
    ["ip", profile.ipFamily],
    ["noize", profile.noize],
    ["fragment", profile.fragmentClientHello],
    ["fragmentSize", profile.fragmentSize],
    ["dataCheck", profile.dataCheck],
    ["quickReconnect", profile.quickReconnect],
    ["perf", profile.performanceProfile],
    ["validateSecs", profile.validateSecs],
    ["startupSecs", profile.startupSecs],
    ["reconnectSecs", profile.reconnectSecs],
    ["keepaliveSecs", profile.keepaliveSecs],
    ["resolvers", profile.dns.length],
    ["logLevel", profile.logLevel],
    ["ech", profile.ech && profile.ech !== "off" ? "set" : "off"],
    ["routeRules", profile.routeBlock.trim().length > 0 || profile.routeDirect.trim().length > 0],
    ["fullTunnel", profile.fullTunnel],
    // Presence only. The URL may carry a password, and this file gets handed
    // to other people — same reason the endpoint and organisation are reported
    // as booleans above.
    ["upstreamProxy", profile.upstreamProxy.trim().length > 0],
    ["routeSniff", profile.routeSniff],
    ["autoReprovision", profile.autoReprovision],
    ["keepaliveSecs", profile.keepaliveSecs],
    ["bypassIranSites", profile.bypassIranSites],
    ["endpoint", profile.endpointMode],
    // Values, not just presence, would put the user's endpoint and their
    // organization into a file they are about to send somewhere.
    ["peerPinned", Boolean(profile.peer?.trim())],
    ["zeroTrust", Boolean(profile.team?.trim())],
    ["gateway", profile.gateway],
    ["systemProxy", profile.systemProxy],
    // Whether the machine is a door onto the tunnel for the rest of the
    // network, and whether that door asks for anything. Never the credentials
    // themselves: this file gets handed to other people.
    ["lanShare", profile.lanShare.enabled],
    [
      "lanShareSignIn",
      profile.lanShare.enabled
        ? Boolean(profile.lanShare.username.trim() && profile.lanShare.password.trim())
        : false,
    ],
  ];
  return `settings ${values.map(([key, value]) => `${key}=${value}`).join(" ")}`;
}
