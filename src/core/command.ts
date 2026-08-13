import type { ConnectionProfile } from "../types";

export function buildCoreCommand(profile: ConnectionProfile): string {
  const args = [
    profile.protocol === "masque" ? "--masque" : profile.protocol === "wg" ? "--wg" : "--gool",
    profile.protocol === "masque" && profile.masqueTransport === "h2" ? "--h2" : "",
    "--scan", profile.scanMode,
    "--ip", profile.ipFamily,
    "--bind", quote(profile.socksAddress),
    profile.quickReconnect ? "--quick-reconnect" : "--no-quick-reconnect",
    "--validate-secs", String(profile.validateSecs),
    "--startup-secs", String(profile.startupSecs),
    "--reconnect-secs", String(profile.reconnectSecs),
    "--dns", quote(profile.dns.join(",")),
    "--noize", profile.noize,
    "--keepalive", String(profile.keepaliveSecs),
    "--log-level", processLogLevel(profile.logLevel),
    profile.dataCheck ? "" : "--no-data-check",
    profile.fragmentClientHello && profile.protocol === "masque" && profile.masqueTransport === "h2"
      ? `--fragment --fragment-size ${quote(profile.fragmentSize)} --fragment-delay ${quote(profile.fragmentDelay)}` : "",
    profile.profileRetry ? "" : "--no-profile-retry",
    profile.endpointMode === "automatic" ? "" : option("--peer", profile.peer),
    option("--wg-peer", profile.wgPeer),
    option("--h2-peer", profile.h2Peer),
    profile.ech && profile.ech !== "off" ? option("--ech", profile.ech) : "",
    option("--tls-groups", profile.tlsGroups),
    profile.performanceProfile === "auto" ? "" : `--perf ${profile.performanceProfile}`,
    option("--route-block", profile.routeBlock),
    option("--route-direct", profile.routeDirect),
    option("--routes", profile.routesFile),
    profile.gateway ? "--gateway" : "",
  ].filter(Boolean);
  return `aether ${args.join(" ")}`;
}

/**
 * Connection state, the selected edge and the latency are all read out of
 * info-level core output, so the supervisor never runs the child below info.
 * Extra verbosity is passed through.
 */
export function processLogLevel(level: ConnectionProfile["logLevel"]): string {
  return level === "debug" || level === "trace" ? level : "info";
}

function option(name: string, value: string | null): string {
  return value?.trim() ? `${name} ${quote(value)}` : "";
}

function quote(value: string): string {
  // Single quotes, not JSON.stringify: its double quotes still expand $(...) and backticks, and
  // this string is offered to the user as the command to run. Also restores real newlines, which
  // JSON.stringify turned into a literal \n.
  return `'${value.replace(/'/g, `'\\''`)}'`;
}
