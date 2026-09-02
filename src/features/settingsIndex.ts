/**
 * What the settings search can find.
 *
 * Written out rather than derived from the rendered controls: the words someone
 * types are rarely the words on the label. Someone looking for "kill switch"
 * will not search for "Reach", and someone who wants to stop DNS leaking will
 * not know the setting is called "Resolvers".
 */
export type SectionId =
  | "status"
  | "routes"
  | "endpoint"
  | "chain"
  | "traffic"
  | "identity"
  | "diagnostics"
  | "licences";

export interface SettingEntry {
  label: string;
  section: SectionId;
  /** Where it lives, shown so the result is findable again without searching. */
  where: string;
  /** Extra words that should match it, including the ones people actually use. */
  keywords: string;
}

export const SECTION_LABELS: Record<SectionId, string> = {
  status: "Status",
  routes: "Routes & transports",
  endpoint: "Endpoint",
  chain: "Exit chain",
  traffic: "Traffic & DNS",
  identity: "Identity",
  diagnostics: "Diagnostics",
  licences: "Licences & notices",
};

export const SETTINGS: SettingEntry[] = [
  { label: "Live event log", section: "status", where: "Status", keywords: "log console output events stderr debug what is happening" },
  { label: "What will run", section: "status", where: "Status", keywords: "command line arguments flags cli invocation" },
  { label: "Round-trip chart", section: "status", where: "Status", keywords: "latency ping ms speed graph chart rtt" },
  { label: "Speed test", section: "status", where: "Status", keywords: "throughput download mbps bandwidth how fast" },

  { label: "Protocol", section: "routes", where: "Routes & transports", keywords: "masque h2 h3 wireguard wg warp in warp gool tcp quic udp transport" },
  { label: "Search depth", section: "routes", where: "Routes & transports", keywords: "scan mode turbo balanced thorough stealth ironclad how hard to look" },
  { label: "Addresses", section: "routes", where: "Routes & transports", keywords: "ipv4 ipv6 dual stack ip family v4 v6" },
  { label: "Reuse the last working edge", section: "routes", where: "Routes & transports", keywords: "quick reconnect cached gateway faster connect" },
  { label: "End-to-end data check", section: "routes", where: "Routes & transports", keywords: "verify tunnel really works data check validation" },
  { label: "Resource profile", section: "routes", where: "Routes & transports", keywords: "performance cpu concurrency low medium high auto" },
  { label: "Timeouts", section: "routes", where: "Routes & transports", keywords: "validation deadline startup deadline reconnect delay seconds timeout" },
  { label: "Split the TLS opening", section: "routes", where: "Routes & transports", keywords: "fragment client hello dpi censorship filtering bypass" },
  { label: "Obfuscation profile", section: "routes", where: "Routes & transports", keywords: "noize noise padding gfw firewall aggressive hide traffic fingerprint" },
  { label: "Encrypted Client Hello", section: "routes", where: "Routes & transports", keywords: "ech sni hostname hiding" },
  { label: "TLS groups", section: "routes", where: "Routes & transports", keywords: "key exchange curves x25519 tls" },
  { label: "WireGuard keepalive", section: "routes", where: "Routes & transports", keywords: "keepalive udp mapping nat" },

  { label: "Endpoint scanner", section: "endpoint", where: "Endpoint", keywords: "scan gateways find ip addresses test candidates rank" },
  { label: "Pinned endpoint", section: "endpoint", where: "Endpoint", keywords: "custom peer address force specific gateway ip port" },
  { label: "How the gateway is chosen", section: "endpoint", where: "Endpoint", keywords: "automatic custom first custom only endpoint mode" },
  { label: "Per-protocol overrides", section: "endpoint", where: "Endpoint", keywords: "h2 peer wireguard peer separate address" },

  { label: "Dial through a local proxy", section: "routes", where: "Routes & transports", keywords: "upstream proxy socks5 http chain behind another vpn local proxy" },
  { label: "Match domain rules on sniffed names", section: "routes", where: "Routes & transports", keywords: "sniff sni host header domain rules match bare address route" },
  { label: "Register again if the identity is refused", section: "routes", where: "Routes & transports", keywords: "reprovision identity refused device cloudflare account handshake nothing passes" },

  { label: "Route through a second hop", section: "chain", where: "Exit chain", keywords: "chain proxy exit country change ip location second hop mihomo geo" },
  { label: "Subscriptions", section: "chain", where: "Exit chain", keywords: "sub subscription link config nodes servers add" },
  { label: "Configs pasted by hand", section: "chain", where: "Exit chain", keywords: "vless vmess trojan shadowsocks ss hysteria tuic paste uri manual config" },
  { label: "Nodes", section: "chain", where: "Exit chain", keywords: "node ping delay speed test which server pick select" },

  { label: "Set the system proxy while connected", section: "traffic", where: "Traffic & DNS", keywords: "whole machine system proxy windows wininet browser all apps" },
  { label: "Block traffic if the tunnel drops", section: "traffic", where: "Traffic & DNS", keywords: "kill switch killswitch fail closed leak protection block traffic drop" },
  { label: "Keep me connected", section: "traffic", where: "Traffic & DNS", keywords: "auto reconnect retry keep alive stay connected reconnection" },
  { label: "Share this connection on my network", section: "traffic", where: "Traffic & DNS", keywords: "lan share network other devices phone tv wifi hotspot proxy for phone username password" },
  { label: "Local proxy address", section: "traffic", where: "Traffic & DNS", keywords: "socks5 socks port 1819 bind listener point apps at" },
  { label: "DNS resolvers", section: "traffic", where: "Traffic & DNS", keywords: "dns resolver 1.1.1.1 leak nameserver" },
  { label: "Iranian sites bypass the tunnel", section: "traffic", where: "Traffic & DNS", keywords: "iran iranian ir domestic local sites bypass direct split geo digikala disconnect speed" },
  { label: "Routing rules", section: "traffic", where: "Traffic & DNS", keywords: "route block direct bypass split tunnel exclude sites rules file" },

  { label: "Cloudflare Zero Trust", section: "identity", where: "Identity", keywords: "team access client id secret token enrolment organisation login" },
  { label: "Send web traffic to Gateway", section: "identity", where: "Identity", keywords: "gateway policy filtering organisation" },

  { label: "Core executable", section: "diagnostics", where: "Diagnostics", keywords: "aether path binary engine location" },
  { label: "Log detail", section: "diagnostics", where: "Diagnostics", keywords: "log level verbose trace debug info warn error" },
  { label: "Profile name", section: "diagnostics", where: "Diagnostics", keywords: "name profile label" },
  { label: "Build a report", section: "diagnostics", where: "Diagnostics", keywords: "diagnostics report share support bug redact save copy" },

  { label: "Licences & notices", section: "licences", where: "Licences & notices", keywords: "licence license gpl agpl open source copyright legal notice attribution third party mihomo aether" },
  { label: "Where the source lives", section: "licences", where: "Licences & notices", keywords: "source code repository github corresponding source obligation download" },
];

/**
 * Ranks matches so the closest one is first and can be taken with Enter.
 *
 * A label match outranks a keyword match, and a match at the start of the label
 * outranks one in the middle -- typing "dns" should reach "DNS resolvers"
 * before "Send web traffic to Gateway", which only mentions it in passing.
 */
export function searchSettings(
  query: string,
  t: (key: string) => string = (key) => key,
  limit = 8,
): SettingEntry[] {
  const needle = query.trim().toLowerCase();
  if (!needle) return SETTINGS.slice(0, limit);

  const scored = SETTINGS.map((entry, order) => {
    const label = entry.label.toLowerCase();
    // Matched in the reader's language and in English both. Someone reading a
    // Persian interface types Persian; someone who learned these settings by
    // their English names, or who is reading a forum post, types English. Only
    // checking one of the two makes half the search useless.
    const translated = t(entry.label).toLowerCase();
    const translatedWhere = t(entry.where).toLowerCase();
    let score = 0;
    if (label.startsWith(needle) || translated.startsWith(needle)) score = 100;
    else if (label.includes(needle) || translated.includes(needle)) score = 70;
    else if (entry.where.toLowerCase().includes(needle) || translatedWhere.includes(needle)) score = 40;
    else if (entry.keywords.includes(needle)) score = 30;
    return { entry, score, order };
  }).filter((candidate) => candidate.score > 0);

  // Ties break on the order these are written in, not alphabetically. Searching
  // a section name matches every setting in it equally, and the one worth
  // offering first is the control the section exists for -- which is the one
  // listed first. Sorting by label instead handed back whichever happened to
  // start with the earliest letter.
  scored.sort((a, b) => b.score - a.score || a.order - b.order);
  return scored.slice(0, limit).map((candidate) => candidate.entry);
}
