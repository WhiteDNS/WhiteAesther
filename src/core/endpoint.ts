/**
 * Canonicalises a pinned endpoint, or rejects it.
 *
 * The core takes a numeric address and a port and nothing else: a hostname
 * cannot be resolved from inside a tunnel that is not up yet. Rejecting one
 * here is what turns a connection that mysteriously never starts into a message
 * next to the field.
 *
 * Returns the canonical `IP:port`, or null if the value is not one.
 */
export function normalizeEndpoint(value: string): string | null {
  const input = value.trim();
  if (!input) return null;

  const [host, portText] = splitHostPort(input) ?? [];
  if (host === undefined || portText === undefined) return null;

  const port = Number(portText);
  if (!/^\d{1,5}$/.test(portText) || !Number.isInteger(port) || port < 1 || port > 65_535) {
    return null;
  }

  if (host.includes(":")) {
    const compact = normalizeIpv6(host);
    return compact && `[${compact}]:${port}`;
  }
  const octets = host.split(".");
  if (octets.length !== 4) return null;
  const parsed = octets.map((octet) => (/^\d{1,3}$/.test(octet) ? Number(octet) : -1));
  if (parsed.some((octet) => octet < 0 || octet > 255)) return null;
  return `${parsed.join(".")}:${port}`;
}

/**
 * The profile as it will actually be run, with a pinned address canonicalised.
 *
 * Applied to both the command preview and the launch so the two cannot disagree
 * about what is being dialled. A value that does not normalise is left alone
 * for the backend to reject with its own message.
 */
export function withNormalizedEndpoint<T extends { endpointMode: string; peer: string | null }>(profile: T): T {
  if (profile.endpointMode === "automatic") return profile;
  const canonical = normalizeEndpoint(profile.peer ?? "");
  return canonical ? { ...profile, peer: canonical } : profile;
}

/** The message to show under the field, or null when there is nothing to say. */
export function endpointError(mode: string, value: string, family: "v4" | "v6" | "both" = "both"): string | null {
  if (mode === "automatic") return null;
  if (!value.trim()) return "Enter an endpoint to pin";
  const canonical = normalizeEndpoint(value);
  if (!canonical) return "Must be a numeric address and port, like 162.159.192.18:443";
  // An IPv6 address normalises into brackets; anything else here is IPv4.
  const v6 = canonical.startsWith("[");
  if ((family === "v6" && !v6) || (family === "v4" && v6)) {
    return "The custom endpoint is not in the address family chosen under Addresses.";
  }
  return null;
}

function splitHostPort(input: string): [string, string] | null {
  if (input.startsWith("[")) {
    const closing = input.indexOf("]");
    if (closing <= 1 || input[closing + 1] !== ":") return null;
    return [input.slice(1, closing), input.slice(closing + 2)];
  }
  // A bare IPv6 has several colons and no port; only a single colon can be the
  // separator, which is why an unbracketed v6 address is rejected rather than
  // guessed at.
  const separator = input.lastIndexOf(":");
  if (separator <= 0 || input.indexOf(":") !== separator) return null;
  return [input.slice(0, separator), input.slice(separator + 1)];
}

function normalizeIpv6(host: string): string | null {
  const doubled = host.split("::");
  if (doubled.length > 2) return null;

  const expand = (part: string) => (part ? part.split(":") : []);
  const head = expand(doubled[0]);
  const tail = doubled.length === 2 ? expand(doubled[1]) : [];
  const groups = doubled.length === 2
    ? [...head, ...Array(8 - head.length - tail.length).fill("0"), ...tail]
    : head;
  if (groups.length !== 8 || (doubled.length === 2 && head.length + tail.length > 7)) return null;

  const values: number[] = [];
  for (const group of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(group)) return null;
    values.push(parseInt(group, 16));
  }
  return compress(values.map((value) => value.toString(16)));
}

/** RFC 5952: lower case, no leading zeroes, longest zero run collapsed once. */
function compress(groups: string[]): string {
  let bestStart = -1;
  let bestLength = 0;
  let start = -1;
  for (let index = 0; index <= groups.length; index += 1) {
    if (index < groups.length && groups[index] === "0") {
      if (start === -1) start = index;
    } else if (start !== -1) {
      const length = index - start;
      if (length > bestLength) { bestStart = start; bestLength = length; }
      start = -1;
    }
  }
  // A single zero group is written out; collapsing it saves nothing.
  if (bestLength < 2) return groups.join(":");
  return `${groups.slice(0, bestStart).join(":")}::${groups.slice(bestStart + bestLength).join(":")}`;
}
