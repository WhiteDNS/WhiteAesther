/**
 * Resolvers the full tunnel can ask over DoH: the same table as
 * `doh_upstreams` in `src-tauri/src/chain.rs`, which is what decides. Kept here
 * only so the screen can say which of the user's resolvers that mode skips.
 */
const HAS_DOH = new Set([
  "1.1.1.1", "2606:4700:4700::1111",
  "1.0.0.1", "2606:4700:4700::1001",
  "8.8.8.8", "2001:4860:4860::8888",
  "8.8.4.4", "2001:4860:4860::8844",
  "9.9.9.9", "2620:fe::fe",
  "149.112.112.112", "2620:fe::9",
]);

/** The resolvers full-tunnel mode will not ask, because they have no known DoH endpoint. */
export function skippedByFullTunnel(resolvers: string[]): string[] {
  return resolvers.filter((resolver) => !HAS_DOH.has(resolver.trim().replace(/^\[|\]$/g, "")));
}
