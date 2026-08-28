/**
 * Noticing that a newer build exists.
 *
 * Deliberately done from the web layer rather than the Rust one. The engine
 * side has `reqwest` in its dependency tree but no TLS backend, so an HTTPS
 * request from there would mean pulling in rustls and its C build — a toolchain
 * requirement on every CI runner, for a version check. The webview already has
 * a TLS stack, so it asks, and the CSP is widened by exactly one host.
 *
 * The check is allowed to fail and say nothing. On the networks this app exists
 * for, GitHub is not reachable until the tunnel is up — so a failure before
 * connecting is the expected case, not an error worth showing anyone.
 */

/** Where releases are published. Read-only, unauthenticated. */
const LATEST_RELEASE = "https://api.github.com/repos/WhiteDNS/WhiteAesther/releases/latest";

/** How long to wait before asking again. */
const CHECK_INTERVAL_MS = 6 * 60 * 60 * 1000;

const LAST_CHECK_KEY = "whiteaesther.update.lastCheck";
const DISMISSED_KEY = "whiteaesther.update.dismissed";

export interface Release {
  /** The version, without the leading "v". */
  version: string;
  /** The page a person is sent to in order to download it. */
  url: string;
}

/**
 * Compares two dotted versions numerically.
 *
 * Returns a negative number when `a` is older, positive when newer, zero when
 * they are the same release. String comparison would be wrong the moment a
 * number reaches double digits — "1.10.0" sorts before "1.9.0" as text — which
 * is exactly when nobody is testing this any more.
 */
export function compareVersions(a: string, b: string): number {
  const parts = (value: string) =>
    value
      .trim()
      .replace(/^v/i, "")
      // A prerelease suffix is dropped rather than ranked. We do not publish
      // them, and guessing an order for something we never ship would be a rule
      // written from nothing.
      .split("-")[0]
      .split(".")
      .map((piece) => Number.parseInt(piece, 10));

  const left = parts(a);
  const right = parts(b);
  for (let index = 0; index < Math.max(left.length, right.length); index += 1) {
    const one = left[index];
    const two = right[index];
    // A missing or unparseable segment counts as zero, so "1.6" and "1.6.0"
    // are the same release rather than an upgrade that never stops offering
    // itself.
    const first = Number.isFinite(one) ? one : 0;
    const second = Number.isFinite(two) ? two : 0;
    if (first !== second) return first - second;
  }
  return 0;
}

/** Whether `candidate` is a release worth telling someone about. */
export function isNewer(candidate: string, running: string): boolean {
  // An unknown running version means the build did not record one. Offering an
  // update against nothing would tell everyone to upgrade, every time.
  if (!running || running === "unknown") return false;
  return compareVersions(candidate, running) > 0;
}

/** Whether enough time has passed to ask GitHub again. */
export function isDueForCheck(now: number, lastCheck: number | null): boolean {
  if (lastCheck === null) return true;
  // A clock that moved backwards would otherwise park the next check in the
  // future and never ask again.
  if (lastCheck > now) return true;
  return now - lastCheck >= CHECK_INTERVAL_MS;
}

function readNumber(key: string): number | null {
  try {
    const raw = window.localStorage.getItem(key);
    if (raw === null) return null;
    const value = Number.parseInt(raw, 10);
    return Number.isFinite(value) ? value : null;
  } catch {
    // Storage can be unavailable. Not knowing when we last asked is a reason to
    // ask, not a reason to fail.
    return null;
  }
}

/**
 * Asks GitHub for the newest release, at most once every few hours.
 *
 * Returns the release only when it is newer than what is running and has not
 * already been dismissed. Every failure — offline, blocked, rate limited,
 * unparseable — resolves to null.
 */
export async function checkForUpdate(running: string, force = false): Promise<Release | null> {
  const now = Date.now();
  if (!force && !isDueForCheck(now, readNumber(LAST_CHECK_KEY))) return null;

  try {
    const response = await fetch(LATEST_RELEASE, {
      headers: { Accept: "application/vnd.github+json" },
    });
    // Record the attempt, not the success: a rate-limited or blocked network
    // should not be retried on every render.
    try {
      window.localStorage.setItem(LAST_CHECK_KEY, String(now));
    } catch {
      // Nothing to do; the check simply happens more often.
    }
    if (!response.ok) return null;

    const body = (await response.json()) as { tag_name?: string; html_url?: string };
    const tag = body.tag_name?.trim();
    if (!tag) return null;

    const version = tag.replace(/^v/i, "");
    if (!isNewer(version, running)) return null;
    if (wasDismissed(version)) return null;

    return {
      version,
      // Fall back to the tag's own page rather than inventing a URL shape.
      url: body.html_url || `https://github.com/WhiteDNS/WhiteAesther/releases/tag/${tag}`,
    };
  } catch {
    return null;
  }
}

/** Whether this exact version was already waved away. */
export function wasDismissed(version: string): boolean {
  try {
    return window.localStorage.getItem(DISMISSED_KEY) === version;
  } catch {
    return false;
  }
}

/**
 * Remembers that this version was dismissed.
 *
 * Per version rather than a flag, so waving away one release does not silence
 * the next one — which is the whole point of the notice.
 */
export function dismiss(version: string): void {
  try {
    window.localStorage.setItem(DISMISSED_KEY, version);
  } catch {
    // A dismissal that cannot be stored comes back next launch. Mildly
    // annoying, and better than failing.
  }
}
