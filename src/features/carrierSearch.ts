import type { CarrierChain, CarrierKind } from "../types.ts";

/**
 * What order to try ways out in, when the user does not know which works.
 *
 * Nine possibilities at up to a minute and a half each is a quarter of an hour,
 * so the order is the whole design: the cheap answer has to come first, and the
 * expensive ones only exist for the network where nothing cheap answers.
 */

/**
 * The single carriers, in measured order of how long they take to connect --
 * Aether around 25s, Psiphon around 40s, Tor around 60s. On most networks the
 * first one answers and the search is over in half a minute.
 */
const SINGLES: CarrierKind[] = ["aether", "psiphon", "tor"];

/**
 * The pairs, tried only once every single has failed -- which is the situation
 * the search exists for.
 *
 * Grouped by first hop in the same measured order, because the first hop is
 * what has to reach the physical network and so decides most of the wait.
 *
 * Chains are worth trying at all only because a single failing does not mean
 * its carrier cannot be reached *through* something else: measured here,
 * Aether reaches Cloudflare perfectly well through Psiphon or Tor on a network
 * where it cannot reach it directly. That is why the orderings ending at
 * Aether are in this list despite not changing the exit country.
 */
const PAIRS: Array<[CarrierKind, CarrierKind]> = [
  ["aether", "psiphon"],
  ["aether", "tor"],
  ["psiphon", "aether"],
  ["psiphon", "tor"],
  ["tor", "aether"],
  ["tor", "psiphon"],
];

/**
 * Every chain to try, in order.
 *
 * `available` is what the backend reports as installed; null means it has not
 * answered yet, and everything is offered rather than nothing. A carrier that
 * is not installed is left out of both halves -- attempting it would spend an
 * attempt on a certainty.
 */
export function searchOrder(available: CarrierKind[] | null): CarrierChain[] {
  const has = (kind: CarrierKind) => !available || available.includes(kind);
  const singles: CarrierChain[] = SINGLES.filter(has).map((first) => ({ first, second: null }));
  const pairs: CarrierChain[] = PAIRS.filter(([first, second]) => has(first) && has(second)).map(
    ([first, second]) => ({ first, second }),
  );
  return [...singles, ...pairs];
}

/**
 * How long to give one attempt before moving on.
 *
 * Long enough for a legitimately slow Psiphon behind a slow Tor, short enough
 * that the whole sweep stays bounded. Enforced by stopping the connection
 * rather than by abandoning it: the supervisor checks between hops and unwinds,
 * so a timed-out attempt leaves nothing running.
 */
export const ATTEMPT_CAP_MS = 90_000;

/** What happened to one attempt, for the list the user watches. */
export interface SearchAttempt {
  chain: CarrierChain;
  outcome: "trying" | "connected" | "failed" | "skipped";
  /** The backend's own words, when it refused or failed. */
  detail?: string;
}

/**
 * Whether a failure means "this can never work here" rather than "this did not
 * work just now".
 *
 * The backend refuses the impossible combinations immediately and by name --
 * no Aether identity to chain behind another carrier, or a manual upstream
 * proxy that a chain would have to overwrite. Those cost no time, so the search
 * attempts them and reads the refusal, rather than keeping a second copy of the
 * rule that could drift from the one the supervisor enforces.
 */
export function isImpossible(detail: string): boolean {
  return (
    detail.includes("cannot register from inside") ||
    detail.includes("already dials through a proxy of your own")
  );
}
