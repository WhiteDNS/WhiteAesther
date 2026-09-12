import type { CarrierChain, CarrierKind, CoreState } from "../types.ts";

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
 * How long each carrier is allowed to take, matching the deadline it already
 * enforces on itself in the backend.
 *
 * These are mirrors, and the backend is the original:
 *
 * | carrier | constant                              | where                   |
 * | ---     | ---                                   | ---                     |
 * | aether  | `AETHER_HOP_TIMEOUT`                  | `core_supervisor.rs`    |
 * | psiphon | `ESTABLISH_TIMEOUT`                   | `psiphon.rs`            |
 * | tor     | `BOOTSTRAP_TIMEOUT`                   | `tor.rs`                |
 *
 * A cap shorter than these does not bound the search -- it *replaces* the
 * deadline the carrier was given, and always wins. The single 90s cap this
 * replaced was shorter than all three: every attempt was cut before the thing
 * it was waiting for could answer, so a Psiphon that needed its first-run
 * tactics fetch (up to tunnel-core's full 300s window, which is why
 * `ESTABLISH_TIMEOUT` is what it is) could never be found by the one feature
 * aimed at the person who does not know what works.
 */
const CARRIER_DEADLINE_MS: Record<CarrierKind, number> = {
  // Replaced per attempt by `aetherDeadlineMs`, which knows how hard this
  // profile asked the engine to look. This is the default mode's figure, for a
  // caller that has no profile to ask.
  aether: 190_000,
  psiphon: 315_000,
  tor: 180_000,
};

/**
 * What the engine's own gateway scan is allowed to take, by scan mode.
 *
 * `overall_deadline` plus `quiet_after_first` from the engine's `prober.rs` --
 * the second is the extra it spends after its first hit before settling. Not
 * one number for every mode: `thorough` looks for more than seven times as long
 * as `turbo`, and a cap that ignores that fails the mode chosen precisely
 * because the network is hard.
 */
const SCAN_DEADLINE_MS: Record<string, number> = {
  turbo: 45_000,
  balanced: 140_000,
  thorough: 330_000,
  stealth: 205_000,
  ironclad: 195_000,
};

/**
 * How long the engine may take, for the profile it is actually being run with.
 *
 * `startupSecs` is added rather than assumed to bound the whole thing:
 * `--startup-secs` wraps only the tunnel handshake *after* a gateway has been
 * chosen, so it sits on top of the scan rather than containing it.
 */
export function aetherDeadlineMs(profile: SearchProfile): number {
  const scan = SCAN_DEADLINE_MS[profile.scanMode] ?? SCAN_DEADLINE_MS.balanced;
  return scan + profile.startupSecs * 1000;
}

/** What the search needs to know about a profile to size its waits. */
export interface SearchProfile {
  scanMode: string;
  startupSecs: number;
}

/**
 * Spawning the process, staging its files, reading Tor's control port: work
 * that happens before any carrier's own deadline starts running.
 */
const HOP_OVERHEAD_MS = 15_000;

/**
 * How long to give one attempt before moving on.
 *
 * The hops of a chain start one after another -- each has to be carrying
 * traffic before the next one begins -- so the wait is their deadlines added
 * up, not the longest of them.
 *
 * A safety net rather than the deadline itself: the backend fails the attempt
 * at its own deadline and returns a reason, which is the ordinary path. This
 * only fires when nothing came back at all. Enforced by stopping the
 * connection rather than by walking away: the supervisor checks between hops
 * and unwinds, so a timed-out attempt leaves nothing running.
 */
export function attemptCapMs(chain: CarrierChain, profile?: SearchProfile): number {
  const hops: CarrierKind[] = chain.second ? [chain.first, chain.second] : [chain.first];
  return hops.reduce((total, hop) => {
    const own = hop === "aether" && profile
      ? aetherDeadlineMs(profile)
      : CARRIER_DEADLINE_MS[hop];
    return total + own + HOP_OVERHEAD_MS;
  }, 0);
}

/**
 * The longest the whole sweep can take, for the sentence that says so before
 * anyone starts one.
 *
 * Worth showing rather than hiding. It is long -- every carrier being given the
 * time it actually needs is what makes it long -- and someone who knows that is
 * someone who waits rather than someone who stops at two minutes believing the
 * app has hung. See "Show a clock and ask for patience".
 */
export function searchBudgetMs(order: CarrierChain[], profile?: SearchProfile): number {
  return order.reduce((total, chain) => total + attemptCapMs(chain, profile), 0);
}

/** How often to ask the supervisor what the current attempt is doing. */
export const SETTLE_POLL_MS = 500;

/**
 * What one attempt's state means to the search.
 *
 * `start_core` returning is not the answer, and reading it as one is what this
 * exists to fix. On the chained path it blocks until a hop is carrying traffic,
 * so returning does mean connected -- but on the engine path it returns as soon
 * as the process is spawned, with the snapshot reading "starting" and the
 * search still ahead of it. Taking that as success meant the sweep settled on
 * Aether alone on the strength of a process having started, and the six chained
 * orderings below it were never reached on any machine where the engine binary
 * exists.
 *
 * "reconnecting" is the engine between its own attempts, which is still trying
 * and not yet an answer. "error" is where it stops for good -- `give_up` and
 * the kill-switch hold both land there -- and "idle" is a session that was
 * released underneath us, which is the Stop button or a supervisor that has let
 * go either way.
 */
export type AttemptVerdict = "waiting" | "connected" | "failed";

export function verdictFor(state: CoreState): AttemptVerdict {
  switch (state) {
    case "connected":
      return "connected";
    case "error":
    case "idle":
    case "stopped":
      return "failed";
    default:
      return "waiting";
  }
}

/** What happened to one attempt, for the list the user watches.
 *
 * "pending" and "skipped" are different facts and are shown differently:
 * the first is "not reached yet", the second is "reached and refused as
 * impossible here". Collapsing them would make a search that stopped early
 * look like one that ruled everything out.
 */
export interface SearchAttempt {
  chain: CarrierChain;
  outcome: "pending" | "trying" | "connected" | "failed" | "skipped";
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
