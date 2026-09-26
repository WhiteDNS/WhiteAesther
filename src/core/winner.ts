import type { ConnectionProfile } from "../types";
import type { RaceWinner } from "./api";

/**
 * The profile a session started from a race has to run: the carrier, framing
 * and tactic the winning lane actually ran. Anything less and the race proves
 * one thing and the session runs another — a network that only lets a split
 * ClientHello through would see the race get out and the connect fail.
 */
export function profileForWinner(profile: ConnectionProfile, winner: RaceWinner): ConnectionProfile {
  return {
    ...profile,
    carriers: { first: winner.carrier, second: null },
    protocol: winner.protocol ?? profile.protocol,
    masqueTransport: winner.masqueTransport ?? profile.masqueTransport,
    fragmentClientHello: winner.fragmentClientHello ?? profile.fragmentClientHello,
    ech: winner.ech ?? profile.ech,
    endpointMode: winner.endpointMode ?? profile.endpointMode,
  };
}
