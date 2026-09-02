import { useCallback, useEffect, useRef, useState } from "react";
import { useT } from "@/core/useT";
import { CheckCircle2, Loader2, Radar, Search, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { cancelScan, scanEndpoints, testEndpoint, type ScanCandidate } from "@/core/api";
import { normalizeEndpoint } from "@/core/endpoint";
import { byNetwork, summarise } from "./grouping";
import type { ConnectionProfile, CoreSnapshot } from "@/types";

type Phase = "idle" | "scanning" | "testing" | "cancelling";

/**
 * The core's own ceiling. Asking for fewer hides whole ranges: results are
 * ranked by round-trip time, so the nearest network fills the list and the
 * alternatives you would want when it is throttled never appear.
 */
const SCAN_LIMIT = 16;

interface ScannerProps {
  profile: ConnectionProfile;
  snapshot: CoreSnapshot;
  onPick: (endpoint: string) => void;
  onToast: (title: string, message: string, error?: boolean) => void;
}

export function Scanner({ profile, snapshot, onPick, onToast }: ScannerProps) {
  const t = useT();
  const [phase, setPhase] = useState<Phase>("idle");
  const [candidates, setCandidates] = useState<ScanCandidate[]>([]);
  const [note, setNote] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  // A scan outlives this panel if the user navigates away mid-search, so the
  // late result must not be written into an unmounted component.
  const live = useRef(true);
  useEffect(() => {
    live.current = true;
    return () => { live.current = false; };
  }, []);

  const busy = phase === "scanning" || phase === "testing";
  // The core's reporting modes wrap a MASQUE-only probe, so the picker under
  // Routes has no effect here. Saying so beats letting someone select WireGuard
  // and conclude the scanner is broken.
  const masqueOnly = profile.protocol !== "masque";
  const connected = snapshot.state !== "idle" && snapshot.state !== "stopped" && snapshot.state !== "error";
  const pinned = normalizeEndpoint(profile.peer ?? "");

  const scan = useCallback(async () => {
    setPhase("scanning");
    setError(null);
    setNote(null);
    try {
      const outcome = await scanEndpoints(profile, SCAN_LIMIT);
      if (!live.current) return;
      setCandidates(outcome.candidates);
      if (outcome.candidates.length === 0) {
        setNote(t("Nothing answered on either transport. This network is filtering hard."));
      } else {
        setNote(
          outcome.fellBack
            ? `Nothing over ${label(profile.masqueTransport)}; these answered over ${label(outcome.transport)}.`
            : summarise(outcome.candidates),
        );
      }
    } catch (raw) {
      if (!live.current) return;
      const message = raw instanceof Error ? raw.message : String(raw);
      // Cancelling is a normal outcome, not a failure to shout about.
      if (message.includes("cancelled")) setNote("Scan cancelled.");
      else setError(message);
    } finally {
      if (live.current) setPhase("idle");
    }
  }, [profile]);

  const stop = useCallback(async () => {
    setPhase("cancelling");
    try {
      await cancelScan();
    } catch {
      /* the scan finished on its own between the click and the call */
    }
  }, []);

  const test = useCallback(async () => {
    const address = normalizeEndpoint(profile.peer ?? "");
    if (!address) {
      setError(t("Enter a numeric address and port first."));
      return;
    }
    setPhase("testing");
    setError(null);
    setNote(null);
    try {
      const result = await testEndpoint(profile, address);
      if (!live.current) return;
      setNote(`${result.peer} answered in ${result.rttMs} ms.`);
    } catch (raw) {
      if (!live.current) return;
      setError(raw instanceof Error ? raw.message : String(raw));
    } finally {
      if (live.current) setPhase("idle");
    }
  }, [profile]);

  return (
    <Card>
      <CardHeader className="flex-row items-start justify-between gap-4 space-y-0 pb-3">
        <div className="flex flex-col gap-1.5">
          <CardTitle className="text-[15px]">{t("Find a gateway")}</CardTitle>
          <CardDescription>
            {/* Split around the transport name so the two halves can be ordered
                the way each language orders them. */}
            {t("Tests real MASQUE gateways over")} {label(profile.masqueTransport)}{" "}
            {t("and ranks them by round-trip time. Nothing is connected until you pick one.")}
          </CardDescription>
        </div>
        <div className="flex shrink-0 gap-2">
          {phase === "scanning" ? (
            <Button variant="outline" size="sm" onClick={() => void stop()}>
              <X />
              {t("Stop")}
            </Button>
          ) : (
            <Button size="sm" disabled={connected || busy || phase === "cancelling"} onClick={() => void scan()}>
              {phase === "cancelling" ? <Loader2 className="animate-spin" /> : <Radar />}
              {t("Scan")}
            </Button>
          )}
          <Button
            variant="outline"
            size="sm"
            disabled={connected || busy || !pinned}
            onClick={() => void test()}
          >
            {phase === "testing" ? <Loader2 className="animate-spin" /> : <Search />}
            {t("Test pinned")}
          </Button>
        </div>
      </CardHeader>

      <CardContent className="pt-0">
        {masqueOnly ? (
          <p className="py-2 text-[13px] text-muted-foreground">
            Your protocol is set to{" "}
            <span className="font-medium text-foreground">
              {profile.protocol === "wg" ? "WireGuard" : "WARP in WARP"}
            </span>
            . This searches for MASQUE gateways only, so anything found here applies when you switch back to
            MASQUE — it will not change how {profile.protocol === "wg" ? "WireGuard" : "WARP in WARP"} connects.
          </p>
        ) : null}

        {connected ? (
          <p className="py-2 text-[13px] text-muted-foreground">
            Disconnect first — scanning while connected competes with the tunnel for the same gateways and
            reports worse numbers than the network really offers.
          </p>
        ) : null}

        {phase === "scanning" ? (
          <div className="flex items-center gap-2.5 py-3 text-[13px] text-muted-foreground">
            <Loader2 className="size-4 animate-spin text-primary" />
            Testing gateways over {label(profile.masqueTransport)}. This takes a while on a filtered network.
          </div>
        ) : null}

        {error ? <p className="py-2 text-[13px] text-destructive">{error}</p> : null}
        {note && !error ? <p className="py-2 text-[13px] text-muted-foreground">{note}</p> : null}

        {candidates.length > 0 ? (
          <div className="mt-1 flex flex-col gap-2.5">
            {byNetwork(candidates).map(({ network, members }) => (
              <div key={network} className="overflow-hidden rounded-md border">
                <div className="flex items-baseline justify-between gap-3 border-b bg-muted/40 px-3.5 py-2">
                  <span className="font-mono text-[12px] font-medium">{network}</span>
                  <span className="text-[11.5px] text-muted-foreground">
                    {members.length} gateway{members.length === 1 ? "" : "s"} · best{" "}
                    <span className="tabular font-mono">{members[0].rttMs} ms</span>
                  </span>
                </div>
                {members.map((candidate) => {
                  const chosen = pinned === candidate.peer;
                  const rank = candidates.indexOf(candidate) + 1;
                  return (
                    <button
                      key={candidate.peer}
                      type="button"
                      onClick={() => {
                        onPick(candidate.peer);
                        onToast("Endpoint pinned", `${candidate.peer} — set Endpoint mode to use it.`);
                      }}
                      className={[
                        "flex w-full items-center justify-between gap-3 border-b px-3.5 py-2.5 text-start transition-colors last:border-b-0",
                        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring",
                        chosen ? "bg-primary/10" : "hover:bg-accent",
                      ].join(" ")}
                    >
                      <div className="flex min-w-0 items-center gap-3">
                        <span className="tabular w-5 shrink-0 font-mono text-[11px] text-muted-foreground">
                          {rank}
                        </span>
                        <span className="truncate font-mono text-[13px]">{candidate.peer}</span>
                        {chosen ? <CheckCircle2 className="size-4 shrink-0 text-primary" /> : null}
                      </div>
                      <div className="flex shrink-0 items-center gap-2.5">
                        <Latency ms={candidate.rttMs} best={candidates[0].rttMs} />
                        <span className="tabular w-16 text-end font-mono text-[13px]">
                          {candidate.rttMs} ms
                        </span>
                      </div>
                    </button>
                  );
                })}
              </div>
            ))}
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
}

/** Relative bar, so the spread between candidates reads without doing the arithmetic. */
function Latency({ ms, best }: { ms: number; best: number }) {
  const ratio = Math.min(1, best > 0 ? best / Math.max(ms, 1) : 1);
  const tone = ms < 120 ? "bg-primary" : ms < 300 ? "bg-warning" : "bg-destructive";
  return (
    <span className="hidden h-1.5 w-20 overflow-hidden rounded-full bg-secondary sm:block">
      <span className={`block h-full rounded-full ${tone}`} style={{ width: `${Math.max(8, ratio * 100)}%` }} />
    </span>
  );
}

function label(transport: string): string {
  return transport === "h2" ? "MASQUE H2" : "MASQUE H3";
}
