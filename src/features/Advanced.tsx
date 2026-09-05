import { useEffect, useMemo, useState } from "react";
import { useT } from "@/core/useT";
import {
  Activity, FileText, Globe, Link2, Route as RouteIcon, Scale, ShieldCheck, Wifi, type LucideIcon,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import { buildCoreCommand } from "@/core/command";
import { endpointError, normalizeEndpoint } from "@/core/endpoint";
import { REPORT_EVENT_LIMIT, buildReport, reportFilename } from "@/core/report";
import {
  type LanStatus,
  carriersAvailable,
  fetchBridges,
  isDesktopRuntime,
  lanShareStatus,
  psiphonStatus,
  saveReport,
  setLanShare,
  setPsiphonRegion,
} from "@/core/api";
import { NumberField, Row, RulesField, Seg, TextField } from "./panels";
import { Chain } from "./Chain";
import { Scanner } from "./Scanner";
import { transportName } from "./Simple";
// Bundled into the app rather than read from disk at runtime: the obligation is
// to ship these words with the binary, and a file read that can fail is not
// that. The same text is installed beside the executable under licences/.
import notices from "../../THIRD_PARTY_NOTICES.md?raw";
import {
  ENDPOINT_MODES, type ConnectionProfile, type LanSettings, type CoreLogEvent, type CoreProbe, type CoreSnapshot,
} from "@/types";

type SectionId =
  | "status"
  | "routes"
  | "endpoint"
  | "chain"
  | "traffic"
  | "identity"
  | "diagnostics"
  | "licences";

const SECTIONS: Array<{ group: string; items: Array<{ id: SectionId; label: string; icon: LucideIcon }> }> = [
  { group: "Connection", items: [
    { id: "status", label: "Status", icon: Activity },
    { id: "routes", label: "Routes & transports", icon: RouteIcon },
    { id: "endpoint", label: "Endpoint", icon: Globe },
    { id: "chain", label: "Exit chain", icon: Link2 },
  ] },
  { group: "System", items: [
    { id: "traffic", label: "Traffic & DNS", icon: Wifi },
    { id: "identity", label: "Identity", icon: ShieldCheck },
  ] },
  { group: "Support", items: [
    { id: "diagnostics", label: "Diagnostics", icon: FileText },
    { id: "licences", label: "Licences & notices", icon: Scale },
  ] },
];

const BLURB: Record<SectionId, string> = {
  status: "What the core is doing right now.",
  routes: "How hard to search, what the tunnel rides on, and how it hides.",
  endpoint: "Pin a specific gateway, or let the core find one.",
  chain: "Send the tunnel's traffic on through a node of your own, so the address you appear from changes.",
  traffic: "Where traffic goes once the tunnel is up.",
  identity: "Cloudflare Zero Trust enrolment.",
  diagnostics: "The core executable, logging, and a report you can hand to someone.",
  licences: "What WhiteAesther is built on, under what terms, and where to get the source.",
};

export interface AdvancedProps {
  profile: ConnectionProfile;
  onChange: (profile: ConnectionProfile) => void;
  snapshot: CoreSnapshot;
  probe: CoreProbe;
  logs: CoreLogEvent[];
  runtime: string;
  appVersion: string;
  onSave: () => void;
  onToast: (title: string, message: string, error?: boolean) => void;
  /**
   * Set by settings search. Carries a nonce as well as the section, because
   * searching for the same setting twice has to move there both times, and an
   * effect keyed on the section alone would only fire the first time.
   */
  jumpTo?: { section: SectionId; at: number } | null;
}

export function Advanced(props: AdvancedProps) {
  const t = useT();
  const [section, setSection] = useState<SectionId>("status");

  const { jumpTo } = props;
  useEffect(() => {
    if (jumpTo) setSection(jumpTo.section);
  }, [jumpTo]);
  const heading = SECTIONS.flatMap((group) => group.items).find((item) => item.id === section);

  return (
    <div className="grid h-full grid-cols-[196px_minmax(0,1fr)] overflow-hidden">
      <nav className="flex flex-col gap-0.5 overflow-y-auto border-r bg-card p-2" aria-label={t("Settings sections")}>
        {SECTIONS.map((group) => (
          <div key={group.group} className="flex flex-col gap-0.5">
            <span className="px-2.5 pb-1 pt-3.5 text-[10.5px] font-semibold uppercase tracking-wider text-muted-foreground">
              {t(group.group)}
            </span>
            {group.items.map(({ id, label, icon: Icon }) => (
              <button
                key={id}
                type="button"
                aria-current={section === id}
                onClick={() => setSection(id)}
                className={[
                  "flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-start text-[13.5px] transition-colors",
                  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
                  section === id
                    ? "bg-primary/10 font-semibold text-primary"
                    : "text-muted-foreground hover:bg-accent hover:text-foreground",
                ].join(" ")}
              >
                <Icon className="size-[15px]" />
                {t(label)}
              </button>
            ))}
          </div>
        ))}
      </nav>

      <div className="flex flex-col gap-4 overflow-y-auto p-6">
        <div className="flex items-start justify-between gap-4">
          <div className="flex flex-col gap-1">
            <h2 className="text-[19px] font-semibold tracking-tight">{heading ? t(heading.label) : null}</h2>
            <p className="text-sm text-muted-foreground">{t(BLURB[section])}</p>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            <StateBadge snapshot={props.snapshot} />
            <Button variant="outline" size="sm" onClick={props.onSave}>
              {t("Save profile")}
            </Button>
          </div>
        </div>

        {section === "status" && <Status {...props} />}
        {section === "routes" && <Routes {...props} />}
        {section === "endpoint" && <Endpoint {...props} />}
        {section === "chain" && (
          <Chain
            profile={props.profile}
            onChange={props.onChange}
            connected={props.snapshot.state === "connected"}
            onToast={props.onToast}
          />
        )}
        {section === "traffic" && <Traffic {...props} />}
        {section === "identity" && <Identity {...props} />}
        {section === "diagnostics" && <Diagnostics {...props} />}
        {section === "licences" && <Licences />}
      </div>
    </div>
  );
}

function StateBadge({ snapshot }: { snapshot: CoreSnapshot }) {
  const t = useT();
  if (snapshot.state === "connected")
    return <Badge variant="ok" className="gap-1.5"><span className="size-1.5 rounded-full bg-current" />{t("Connected")}</Badge>;
  if (snapshot.state === "error")
    return <Badge variant="bad" className="gap-1.5"><span className="size-1.5 rounded-full bg-current" />{t("Stopped")}</Badge>;
  if (snapshot.state === "idle") return <Badge variant="outline">{t("Idle")}</Badge>;
  return (
    <Badge variant="warn" className="gap-1.5">
      <span className="size-1.5 animate-pulse rounded-full bg-current" />
      {snapshot.attempt > 0 ? `${t("Attempt")} ${snapshot.attempt}/${snapshot.maxAttempts}` : t("Working")}
    </Badge>
  );
}

// ---------------------------------------------------------------------- status

function Status({ snapshot, probe, logs, profile }: AdvancedProps) {
  const t = useT();
  return (
    <>
      <div className="grid grid-cols-4 gap-3">
        <Metric label="Core" value={probe.available ? "Ready" : t("Missing")} />
        <Metric label="Transport" value={snapshot.transport ? transportName(snapshot.transport) : "—"} />
        <Metric label="Edge" value={snapshot.endpoint ?? "—"} mono />
        <Metric label="Latency" value={snapshot.latencyMs == null ? "—" : `${snapshot.latencyMs.toFixed(1)} ms`} mono />
      </div>

      <Card>
        <CardHeader className="pb-2"><CardTitle className="text-[15px]">{t("Live")}</CardTitle></CardHeader>
        <CardContent><LogList logs={logs} /></CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-[15px]">{t("What will run")}</CardTitle>
          <CardDescription>
            {t(
              "The core is launched with these arguments. Zero Trust secrets go through the environment and are not shown here.",
            )}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <pre className="overflow-x-auto whitespace-pre-wrap break-all rounded-md bg-muted/50 p-3 font-mono text-[11.5px] leading-relaxed text-foreground/80">
            {buildCoreCommand(profile)}
          </pre>
        </CardContent>
      </Card>
    </>
  );
}

function Metric({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  const t = useT();
  return (
    <Card className="p-3.5">
      <div className="flex flex-col gap-1">
        <span className="text-[10.5px] font-semibold uppercase tracking-wider text-muted-foreground">{t(label)}</span>
        <span className={`truncate text-[15px] font-medium ${mono ? "tabular font-mono" : ""}`}>{value}</span>
      </div>
    </Card>
  );
}

const LEVEL: Record<string, string> = {
  error: "text-destructive",
  warn: "text-warning",
  info: "text-primary",
  debug: "text-muted-foreground",
  trace: "text-muted-foreground",
};

function LogList({ logs }: { logs: CoreLogEvent[] }) {
  const t = useT();
  if (!logs.length)
    return <p className="py-6 text-center text-[13px] text-muted-foreground">{t("No events yet. Connect to populate this.")}</p>;
  return (
    <div className="flex max-h-[260px] flex-col gap-1 overflow-y-auto rounded-md bg-muted/50 p-3 font-mono text-[11.5px]">
      {logs.slice(-200).map((entry, index) => (
        <div key={`${entry.timestamp}-${index}`} className="grid grid-cols-[64px_78px_minmax(0,1fr)] gap-2.5">
          <span className="tabular text-muted-foreground">{new Date(entry.timestamp).toLocaleTimeString()}</span>
          <span className={LEVEL[entry.level] ?? "text-muted-foreground"}>{entry.stream}</span>
          <span className="break-words text-foreground/80">{entry.message}</span>
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------- routes

/**
 * What WhiteAesther is built on and under what terms.
 *
 * Aether is linked, so WhiteAesther is a derivative work and AGPL-3.0 obliges us
 * to point at the source of the build someone is actually running. mihomo is
 * conveyed as a separate executable under GPL-3.0, which obliges us to pass its
 * licence on with it. Neither obligation is met by a licence file sitting in a
 * repository nobody opens, so the text ships in the app and beside the binary.
 */
function Licences() {
  const t = useT();
  return (
    <div className="space-y-3.5">
      <Card>
        <CardHeader>
          <CardTitle>{t("What this is built on")}</CardTitle>
          <CardDescription>
            Each component below keeps its own licence. WhiteAesther&apos;s own source is public, and
            the full licence texts are installed next to the application under{" "}
            <code className="font-mono text-[12px]">licences/</code>.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-2.5">
          <Row first title="WhiteAesther" help="This application. Source at github.com/WhiteDNS/WhiteAesther">
            <span className="font-mono text-[12.5px] text-muted-foreground">AGPL-3.0</span>
          </Row>
          <Separator />
          <Row title="Aether" help="The connection engine, shipped as a binary and run by this app. Aether 1.8.0">
            <span className="font-mono text-[12.5px] text-muted-foreground">AGPL-3.0</span>
          </Row>
          <Separator />
          <Row
            title="mihomo"
            help="The second hop behind Exit chain, run as a separate program. Source at github.com/MetaCubeX/mihomo at tag v1.19.30"
          >
            <span className="font-mono text-[12.5px] text-muted-foreground">GPL-3.0</span>
          </Row>
          <Separator />
          <Row
            title="Iran routing lists"
            help="The addresses and domains behind “Iranian sites bypass the tunnel”, bundled as data. Source at github.com/Chocolate4U/Iran-clash-rules"
          >
            <span className="font-mono text-[12.5px] text-muted-foreground">GPL-3.0</span>
          </Row>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>{t("Full notices")}</CardTitle>
          <CardDescription>
            The same text that ships with the installer, including trademark terms and where each
            component&apos;s corresponding source lives.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <pre className="max-h-[420px] overflow-auto whitespace-pre-wrap break-words rounded-md border bg-muted/40 p-3.5 font-mono text-[11.5px] leading-relaxed text-muted-foreground">
            {notices}
          </pre>
        </CardContent>
      </Card>
    </div>
  );
}

/** The four things the core can actually be, rather than a transport toggle alone. */
const PROTOCOLS: Array<{ id: string; label: string; detail: string; protocol: ConnectionProfile["protocol"]; transport?: "h2" | "h3" }> = [
  { id: "h2", label: "MASQUE H2", detail: "TCP. Survives networks that block UDP.", protocol: "masque", transport: "h2" },
  { id: "h3", label: "MASQUE H3", detail: "QUIC. Lower overhead where UDP gets through.", protocol: "masque", transport: "h3" },
  { id: "wg", label: "WireGuard", detail: "UDP, with an obfuscation profile sweep.", protocol: "wg" },
  { id: "gool", label: "WARP in WARP", detail: "Nested tunnel. Slower, harder to classify.", protocol: "gool" },
];

/**
 * The ways out of the network, and what each one costs.
 *
 * Tor is deliberately absent until it exists: an option that saves and does
 * nothing is worse than one that is not offered.
 */
const CARRIERS: Array<{ id: ConnectionProfile["carrier"]; label: string; detail: string }> = [
  {
    id: "aether",
    label: "Aether",
    detail: "Cloudflare's network. Fast, and exits near you — it does not change your country.",
  },
  {
    id: "psiphon",
    label: "Psiphon",
    detail: "Finds its own way out and can exit from another country. Slower to connect.",
  },
  {
    id: "tor",
    label: "Tor",
    detail: "Three relays. The strongest against being identified, and the slowest. No UDP.",
  },
];

/**
 * Where Tor's bridges come from.
 *
 * The built-in list is Tor's own, shipped inside the expert bundle beside the
 * binary it belongs to — so it can only go stale when the bundle does.
 */
const BRIDGE_MODES: Array<[ConnectionProfile["tor"]["bridges"], string]> = [
  ["none", "Off"],
  ["built-in", "Built-in"],
  ["custom", "Pasted"],
];

const BRIDGE_TRANSPORTS: Array<[string, string]> = [
  ["obfs4", "obfs4"],
  ["snowflake", "snowflake"],
  ["meek", "meek"],
];

/** Tor's bridges: off, Tor's own list, or lines the user was given. */
function TorPanel({
  profile,
  onChange,
}: Pick<AdvancedProps, "profile" | "onChange">) {
  const set = (patch: Partial<ConnectionProfile["tor"]>) =>
    onChange({ ...profile, tor: { ...profile.tor, ...patch } });

  return (
    <>
      <Row
        title="Bridges"
        help="Only needed where Tor itself is blocked. Off is faster and works on an ordinary network."
      >
        <Seg value={profile.tor.bridges} options={BRIDGE_MODES} onChange={(bridges) => set({ bridges })} />
      </Row>

      {profile.tor.bridges === "built-in" ? (
        <Row
          title="Bridge transport"
          help="Tor ships these bridges itself, so they are as current as this build. They are also public, which is what a censor blocks first."
        >
          <Seg
            value={profile.tor.transport || "obfs4"}
            options={BRIDGE_TRANSPORTS}
            onChange={(transport) => set({ transport })}
          />
        </Row>
      ) : null}

      {profile.tor.bridges === "custom" ? (
        <>
          <RulesField
            label="Bridge lines"
            help="One per line, from bridges.torproject.org or someone who has one. A leading “Bridge” is fine — it is stripped."
            value={profile.tor.customBridges}
            onChange={(customBridges) => set({ customBridges })}
            placeholder="obfs4 1.2.3.4:443 FINGERPRINT cert=… iat-mode=0"
          />
          <BridgeFetch
            onFetched={(lines) =>
              set({
                // Appended rather than replacing: someone who was given a
                // working line by a friend should not lose it to a button.
                customBridges: [profile.tor.customBridges.trim(), lines.join("\n")]
                  .filter(Boolean)
                  .join("\n"),
              })
            }
          />
        </>
      ) : null}
    </>
  );
}

/**
 * The one-tap fetch: ask Tor which bridges work in a country.
 *
 * The request goes out through whichever carrier is already up, because
 * `bridges.torproject.org` is blocked in most of the places its answer is
 * wanted. And it asks about the country the person is *in*, which is why there
 * is a field rather than a guess — a desktop has no SIM to read one from, and
 * inferring it from the current exit would ask about the one country the answer
 * does not apply to.
 */
function BridgeFetch({ onFetched }: { onFetched: (lines: string[]) => void }) {
  const t = useT();
  const [country, setCountry] = useState("");
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);
  const [failure, setFailure] = useState<string | null>(null);

  const ask = async () => {
    setFailure(null);
    setNote(null);
    setBusy(true);
    try {
      const lines = await fetchBridges(country);
      onFetched(lines);
      setNote(`${lines.length} ${lines.length === 1 ? "bridge added" : "bridges added"}`);
    } catch (error) {
      setFailure(String(error));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <Row
        title="Ask Tor for bridges"
        help="The country you are connecting from, not the one you want to appear in. Sent through your current connection, because this service is itself blocked in most places it is needed."
      >
        <div className="flex items-center gap-2">
          <Input
            value={country}
            onChange={(event) => setCountry(event.target.value.toUpperCase().slice(0, 2))}
            placeholder="IR"
            className="h-9 w-16 text-center font-mono text-[13px]"
            aria-label={t("Country you are connecting from")}
          />
          <Button
            variant="outline"
            size="sm"
            disabled={busy || country.trim().length !== 2}
            onClick={() => void ask()}
          >
            {busy ? t("Asking…") : t("Fetch")}
          </Button>
        </div>
      </Row>
      {note ? <p className="pb-1 text-[12.5px] text-muted-foreground">{note}</p> : null}
      {failure ? <p className="pb-1 text-[12.5px] text-destructive">{failure}</p> : null}
    </>
  );
}

/**
 * Choosing the way out, and where it comes out.
 *
 * The country list is Psiphon's own answer rather than a table of ours, so it
 * is empty until the first successful connect — the field says "best available"
 * until then instead of offering countries it cannot promise.
 */
function CarrierPanel({
  profile,
  onChange,
}: Pick<AdvancedProps, "profile" | "onChange">) {
  const t = useT();
  const set = (patch: Partial<ConnectionProfile>) => onChange({ ...profile, ...patch });
  const [regions, setRegions] = useState<string[]>([]);
  const [moving, setMoving] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);
  // Everything until the backend answers. A picker that starts empty and fills
  // in would flicker; one that starts full and removes a carrier is worse,
  // because someone may have clicked it already.
  const [available, setAvailable] = useState<ConnectionProfile["carrier"][] | null>(null);

  useEffect(() => {
    if (!isDesktopRuntime()) return;
    let cancelled = false;
    carriersAvailable()
      .then((list) => {
        if (!cancelled) setAvailable(list);
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (profile.carrier !== "psiphon" || !isDesktopRuntime()) return;
    let cancelled = false;
    const read = () =>
      psiphonStatus()
        .then((status) => {
          if (!cancelled) setRegions(status.availableRegions);
        })
        .catch(() => {});
    read();
    // Psiphon reports its countries after a handshake, so the list arrives some
    // time after the screen does. Polling rather than waiting for an event
    // because it changes at most once per session.
    const timer = window.setInterval(read, 5_000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [profile.carrier]);

  const chooseRegion = async (region: string) => {
    set({ psiphon: { ...profile.psiphon, egressRegion: region } });
    if (!isDesktopRuntime()) return;
    setFailure(null);
    setMoving(true);
    try {
      // Applies to a live session; a no-op when nothing is connected, in which
      // case the choice above still stands for the next connect.
      await setPsiphonRegion(region);
    } catch (error) {
      setFailure(String(error));
    } finally {
      setMoving(false);
    }
  };

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-[15px]">{t("Way out")}</CardTitle>
        <CardDescription>
          {t("What carries your traffic off this network. Everything below applies to Aether only.")}
        </CardDescription>
      </CardHeader>
      <CardContent className="pt-0">
        <div className="grid grid-cols-2 gap-2.5">
          {CARRIERS.filter((option) => !available || available.includes(option.id)).map((option) => {
            const on = profile.carrier === option.id;
            return (
              <button
                key={option.id}
                type="button"
                aria-pressed={on}
                onClick={() => set({ carrier: option.id })}
                className={`rounded-lg border p-3 text-left transition ${
                  on ? "border-primary bg-primary/5" : "border-border hover:border-primary/40"
                }`}
              >
                <div className="text-[13.5px] font-medium">{t(option.label)}</div>
                <div className="mt-1 text-[12.5px] leading-snug text-muted-foreground">
                  {t(option.detail)}
                </div>
              </button>
            );
          })}
        </div>

        {profile.carrier === "psiphon" ? (
          <>
            <Row title="Exit country" help="A preference, not a guarantee. Psiphon keeps trying rather than substituting, so a country with no capacity is a slow connect.">
              <select
                value={profile.psiphon.egressRegion}
                disabled={moving}
                onChange={(event) => void chooseRegion(event.target.value)}
                className="h-9 rounded-md border border-input bg-background px-2 text-[13px]"
              >
                <option value="">{t("Best available")}</option>
                {regions.map((region) => (
                  <option key={region} value={region}>
                    {region}
                  </option>
                ))}
              </select>
            </Row>
            {moving ? (
              <p className="pb-1 text-[12.5px] text-muted-foreground">
                {t("Moving the exit. This reconnects, so it takes as long as connecting does.")}
              </p>
            ) : null}
            {failure ? <p className="pb-1 text-[12.5px] text-destructive">{failure}</p> : null}
            {regions.length === 0 ? (
              <p className="pb-1 text-[12.5px] text-muted-foreground">
                {t("The country list is Psiphon's own and arrives once you have connected at least once.")}
              </p>
            ) : null}
            {/* The brief's rule, made visible rather than left to be discovered:
                the scanner, the pinned endpoint and the discovery depth all
                describe a hunt for a Cloudflare gateway, and none of them do
                anything here. */}
            <p className="pt-2 text-[12.5px] leading-snug text-muted-foreground">
              {t("Under Psiphon the endpoint scanner, the pinned endpoint and the transport choice do nothing — Psiphon finds its own route.")}
            </p>
          </>
        ) : null}

        {profile.carrier === "tor" ? (
          <>
            <TorPanel profile={profile} onChange={onChange} />
            {/* Said plainly rather than left to be met as a fault. Tor carries
                no datagrams, so the chain refuses them rather than swallowing
                them — which is what makes a resolver fall back to TCP within a
                round trip instead of hanging. */}
            <p className="pt-2 text-[12.5px] leading-snug text-muted-foreground">
              {t("Tor carries no UDP, so QUIC and plain DNS are refused rather than left to hang. Pages still load and names still resolve.")}
            </p>
            <p className="pt-1 text-[12.5px] leading-snug text-muted-foreground">
              {t("Under Tor the endpoint scanner, the pinned endpoint and the transport choice do nothing — Tor picks its own relays.")}
            </p>
          </>
        ) : null}
      </CardContent>
    </Card>
  );
}

function Routes({ profile, onChange }: AdvancedProps) {
  const t = useT();
  const set = (patch: Partial<ConnectionProfile>) => onChange({ ...profile, ...patch });
  const active =
    profile.protocol === "masque" ? profile.masqueTransport : profile.protocol === "wg" ? "wg" : "gool";
  const isMasque = profile.protocol === "masque";
  const isH2 = isMasque && profile.masqueTransport === "h2";

  return (
    <>
      <CarrierPanel profile={profile} onChange={onChange} />
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-[15px]">{t("Protocol")}</CardTitle>
          <CardDescription>{t("Retries alternate the two MASQUE transports automatically.")}</CardDescription>
        </CardHeader>
        <CardContent className="grid grid-cols-2 gap-2.5 pt-0">
          {PROTOCOLS.map((option) => {
            const on = active === option.id;
            return (
              <button
                key={option.id}
                type="button"
                aria-pressed={on}
                onClick={() =>
                  set({ protocol: option.protocol, ...(option.transport ? { masqueTransport: option.transport } : {}) })
                }
                className={[
                  "flex flex-col gap-1 rounded-lg border p-3 text-start transition-colors",
                  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
                  on ? "border-primary bg-primary/10 ring-1 ring-primary" : "border-border hover:bg-accent",
                ].join(" ")}
              >
                {/* The label is a protocol name and stays as it is; only the
                    sentence under it is ours to translate. */}
                <span className="text-[13.5px] font-semibold">{option.label}</span>
                <span className="text-xs leading-snug text-muted-foreground">{t(option.detail)}</span>
              </button>
            );
          })}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-1"><CardTitle className="text-[15px]">{t("Search")}</CardTitle></CardHeader>
        <CardContent className="pt-0">
          <Row first title="Search depth" help="Deeper searches take longer but survive stricter filtering.">
            <Seg
              value={profile.scanMode}
              onChange={(scanMode) => set({ scanMode })}
              options={[["turbo", "turbo"], ["balanced", "balanced"], ["thorough", "thorough"], ["stealth", "stealth"], ["ironclad", "ironclad"]]}
            />
          </Row>
          <Row title="Addresses" help="Turn off IPv6 where the network handles it badly.">
            <Seg
              value={profile.ipFamily}
              onChange={(ipFamily) => set({ ipFamily })}
              options={[["both", "both"], ["v4", "IPv4"], ["v6", "IPv6"]]}
            />
          </Row>
          <Row title="Reuse the last working edge" help="Verify the cached gateway before scanning fresh.">
            <Switch checked={profile.quickReconnect} onCheckedChange={(quickReconnect) => set({ quickReconnect })} />
          </Row>
          <Row title="End-to-end data check" help="Expose the proxy only after a real tunnelled request succeeds.">
            <Switch checked={profile.dataCheck} onCheckedChange={(dataCheck) => set({ dataCheck })} />
          </Row>
          <Row title="Resource profile" help="How much concurrency the core gives the scan.">
            <Seg
              value={profile.performanceProfile}
              onChange={(performanceProfile) => set({ performanceProfile })}
              options={[["auto", "auto"], ["low", "low"], ["medium", "medium"], ["high", "high"]]}
            />
          </Row>
          <Separator />
          <div className="grid grid-cols-3 gap-4 pt-4">
            <NumberField
              label="Validation deadline" unit="sec" min={1} max={120}
              value={profile.validateSecs} onChange={(validateSecs) => set({ validateSecs })}
            />
            <NumberField
              label="Startup deadline" unit="sec" min={5} max={300}
              value={profile.startupSecs} onChange={(startupSecs) => set({ startupSecs })}
            />
            <NumberField
              label="Reconnect delay" unit="sec" min={0} max={120}
              value={profile.reconnectSecs} onChange={(reconnectSecs) => set({ reconnectSecs })}
            />
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-1">
          <CardTitle className="text-[15px]">{t("Anti-blocking")}</CardTitle>
          <CardDescription>
            {isMasque
              ? t("Both cost a little on a healthy network and only matter on a filtered one.")
              : t("Obfuscation applies to WireGuard; the TLS options are MASQUE H2 only.")}
          </CardDescription>
        </CardHeader>
        <CardContent className="pt-0">
          <Row
            first
            title="Split the TLS opening"
            help={isH2 ? t("Defeats filtering that reads only the first packet.") : t("MASQUE H2 only — has no effect on the selected protocol.")}
          >
            <Switch
              disabled={!isH2}
              checked={profile.fragmentClientHello}
              onCheckedChange={(fragmentClientHello) => set({ fragmentClientHello })}
            />
          </Row>
          {isH2 && profile.fragmentClientHello ? (
            <>
              <Separator />
              <div className="grid grid-cols-2 gap-4 py-4">
                <TextField
                  label="Fragment size" mono value={profile.fragmentSize}
                  onChange={(fragmentSize) => set({ fragmentSize })}
                  help="Bytes per write, or a range like 16-32."
                />
                <TextField
                  label="Fragment delay" mono value={profile.fragmentDelay}
                  onChange={(fragmentDelay) => set({ fragmentDelay })}
                  help="Milliseconds between writes, or a range."
                />
              </div>
            </>
          ) : null}
          <Row title="Obfuscation profile" help="Padding that makes tunnel traffic harder to fingerprint.">
            <Seg
              value={profile.noize}
              onChange={(noize) => set({ noize })}
              options={[["off", "off"], ["light", "light"], ["firewall", "firewall"], ["balanced", "balanced"], ["gfw", "gfw"], ["aggressive", "aggressive"]]}
            />
          </Row>
          <Row title="Try other obfuscation profiles" help="On WireGuard, fall back through the other profiles when one finds nothing.">
            <Switch checked={profile.profileRetry} onCheckedChange={(profileRetry) => set({ profileRetry })} />
          </Row>
          <Row title="WireGuard keepalive" help="How often to hold the UDP mapping open. Zero leaves it to the engine.">
            <div className="w-[132px]">
              <NumberField
                unit="sec" min={0} max={300}
                value={profile.keepaliveSecs} onChange={(keepaliveSecs) => set({ keepaliveSecs })}
              />
            </div>
          </Row>
          <Row
            title="Match domain rules on sniffed names"
            help="Reads the host name from the first bytes of a connection, so rules written as domains still match when a program connects to a bare address. Off, those rules only match when a name was supplied."
          >
            <Switch checked={profile.routeSniff} onCheckedChange={(routeSniff) => set({ routeSniff })} />
          </Row>
          <Row
            title="Register again if the identity is refused"
            help="Cloudflare sometimes stops accepting a saved device, and the handshake then succeeds while nothing passes. Off, the refusal is reported and the identity kept — which is what you want while diagnosing an account, and not otherwise."
          >
            <Switch
              checked={profile.autoReprovision}
              onCheckedChange={(autoReprovision) => set({ autoReprovision })}
            />
          </Row>
          <Separator />
          <div className="grid grid-cols-2 gap-4 pt-4">
            <TextField
              label="Encrypted Client Hello" mono value={profile.ech ?? ""}
              placeholder="off, auto, or base64"
              onChange={(value) => set({ ech: value || null })}
              help="Hides the hostname where the upstream supports it."
            />
            <TextField
              label="TLS groups" mono value={profile.tlsGroups ?? ""}
              placeholder="Core default"
              onChange={(value) => set({ tlsGroups: value || null })}
              help="Key exchange groups to offer, comma separated."
            />
            <TextField
              label="Dial through a local proxy" mono value={profile.upstreamProxy}
              placeholder="socks5://host:port"
              onChange={(upstreamProxy) => set({ upstreamProxy })}
              help="The endpoint search goes through it too, so it never reveals the address the tunnel hides."
            />
          </div>
        </CardContent>
      </Card>
    </>
  );
}

// -------------------------------------------------------------------- endpoint

function Endpoint({ profile, onChange, snapshot, onToast }: AdvancedProps) {
  const t = useT();
  const set = (patch: Partial<ConnectionProfile>) => onChange({ ...profile, ...patch });
  const error = endpointError(profile.endpointMode, profile.peer ?? "");
  const canonical = normalizeEndpoint(profile.peer ?? "");
  return (
    <>
      <Scanner
        profile={profile}
        snapshot={snapshot}
        onToast={onToast}
        // Picking a candidate is only useful if it is actually used, so the mode
        // moves off Automatic at the same time.
        onPick={(peer) =>
          set({ peer, endpointMode: profile.endpointMode === "automatic" ? "custom-first" : profile.endpointMode })
        }
      />
      <Card>
        <CardHeader className="pb-1"><CardTitle className="text-[15px]">{t("Pinned endpoint")}</CardTitle></CardHeader>
        <CardContent className="pt-0">
          <Row first title="How the gateway is chosen" help="Custom first spends one attempt on your address before searching. Custom only never searches.">
            <Seg
              value={profile.endpointMode}
              onChange={(endpointMode) => set({ endpointMode })}
              options={ENDPOINT_MODES.map((mode) => [mode.id, mode.label] as [typeof mode.id, string])}
            />
          </Row>
          {profile.endpointMode !== "automatic" ? (
            <>
              <Separator />
              <div className="py-4">
                <TextField
                  label="Address" mono value={profile.peer ?? ""}
                  placeholder="162.159.192.18:443"
                  onChange={(value) => set({ peer: value || null })}
                  error={error}
                  help={`${canonical && canonical !== profile.peer?.trim() ? `Reads as ${canonical}. ` : ""}${
                    profile.endpointMode === "custom-first"
                      ? t("One attempt goes here; if it fails the core searches instead and says so.")
                      : t("Every attempt goes here. Nothing else is tried.")
                  }`}
                />
              </div>
            </>
          ) : profile.peer?.trim() ? (
            <>
              <Separator />
              <p className="py-3.5 text-[13px] text-muted-foreground">
                {t("A saved address is kept but not used while this is Automatic.")}
              </p>
            </>
          ) : null}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-1">
          <CardTitle className="text-[15px]">{t("Per-protocol overrides")}</CardTitle>
          <CardDescription>{t("Left empty, each protocol uses the pinned endpoint above or its own search.")}</CardDescription>
        </CardHeader>
        <CardContent className="grid grid-cols-2 gap-4 pt-2">
          <TextField
            label="HTTP/2 gateway" mono value={profile.h2Peer ?? ""}
            placeholder="Automatic · IP:port"
            onChange={(value) => set({ h2Peer: value || null })}
          />
          <TextField
            label="WireGuard endpoint" mono value={profile.wgPeer ?? ""}
            placeholder="Automatic · IP:port"
            onChange={(value) => set({ wgPeer: value || null })}
          />
        </CardContent>
      </Card>
    </>
  );
}

// --------------------------------------------------------------------- traffic

function Traffic({ profile, onChange, runtime, snapshot, onToast }: AdvancedProps) {
  const t = useT();
  const set = (patch: Partial<ConnectionProfile>) => onChange({ ...profile, ...patch });
  return (
    <>
      <Card>
        <CardHeader className="pb-1"><CardTitle className="text-[15px]">{t("Reach")}</CardTitle></CardHeader>
        <CardContent className="pt-0">
          <Row first title="Set the system proxy while connected" help={systemProxyHelp(runtime)}>
            <Switch checked={profile.systemProxy} onCheckedChange={(systemProxy) => set({ systemProxy })} />
          </Row>
          <Row
            title="Keep me connected"
            help="Search again when a route drops. Off, a dead session stays dead, which is what you want while testing a network."
          >
            <Switch
              checked={profile.autoReconnect}
              onCheckedChange={(autoReconnect) => set({ autoReconnect })}
            />
          </Row>
          <Row
            title="Block traffic if the tunnel drops"
            help="Applications fail rather than send traffic in the clear. Until a route comes back or you disconnect, this machine has no working proxy."
          >
            <Switch checked={profile.killSwitch} onCheckedChange={(killSwitch) => set({ killSwitch })} />
          </Row>
          <p className="pb-1 text-[13px] text-muted-foreground">
            {t("Put back on disconnect. If the app is killed rather than closed, the next launch restores it.")}
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-1"><CardTitle className="text-[15px]">{t("Local proxy and DNS")}</CardTitle></CardHeader>
        <CardContent className="grid grid-cols-2 gap-4 pt-2">
          <TextField
            label="Proxy address" mono value={profile.socksAddress}
            onChange={(socksAddress) => set({ socksAddress })}
            help="Where the SOCKS5 listener binds."
          />
          <TextField
            label="DNS resolvers" mono value={profile.dns.join(", ")}
            onChange={(value) => set({ dns: value.split(",").map((item) => item.trim()).filter(Boolean) })}
            help="One to eight addresses, comma separated."
          />
        </CardContent>
      </Card>

      <LanSharing
        profile={profile}
        onChange={onChange}
        connected={snapshot.state === "connected"}
        onToast={onToast}
      />

      <Card>
        <CardHeader className="pb-1">
          <CardTitle className="text-[15px]">{t("Routing rules")}</CardTitle>
          <CardDescription>
            {t("Blocked first, then direct; everything left over enters the tunnel. One rule per line.")}
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4 pt-2">
          <Row
            first
            title="Iranian sites bypass the tunnel"
            help="Filtering only applies to traffic that looks like it left Iran, so these sites gain nothing from the tunnel and only pay for the exit's bandwidth. The list ships with the app and is not fetched."
          >
            <Switch
              checked={profile.bypassIranSites}
              onCheckedChange={(bypassIranSites) => set({ bypassIranSites })}
            />
          </Row>
          <div className="grid grid-cols-2 gap-4">
            <RulesField
              label="Never send" value={profile.routeBlock}
              placeholder={"keyword:doubleclick\nport:25"}
              onChange={(routeBlock) => set({ routeBlock })}
            />
            <RulesField
              label="Bypass the tunnel" value={profile.routeDirect}
              placeholder={"private\n10.0.0.0/8"}
              onChange={(routeDirect) => set({ routeDirect })}
            />
          </div>
          <TextField
            label="Rules file" mono value={profile.routesFile ?? ""}
            placeholder="Optional absolute path"
            onChange={(value) => set({ routesFile: value || null })}
            help="Read in addition to the rules above."
          />
        </CardContent>
      </Card>
    </>
  );
}

/**
 * Sharing this machine's tunnel with the rest of the network.
 *
 * The switch is the whole feature and the warning is half of it: a proxy on a
 * network port is a proxy anyone on that network can use, and on a café or
 * office network that is everyone. Sign-in is optional because a home network
 * where it does not matter is the common case -- but the consequence is stated
 * on screen while it is off, not buried in a help line nobody opens.
 */
function LanSharing({
  profile,
  onChange,
  connected,
  onToast,
}: {
  profile: ConnectionProfile;
  onChange: (profile: ConnectionProfile) => void;
  connected: boolean;
  onToast: (title: string, message: string, error?: boolean) => void;
}) {
  const t = useT();
  const share = profile.lanShare;
  const [status, setStatus] = useState<LanStatus>({ running: false, address: null, open: false });
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    lanShareStatus().then(setStatus).catch(() => setStatus({ running: false, address: null, open: false }));
  }, [connected]);

  /**
   * Saves and applies together. A port or a password that was typed but never
   * reached the listener is the worst of both: the screen says one thing and
   * the open port does another.
   */
  const apply = async (patch: Partial<LanSettings>) => {
    const next = { ...share, ...patch };
    onChange({ ...profile, lanShare: next });
    if (!connected && next.enabled) return;
    setBusy(true);
    try {
      setStatus(await setLanShare(next));
    } catch (error) {
      // Put the switch back: it must not sit on over a door that never opened.
      onChange({ ...profile, lanShare: { ...next, enabled: false } });
      setStatus({ running: false, address: null, open: false });
      onToast("Could not share", error instanceof Error ? error.message : String(error), true);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card>
      <CardHeader className="pb-1">
        <CardTitle className="text-[15px]">{t("Share with other devices")}</CardTitle>
        <CardDescription>
          {t(
            "Opens a proxy on this machine that phones, televisions and anything else on the same network can point at. They go out through whatever is carrying traffic here — the second hop when one is running, the tunnel when it is not.",
          )}
        </CardDescription>
      </CardHeader>
      <CardContent className="pt-0">
        <Row
          first
          title="Share this connection on my network"
          help={
            connected
              ? t("The port is opened while connected and closed when you disconnect.")
              : t("Connect first — there is nothing to share until the tunnel is carrying traffic.")
          }
        >
          <Switch
            checked={share.enabled}
            disabled={busy || (!connected && !share.enabled)}
            onCheckedChange={(enabled) => void apply({ enabled })}
          />
        </Row>

        {share.enabled ? (
          <>
            <div className="grid grid-cols-3 gap-4 py-3">
              <TextField
                label="Port"
                mono
                value={String(share.port)}
                onChange={(value) => {
                  const port = Number(value.replace(/[^0-9]/g, ""));
                  onChange({
                    ...profile,
                    lanShare: { ...share, port: Number.isFinite(port) ? port : 0 },
                  });
                }}
                help="Typed into the other device."
              />
              <TextField
                label="Username"
                value={share.username}
                onChange={(username) => onChange({ ...profile, lanShare: { ...share, username } })}
                help="Optional."
              />
              <TextField
                label="Password"
                value={share.password}
                onChange={(password) => onChange({ ...profile, lanShare: { ...share, password } })}
                help="Optional."
              />
            </div>

            {!share.username.trim() || !share.password.trim() ? (
              <div className="mb-3 rounded-lg border border-amber-500/40 bg-amber-500/[0.08] p-3">
                <div className="text-[12.5px] font-semibold text-amber-500">
                  {t("No sign-in: anyone on this network can use your tunnel")}
                </div>
                <div className="mt-1 text-[12px] text-muted-foreground">
                  Every device that can reach this machine — including guests and anything else on a
                  shared or public network — can send traffic through your connection, and it will
                  leave from your exit address. Fill in both a username and a password to require a
                  sign-in.
                </div>
              </div>
            ) : null}

            <div className="flex items-center justify-between gap-4 border-t pt-3">
              <div className="min-w-0">
                <div className="text-[13px] font-medium">
                  {status.running ? t("Open") : t("Not open")}
                </div>
                <div className="truncate font-mono text-[11.5px] text-muted-foreground">
                  {status.running && status.address
                    ? `Point devices at ${status.address} — HTTP or SOCKS5, same port`
                    : t("Apply to open the port.")}
                </div>
              </div>
              <Button
                variant="outline"
                size="sm"
                disabled={busy || !connected}
                onClick={() => void apply({})}
              >
                {t("Apply")}
              </Button>
            </div>

            <p className="pt-2 text-[12px] text-muted-foreground">
              Windows asks to allow this the first time. Until you say yes, the port answers on this
              machine only.
            </p>
          </>
        ) : null}
      </CardContent>
    </Card>
  );
}

function systemProxyHelp(runtime: string): string {
  const t = useT();
  const os = runtime.split(" · ")[0]?.toLowerCase();
  if (os === "windows") return "Sets the WinINET proxy. Most apps follow it; some bring their own settings.";
  if (os === "macos") return "Sets the SOCKS proxy on every active network service.";
  if (os === "linux") return "Sets the GNOME proxy. Desktops that ignore gsettings are unaffected.";
  return t("Sets the operating system's proxy settings.");
}

// -------------------------------------------------------------------- identity

function Identity({ profile, onChange }: AdvancedProps) {
  const t = useT();
  const set = (patch: Partial<ConnectionProfile>) => onChange({ ...profile, ...patch });
  return (
    <Card>
      <CardHeader className="pb-1">
        <CardTitle className="text-[15px]">Cloudflare Zero Trust</CardTitle>
        <CardDescription>{t("Leave empty to stay on a personal WARP identity.")}</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4 pt-2">
        <div className="grid grid-cols-2 gap-4">
          <TextField label="Team" value={profile.team ?? ""} placeholder="team name"
            onChange={(value) => set({ team: value || null })} />
          <TextField label="Email" value={profile.accessEmail ?? ""} placeholder="you@example.com"
            onChange={(value) => set({ accessEmail: value || null })} />
          <TextField label="Access client ID" mono value={profile.accessClientId ?? ""}
            onChange={(value) => set({ accessClientId: value || null })} />
          <TextField label="Access client secret" type="password" value={profile.accessClientSecret ?? ""}
            onChange={(value) => set({ accessClientSecret: value || null })} />
          <TextField label="Existing token" type="password" value={profile.accessToken ?? ""}
            onChange={(value) => set({ accessToken: value || null })}
            help="Skips sign-in when you already hold one." />
        </div>
        <p className="text-[13px] text-muted-foreground">
          {t(
            "The client secret and the token are held in memory and passed to the core through its environment. Neither is written to the profile on disk, and neither appears in a diagnostics report. The team, client ID and email are saved with the profile on this device.",
          )}
        </p>
        <Separator />
        <Row first title="Send web traffic to Gateway" help="Applies the enrolled organisation's policy. Adds a hop, and permits its logging.">
          <Switch checked={profile.gateway} onCheckedChange={(gateway) => set({ gateway })} />
        </Row>
      </CardContent>
    </Card>
  );
}

// ----------------------------------------------------------------- diagnostics

function Diagnostics({ snapshot, profile, onChange, probe, logs, runtime, appVersion, onToast }: AdvancedProps) {
  const t = useT();
  const set = (patch: Partial<ConnectionProfile>) => onChange({ ...profile, ...patch });
  const [includeSystem, setIncludeSystem] = useState(true);
  const [includeSettings, setIncludeSettings] = useState(true);
  const [includeEvents, setIncludeEvents] = useState(true);
  const [redact, setRedact] = useState(true);

  const report = useMemo(
    () =>
      buildReport({
        appVersion,
        engineVersion: probe.version,
        system: runtime,
        snapshot,
        profile,
        logs,
        options: { includeSystem, includeSettings, includeEvents, redact },
      }),
    [appVersion, probe.version, runtime, snapshot, profile, logs, includeSystem, includeSettings, includeEvents, redact],
  );

  return (
    <>
      <Card>
        <CardHeader className="pb-1"><CardTitle className="text-[15px]">{t("Core and profile")}</CardTitle></CardHeader>
        <CardContent className="flex flex-col gap-4 pt-2">
          <div className="grid grid-cols-2 gap-4">
            <TextField
              label="Profile name" value={profile.name}
              onChange={(name) => set({ name })}
              help="Shown in reports so you can tell saved setups apart."
            />
            <TextField
              label="Core executable" mono value={profile.corePath ?? ""}
              placeholder="Auto-detect"
              onChange={(value) => set({ corePath: value || null })}
              help={probe.path ?? probe.message}
            />
          </div>
          <Separator />
          <Row first title="Log detail" help="Connection state is read from info-level output, so info is the floor.">
            <Seg
              value={profile.logLevel}
              onChange={(logLevel) => set({ logLevel })}
              options={[["error", "error"], ["warn", "warn"], ["info", "info"], ["debug", "debug"], ["trace", "trace"]]}
            />
          </Row>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-1">
          <CardTitle className="text-[15px]">{t("Report")}</CardTitle>
          <CardDescription>{t("Raise the log detail, reproduce the problem, then build this.")}</CardDescription>
        </CardHeader>
        <CardContent className="pt-0">
          <Row first title="App and engine version" help="Always included — a report without it cannot be read.">
            <Switch checked disabled />
          </Row>
          <Row title="Operating system" help={runtime}>
            <Switch checked={includeSystem} onCheckedChange={setIncludeSystem} />
          </Row>
          <Row title="Connection settings" help="No Zero Trust credentials and no pinned address — only whether one is set.">
            <Switch checked={includeSettings} onCheckedChange={setIncludeSettings} />
          </Row>
          <Row title={`${t("Recent events (up to")} ${REPORT_EVENT_LIMIT})`} help="What the core and the supervisor did.">
            <Switch checked={includeEvents} onCheckedChange={setIncludeEvents} />
          </Row>
          <Row title="Replace IP addresses" help="Swaps them for placeholders. Most problems can still be diagnosed.">
            <Switch checked={redact} onCheckedChange={setRedact} />
          </Row>
        </CardContent>
      </Card>

      <Card>
        <CardContent className="flex flex-col gap-3 p-4">
          <pre className="max-h-[240px] overflow-auto whitespace-pre-wrap break-words rounded-md bg-muted/50 p-3 font-mono text-[11.5px] leading-relaxed">
            {report}
          </pre>
          <div className="flex justify-end gap-2">
            <Button
              variant="outline"
              onClick={async () => {
                try {
                  await navigator.clipboard.writeText(report);
                  onToast("Copied", "The report is on the clipboard.");
                } catch (error) {
                  onToast("Copy failed", String(error), true);
                }
              }}
            >
              {t("Copy")}
            </Button>
            <Button
              onClick={async () => {
                try {
                  onToast("Report saved", await saveReport(report, reportFilename()));
                } catch (error) {
                  onToast("Save failed", error instanceof Error ? error.message : String(error), true);
                }
              }}
            >
              {t("Save report")}
            </Button>
          </div>
        </CardContent>
      </Card>
    </>
  );
}
