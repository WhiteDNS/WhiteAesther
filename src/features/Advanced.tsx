import { useMemo, useState } from "react";
import {
  Activity, FileText, Globe, Route as RouteIcon, ShieldCheck, Wifi, type LucideIcon,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import { buildCoreCommand } from "@/core/command";
import { endpointError, normalizeEndpoint } from "@/core/endpoint";
import { REPORT_EVENT_LIMIT, buildReport, reportFilename } from "@/core/report";
import { saveReport } from "@/core/api";
import { NumberField, Row, RulesField, Seg, TextField } from "./panels";
import { Scanner } from "./Scanner";
import { transportName } from "./Simple";
import {
  ENDPOINT_MODES, type ConnectionProfile, type CoreLogEvent, type CoreProbe, type CoreSnapshot,
} from "@/types";

type SectionId = "status" | "routes" | "endpoint" | "traffic" | "identity" | "diagnostics";

const SECTIONS: Array<{ group: string; items: Array<{ id: SectionId; label: string; icon: LucideIcon }> }> = [
  { group: "Connection", items: [
    { id: "status", label: "Status", icon: Activity },
    { id: "routes", label: "Routes & transports", icon: RouteIcon },
    { id: "endpoint", label: "Endpoint", icon: Globe },
  ] },
  { group: "System", items: [
    { id: "traffic", label: "Traffic & DNS", icon: Wifi },
    { id: "identity", label: "Identity", icon: ShieldCheck },
  ] },
  { group: "Support", items: [{ id: "diagnostics", label: "Diagnostics", icon: FileText }] },
];

const BLURB: Record<SectionId, string> = {
  status: "What the core is doing right now.",
  routes: "How hard to search, what the tunnel rides on, and how it hides.",
  endpoint: "Pin a specific gateway, or let the core find one.",
  traffic: "Where traffic goes once the tunnel is up.",
  identity: "Cloudflare Zero Trust enrolment.",
  diagnostics: "The core executable, logging, and a report you can hand to someone.",
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
}

export function Advanced(props: AdvancedProps) {
  const [section, setSection] = useState<SectionId>("status");
  const heading = SECTIONS.flatMap((group) => group.items).find((item) => item.id === section);

  return (
    <div className="grid h-full grid-cols-[196px_minmax(0,1fr)] overflow-hidden">
      <nav className="flex flex-col gap-0.5 overflow-y-auto border-r bg-card p-2" aria-label="Settings sections">
        {SECTIONS.map((group) => (
          <div key={group.group} className="flex flex-col gap-0.5">
            <span className="px-2.5 pb-1 pt-3.5 text-[10.5px] font-semibold uppercase tracking-wider text-muted-foreground">
              {group.group}
            </span>
            {group.items.map(({ id, label, icon: Icon }) => (
              <button
                key={id}
                type="button"
                aria-current={section === id}
                onClick={() => setSection(id)}
                className={[
                  "flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-left text-[13.5px] transition-colors",
                  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
                  section === id
                    ? "bg-primary/10 font-semibold text-primary"
                    : "text-muted-foreground hover:bg-accent hover:text-foreground",
                ].join(" ")}
              >
                <Icon className="size-[15px]" />
                {label}
              </button>
            ))}
          </div>
        ))}
      </nav>

      <div className="flex flex-col gap-4 overflow-y-auto p-6">
        <div className="flex items-start justify-between gap-4">
          <div className="flex flex-col gap-1">
            <h2 className="text-[19px] font-semibold tracking-tight">{heading?.label}</h2>
            <p className="text-sm text-muted-foreground">{BLURB[section]}</p>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            <StateBadge snapshot={props.snapshot} />
            <Button variant="outline" size="sm" onClick={props.onSave}>
              Save profile
            </Button>
          </div>
        </div>

        {section === "status" && <Status {...props} />}
        {section === "routes" && <Routes {...props} />}
        {section === "endpoint" && <Endpoint {...props} />}
        {section === "traffic" && <Traffic {...props} />}
        {section === "identity" && <Identity {...props} />}
        {section === "diagnostics" && <Diagnostics {...props} />}
      </div>
    </div>
  );
}

function StateBadge({ snapshot }: { snapshot: CoreSnapshot }) {
  if (snapshot.state === "connected")
    return <Badge variant="ok" className="gap-1.5"><span className="size-1.5 rounded-full bg-current" />Connected</Badge>;
  if (snapshot.state === "error")
    return <Badge variant="bad" className="gap-1.5"><span className="size-1.5 rounded-full bg-current" />Stopped</Badge>;
  if (snapshot.state === "idle") return <Badge variant="outline">Idle</Badge>;
  return (
    <Badge variant="warn" className="gap-1.5">
      <span className="size-1.5 animate-pulse rounded-full bg-current" />
      {snapshot.attempt > 0 ? `Attempt ${snapshot.attempt}/${snapshot.maxAttempts}` : "Working"}
    </Badge>
  );
}

// ---------------------------------------------------------------------- status

function Status({ snapshot, probe, logs, profile }: AdvancedProps) {
  return (
    <>
      <div className="grid grid-cols-4 gap-3">
        <Metric label="Core" value={probe.available ? "Ready" : "Missing"} />
        <Metric label="Transport" value={snapshot.transport ? transportName(snapshot.transport) : "—"} />
        <Metric label="Edge" value={snapshot.endpoint ?? "—"} mono />
        <Metric label="Latency" value={snapshot.latencyMs == null ? "—" : `${snapshot.latencyMs.toFixed(1)} ms`} mono />
      </div>

      <Card>
        <CardHeader className="pb-2"><CardTitle className="text-[15px]">Live</CardTitle></CardHeader>
        <CardContent><LogList logs={logs} /></CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-[15px]">What will run</CardTitle>
          <CardDescription>
            The core is launched with these arguments. Zero Trust secrets go through the environment and are not
            shown here.
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
  return (
    <Card className="p-3.5">
      <div className="flex flex-col gap-1">
        <span className="text-[10.5px] font-semibold uppercase tracking-wider text-muted-foreground">{label}</span>
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
  if (!logs.length)
    return <p className="py-6 text-center text-[13px] text-muted-foreground">No events yet. Connect to populate this.</p>;
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

/** The four things the core can actually be, rather than a transport toggle alone. */
const PROTOCOLS: Array<{ id: string; label: string; detail: string; protocol: ConnectionProfile["protocol"]; transport?: "h2" | "h3" }> = [
  { id: "h2", label: "MASQUE H2", detail: "TCP. Survives networks that block UDP.", protocol: "masque", transport: "h2" },
  { id: "h3", label: "MASQUE H3", detail: "QUIC. Lower overhead where UDP gets through.", protocol: "masque", transport: "h3" },
  { id: "wg", label: "WireGuard", detail: "UDP, with an obfuscation profile sweep.", protocol: "wg" },
  { id: "gool", label: "WARP in WARP", detail: "Nested tunnel. Slower, harder to classify.", protocol: "gool" },
];

function Routes({ profile, onChange }: AdvancedProps) {
  const set = (patch: Partial<ConnectionProfile>) => onChange({ ...profile, ...patch });
  const active =
    profile.protocol === "masque" ? profile.masqueTransport : profile.protocol === "wg" ? "wg" : "gool";
  const isMasque = profile.protocol === "masque";
  const isH2 = isMasque && profile.masqueTransport === "h2";

  return (
    <>
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-[15px]">Protocol</CardTitle>
          <CardDescription>Retries alternate the two MASQUE transports automatically.</CardDescription>
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
                  "flex flex-col gap-1 rounded-lg border p-3 text-left transition-colors",
                  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
                  on ? "border-primary bg-primary/10 ring-1 ring-primary" : "border-border hover:bg-accent",
                ].join(" ")}
              >
                <span className="text-[13.5px] font-semibold">{option.label}</span>
                <span className="text-xs leading-snug text-muted-foreground">{option.detail}</span>
              </button>
            );
          })}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-1"><CardTitle className="text-[15px]">Search</CardTitle></CardHeader>
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
          <CardTitle className="text-[15px]">Anti-blocking</CardTitle>
          <CardDescription>
            {isMasque
              ? "Both cost a little on a healthy network and only matter on a filtered one."
              : "Obfuscation applies to WireGuard; the TLS options are MASQUE H2 only."}
          </CardDescription>
        </CardHeader>
        <CardContent className="pt-0">
          <Row
            first
            title="Split the TLS opening"
            help={isH2 ? "Defeats filtering that reads only the first packet." : "MASQUE H2 only — has no effect on the selected protocol."}
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
          <Row title="WireGuard keepalive" help="How often to hold the UDP mapping open.">
            <div className="w-[132px]">
              <NumberField
                unit="sec" min={1} max={300}
                value={profile.keepaliveSecs} onChange={(keepaliveSecs) => set({ keepaliveSecs })}
              />
            </div>
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
          </div>
        </CardContent>
      </Card>
    </>
  );
}

// -------------------------------------------------------------------- endpoint

function Endpoint({ profile, onChange, snapshot, onToast }: AdvancedProps) {
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
        <CardHeader className="pb-1"><CardTitle className="text-[15px]">Pinned endpoint</CardTitle></CardHeader>
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
                      ? "One attempt goes here; if it fails the core searches instead and says so."
                      : "Every attempt goes here. Nothing else is tried."
                  }`}
                />
              </div>
            </>
          ) : profile.peer?.trim() ? (
            <>
              <Separator />
              <p className="py-3.5 text-[13px] text-muted-foreground">
                A saved address is kept but not used while this is Automatic.
              </p>
            </>
          ) : null}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-1">
          <CardTitle className="text-[15px]">Per-protocol overrides</CardTitle>
          <CardDescription>Left empty, each protocol uses the pinned endpoint above or its own search.</CardDescription>
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

function Traffic({ profile, onChange, runtime }: AdvancedProps) {
  const set = (patch: Partial<ConnectionProfile>) => onChange({ ...profile, ...patch });
  return (
    <>
      <Card>
        <CardHeader className="pb-1"><CardTitle className="text-[15px]">Reach</CardTitle></CardHeader>
        <CardContent className="pt-0">
          <Row first title="Set the system proxy while connected" help={systemProxyHelp(runtime)}>
            <Switch checked={profile.systemProxy} onCheckedChange={(systemProxy) => set({ systemProxy })} />
          </Row>
          <p className="pb-1 text-[13px] text-muted-foreground">
            Put back on disconnect. If the app is killed rather than closed, the next launch restores it.
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-1"><CardTitle className="text-[15px]">Local proxy and DNS</CardTitle></CardHeader>
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

      <Card>
        <CardHeader className="pb-1">
          <CardTitle className="text-[15px]">Routing rules</CardTitle>
          <CardDescription>
            Blocked first, then direct; everything left over enters the tunnel. One rule per line.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4 pt-2">
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

function systemProxyHelp(runtime: string): string {
  const os = runtime.split(" · ")[0]?.toLowerCase();
  if (os === "windows") return "Sets the WinINET proxy. Most apps follow it; some bring their own settings.";
  if (os === "macos") return "Sets the SOCKS proxy on every active network service.";
  if (os === "linux") return "Sets the GNOME proxy. Desktops that ignore gsettings are unaffected.";
  return "Sets the operating system's proxy settings.";
}

// -------------------------------------------------------------------- identity

function Identity({ profile, onChange }: AdvancedProps) {
  const set = (patch: Partial<ConnectionProfile>) => onChange({ ...profile, ...patch });
  return (
    <Card>
      <CardHeader className="pb-1">
        <CardTitle className="text-[15px]">Cloudflare Zero Trust</CardTitle>
        <CardDescription>Leave empty to stay on a personal WARP identity.</CardDescription>
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
          The client secret and the token are held in memory and passed to the core through its environment.
          Neither is written to the profile on disk, and neither appears in a diagnostics report. The team,
          client ID and email <b className="font-medium text-foreground">are</b> saved with the profile on this
          device.
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
        <CardHeader className="pb-1"><CardTitle className="text-[15px]">Core and profile</CardTitle></CardHeader>
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
          <CardTitle className="text-[15px]">Report</CardTitle>
          <CardDescription>Raise the log detail, reproduce the problem, then build this.</CardDescription>
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
          <Row title={`Recent events (up to ${REPORT_EVENT_LIMIT})`} help="What the core and the supervisor did.">
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
              Copy
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
              Save report
            </Button>
          </div>
        </CardContent>
      </Card>
    </>
  );
}
