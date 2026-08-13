import { useEffect, useMemo, useState } from "react";
import {
  Activity, ArrowRight, BadgeCheck, Clock3, CloudCog, Command, Copy, FlaskConical,
  Gauge, Globe2, Laptop, LockKeyhole, Network, PackageCheck, Radar, RefreshCw,
  Route, Save, ScanSearch, Settings2, ShieldCheck, Split, TerminalSquare,
  TimerReset, Waypoints,
} from "lucide-react";
import { Badge } from "./components/ui/badge";
import { Button } from "./components/ui/button";
import { Switch } from "./components/ui/switch";
import {
  getCoreLogs, getCoreStatus, isDesktopRuntime, loadProfile, probeCore, runtimeInfo,
  saveProfile as persistProfile, startCore, stopCore, subscribeCore, subscribeTrayActions,
} from "./core/api";
import { buildCoreCommand } from "./core/command";
import {
  DEFAULT_PROFILE, IDLE_SNAPSHOT, type ConnectionPhase, type ConnectionProfile,
  type CoreLogEvent, type CoreProbe, type CoreSnapshot, type ViewId,
} from "./types";
import "./App.css";

const navigation: Array<{ id: ViewId; label: string; icon: typeof Gauge; group?: string }> = [
  { id: "overview", label: "Overview", icon: Gauge, group: "Workspace" },
  { id: "lab", label: "Connection Lab", icon: FlaskConical },
  { id: "discovery", label: "Discovery", icon: Radar },
  { id: "transports", label: "Transports", icon: Waypoints },
  { id: "routing", label: "Routing & DNS", icon: Split, group: "Network" },
  { id: "identity", label: "Zero Trust", icon: ShieldCheck },
  { id: "diagnostics", label: "Diagnostics", icon: Activity },
];

const phaseCopy: Record<ConnectionPhase, { label: string; detail: string }> = {
  h2: { label: "MASQUE H2", detail: "TCP · fragmented ClientHello" },
  h3: { label: "MASQUE H3", detail: "QUIC · ECH auto · UDP" },
  wg: { label: "WireGuard", detail: "Noize profile · UDP port matrix" },
};

const activeStates = new Set(["starting", "scanning", "connecting", "connected", "reconnecting"]);
const appVersion = import.meta.env.VITE_APP_VERSION || "1.0.0";
const appVersionLabel = appVersion.replace(
  /^(\d+\.\d+\.\d+)-.*\.(\d+)\+([0-9a-z]+)$/,
  "v$1 · b$2 · $3",
).replace(/^(\d+\.\d+\.\d+)$/, "v$1");

function App() {
  const [view, setView] = useState<ViewId>("overview");
  const [profile, setProfile] = useState<ConnectionProfile>(DEFAULT_PROFILE);
  const [snapshot, setSnapshot] = useState<CoreSnapshot>(IDLE_SNAPSHOT);
  const [probe, setProbe] = useState<CoreProbe>({ available: false, path: null, version: null, message: "Checking core…" });
  const [logs, setLogs] = useState<CoreLogEvent[]>([]);
  const [runtime, setRuntime] = useState("Desktop shell");
  const [toast, setToast] = useState<{ title: string; message: string; error?: boolean } | null>(null);
  const command = useMemo(() => buildCoreCommand(profile), [profile]);
  const desktop = isDesktopRuntime();
  const running = activeStates.has(snapshot.state);

  useEffect(() => {
    let disposed = false;
    let unsubscribe: (() => void) | undefined;
    async function initialize() {
      if (!desktop) {
        setRuntime("Browser preview");
        setProbe({ available: false, path: null, version: null, message: "Open the Tauri desktop app to control Aether." });
        return;
      }
      try {
        // Subscribe first, then settle the rest independently: with Promise.all, one rejection
        // (loadProfile throws on any stored profile that fails validation) skipped subscribeCore
        // too, leaving the app blind to a running core for the whole session.
        unsubscribe = await subscribeCore(
          (next) => { if (!disposed) setSnapshot(next); },
          (entry) => { if (!disposed) setLogs((currentLogs) => [...currentLogs.slice(-999), entry]); },
        );
        if (disposed) return;
        const [info, saved, current, history] = await Promise.allSettled([runtimeInfo(), loadProfile(), getCoreStatus(), getCoreLogs()]);
        if (disposed) return;
        if (info.status === "fulfilled") setRuntime(`${info.value.os} · ${info.value.arch}`);
        if (saved.status === "fulfilled") setProfile(saved.value);
        if (current.status === "fulfilled") setSnapshot(current.value);
        if (history.status === "fulfilled") setLogs(history.value);
        if (saved.status === "rejected") showError(saved.reason);
        setProbe(await probeCore(saved.status === "fulfilled" ? saved.value : DEFAULT_PROFILE));
      } catch (error) {
        showError(error);
      }
    }
    void initialize();
    return () => { disposed = true; unsubscribe?.(); };
  }, [desktop]);

  useEffect(() => {
    if (!toast) return;
    const timeout = window.setTimeout(() => setToast(null), 3_500);
    return () => window.clearTimeout(timeout);
  }, [toast]);

  useEffect(() => {
    function handleShortcut(event: KeyboardEvent) {
      if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
        event.preventDefault();
        void toggleConnection();
      }
    }
    window.addEventListener("keydown", handleShortcut);
    return () => window.removeEventListener("keydown", handleShortcut);
  });

  useEffect(() => {
    if (!desktop) return;
    let disposed = false;
    let unsubscribe: (() => void) | undefined;
    void subscribeTrayActions((action) => {
      if (disposed) return;
      if (action === "open-diagnostics") {
        setView("diagnostics");
        return;
      }
      void toggleConnection();
    }).then((cleanup) => {
      if (disposed) cleanup();
      else unsubscribe = cleanup;
    }).catch(showError);
    return () => { disposed = true; unsubscribe?.(); };
  }, [desktop, profile, running]);

  function showError(error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    setToast({ title: "Action failed", message, error: true });
  }

  async function refreshProbe(nextProfile = profile) {
    try {
      const result = await probeCore(nextProfile);
      setProbe(result);
      return result;
    } catch (error) {
      showError(error);
      return null;
    }
  }

  async function toggleConnection() {
    setView("overview");
    try {
      if (running) {
        setSnapshot(await stopCore());
        setToast({ title: "Disconnected", message: "Aether core stopped cleanly." });
        return;
      }
      const latestProbe = await refreshProbe();
      if (!latestProbe?.available) throw new Error(latestProbe?.message ?? "Aether core is unavailable");
      setSnapshot(await startCore(profile));
    } catch (error) {
      showError(error);
    }
  }

  async function saveProfile() {
    try {
      if (desktop) {
        const saved = await persistProfile(profile);
        setProfile((current) => ({ ...saved, accessClientSecret: current.accessClientSecret, accessToken: current.accessToken }));
      } else {
        localStorage.setItem("whiteaesther-profile", JSON.stringify(profile));
      }
      setToast({ title: "Profile saved", message: "Settings are stored locally on this device." });
      await refreshProbe(profile);
    } catch (error) {
      showError(error);
    }
  }

  async function copyCommand() {
    await navigator.clipboard.writeText(command);
    setToast({ title: "Command copied", message: "The equivalent Aether command is on the clipboard." });
  }

  const title = navigation.find((item) => item.id === view)?.label ?? "Preferences";

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand"><img className="brand-mark" src="/whiteaesther-logo.png" alt="" /><div><strong>WhiteAesther</strong><small title={`WhiteAesther ${appVersion}`}>{appVersionLabel}</small></div></div>
        <nav className="navigation" aria-label="Main navigation">
          {navigation.map(({ id, label, icon: Icon, group }) => <div key={id}>{group && <p className="nav-label">{group}</p>}<button className={`nav-item ${view === id ? "active" : ""}`} onClick={() => setView(id)}><Icon /><span>{label}</span>{id === "diagnostics" && <i className={`nav-dot ${snapshot.lastError ? "error" : ""}`} />}</button></div>)}
        </nav>
        <div className="sidebar-footer">
          <button className={`nav-item ${view === "preferences" ? "active" : ""}`} onClick={() => setView("preferences")}><Settings2 /><span>Preferences</span></button>
          <div className="core-card"><span className={`core-pulse ${probe.available ? "" : "offline"}`} /><div><strong>{probe.available ? probe.version : "Core unavailable"}</strong><small>{runtime}</small></div><ArrowRight /></div>
        </div>
      </aside>
      <main className="main">
        <header className="topbar"><div><p className="eyebrow">Workspace / {title}</p><h1>{title}</h1></div><div className="top-actions"><Button variant="icon" title="Copy core command" onClick={copyCommand}><TerminalSquare /></Button><Button variant="secondary" onClick={saveProfile}><Save />Save profile</Button></div></header>
        <div className="content">
          {view === "overview" && <Overview snapshot={snapshot} profile={profile} probe={probe} onConnect={toggleConnection} onOpenLab={() => setView("lab")} />}
          {view === "lab" && <ConnectionLab profile={profile} onChange={setProfile} command={command} onCopy={copyCommand} onRun={toggleConnection} />}
          {view === "discovery" && <Discovery profile={profile} onChange={setProfile} />}
          {view === "transports" && <Transports profile={profile} onChange={setProfile} />}
          {view === "routing" && <Routing profile={profile} onChange={setProfile} />}
          {view === "identity" && <Identity profile={profile} onChange={setProfile} />}
          {view === "diagnostics" && <Diagnostics snapshot={snapshot} logs={logs} />}
          {view === "preferences" && <Preferences profile={profile} onChange={setProfile} probe={probe} onProbe={() => refreshProbe()} />}
        </div>
      </main>
      {toast && <div className={`toast ${toast.error ? "error" : ""}`}><BadgeCheck /><div><strong>{toast.title}</strong><span>{toast.message}</span></div></div>}
    </div>
  );
}

function Overview({ snapshot, profile, probe, onConnect, onOpenLab }: { snapshot: CoreSnapshot; profile: ConnectionProfile; probe: CoreProbe; onConnect: () => void; onOpenLab: () => void }) {
  const connected = snapshot.state === "connected";
  const busy = activeStates.has(snapshot.state) && !connected;
  const phase = currentPhase(snapshot, profile);
  const statusLabel = connected ? `Connected · ${transportName(snapshot.transport)}` : busy ? stateName(snapshot.state) : snapshot.state === "error" ? "Core stopped with an error" : probe.available ? "Ready to search" : "Aether core required";
  return <>
    <section className="status-panel">
      <div className="connect-zone">
        <div className="status-heading"><span className={`status-indicator ${connected ? "connected" : busy ? "scanning" : snapshot.state === "error" ? "error" : ""}`} />{statusLabel}<Badge>SOCKS5</Badge></div>
        <h2>{connected ? <>A healthy route<br />is active.</> : busy ? <>Aether is testing<br />real network paths.</> : <>Find the route that works<br />on this network.</>}</h2>
        <p>{connected ? `${transportName(snapshot.transport)} · ${snapshot.endpoint ?? "edge active"} · ${profile.ipFamily.toUpperCase()}` : snapshot.lastError ?? probe.message}</p>
        <Button size="large" onClick={onConnect}><ScanSearch />{activeStates.has(snapshot.state) ? "Stop Aether" : "Find best connection"}<kbd>Ctrl ↵</kbd></Button>
        <small className="privacy"><LockKeyhole />Identity, settings and logs remain on this device.</small>
      </div>
      <div className="route-card">
        <div className="section-head"><div><span className="label">SEARCH STRATEGY</span><h3>{profile.name}</h3></div><button onClick={onOpenLab}>Tune</button></div>
        <div className="route-stack">{(["h2", "h3", "wg"] as ConnectionPhase[]).map((item, index) => <div className={`route-step ${phase === item && busy ? "testing" : ""} ${phase === item && connected ? "passed" : ""}`} key={item}><span>0{index + 1}</span><div><strong>{phaseCopy[item].label}</strong><small>{phaseCopy[item].detail}</small></div><em>{phase === item ? connected ? "ACTIVE" : busy ? "TESTING" : "SELECTED" : index === 0 ? "FIRST" : "OPTION"}</em></div>)}</div>
        <div className="roadmap"><Command /><div><strong>Automatic cross-transport failover</strong><span>The supervisor currently launches the selected core transport.</span></div><Badge tone="roadmap">NEXT SLICE</Badge></div>
      </div>
    </section>
    <section className="metric-grid"><Metric icon={Clock3} value={snapshot.latencyMs == null ? "—" : `${snapshot.latencyMs.toFixed(1)} ms`} label="Selected-edge latency" note="CORE" /><Metric icon={PackageCheck} value="—" label="Packet loss" note="NOT EXPOSED" /><Metric icon={TimerReset} value={`${profile.reconnectSecs}.0 s`} label="Recovery delay" note="PROFILE" /><Metric icon={Network} value={snapshot.socksAddress} label="SOCKS endpoint" note={connected ? "LISTENING" : "CONFIGURED"} /></section>
    <section className="dashboard-grid"><article className="card profile-card"><div className="section-head"><div><span className="label">ACTIVE PROFILE</span><h3>{profile.name}</h3></div><Badge tone="current">REAL CORE</Badge></div>{[["IP family",ipName(profile.ipFamily)],["Scan depth",profile.scanMode],["Validation",`Real HTTP · ${profile.validateSecs} s`],["Reconnect",profile.quickReconnect?"Last healthy edge":"Fresh scan"]].map(([a,b])=><div className="profile-row" key={a}><span>{a}</span><strong>{b}</strong></div>)}<Button variant="secondary" full onClick={onOpenLab}>Open Connection Lab<ArrowRight /></Button></article><article className="card"><div className="section-head"><div><span className="label">NETWORK SNAPSHOT</span><h3>{connected ? "Live connection" : "Current environment"}</h3></div></div><div className="network-path"><PathNode icon={Laptop} label="This device" active /><span /><PathNode icon={CloudCog} label={snapshot.endpoint ?? "Edge pending"} active={connected} /><span /><PathNode icon={Globe2} label="Internet" active={connected} /></div><div className="signal"><span>Core process</span><strong>{snapshot.pid ? `PID ${snapshot.pid}` : "Stopped"}</strong></div><div className="signal"><span>Data-plane validation</span><strong>{connected ? "Passed" : "Waiting"}</strong></div></article></section>
  </>;
}

function ConnectionLab({ profile, onChange, command, onCopy, onRun }: { profile: ConnectionProfile; onChange: (profile: ConnectionProfile) => void; command: string; onCopy: () => void; onRun: () => void }) {
  const presets: Array<{ name: string; detail: string; patch: Partial<ConnectionProfile> }> = [
    { name: "Adaptive · Iran", detail: "TCP-first with full validation and fragmentation.", patch: { protocol: "masque", masqueTransport: "h2", scanMode: "balanced", quickReconnect: true, fragmentClientHello: true } },
    { name: "Lossy Mobile", detail: "Fast recovery and persistent WireGuard keepalive.", patch: { protocol: "wg", scanMode: "turbo", reconnectSecs: 1, keepaliveSecs: 5, quickReconnect: true } },
    { name: "UDP Blocked", detail: "MASQUE H2 with shaped TLS ClientHello writes.", patch: { protocol: "masque", masqueTransport: "h2", scanMode: "stealth", fragmentClientHello: true } },
    { name: "Manual Expert", detail: "Keep all current values and expose every override.", patch: {} },
  ];
  const applyPreset = (preset: typeof presets[number]) => onChange({ ...profile, ...preset.patch, name: preset.name });
  const strategies: Array<{ id: string; name: string; detail: string; selected: boolean; patch: Partial<ConnectionProfile> }> = [
    { id: "h2", name: "MASQUE over HTTP/2", detail: "Best when UDP is filtered", selected: profile.protocol === "masque" && profile.masqueTransport === "h2", patch: { protocol: "masque", masqueTransport: "h2" } },
    { id: "h3", name: "MASQUE over HTTP/3", detail: "Lower overhead when QUIC survives", selected: profile.protocol === "masque" && profile.masqueTransport === "h3", patch: { protocol: "masque", masqueTransport: "h3" } },
    { id: "wg", name: "WireGuard + Noize", detail: "Port and profile sweep", selected: profile.protocol === "wg", patch: { protocol: "wg" } },
    { id: "wiw", name: "WARP in WARP", detail: "Nested tunnel path", selected: profile.protocol === "gool", patch: { protocol: "gool" } },
  ];
  return <><PageIntro badge="CORE-WIRED" title="Connection Lab" copy="Every active control below maps to validated Aether arguments." action={<Button onClick={onRun}><ScanSearch />Run strategy</Button>} /><div className="preset-grid">{presets.map((preset)=><button key={preset.name} className={`preset ${profile.name===preset.name?"selected":""}`} onClick={()=>applyPreset(preset)}><FlaskConical /><strong>{preset.name}</strong><span>{preset.detail}</span><small>{preset.name==="Adaptive · Iran"?"RECOMMENDED":"PROFILE"}</small></button>)}</div><div className="two-col"><article className="card"><div className="section-head"><div><span className="label">SELECTED TRANSPORT</span><h3>One core process</h3></div><Badge tone="current">FUNCTIONAL</Badge></div>{strategies.map((strategy,index)=><div className={`strategy ${strategy.selected?"selected":""}`} key={strategy.id}><span className={`protocol p${index}`}>{["H2","H3","WG","WiW"][index]}</span><div><strong>{strategy.name}</strong><small>{strategy.detail}</small></div><Switch checked={strategy.selected} aria-label={`Select ${strategy.name}`} onCheckedChange={()=>onChange({...profile,...strategy.patch})} /></div>)}</article><article className="card command-card"><div className="section-head"><div><span className="label">WHAT WILL RUN</span><h3>Core command</h3></div><Badge tone="current">LIVE</Badge></div><pre>{command}</pre><p>Zero Trust secrets are passed through the child environment and never shown here.</p><Button variant="secondary" full onClick={onCopy}><Copy />Copy command</Button></article></div><GlobalTuning profile={profile} onChange={onChange} /></>;
}

function GlobalTuning({ profile, onChange }: ProfileProps) {
  return <article className="card global"><div className="section-head"><div><span className="label">GLOBAL TUNING</span><h3>Selection and validation</h3></div></div><div className="form-grid four"><SelectField label="IP family" value={profile.ipFamily} onChange={(value)=>onChange({...profile,ipFamily:value as ConnectionProfile["ipFamily"]})} options={[["both","IPv4 + IPv6"],["v4","IPv4 only"],["v6","IPv6 only"]]} /><SelectField label="Scan mode" value={profile.scanMode} onChange={(value)=>onChange({...profile,scanMode:value as ConnectionProfile["scanMode"]})} options={["turbo","balanced","thorough","stealth","ironclad"].map(value=>[value,value])} /><NumberField label="Validation deadline" value={profile.validateSecs} min={1} max={120} unit="sec" onChange={(value)=>onChange({...profile,validateSecs:value})} /><NumberField label="Startup deadline" value={profile.startupSecs} min={5} max={300} unit="sec" onChange={(value)=>onChange({...profile,startupSecs:value})} /><NumberField label="Reconnect delay" value={profile.reconnectSecs} min={0} max={120} unit="sec" onChange={(value)=>onChange({...profile,reconnectSecs:value})} /><TextField label="Forced peer" value={profile.peer ?? ""} placeholder="Automatic · IP:port" onChange={(value)=>onChange({...profile,peer:value||null})} /><TextField label="SOCKS address" value={profile.socksAddress} onChange={(value)=>onChange({...profile,socksAddress:value})} /><SelectField label="Log level" value={profile.logLevel} onChange={(value)=>onChange({...profile,logLevel:value as ConnectionProfile["logLevel"]})} options={["error","warn","info","debug","trace"].map(value=>[value,value])} /><SelectField label="Performance" value={profile.performanceProfile} onChange={(value)=>onChange({...profile,performanceProfile:value as ConnectionProfile["performanceProfile"]})} options={[["auto","Automatic"],["low","Low resource"],["medium","Desktop"],["high","High concurrency"]]} /></div><div className="toggle-row"><div><strong>Quick reconnect</strong><span>Verify the last healthy edge before scanning.</span></div><Switch checked={profile.quickReconnect} onCheckedChange={(checked)=>onChange({...profile,quickReconnect:checked})} /></div></article>;
}

function Discovery({ profile, onChange }: ProfileProps) {
  return <><PageIntro badge="CORE TODAY" title="Endpoint discovery" copy="Aether owns concurrency and candidate budgets; the exposed controls below are live." /><div className="two-col"><article className="card"><div className="section-head"><div><span className="label">SCAN POLICY</span><h3>Coverage</h3></div></div><div className="form-grid two"><SelectField label="Scan mode" value={profile.scanMode} onChange={(value)=>onChange({...profile,scanMode:value as ConnectionProfile["scanMode"]})} options={["turbo","balanced","thorough","stealth","ironclad"].map(value=>[value,value])}/><SelectField label="Address family" value={profile.ipFamily} onChange={(value)=>onChange({...profile,ipFamily:value as ConnectionProfile["ipFamily"]})} options={[["both","IPv4 + IPv6"],["v4","IPv4 only"],["v6","IPv6 only"]]}/></div><SettingRow name="Probe parallelism" value="Core resource profile" /><SettingRow name="Candidate budget" value="Core scan mode" /></article><article className="card"><div className="section-head"><div><span className="label">ACCEPTANCE</span><h3>Winner criteria</h3></div></div><NumberField label="Data-plane deadline" value={profile.validateSecs} min={1} max={120} unit="sec" onChange={(value)=>onChange({...profile,validateSecs:value})}/><ToggleField label="End-to-end data check" copy="Expose SOCKS only after a real tunneled request succeeds." checked={profile.dataCheck} onChange={(checked)=>onChange({...profile,dataCheck:checked})}/><SettingRow name="Cache policy" value={profile.quickReconnect?"Verify before reuse":"Always scan fresh"} /></article></div></>;
}

function Transports({ profile, onChange }: ProfileProps) {
  return <><PageIntro badge="CORE TODAY" title="Transport controls" copy="Protocol-specific values are passed directly to Aether after validation." /><div className="settings-grid"><article className={`card transport-card ${profile.protocol==="masque"&&profile.masqueTransport==="h2"?"selected":""}`}><div className="section-head"><div><span className="label">TCP</span><h3>MASQUE H2</h3></div><Switch checked={profile.protocol==="masque"&&profile.masqueTransport==="h2"} onCheckedChange={()=>onChange({...profile,protocol:"masque",masqueTransport:"h2"})}/></div><ToggleField label="Fragment ClientHello" copy="Split the TLS opening across TCP writes." checked={profile.fragmentClientHello} onChange={(checked)=>onChange({...profile,fragmentClientHello:checked})}/><div className="form-grid two"><TextField label="Fragment size" value={profile.fragmentSize} onChange={(value)=>onChange({...profile,fragmentSize:value})}/><TextField label="Fragment delay" value={profile.fragmentDelay} onChange={(value)=>onChange({...profile,fragmentDelay:value})}/><TextField label="HTTP/2 peer" value={profile.h2Peer??""} placeholder="Automatic · IP:port" onChange={(value)=>onChange({...profile,h2Peer:value||null})}/></div></article><article className={`card transport-card ${profile.protocol==="masque"&&profile.masqueTransport==="h3"?"selected":""}`}><div className="section-head"><div><span className="label">QUIC</span><h3>MASQUE H3</h3></div><Switch checked={profile.protocol==="masque"&&profile.masqueTransport==="h3"} onCheckedChange={()=>onChange({...profile,protocol:"masque",masqueTransport:"h3"})}/></div><div className="form-grid two"><TextField label="ECH" value={profile.ech??""} placeholder="Off · auto or base64" onChange={(value)=>onChange({...profile,ech:value||null})}/><TextField label="TLS groups" value={profile.tlsGroups??""} placeholder="Core default" onChange={(value)=>onChange({...profile,tlsGroups:value||null})}/></div><SettingRow name="Migration" value="Core primitive available"/><SettingRow name="Continuous health" value="Next core slice"/></article><article className={`card transport-card ${profile.protocol==="wg"?"selected":""}`}><div className="section-head"><div><span className="label">UDP</span><h3>WireGuard</h3></div><Switch checked={profile.protocol==="wg"} onCheckedChange={()=>onChange({...profile,protocol:"wg"})}/></div><div className="form-grid two"><NumberField label="Keepalive" value={profile.keepaliveSecs} min={1} max={300} unit="sec" onChange={(value)=>onChange({...profile,keepaliveSecs:value})}/><SelectField label="Noize profile" value={profile.noize} onChange={(value)=>onChange({...profile,noize:value as ConnectionProfile["noize"]})} options={["off","light","firewall","balanced","gfw","aggressive"].map(value=>[value,value])}/><TextField label="Forced WG peer" value={profile.wgPeer??""} placeholder="Automatic · IP:port" onChange={(value)=>onChange({...profile,wgPeer:value||null})}/></div><ToggleField label="Retry profiles" copy="Try alternative obfuscation profiles." checked={profile.profileRetry} onChange={(checked)=>onChange({...profile,profileRetry:checked})}/></article><article className={`card transport-card ${profile.protocol==="gool"?"selected":""}`}><div className="section-head"><div><span className="label">NESTED</span><h3>WARP in WARP</h3></div><Switch checked={profile.protocol==="gool"} onCheckedChange={()=>onChange({...profile,protocol:"gool"})}/></div><SettingRow name="Outer identity" value="Primary config"/><SettingRow name="Inner identity" value="Secondary config"/><SettingRow name="MTU" value="Core managed"/></article></div></>;
}

function Routing({ profile, onChange }: ProfileProps) {
  return <><PageIntro badge="CORE TODAY" title="Routing & DNS" copy="Block rules are checked first, then direct rules; all remaining traffic enters the tunnel." /><div className="settings-grid"><article className="card"><div className="section-head"><div><span className="label">NEVER SEND</span><h3>Block rules</h3></div></div><TextAreaField value={profile.routeBlock} placeholder={"keyword:doubleclick\nport:25"} onChange={(value)=>onChange({...profile,routeBlock:value})}/></article><article className="card"><div className="section-head"><div><span className="label">BYPASS TUNNEL</span><h3>Direct rules</h3></div></div><TextAreaField value={profile.routeDirect} placeholder={"private\n10.0.0.0/8"} onChange={(value)=>onChange({...profile,routeDirect:value})}/></article></div><article className="card global"><div className="section-head"><div><span className="label">TUNNEL DNS</span><h3>Resolvers and local frontend</h3></div></div><div className="form-grid three"><TextField label="Resolvers" value={profile.dns.join(", ")} onChange={(value)=>onChange({...profile,dns:value.split(",").map(item=>item.trim()).filter(Boolean)})}/><TextField label="SOCKS address" value={profile.socksAddress} onChange={(value)=>onChange({...profile,socksAddress:value})}/><TextField label="Rules file" value={profile.routesFile??""} placeholder="Optional path" onChange={(value)=>onChange({...profile,routesFile:value||null})}/></div></article></>;
}

function Identity({ profile, onChange }: ProfileProps) {
  return <><PageIntro badge="CORE TODAY" title="Zero Trust identity" copy="Enrollment settings are sent to Aether. The client secret and token stay in memory only; the team, client ID and email are saved with the profile on this device." /><div className="two-col"><article className="card"><div className="section-head"><div><span className="label">ORGANIZATION</span><h3>Cloudflare Zero Trust</h3></div></div><div className="form-grid two"><TextField label="Team" value={profile.team??""} placeholder="team name" onChange={(value)=>onChange({...profile,team:value||null})}/><TextField label="Email" value={profile.accessEmail??""} placeholder="you@example.com" onChange={(value)=>onChange({...profile,accessEmail:value||null})}/><TextField label="Access client ID" value={profile.accessClientId??""} onChange={(value)=>onChange({...profile,accessClientId:value||null})}/><TextField label="Access client secret" type="password" value={profile.accessClientSecret??""} onChange={(value)=>onChange({...profile,accessClientSecret:value||null})}/><TextField label="Existing token" type="password" value={profile.accessToken??""} onChange={(value)=>onChange({...profile,accessToken:value||null})}/></div></article><article className="card"><div className="section-head"><div><span className="label">GATEWAY</span><h3>Organization filtering</h3></div><Switch checked={profile.gateway} onCheckedChange={(checked)=>onChange({...profile,gateway:checked})}/></div><p className="warning">Gateway adds a hop and permits organization filtering and logging for web traffic.</p><ToggleField label="Send web traffic to Gateway" copy="Applies the enrolled organization policy." checked={profile.gateway} onChange={(checked)=>onChange({...profile,gateway:checked})}/><SettingRow name="Client secret & token" value="Never stored"/><SettingRow name="Team, client ID, email" value="Stored on this device"/></article></div></>;
}

function Diagnostics({ snapshot, logs }: { snapshot: CoreSnapshot; logs: CoreLogEvent[] }) {
  return <><PageIntro badge="LIVE LOCAL" title="Diagnostics" copy="Real process state and Aether output, capped at the latest 1,000 lines." /><div className="metric-grid"><Metric icon={Activity} value={stateName(snapshot.state)} label="Core status" note="LIVE"/><Metric icon={Route} value={transportName(snapshot.transport)} label="Current transport" note="CORE"/><Metric icon={Network} value={snapshot.pid?.toString()??"—"} label="Process ID" note="LOCAL"/><Metric icon={Clock3} value={snapshot.endpoint??"—"} label="Selected edge" note="CORE"/></div><article className="card log"><div className="section-head"><div><span className="label">EVENT STREAM</span><h3>Aether core log</h3></div><Badge tone="current">{logs.length} LINES</Badge></div><div className="log-lines">{logs.length ? logs.map((entry,index)=><div key={`${entry.timestamp}-${index}`}><time>{new Date(entry.timestamp).toLocaleTimeString()}</time><span className={entry.level}>{entry.level.toUpperCase()}</span><code>{entry.message}</code></div>) : <p>No core events yet. Start a connection to populate this stream.</p>}</div></article></>;
}

function Preferences({ profile, onChange, probe, onProbe }: ProfileProps & { probe: CoreProbe; onProbe: () => void }) {
  const [platform,setPlatform]=useState("Windows");
  return <><PageIntro badge="DESKTOP SHELL" title="Preferences" copy="Cross-platform behavior and the managed core executable." action={<Button variant="secondary" onClick={onProbe}><RefreshCw/>Check core</Button>} /><div className="platforms">{["Windows","macOS","Linux"].map(name=><button className={platform===name?"active":""} onClick={()=>setPlatform(name)} key={name}>{name}</button>)}</div><div className="two-col"><article className="card"><div className="section-head"><div><span className="label">AETHER CORE</span><h3>{probe.available?probe.version:"Not detected"}</h3></div><span className={`availability ${probe.available?"online":"offline"}`}>{probe.available?"READY":"MISSING"}</span></div><TextField label="Core executable" value={profile.corePath??""} placeholder="Auto-detect or absolute path" onChange={(value)=>onChange({...profile,corePath:value||null})}/><p className="field-help">{probe.path??probe.message}</p></article><article className="card"><div className="section-head"><div><span className="label">{platform.toUpperCase()}</span><h3>System integration</h3></div><Badge tone="roadmap">NEXT</Badge></div><SettingRow name="Launch at sign-in" value="Planned"/><SettingRow name="System proxy" value="Planned"/><SettingRow name="Full-device tunnel" value="Roadmap"/><SettingRow name="Current frontend" value="SOCKS5"/></article></div></>;
}

type ProfileProps = { profile: ConnectionProfile; onChange: (profile: ConnectionProfile) => void };
function Metric({ icon: Icon, value, label, note }: { icon: typeof Clock3; value: string; label: string; note: string }) { return <article className="metric"><div><span><Icon /></span><em>{note}</em></div><strong>{value}</strong><small>{label}</small></article>; }
function PathNode({ icon: Icon, label, active=false }: { icon: typeof Laptop; label: string; active?: boolean }) { return <div className={`path-node ${active?"active":""}`}><Icon /><small>{label}</small></div>; }
function PageIntro({ badge, title, copy, action }: { badge: string; title: string; copy: string; action?: React.ReactNode }) { return <div className="page-intro"><div><Badge tone="current">{badge}</Badge><h2>{title}</h2><p>{copy}</p></div>{action}</div>; }
function SettingRow({ name, value }: { name: string; value: string }) { return <div className="setting-row"><span>{name}</span><strong>{value}</strong></div>; }
function SelectField({ label, value, options, onChange }: { label: string; value: string; options: string[][]; onChange: (value: string)=>void }) { return <label className="field">{label}<select value={value} onChange={(event)=>onChange(event.target.value)}>{options.map(([option,labelText])=><option value={option} key={option}>{labelText}</option>)}</select></label>; }
function TextField({ label, value, onChange, placeholder, type="text" }: { label: string; value: string; onChange: (value:string)=>void; placeholder?: string; type?: string }) { return <label className="field">{label}<input type={type} value={value} placeholder={placeholder} onChange={(event)=>onChange(event.target.value)}/></label>; }
function NumberField({ label, value, onChange, min, max, unit }: { label:string; value:number; onChange:(value:number)=>void; min:number; max:number; unit:string }) { return <label className="field">{label}<span className="input-unit"><input type="number" value={value} min={min} max={max} onChange={(event)=>onChange(Number(event.target.value))}/><em>{unit}</em></span></label>; }
function TextAreaField({ value, onChange, placeholder }: { value:string; onChange:(value:string)=>void; placeholder:string }) { return <textarea className="rules-area" value={value} onChange={(event)=>onChange(event.target.value)} placeholder={placeholder} rows={8}/>; }
function ToggleField({ label, copy, checked, onChange }: { label:string; copy:string; checked:boolean; onChange:(checked:boolean)=>void }) { return <div className="toggle-row"><div><strong>{label}</strong><span>{copy}</span></div><Switch checked={checked} onCheckedChange={onChange}/></div>; }
function currentPhase(snapshot: CoreSnapshot, profile: ConnectionProfile): ConnectionPhase { if (snapshot.transport === "masque-h3") return "h3"; if (snapshot.transport === "wireguard" || snapshot.transport === "warp-in-warp") return "wg"; if (snapshot.transport === "masque-h2") return "h2"; return profile.protocol === "wg" || profile.protocol === "gool" ? "wg" : profile.masqueTransport; }
function transportName(value: CoreSnapshot["transport"]): string { return ({"masque-h2":"MASQUE H2","masque-h3":"MASQUE H3","wireguard":"WireGuard","warp-in-warp":"WARP in WARP"} as Record<string,string>)[value??""]??"None"; }
function stateName(value: CoreSnapshot["state"]): string { return ({idle:"Ready",starting:"Starting",scanning:"Scanning",connecting:"Validating",connected:"Connected",reconnecting:"Reconnecting",stopped:"Stopped",error:"Error"} as Record<string,string>)[value]; }
function ipName(value: ConnectionProfile["ipFamily"]): string { return value === "both" ? "IPv4 + IPv6" : value === "v4" ? "IPv4 only" : "IPv6 only"; }

export default App;
