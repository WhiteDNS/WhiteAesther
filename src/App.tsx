import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { BadgeCheck, Settings2, Shield } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Advanced } from "@/features/Advanced";
import { Simple } from "@/features/Simple";
import { type CarryMode, carryFromProfile } from "@/features/carry";
import {
  getCoreLogs, getCoreStatus, isDesktopRuntime, loadProfile, probeCore, runtimeInfo,
  saveProfile as persistProfile, startCore, stopCore, subscribeCore, subscribeTrayActions,
} from "@/core/api";
import { withNormalizedEndpoint } from "@/core/endpoint";
import {
  DEFAULT_PROFILE, IDLE_SNAPSHOT, type ConnectionProfile, type CoreLogEvent, type CoreProbe,
  type CoreSnapshot,
} from "@/types";

const ACTIVE = new Set(["starting", "scanning", "connecting", "connected", "reconnecting"]);
const MODE_KEY = "whiteaesther.mode";
const appVersion = import.meta.env.VITE_APP_VERSION || "1.0.0";

type Mode = "simple" | "advanced";
type Toast = { title: string; message: string; error?: boolean };

export default function App() {
  const [mode, setMode] = useState<Mode>(
    () => (localStorage.getItem(MODE_KEY) as Mode | null) ?? "simple",
  );
  const [profile, setProfile] = useState<ConnectionProfile>(DEFAULT_PROFILE);
  const [snapshot, setSnapshot] = useState<CoreSnapshot>(IDLE_SNAPSHOT);
  const [probe, setProbe] = useState<CoreProbe>({
    available: false, path: null, version: null, message: "Checking core…",
  });
  const [logs, setLogs] = useState<CoreLogEvent[]>([]);
  const [runtime, setRuntime] = useState("Desktop shell");
  const [toast, setToast] = useState<Toast | null>(null);

  const desktop = isDesktopRuntime();
  const running = ACTIVE.has(snapshot.state);
  const effective = useMemo(() => withNormalizedEndpoint(profile), [profile]);

  const notify = useCallback((title: string, message: string, error?: boolean) => {
    setToast({ title, message, error });
  }, []);
  const showError = useCallback(
    (error: unknown) => notify("Action failed", error instanceof Error ? error.message : String(error), true),
    [notify],
  );

  useEffect(() => {
    localStorage.setItem(MODE_KEY, mode);
  }, [mode]);

  useEffect(() => {
    let disposed = false;
    let unsubscribe: (() => void) | undefined;
    void (async () => {
      if (!desktop) {
        setRuntime("Browser preview");
        setProbe({ available: false, path: null, version: null, message: "Open the desktop app to control Aether." });
        return;
      }
      try {
        // Subscribe first, then settle the rest independently: with Promise.all, one rejection
        // (loadProfile throws on any stored profile that fails validation) skipped subscribeCore
        // too, leaving the app blind to a running core for the whole session.
        unsubscribe = await subscribeCore(
          (next) => { if (!disposed) setSnapshot(next); },
          (entry) => { if (!disposed) setLogs((current) => [...current.slice(-999), entry]); },
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
        if (!disposed) showError(error);
      }
    })();
    return () => { disposed = true; unsubscribe?.(); };
  }, [desktop, showError]);

  useEffect(() => {
    if (!toast) return;
    const timeout = window.setTimeout(() => setToast(null), 4_000);
    return () => window.clearTimeout(timeout);
  }, [toast]);

  const toggleConnection = useCallback(async () => {
    try {
      if (ACTIVE.has(snapshot.state)) {
        setSnapshot(await stopCore());
        notify("Disconnected", "The core stopped cleanly.");
        return;
      }
      const latest = await probeCore(effective);
      setProbe(latest);
      if (!latest.available) throw new Error(latest.message);
      setSnapshot(await startCore(effective));
    } catch (error) {
      showError(error);
    }
  }, [snapshot.state, effective, notify, showError]);

  // Held in a ref so the listeners below never need re-registering. Depending on
  // the callback itself tore down and rebuilt a Tauri listener over IPC on every
  // keystroke, and re-bound the shortcut handler on every render.
  const toggleRef = useRef(toggleConnection);
  useEffect(() => {
    toggleRef.current = toggleConnection;
  }, [toggleConnection]);

  useEffect(() => {
    function onKey(event: KeyboardEvent) {
      if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
        event.preventDefault();
        void toggleRef.current();
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  useEffect(() => {
    if (!desktop) return;
    let disposed = false;
    let unsubscribe: (() => void) | undefined;
    void subscribeTrayActions((action) => {
      if (disposed) return;
      if (action === "open-diagnostics") setMode("advanced");
      else void toggleRef.current();
    })
      .then((cleanup) => { if (disposed) cleanup(); else unsubscribe = cleanup; })
      .catch(showError);
    return () => { disposed = true; unsubscribe?.(); };
  }, [desktop, showError]);

  const saveProfile = useCallback(async () => {
    try {
      if (!desktop) {
        localStorage.setItem("whiteaesther-profile", JSON.stringify(profile));
      } else {
        const saved = await persistProfile(effective);
        setProfile((current) => ({
          ...saved,
          accessClientSecret: current.accessClientSecret,
          accessToken: current.accessToken,
        }));
      }
      notify("Profile saved", "Settings are stored locally on this device.");
    } catch (error) {
      showError(error);
    }
  }, [desktop, profile, effective, notify, showError]);

  const carry: CarryMode = carryFromProfile(profile.systemProxy);
  const setCarry = useCallback((next: CarryMode) => {
    if (next === "tun") return;
    setProfile((current) => ({ ...current, systemProxy: next === "system" }));
  }, []);

  const retryStealth = useCallback(async () => {
    const next: ConnectionProfile = { ...profile, scanMode: "stealth" };
    setProfile(next);
    try {
      setSnapshot(await startCore(withNormalizedEndpoint(next)));
    } catch (error) {
      showError(error);
    }
  }, [profile, showError]);

  return (
    <div className="flex h-full flex-col bg-background">
      <header className="flex h-[52px] shrink-0 items-center justify-between border-b bg-card px-5">
        <div className="flex items-center gap-2.5">
          <span className="grid size-[26px] place-items-center rounded-[7px] bg-primary text-primary-foreground">
            <Shield className="size-[15px]" />
          </span>
          <span className="text-sm font-semibold tracking-tight">WhiteAesther</span>
          {running ? <span className="ml-1 size-1.5 rounded-full bg-primary" aria-hidden /> : null}
        </div>
        <div className="flex items-center gap-2.5">
          <Tabs value={mode} onValueChange={(value) => setMode(value as Mode)}>
            <TabsList className="h-8">
              <TabsTrigger value="simple" className="px-3 py-1 text-[13px]">Simple</TabsTrigger>
              <TabsTrigger value="advanced" className="px-3 py-1 text-[13px]">Advanced</TabsTrigger>
            </TabsList>
          </Tabs>
          <Button variant="ghost" size="icon" aria-label="Advanced settings" onClick={() => setMode("advanced")}>
            <Settings2 />
          </Button>
        </div>
      </header>

      <main className="min-h-0 flex-1">
        {mode === "simple" ? (
          <Simple
            snapshot={snapshot}
            profile={profile}
            probe={probe}
            carry={carry}
            onCarry={setCarry}
            onToggle={() => void toggleConnection()}
            onAdvanced={() => setMode("advanced")}
            onRetryStealth={() => void retryStealth()}
            onReport={() => setMode("advanced")}
          />
        ) : (
          <Advanced
            profile={profile}
            onChange={setProfile}
            snapshot={snapshot}
            probe={probe}
            logs={logs}
            runtime={runtime}
            appVersion={appVersion}
            onSave={() => void saveProfile()}
            onToast={notify}
          />
        )}
      </main>

      {toast ? (
        <div
          role="status"
          className={[
            "fixed bottom-5 right-5 z-50 flex max-w-[420px] items-start gap-2.5 rounded-lg border bg-popover p-3.5 shadow-lg",
            toast.error ? "border-destructive/50" : "border-border",
          ].join(" ")}
        >
          <BadgeCheck className={toast.error ? "size-4 text-destructive" : "size-4 text-primary"} />
          <div className="flex min-w-0 flex-col gap-0.5">
            <span className="text-[13px] font-semibold">{toast.title}</span>
            <span className="break-words text-xs text-muted-foreground">{toast.message}</span>
          </div>
        </div>
      ) : null}
    </div>
  );
}
