import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useT } from "@/core/useT";
import { Download, Link2, Plus, RefreshCw, Search, Trash2, Zap } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { Row } from "./panels";
import {
  AUTOMATIC_NODE, type ChainNode, chainNodes, chainPreview, chainPreviewStop, chainSelect,
  chainStatus, chainTest, setChain,
} from "@/core/api";
import type { ChainSource, ConnectionProfile } from "@/types";

interface ChainProps {
  profile: ConnectionProfile;
  onChange: (profile: ConnectionProfile) => void;
  connected: boolean;
  onToast: (title: string, message: string, error?: boolean) => void;
}

/** How many nodes one batch test measures at once. */
const TEST_BATCH = 4;

const keyOf = (node: ChainNode) => `${node.source}/${node.name}`;

export function Chain({ profile, onChange, connected, onToast }: ChainProps) {
  const t = useT();
  const chain = profile.chain;
  // Read by `refresh` without making it a dependency: the pasted configs change
  // on every keystroke and only count once applied.
  const chainRef = useRef(chain);
  chainRef.current = chain;

  const [running, setRunning] = useState(false);
  const [address, setAddress] = useState<string | null>(null);
  /** What the live exit group is on, and what the fastest-node group picked. */
  const [live, setLive] = useState<{ node: string | null; auto: string | null }>({ node: null, auto: null });
  const [nodes, setNodes] = useState<ChainNode[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [applying, setApplying] = useState(false);
  const [updating, setUpdating] = useState(false);
  const [updateFailure, setUpdateFailure] = useState<string | null>(null);
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null);
  const stopTests = useRef<{ stopped: boolean } | null>(null);
  /**
   * Kept on screen rather than shown as a toast. A chain that failed to start
   * leaves the switch on and the node list empty, and a message that has
   * already faded is no help at all to whoever is looking at that.
   */
  const [failure, setFailure] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    const current = chainRef.current;
    try {
      const status = await chainStatus();
      setRunning(status.running);
      setAddress(status.address);
      setLive({ node: status.node, auto: status.auto });
      if (status.running) {
        setNodes(await chainNodes());
      } else if (current.enabled) {
        // Read from the cached subscriptions, so the list is there before the
        // first connect. Nothing cached yet is an empty list, not an error.
        await chainPreview(current, false);
        setNodes(await chainNodes().catch(() => []));
      } else {
        setNodes([]);
      }
    } catch (error) {
      // Not running is ordinary; being unable to ask is not. Swallowing this
      // made a failed status read indistinguishable from a stopped chain.
      setRunning(false);
      setNodes([]);
      setFailure(error instanceof Error ? error.message : String(error));
    }
  }, []);

  const sourcesKey = chain.sources.map((source) => `${source.enabled}${source.url}`).join("|");
  useEffect(() => {
    void refresh();
  }, [refresh, connected, chain.enabled, chain.throughTunnel, sourcesKey]);

  // The listener-less engine exists for this screen only.
  useEffect(() => () => {
    stopTests.current && (stopTests.current.stopped = true);
    void chainPreviewStop().catch(() => {});
  }, []);

  /**
   * Saves a change and makes it take effect now.
   *
   * mihomo reads its sources once at startup, so a new subscription or a
   * flipped switch means nothing until it is restarted -- and doing that only
   * at the next connect is what made this screen look broken while the user
   * was already connected.
   */
  const apply = async (patch: Partial<ConnectionProfile["chain"]>) => {
    const next = { ...chain, ...patch };
    onChange({ ...profile, chain: next });
    chainRef.current = next;
    setApplying(true);
    setFailure(null);
    try {
      await setChain(next);
      await refresh();
    } catch (error) {
      setFailure(error instanceof Error ? error.message : String(error));
      await refresh();
    } finally {
      setApplying(false);
    }
  };
  const set = (patch: Partial<ConnectionProfile["chain"]>) => void apply(patch);
  /** Remembers the chosen node without restarting anything. */
  const remember = (node: string | null) => {
    const next = { ...chain, node };
    chainRef.current = next;
    onChange({ ...profile, chain: next });
  };

  const update = async () => {
    setUpdating(true);
    setUpdateFailure(null);
    try {
      await chainPreview(chain, true);
    } catch (error) {
      setUpdateFailure(error instanceof Error ? error.message : String(error));
    } finally {
      await refresh();
      setUpdating(false);
    }
  };

  const measure = (node: ChainNode, delay: number | null) =>
    setNodes((current) => current.map((entry) => (keyOf(entry) === keyOf(node) ? { ...entry, delay } : entry)));

  const testMany = async (targets: ChainNode[]) => {
    const run = { stopped: false };
    stopTests.current = run;
    let next = 0;
    let done = 0;
    setProgress({ done, total: targets.length });
    const worker = async () => {
      while (!run.stopped && next < targets.length) {
        const node = targets[next++];
        const delay = await chainTest(node.source, node.name).catch(() => null);
        if (run.stopped) return;
        measure(node, delay);
        setProgress({ done: ++done, total: targets.length });
      }
    };
    await Promise.all(Array.from({ length: TEST_BATCH }, worker));
    if (stopTests.current === run) {
      stopTests.current = null;
      setProgress(null);
    }
  };
  const stop = () => {
    if (stopTests.current) stopTests.current.stopped = true;
    stopTests.current = null;
    setProgress(null);
  };

  // Nothing saved, or a saved node the subscription dropped, means automatic.
  const automatic = running
    ? live.node === AUTOMATIC_NODE
    : chain.node == null || (nodes.length > 0 && !nodes.some((node) => node.name === chain.node));
  const inUse = running ? (live.node === AUTOMATIC_NODE ? live.auto : live.node) : automatic ? null : chain.node;

  const choose = async (name: string | null) => {
    const target = name ?? AUTOMATIC_NODE;
    setBusy(target);
    try {
      if (running) {
        await chainSelect(target);
        setLive({ node: target, auto: name == null ? live.auto : null });
      }
      remember(name);
      if (running && name) onToast("Exit changed", `Traffic now leaves through ${name}.`);
      if (running) void refresh();
    } catch (error) {
      onToast("Could not switch", error instanceof Error ? error.message : String(error), true);
    } finally {
      setBusy(null);
    }
  };

  const outsideTunnel = chain.throughTunnel && !connected;

  return (
    <>
      <Card>
        <CardHeader className="pb-1">
          <CardTitle className="text-[15px]">{t("Change the address you appear from")}</CardTitle>
          <CardDescription>
            {t(
              "The tunnel hides your traffic but keeps your country — Cloudflare places you near where you already are. Sending it on through a node of your own is what changes that.",
            )}
          </CardDescription>
        </CardHeader>
        <CardContent className="pt-0">
          <Row
            first
            title="Route through a second hop"
            help="Every node is dialled from inside the tunnel, so this network only ever sees Cloudflare."
          >
            <Switch checked={chain.enabled} onCheckedChange={(enabled) => set({ enabled })} />
          </Row>
          {chain.enabled ? (
            <>
              <Row
                title="Dial nodes through the tunnel"
                help={
                  chain.throughTunnel
                    ? t("This network sees only Cloudflare, never your node's address. Needs the tunnel connected.")
                    : "Your node is reached directly, so this network can see its address. Use when the tunnel will not connect."
                }
              >
                <Switch
                  checked={chain.throughTunnel}
                  onCheckedChange={(throughTunnel) => set({ throughTunnel })}
                />
              </Row>
              <Separator />
              <div className="flex items-center justify-between gap-4 py-3">
                <div className="flex min-w-0 items-center gap-2.5">
                  <span
                    className={[
                      "size-1.5 shrink-0 rounded-full",
                      running ? "bg-primary" : connected ? "bg-destructive" : "bg-muted-foreground",
                    ].join(" ")}
                  />
                  <span className="text-[13px] text-muted-foreground">
                    {applying
                      ? t("Starting…")
                      : running
                        ? `Carrying traffic on ${address}`
                        : connected
                          ? t("Switched on, but not running.")
                          : chain.throughTunnel
                            ? t("Waiting for the tunnel. Turn off the switch above to run without it.")
                            : t("Switched on, but not running.")}
                  </span>
                </div>
                {connected && !running && !applying ? (
                  <Button variant="outline" size="sm" className="shrink-0" onClick={() => set({})}>
                    <RefreshCw />
                    {t("Start now")}
                  </Button>
                ) : null}
              </div>
              {failure ? (
                <div className="mb-3 rounded-lg border border-destructive/40 bg-destructive/[0.08] p-3">
                  <div className="text-[12.5px] font-semibold text-destructive">
                    {t("The chain did not start")}
                  </div>
                  <div className="mt-1 break-words text-[12px] text-muted-foreground">{failure}</div>
                </div>
              ) : null}
            </>
          ) : null}
        </CardContent>
      </Card>

      <Sources sources={chain.sources} onChange={(sources) => set({ sources })} />

      <Card>
        <CardHeader className="pb-1">
          <CardTitle className="text-[15px]">{t("Configs pasted by hand")}</CardTitle>
          <CardDescription>
            {t(
              "One per line. vless, vmess, trojan, ss, hysteria2 and tuic are all understood as they are — nothing needs converting first.",
            )}
          </CardDescription>
        </CardHeader>
        <CardContent className="pt-2">
          <Textarea
            rows={4}
            className="font-mono text-[12.5px]"
            value={chain.manual}
            placeholder={"vless://…\ntrojan://…"}
            // Typed into freely; applied on the button below. Restarting the
            // chain on every keystroke would tear the connection down
            // repeatedly while someone is still pasting.
            onChange={(event) =>
              onChange({ ...profile, chain: { ...chain, manual: event.target.value } })
            }
          />
          <div className="mt-3 flex items-center justify-between gap-4">
            <p className="text-[12px] text-muted-foreground">
              {t("Read when the chain starts, so they take effect once applied.")}
            </p>
            <Button variant="outline" size="sm" disabled={applying} onClick={() => set({})}>
              {t("Apply")}
            </Button>
          </div>
        </CardContent>
      </Card>

      <Nodes
        nodes={nodes}
        running={running}
        enabled={chain.enabled}
        hasSubscriptions={chain.sources.some((source) => source.enabled)}
        outsideTunnel={outsideTunnel}
        blocked={
          !chain.enabled
            ? t("Turn on “Route through a second hop” above to load nodes.")
            : outsideTunnel
              ? t("Nothing downloaded yet. Press Update, or connect first, or turn off “Dial nodes through the tunnel”.")
              : connected && !running
                ? t("The chain did not start. The reason is shown above.")
                : t("No nodes arrived. Check that a subscription is enabled and that its link is still valid.")
        }
        automatic={automatic}
        autoPick={live.auto}
        inUse={inUse}
        busy={busy}
        updating={updating}
        updateFailure={updateFailure}
        progress={progress}
        onUpdate={update}
        onRefresh={refresh}
        onAutomatic={(on) => {
          if (on) return void choose(null);
          // Off keeps the node automatic was using, so traffic does not jump.
          const usable = nodes.filter((node) => !node.unusable);
          const fastest = [...usable].sort(byFastest)[0];
          const pick = live.auto ?? fastest?.name ?? usable[0]?.name;
          if (pick) void choose(pick);
        }}
        onTestMany={testMany}
        onStop={stop}
        onTest={async (node) => {
          setBusy(`test:${keyOf(node)}`);
          try {
            const delay = await chainTest(node.source, node.name);
            measure(node, delay);
            if (delay == null) {
              onToast("Not usable", `${node.name} could not be reached.`, true);
            }
          } catch (error) {
            onToast("Test failed", error instanceof Error ? error.message : String(error), true);
          } finally {
            setBusy(null);
          }
        }}
        onSelect={(node) => void choose(node.name)}
      />
    </>
  );
}

/** Fastest first, then untested or failed, then the ones that cannot work here. */
function byFastest(a: ChainNode, b: ChainNode): number {
  const rank = (node: ChainNode) => (node.unusable ? 2 : node.delay == null ? 1 : 0);
  return rank(a) - rank(b) || (a.delay ?? 0) - (b.delay ?? 0) || a.name.localeCompare(b.name);
}

/**
 * Two words for a reason that needs a sentence.
 *
 * The column is 132 pixels wide and the full reason is in the tooltip, so this
 * only has to be enough to tell the two cases apart at a glance: a node this
 * build cannot use at all, and one that only needs a different first hop.
 */
function unusableLabel(reason: string): string {
  return reason.startsWith("REALITY") ? "not supported" : "needs WireGuard";
}

function Sources({
  sources,
  onChange,
}: {
  sources: ChainSource[];
  onChange: (sources: ChainSource[]) => void;
}) {
  const t = useT();
  const [url, setUrl] = useState("");

  return (
    <Card>
      <CardHeader className="pb-1">
        <CardTitle className="text-[15px]">{t("Subscriptions")}</CardTitle>
        <CardDescription>
          {t(
            "Kept up to date automatically. A subscription link is a credential — anyone holding it can use your nodes.",
          )}
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3 pt-2">
        {sources.length ? (
          <div className="flex flex-col">
            {sources.map((source, index) => (
              <div key={`${source.url}-${index}`} className="flex items-center gap-3 border-b py-2.5 last:border-b-0">
                <Switch
                  checked={source.enabled}
                  onCheckedChange={(enabled) =>
                    onChange(sources.map((entry, at) => (at === index ? { ...entry, enabled } : entry)))
                  }
                />
                <div className="min-w-0 flex-1">
                  <div className="truncate text-[13px] font-medium">{source.name || "Subscription"}</div>
                  <div className="truncate font-mono text-[11px] text-muted-foreground">
                    {redact(source.url)}
                  </div>
                </div>
                <Button
                  variant="ghost"
                  size="icon"
                  aria-label={`Remove ${source.name}`}
                  onClick={() => onChange(sources.filter((_, at) => at !== index))}
                >
                  <Trash2 className="size-4" />
                </Button>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-[13px] text-muted-foreground">{t("No subscriptions yet.")}</p>
        )}

        <div className="flex items-end gap-2">
          <div className="flex flex-1 flex-col gap-2">
            <Label className="text-[13.5px]">{t("Add a subscription")}</Label>
            <Input
              className="font-mono"
              value={url}
              placeholder="https://…"
              onChange={(event) => setUrl(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter") add();
              }}
            />
          </div>
          <Button variant="outline" onClick={add} disabled={!url.trim()}>
            <Plus />
            {t("Add")}
          </Button>
        </div>
      </CardContent>
    </Card>
  );

  function add() {
    const trimmed = url.trim();
    if (!trimmed) return;
    onChange([...sources, { name: labelFor(trimmed, sources.length), url: trimmed, enabled: true }]);
    setUrl("");
  }
}

function Nodes({
  nodes,
  running,
  enabled,
  hasSubscriptions,
  outsideTunnel,
  blocked,
  automatic,
  autoPick,
  inUse,
  busy,
  updating,
  updateFailure,
  progress,
  onUpdate,
  onRefresh,
  onAutomatic,
  onTestMany,
  onStop,
  onTest,
  onSelect,
}: {
  nodes: ChainNode[];
  running: boolean;
  enabled: boolean;
  hasSubscriptions: boolean;
  /** Nodes would be dialled through the tunnel, but it is not connected. */
  outsideTunnel: boolean;
  /** Why there is nothing to show, in terms of what to do about it. */
  blocked: string;
  automatic: boolean;
  autoPick: string | null;
  inUse: string | null;
  busy: string | null;
  updating: boolean;
  updateFailure: string | null;
  progress: { done: number; total: number } | null;
  onUpdate: () => void;
  onRefresh: () => void;
  onAutomatic: (on: boolean) => void;
  onTestMany: (nodes: ChainNode[]) => void;
  onStop: () => void;
  onTest: (node: ChainNode) => void;
  onSelect: (node: ChainNode) => void;
}) {
  const t = useT();
  const [query, setQuery] = useState("");
  const [protocol, setProtocol] = useState<string | null>(null);
  const [ticked, setTicked] = useState<Set<string>>(new Set());

  const protocols = useMemo(() => [...new Set(nodes.map((node) => node.kind))].sort(), [nodes]);
  const shown = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return nodes
      .filter((node) => (protocol ? node.kind === protocol : true))
      .filter((node) => !needle || node.name.toLowerCase().includes(needle))
      .sort(byFastest);
  }, [nodes, query, protocol]);
  const testable = shown.filter((node) => !node.unusable);
  const selected = testable.filter((node) => ticked.has(keyOf(node)));

  return (
    <Card>
      <CardHeader className="flex-row items-start justify-between gap-4 pb-1 space-y-0">
        <div>
          <CardTitle className="text-[15px]">{t("Nodes")}</CardTitle>
          <CardDescription>
            {running
              ? t(
                  "Every measurement here travels the tunnel, so a figure means the node works from behind it — and a failure means it does not. A node marked in amber is not broken and was not measured: hover it to read why this build cannot use it, and what to change.",
                )
              : t("Not connected: a test reaches each node directly from this device.")}
          </CardDescription>
        </div>
        {enabled ? (
          hasSubscriptions ? (
            <Button variant="outline" size="sm" className="shrink-0" disabled={updating} onClick={onUpdate}>
              <Download />
              {updating ? t("Updating…") : t("Update subscriptions")}
            </Button>
          ) : (
            <Button variant="outline" size="sm" className="shrink-0" onClick={onRefresh}>
              <RefreshCw />
              {t("Refresh")}
            </Button>
          )
        ) : null}
      </CardHeader>
      <CardContent className="pt-2">
        {enabled && hasSubscriptions && outsideTunnel ? (
          <p className="mb-2 text-[12px] text-muted-foreground">
            {t("Not connected: Update and the ping tests reach the subscription and its nodes from this device, outside the tunnel.")}
          </p>
        ) : null}
        {updateFailure ? (
          <p className="mb-2 break-words text-[12px] text-destructive">{updateFailure}</p>
        ) : null}
        {!enabled || !nodes.length ? (
          <p className="py-6 text-center text-[13px] text-muted-foreground">{blocked}</p>
        ) : (
          <>
            <Row
              first
              title="Automatic node"
              help={
                automatic
                  ? autoPick
                    ? `${t("On. Now using")} ${autoPick}, ${t("the fastest")}`
                    : t("On. The fastest node carries your traffic.")
                  : t("Off. The node you choose below carries your traffic.")
              }
            >
              <Switch checked={automatic} disabled={busy === AUTOMATIC_NODE} onCheckedChange={onAutomatic} />
            </Row>
            <Separator />
            <div className="flex flex-wrap items-center gap-2 py-3">
              <div className="relative min-w-[180px] flex-1">
                <Search className="pointer-events-none absolute start-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
                <Input
                  className="h-8 ps-8 text-[12.5px]"
                  value={query}
                  placeholder={t("Search nodes")}
                  onChange={(event) => setQuery(event.target.value)}
                />
              </div>
              {progress ? (
                <Button variant="outline" size="sm" onClick={onStop}>
                  {`${t("Stop")} (${progress.done}/${progress.total})`}
                </Button>
              ) : (
                <>
                  {selected.length ? (
                    <Button variant="outline" size="sm" onClick={() => onTestMany(selected)}>
                      {`${t("Test selected")} (${selected.length})`}
                    </Button>
                  ) : null}
                  <Button variant="outline" size="sm" disabled={!testable.length} onClick={() => onTestMany(testable)}>
                    {t("Test all")}
                  </Button>
                </>
              )}
            </div>
            {protocols.length > 1 ? (
              <div className="flex flex-wrap gap-1.5 pb-2">
                {[null, ...protocols].map((kind) => (
                  <Button
                    key={kind ?? "all"}
                    variant={protocol === kind ? "secondary" : "ghost"}
                    size="sm"
                    className="h-7 px-2.5 text-[12px]"
                    onClick={() => setProtocol(kind)}
                  >
                    {kind ?? t("All protocols")}
                  </Button>
                ))}
              </div>
            ) : null}
            <div className="flex flex-col">
              {shown.map((node) => {
                const active = node.name === inUse;
                const key = keyOf(node);
                return (
                  <div key={key} className="flex items-center gap-3 border-b py-2.5 last:border-b-0">
                    <span
                      className={[
                        "grid size-7 shrink-0 place-items-center rounded-md",
                        active ? "bg-primary/15 text-primary" : "bg-muted text-muted-foreground",
                      ].join(" ")}
                    >
                      <Link2 className="size-3.5" />
                    </span>
                    <div className="min-w-0 flex-1">
                      <div className="truncate text-[13px] font-medium">{node.name}</div>
                      <div className="truncate text-[11px] text-muted-foreground">
                        {node.kind} · {node.source}
                      </div>
                    </div>
                    <span
                      title={node.unusable ?? undefined}
                      className={[
                        "tabular shrink-0 text-end font-mono text-[12.5px]",
                        node.unusable ? "w-[132px] text-amber-500/90" : "w-[68px]",
                        node.delay == null ? "text-muted-foreground" : "text-primary",
                        node.unusable ? "text-amber-500/90" : "",
                      ].join(" ")}
                    >
                      {node.unusable
                        ? unusableLabel(node.unusable)
                        : node.delay == null
                          ? "—"
                          : `${node.delay} ms`}
                    </span>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="shrink-0"
                      disabled={busy === `test:${key}` || node.unusable != null}
                      onClick={() => onTest(node)}
                    >
                      {t("Test")}
                    </Button>
                    <Button
                      variant={active ? "secondary" : "outline"}
                      size="sm"
                      className="w-[86px] shrink-0"
                      title={node.unusable ?? undefined}
                      disabled={busy === node.name || node.unusable != null}
                      onClick={() => onSelect(node)}
                    >
                      {active ? t("In use") : <><Zap />{t("Use")}</>}
                    </Button>
                    <input
                      type="checkbox"
                      className="size-4 shrink-0 accent-primary"
                      aria-label={`${t("Test selected")}: ${node.name}`}
                      disabled={node.unusable != null}
                      checked={ticked.has(key)}
                      onChange={(event) =>
                        setTicked((current) => {
                          const next = new Set(current);
                          if (event.target.checked) next.add(key);
                          else next.delete(key);
                          return next;
                        })
                      }
                    />
                  </div>
                );
              })}
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}

/**
 * A subscription link is a credential, and this screen gets shown in support
 * threads and screenshots. Enough of it stays visible to tell two apart.
 */
export function redact(url: string): string {
  try {
    const parsed = new URL(url);
    return `${parsed.protocol}//${parsed.host}/…`;
  } catch {
    return "…";
  }
}

function labelFor(url: string, index: number): string {
  try {
    return new URL(url).hostname;
  } catch {
    return `Subscription ${index + 1}`;
  }
}
