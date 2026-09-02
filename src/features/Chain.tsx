import { useCallback, useEffect, useState } from "react";
import { Link2, Plus, RefreshCw, Trash2, Zap } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { Row } from "./panels";
import {
  type ChainNode, chainNodes, chainSelect, chainStatus, chainTest, setChain,
} from "@/core/api";
import type { ChainSource, ConnectionProfile } from "@/types";

interface ChainProps {
  profile: ConnectionProfile;
  onChange: (profile: ConnectionProfile) => void;
  connected: boolean;
  onToast: (title: string, message: string, error?: boolean) => void;
}

export function Chain({ profile, onChange, connected, onToast }: ChainProps) {
  const chain = profile.chain;

  const [running, setRunning] = useState(false);
  const [address, setAddress] = useState<string | null>(null);
  const [nodes, setNodes] = useState<ChainNode[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [applying, setApplying] = useState(false);
  /**
   * Kept on screen rather than shown as a toast. A chain that failed to start
   * leaves the switch on and the node list empty, and a message that has
   * already faded is no help at all to whoever is looking at that.
   */
  const [failure, setFailure] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const status = await chainStatus();
      setRunning(status.running);
      setAddress(status.address);
      setNodes(status.running ? await chainNodes() : []);
    } catch (error) {
      // Not running is ordinary; being unable to ask is not. Swallowing this
      // made a failed status read indistinguishable from a stopped chain.
      setRunning(false);
      setNodes([]);
      setFailure(error instanceof Error ? error.message : String(error));
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh, connected]);

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

  return (
    <>
      <Card>
        <CardHeader className="pb-1">
          <CardTitle className="text-[15px]">Change the address you appear from</CardTitle>
          <CardDescription>
            The tunnel hides your traffic but keeps your country — Cloudflare places you near where
            you already are. Sending it on through a node of your own is what changes that.
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
                    ? "This network sees only Cloudflare, never your node's address. Needs the tunnel connected."
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
                      ? "Starting…"
                      : running
                        ? `Carrying traffic on ${address}`
                        : connected
                          ? "Switched on, but not running."
                          : chain.throughTunnel
                            ? "Waiting for the tunnel. Turn off the switch above to run without it."
                            : "Switched on, but not running."}
                  </span>
                </div>
                {(connected || !chain.throughTunnel) && !running && !applying ? (
                  <Button variant="outline" size="sm" className="shrink-0" onClick={() => set({})}>
                    <RefreshCw />
                    Start now
                  </Button>
                ) : null}
              </div>
              {failure ? (
                <div className="mb-3 rounded-lg border border-destructive/40 bg-destructive/[0.08] p-3">
                  <div className="text-[12.5px] font-semibold text-destructive">
                    The chain did not start
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
          <CardTitle className="text-[15px]">Configs pasted by hand</CardTitle>
          <CardDescription>
            One per line. vless, vmess, trojan, ss, hysteria2 and tuic are all understood as they
            are — nothing needs converting first.
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
              Read when the chain starts, so they take effect once applied.
            </p>
            <Button variant="outline" size="sm" disabled={applying} onClick={() => set({})}>
              Apply
            </Button>
          </div>
        </CardContent>
      </Card>

      <Nodes
        nodes={nodes}
        running={running}
        blocked={
          !chain.enabled
            ? "Turn on “Route through a second hop” above to load nodes."
            : chain.throughTunnel && !connected
              ? "Connect first, or turn off “Dial nodes through the tunnel”."
              : "The chain did not start. The reason is shown above."
        }
        selected={chain.node}
        busy={busy}
        onRefresh={refresh}
        onTest={async (node) => {
          setBusy(node.name);
          try {
            const delay = await chainTest(node.source, node.name);
            setNodes((current) =>
              current.map((entry) => (entry.name === node.name ? { ...entry, delay } : entry)),
            );
            if (delay == null) {
              onToast("Not usable", `${node.name} could not be reached through the tunnel.`, true);
            }
          } catch (error) {
            onToast("Test failed", error instanceof Error ? error.message : String(error), true);
          } finally {
            setBusy(null);
          }
        }}
        onSelect={async (node) => {
          setBusy(node.name);
          try {
            await chainSelect(node.name);
            set({ node: node.name });
            onToast("Exit changed", `Traffic now leaves through ${node.name}.`);
          } catch (error) {
            onToast("Could not switch", error instanceof Error ? error.message : String(error), true);
          } finally {
            setBusy(null);
          }
        }}
      />
    </>
  );
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
  const [url, setUrl] = useState("");

  return (
    <Card>
      <CardHeader className="pb-1">
        <CardTitle className="text-[15px]">Subscriptions</CardTitle>
        <CardDescription>
          Kept up to date automatically. A subscription link is a credential — anyone holding it can
          use your nodes.
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
          <p className="text-[13px] text-muted-foreground">No subscriptions yet.</p>
        )}

        <div className="flex items-end gap-2">
          <div className="flex flex-1 flex-col gap-2">
            <Label className="text-[13.5px]">Add a subscription</Label>
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
            Add
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
  blocked,
  selected,
  busy,
  onRefresh,
  onTest,
  onSelect,
}: {
  nodes: ChainNode[];
  running: boolean;
  /** Why there is nothing to show, in terms of what to do about it. */
  blocked: string;
  selected: string | null;
  busy: string | null;
  onRefresh: () => void;
  onTest: (node: ChainNode) => void;
  onSelect: (node: ChainNode) => void;
}) {
  return (
    <Card>
      <CardHeader className="flex-row items-start justify-between gap-4 pb-1 space-y-0">
        <div>
          <CardTitle className="text-[15px]">Nodes</CardTitle>
          <CardDescription>
            Every measurement here travels the tunnel, so a figure means the node works from behind
            it — and a failure means it does not. A node marked in amber is not broken and was not
            measured: hover it to read why this build cannot use it, and what to change.
          </CardDescription>
        </div>
        <Button variant="outline" size="sm" className="shrink-0" onClick={onRefresh}>
          <RefreshCw />
          Refresh
        </Button>
      </CardHeader>
      <CardContent className="pt-2">
        {!running ? (
          <p className="py-6 text-center text-[13px] text-muted-foreground">{blocked}</p>
        ) : !nodes.length ? (
          <p className="py-6 text-center text-[13px] text-muted-foreground">
            The chain is running but no nodes arrived — check that a subscription is enabled and
            that its link is still valid.
          </p>
        ) : (
          <div className="flex flex-col">
            {nodes.map((node) => {
              const active = node.name === selected;
              return (
                <div
                  key={`${node.source}/${node.name}`}
                  className="flex items-center gap-3 border-b py-2.5 last:border-b-0"
                >
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
                    disabled={busy === node.name || node.unusable != null}
                    onClick={() => onTest(node)}
                  >
                    Test
                  </Button>
                  <Button
                    variant={active ? "secondary" : "outline"}
                    size="sm"
                    className="w-[86px] shrink-0"
                    title={node.unusable ?? undefined}
                    disabled={busy === node.name || node.unusable != null}
                    onClick={() => onSelect(node)}
                  >
                    {active ? "In use" : <><Zap />Use</>}
                  </Button>
                </div>
              );
            })}
          </div>
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
