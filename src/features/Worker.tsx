import { useEffect, useState } from "react";
import { openUrl } from "@tauri-apps/plugin-opener";
import { useT } from "@/core/useT";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import {
  isDesktopRuntime,
  workerAccounts,
  workerAttachDomain,
  workerCreate,
  workerAccountDelete,
  workerAccountList,
  workerDelete,
  workerForget,
  workerDeployments,
  workerDetachDomain,
  workerSaveOptions,
  workerStatus,
  workerTokenUrl,
  workerUpdate,
  workerUsage,
} from "@/core/api";
import type {
  ConnectionProfile,
  WorkerAccount,
  WorkerDeployment,
  WorkerFragment,
  WorkerMode,
  WorkerOptions,
  WorkerSnapshot,
} from "@/types";
import { Row, Seg } from "./panels";

const FINGERPRINTS = ["chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized"];
const NEW_FRAGMENT: WorkerFragment = { packets: "tlshello", lengths: "100-200", delays: "1", maxSplit: "" };

export interface WorkerPageProps {
  profile: ConnectionProfile;
  onChange: (profile: ConnectionProfile) => void;
  onSave: () => void;
  onToast: (title: string, message: string, error?: boolean) => void;
}

/** A labelled input. Its focus ring is the input's own, so the two never draw as separate boxes. */
function Field({
  label,
  value,
  onChange,
  disabled,
  multiline,
  secret,
  placeholder,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  disabled?: boolean;
  multiline?: boolean;
  secret?: boolean;
  placeholder?: string;
}) {
  return (
    <label className="block space-y-1.5 pb-3">
      <span className="text-[12.5px] font-medium">{label}</span>
      {multiline ? (
        <Textarea
          value={value}
          disabled={disabled}
          placeholder={placeholder}
          onChange={(event) => onChange(event.target.value)}
          className="min-h-[72px] font-mono text-[12.5px]"
          spellCheck={false}
        />
      ) : (
        <Input
          value={value}
          disabled={disabled}
          placeholder={placeholder}
          type={secret ? "password" : "text"}
          autoComplete="off"
          spellCheck={false}
          onChange={(event) => onChange(event.target.value)}
          className="font-mono text-[12.5px]"
        />
      )}
    </label>
  );
}

function Note({ children }: { children: React.ReactNode }) {
  return <p className="pb-3 text-[12.5px] leading-snug text-muted-foreground">{children}</p>;
}

const entries = (text: string) => text.split(/[\s,;]+/).filter(Boolean);

export function WorkerPage({ profile, onChange, onSave, onToast }: WorkerPageProps) {
  const t = useT();
  // Held in this component's memory only, never in the profile or storage.
  const [token, setToken] = useState("");
  const [accounts, setAccounts] = useState<WorkerAccount[]>([]);
  const [accountId, setAccountId] = useState("");
  const [pages, setPages] = useState(false);
  const [relay, setRelay] = useState("");
  const [deployments, setDeployments] = useState<WorkerDeployment[]>([]);
  const [usage, setUsage] = useState<Record<string, [number, number]>>({});
  const [status, setStatus] = useState<WorkerSnapshot | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const desktop = isDesktopRuntime();

  const refresh = async () => {
    if (!desktop) return;
    setDeployments(await workerDeployments());
    setStatus(await workerStatus());
  };

  useEffect(() => {
    refresh().catch((failure) => setError(String(failure)));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Also a toast, so a failure is seen next to whichever card was clicked.
  const fail = (message: string) => {
    setError(message);
    onToast(t("Cloudflare Workers"), message, true);
  };

  const [others, setOthers] = useState<Array<{ name: string; pages: boolean; host: string }>>([]);
  const loadOthers = async () => {
    if (desktop && token.trim() && accountId) setOthers(await workerAccountList(token, accountId));
  };
  useEffect(() => {
    setOthers([]);
    loadOthers().catch((failure) => fail(String(failure)));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [accountId]);

  const run = async (action: () => Promise<void>) => {
    if (busy || !desktop) return;
    setBusy(true);
    setError(null);
    try {
      await action();
    } catch (failure) {
      fail(String(failure));
    } finally {
      await refresh().catch(() => {});
      await loadOthers().catch(() => {});
      setBusy(false);
    }
  };

  const connect = (deployment: WorkerDeployment) => {
    onChange({
      ...profile,
      autoRoute: false,
      carriers: { first: "worker", second: null },
      worker: { deployment: deployment.key },
    });
    onSave();
    onToast(t("Cloudflare Worker"), t("TCP only. Connecting uses this Worker directly, changes the current connection method, and keeps your existing nodes and identity. Your network can see the Worker hostname."));
  };

  const active = (key: string) =>
    status?.deployment === key && (status.state === "connected" || status.state === "connecting");

  return (
    <div className="space-y-3.5">
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-[15px]">{t("Cloudflare Workers")}</CardTitle>
          <CardDescription>{t("Deploy and manage your own TCP proxy on Workers or Pages.")}</CardDescription>
        </CardHeader>
        <CardContent className="pt-0">
          <Note>{t("This screen manages deployments created on this device. Connection identities stay in app-private storage; API tokens are never saved. Cloudflare plan limits still apply.")}</Note>
          <Field label={t("Cloudflare API token")} value={token} onChange={setToken} disabled={busy} secret />
          <Note>{t("The API token stays in memory while this screen is open. Paste it again next time.")}</Note>
          <div className="flex flex-wrap gap-2 pb-3">
            <Button
              variant="outline"
              disabled={!desktop}
              onClick={() =>
                void workerTokenUrl()
                  .then((url) => openUrl(url))
                  .catch(() => setError(t("No browser could open the token page.")))
              }
            >
              {t("Create API token")}
            </Button>
            <Button
              disabled={busy || !token.trim()}
              onClick={() =>
                void run(async () => {
                  const list = await workerAccounts(token);
                  setAccounts(list);
                  setAccountId((current) => list.find((a) => a.id === current)?.id ?? list[0]?.id ?? "");
                  if (list.length === 0) setError(t("This token has no accessible Cloudflare accounts"));
                })
              }
            >
              {t("Load accounts")}
            </Button>
          </div>
          <Note>{t("The form prefills deployment permissions plus Zone: Read and DNS: Edit for custom domains, and Account Analytics: Read for usage. Review Account Resources and Zone Resources, select your account and zones, then create and paste the token.")}</Note>
          {accounts.length > 0 ? (
            <Row first title={t("Cloudflare account")}>
              <select
                value={accountId}
                disabled={busy}
                onChange={(event) => setAccountId(event.target.value)}
                className="h-9 rounded-md border border-input bg-background px-2 text-[13px] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              >
                {accounts.map((account) => (
                  <option key={account.id} value={account.id}>
                    {account.name}
                  </option>
                ))}
              </select>
            </Row>
          ) : null}
          {error ? <p className="pt-1 text-[12.5px] text-destructive">{error}</p> : null}
        </CardContent>
      </Card>

      {accounts.length > 0 ? (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-[15px]">{t("New deployment")}</CardTitle>
          </CardHeader>
          <CardContent className="pt-0">
            <Row first title={pages ? "Pages" : "Workers"} help={pages ? t("A private proxy on a pages.dev hostname.") : t("A private proxy on a workers.dev hostname.")}>
              <Seg value={pages ? "pages" : "workers"} options={[["workers", "Workers"], ["pages", "Pages"]]} onChange={(value) => setPages(value === "pages")} />
            </Row>
            <Field label={t("Optional public relay host:port")} value={relay} onChange={setRelay} disabled={busy} />
            <Note>{t("Used only when a destination refuses Worker connections, such as sites behind Cloudflare. When blank, or when the relay fails, the Worker uses public NAT64 gateways; they see destination addresses but not encrypted content. Only enter a relay you trust.")}</Note>
            <Button
              disabled={busy || !accountId}
              onClick={() =>
                void run(async () => {
                  await workerCreate(token, accountId, pages, relay.trim());
                  setRelay("");
                })
              }
            >
              {t("Deploy")}
            </Button>
          </CardContent>
        </Card>
      ) : null}

      {deployments.map((deployment) => (
        <DeploymentCard
          key={deployment.key}
          deployment={deployment}
          token={token}
          busy={busy}
          active={active(deployment.key)}
          selected={profile.carriers.first === "worker" && profile.worker.deployment === deployment.key}
          usage={usage[deployment.key]}
          run={run}
          onConnect={() => connect(deployment)}
          onUsage={(value) => setUsage((current) => ({ ...current, [deployment.key]: value }))}
          onDeleted={() => {
            if (profile.worker.deployment === deployment.key) {
              onChange({ ...profile, worker: { deployment: "" } });
            }
          }}
          onError={fail}
        />
      ))}

      {accountId && token.trim() ? (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-[15px]">{t("Other Workers and Pages in this account")}</CardTitle>
            <CardDescription>{t("Made outside this computer, so they can be deleted here but not connected through.")}</CardDescription>
          </CardHeader>
          <CardContent className="pt-0">
            <div className="pb-3">
              <Button variant="outline" disabled={busy} onClick={() => void run(loadOthers)}>
                {t("Refresh list")}
              </Button>
            </div>
            {others
              .filter((item) => !deployments.some((row) => row.accountId === accountId && row.name === item.name && row.pages === item.pages))
              .map((item) => (
                <div key={`${item.pages}/${item.name}`} className="flex flex-wrap items-center gap-2 border-t border-border py-2.5">
                  <span className="font-mono text-[12.5px]">{item.name}</span>
                  <Badge variant="outline">{item.pages ? "Pages" : "Workers"}</Badge>
                  <span className="font-mono text-[12px] text-muted-foreground">{item.host || "—"}</span>
                  <Button
                    variant="outline"
                    className="ms-auto"
                    disabled={busy}
                    onClick={() => {
                      const question = t("Delete %1$s from Cloudflare? This cannot be undone.").replace("%1$s", item.name);
                      if (!window.confirm(question)) return;
                      void run(async () => void (await workerAccountDelete(token, accountId, item.name, item.pages)));
                    }}
                  >
                    {t("Delete")}
                  </Button>
                </div>
              ))}
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}

function DeploymentCard({
  deployment,
  token,
  busy,
  active,
  selected,
  usage,
  run,
  onConnect,
  onUsage,
  onDeleted,
  onError,
}: {
  deployment: WorkerDeployment;
  token: string;
  busy: boolean;
  active: boolean;
  selected: boolean;
  usage: [number, number] | undefined;
  run: (action: () => Promise<void>) => Promise<void>;
  onConnect: () => void;
  onUsage: (value: [number, number]) => void;
  onDeleted: () => void;
  onError: (message: string) => void;
}) {
  const t = useT();
  const [domain, setDomain] = useState(deployment.customDomain);
  const host = deployment.domainPending || !deployment.customDomain ? deployment.host : deployment.customDomain;

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex flex-wrap items-center gap-2 text-[15px]">
          <span className="font-mono text-[13px]">{deployment.name}</span>
          <Badge variant="outline">{deployment.pages ? "Pages" : "Workers"}</Badge>
          {selected ? <Badge>{t("Cloudflare Worker")}</Badge> : null}
        </CardTitle>
        <CardDescription className="font-mono text-[12px]">{host || "—"}</CardDescription>
      </CardHeader>
      <CardContent className="pt-0">
        {!deployment.ready ? <Note>{t("Setup incomplete. Retry or delete this deployment.")}</Note> : null}
        <div className="flex flex-wrap gap-2 pb-3">
          {deployment.ready ? (
            <Button disabled={busy} onClick={onConnect}>
              {t("Connect through this deployment")}
            </Button>
          ) : null}
          <Button
            variant="outline"
            disabled={busy}
            onClick={() => {
              if (!token.trim()) return onError(t("Paste the API token above to update or delete this deployment."));
              void run(async () => void (await workerUpdate(token, deployment.key, deployment.relay)));
            }}
          >
            {deployment.ready ? t("Update deployment") : t("Retry deployment")}
          </Button>
          <Button
            variant="outline"
            disabled={busy}
            onClick={() => {
              // Without a token Cloudflare cannot be asked, so only the record here can go.
              const remote = Boolean(token.trim());
              const question = remote
                ? t("Delete %1$s from Cloudflare? This removes its remote proxy. Disconnect the VPN first.").replace("%1$s", deployment.name)
                : t("Without the API token this only removes %1$s from this computer; it stays on Cloudflare. Remove it here?").replace("%1$s", deployment.name);
              if (!window.confirm(question)) return;
              void run(async () => {
                await (remote ? workerDelete(token, deployment.key) : workerForget(deployment.key));
                onDeleted();
              });
            }}
          >
            {t("Delete deployment")}
          </Button>
        </div>
        {deployment.ready ? (
          <Note>{t("TCP only. Connecting uses this Worker directly, changes the current connection method, and keeps your existing nodes and identity. Your network can see the Worker hostname.")}</Note>
        ) : null}

        {deployment.ready ? (
          <>
            <Separator className="mb-3" />
            <Field label={t("Custom domain · vpn.example.com")} value={domain} onChange={setDomain} disabled={busy} />
            <Note>{t("Use a domain in this Cloudflare account. Attach creates its route and DNS record; existing website records are kept. Certificate activation may take time. Detach returns to the deployment hostname.")}</Note>
            {deployment.domainPending ? (
              <Note>{t("Domain setup is incomplete. Retry or detach it; connections still use the deployment hostname.")}</Note>
            ) : null}
            <div className="flex flex-wrap gap-2 pb-3">
              <Button
                variant="outline"
                disabled={busy || !token.trim() || !domain.trim() || active}
                onClick={() => void run(async () => void (await workerAttachDomain(token, deployment.key, domain)))}
              >
                {t("Attach or retry custom domain")}
              </Button>
              {deployment.customDomain ? (
                <Button
                  variant="outline"
                  disabled={busy || !token.trim() || active}
                  onClick={() =>
                    void run(async () => {
                      await workerDetachDomain(token, deployment.key);
                      setDomain("");
                    })
                  }
                >
                  {t("Detach custom domain")}
                </Button>
              ) : null}
              {!deployment.pages ? (
                <Button
                  variant="outline"
                  disabled={busy || !token.trim()}
                  onClick={() => void run(async () => onUsage(await workerUsage(token, deployment.key)))}
                >
                  {t("Refresh Worker usage · last 24 hours")}
                </Button>
              ) : null}
            </div>
            {usage ? (
              <Note>
                {t("Requests over the last 24 hours — account: %1$d; this Worker: %2$d. Cloudflare analytics may be sampled.")
                  .replace("%1$d", String(usage[0]))
                  .replace("%2$d", String(usage[1]))}
              </Note>
            ) : null}
            <Separator className="mb-3" />
            <WorkerSettingsForm deployment={deployment} token={token} busy={busy} active={active} run={run} onError={onError} />
          </>
        ) : null}
      </CardContent>
    </Card>
  );
}

function WorkerSettingsForm({
  deployment,
  token,
  busy,
  active,
  run,
  onError,
}: {
  deployment: WorkerDeployment;
  token: string;
  busy: boolean;
  active: boolean;
  run: (action: () => Promise<void>) => Promise<void>;
  onError: (message: string) => void;
}) {
  const t = useT();
  const [expanded, setExpanded] = useState(false);
  const [draft, setDraft] = useState<WorkerOptions>(deployment.options);
  const [clean, setClean] = useState(deployment.options.cleanAddresses.join("\n"));
  const [ports, setPorts] = useState(deployment.options.ports.join(", "));
  const [cdn, setCdn] = useState(deployment.options.cdnAddresses.join("\n"));
  const [proxy, setProxy] = useState(
    [...new Set([...deployment.options.proxyIps, deployment.relay].filter(Boolean))].join("\n"),
  );
  const [interval, setInterval] = useState(String(deployment.options.probeInterval));
  const set = (patch: Partial<WorkerOptions>) => setDraft((current) => ({ ...current, ...patch }));
  const setFragment = (index: number, patch: Partial<WorkerFragment>) =>
    set({ fragments: draft.fragments.map((old, i) => (i === index ? { ...old, ...patch } : old)) });

  useEffect(() => {
    setDraft(deployment.options);
    setClean(deployment.options.cleanAddresses.join("\n"));
    setPorts(deployment.options.ports.join(", "));
    setCdn(deployment.options.cdnAddresses.join("\n"));
    setProxy([...new Set([...deployment.options.proxyIps, deployment.relay].filter(Boolean))].join("\n"));
    setInterval(String(deployment.options.probeInterval));
  }, [deployment]);

  const modes: Array<[WorkerMode, string]> = [
    ["NORMAL", t("Normal · Best Ping")],
    ["FRAGMENT", t("Fragment · Best Ping")],
    ["BROWSER", "Browser Dialer"],
  ];

  const save = () => {
    const portList = entries(ports).map(Number);
    const probe = Number(interval);
    if (portList.some((port) => !Number.isInteger(port)) || !Number.isInteger(probe)) {
      onError(t("Invalid Worker settings"));
      return;
    }
    const options: WorkerOptions = {
      ...draft,
      cleanAddresses: entries(clean),
      ports: portList,
      cdnAddresses: entries(cdn),
      proxyIps: entries(proxy),
      probeInterval: probe,
    };
    void run(async () => void (await workerSaveOptions(token, deployment.key, options)));
  };

  return (
    <div>
      <button
        type="button"
        aria-expanded={expanded}
        onClick={() => setExpanded(!expanded)}
        className="w-full rounded-md pb-3 text-left text-[13.5px] font-medium focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      >
        {expanded ? "▾ " : "▸ "}
        {t("Worker connection settings")}
      </button>
      {expanded ? (
        <div>
          <Row first title={t("Protocol")} help="VLESS · WebSocket · TLS">
            <span />
          </Row>
          <Note>{t("This Worker serves VLESS over WebSocket. VMess, Trojan and other server profiles belong in Proxy profiles.")}</Note>
          <div className="pb-3">
            <Seg value={draft.mode} options={modes} onChange={(mode) => !busy && set({ mode })} />
          </div>
          <Field label={t("Remote DNS · HTTPS or TCP URL")} value={draft.remoteDns} onChange={(remoteDns) => set({ remoteDns })} disabled={busy} />
          {draft.mode === "BROWSER" ? (
            <Note>{t("The app's built-in browser opens the secure WebSocket using its browser TLS stack. This mode uses the deployment domain on port 443; clean IPs, fingerprint, ECH, fragments and CDN settings apply to the other modes.")}</Note>
          ) : (
            <>
              <Field label={t("Clean IPs or domains · one per line")} value={clean} onChange={setClean} disabled={busy} multiline />
              <Field label={t("TLS ports · separated by commas")} value={ports} onChange={setPorts} disabled={busy} />
              <Note>{t("443, 8443, 2053, 2083, 2087, 2096. Best Ping tests the selected addresses and ports.")}</Note>
              <Field label={t("Best Ping interval · seconds, 10–300")} value={interval} onChange={setInterval} disabled={busy} />
              <Row title="TCP Fast Open">
                <Switch checked={draft.tcpFastOpen} disabled={busy} onCheckedChange={(tcpFastOpen) => set({ tcpFastOpen })} />
              </Row>
              <Row title={t("TLS fingerprint")}>
                <select
                  value={draft.fingerprint}
                  disabled={busy}
                  onChange={(event) => set({ fingerprint: event.target.value })}
                  className="h-9 rounded-md border border-input bg-background px-2 text-[13px] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                >
                  {FINGERPRINTS.map((fingerprint) => (
                    <option key={fingerprint} value={fingerprint}>
                      {fingerprint}
                    </option>
                  ))}
                </select>
              </Row>
              {draft.mode === "NORMAL" ? (
                <>
                  <Row title="TLS ECH">
                    <Switch checked={draft.ech} disabled={busy} onCheckedChange={(ech) => set({ ech })} />
                  </Row>
                  {draft.ech ? (
                    <Field label={t("ECH DNS · HTTPS or TCP URL")} value={draft.echDns} onChange={(echDns) => set({ echDns })} disabled={busy} />
                  ) : null}
                  <Row title={t("Custom CDN")}>
                    <Switch checked={draft.customCdn} disabled={busy} onCheckedChange={(customCdn) => set({ customCdn })} />
                  </Row>
                  {draft.customCdn ? (
                    <>
                      <Field label={t("Custom CDN addresses · one per line")} value={cdn} onChange={setCdn} disabled={busy} multiline />
                      <Field label={t("Custom CDN Host")} value={draft.cdnHost} onChange={(cdnHost) => set({ cdnHost })} disabled={busy} />
                      <Field label={t("Custom CDN TLS SNI")} value={draft.cdnSni} onChange={(cdnSni) => set({ cdnSni })} disabled={busy} />
                    </>
                  ) : null}
                  <Field label={t("Upstream TCP relay · host:port, optional")} value={draft.upstreamProxy} onChange={(upstreamProxy) => set({ upstreamProxy })} disabled={busy} />
                  <Note>{t("An additional way to reach Cloudflare. This is separate from the proxy IPs used by the Worker to reach destination websites.")}</Note>
                </>
              ) : null}
              {draft.mode === "FRAGMENT" ? (
                <>
                  <Note>{t("Lengths are bytes; delays are milliseconds. Enter ranges such as 100-200, 50-100. Fragment mode uses its own TLS connection, without ECH, custom CDN or the upstream relay.")}</Note>
                  {draft.fragments.map((fragment, index) => (
                    <div key={index} className="mb-3 rounded-md border border-border p-3">
                      <Field label={t("Packets · tlshello or a range such as 1-3")} value={fragment.packets} onChange={(packets) => setFragment(index, { packets })} disabled={busy} />
                      <Field label={t("Fragment lengths")} value={fragment.lengths} onChange={(lengths) => setFragment(index, { lengths })} disabled={busy} />
                      <Field label={t("Fragment delays")} value={fragment.delays} onChange={(delays) => setFragment(index, { delays })} disabled={busy} />
                      <Field label={t("Maximum split · optional range")} value={fragment.maxSplit} onChange={(maxSplit) => setFragment(index, { maxSplit })} disabled={busy} />
                      {draft.fragments.length > 1 ? (
                        <Button variant="outline" disabled={busy} onClick={() => set({ fragments: draft.fragments.filter((_, i) => i !== index) })}>
                          {t("Remove fragment entry")}
                        </Button>
                      ) : null}
                    </div>
                  ))}
                  {draft.fragments.length < 8 ? (
                    <div className="pb-3">
                      <Button variant="outline" disabled={busy} onClick={() => set({ fragments: [...draft.fragments, NEW_FRAGMENT] })}>
                        {t("Add fragment entry")}
                      </Button>
                    </div>
                  ) : null}
                </>
              ) : null}
            </>
          )}
          <Field label={t("Worker proxy IPs or domains · one per line")} value={proxy} onChange={setProxy} disabled={busy} multiline />
          <Field label={t("Fallback website · HTTPS URL, optional")} value={draft.fallbackUrl} onChange={(fallbackUrl) => set({ fallbackUrl })} disabled={busy} />
          <Note>{t("Disconnect this Worker before saving. Connection settings apply next time you connect. Changing proxy IPs or the fallback website also redeploys the Worker and needs the API token.")}</Note>
          <Button disabled={busy || active} onClick={save}>
            {t("Save Worker settings")}
          </Button>
        </div>
      ) : null}
    </div>
  );
}
