import { useCallback, useEffect, useState } from "react";
import { Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import {
  type IgnoredBecause,
  type RuleAction,
  type RuleList,
  type RuleMatch,
  deleteRuleList,
  importRuleList,
  matchRule,
  ruleLists,
  setRuleListEnabled,
} from "@/core/api";
import { useT } from "@/core/useT";

const REASONS: Record<IgnoredBecause, string> = {
  unsupported: "no equivalent here",
  needsDatabase: "needs a geosite or geoip database",
  tooBroad: "too broad",
  duplicate: "duplicate",
  overLimit: "over the 5,000-rule limit",
};

/**
 * Lists imported from local files, each on, off or deleted on its own, and a
 * box that says which rule a destination meets. Any change to the lists calls
 * `onChanged`, which reconnects a live session so the engines read them again.
 */
export function ImportedRuleLists({
  routeBlock,
  routeDirect,
  onChanged,
  onToast,
}: {
  routeBlock: string;
  routeDirect: string;
  onChanged: () => void;
  onToast: (title: string, message: string, error?: boolean) => void;
}) {
  const t = useT();
  const [lists, setLists] = useState<RuleList[]>([]);
  const [busy, setBusy] = useState(false);
  const [destination, setDestination] = useState("");
  const [match, setMatch] = useState<RuleMatch | null>(null);

  const refresh = useCallback(async () => setLists(await ruleLists()), []);
  useEffect(() => {
    void refresh().catch(() => undefined);
  }, [refresh]);

  const fail = (error: unknown) => onToast(t("Action failed"), t(error instanceof Error ? error.message : String(error)), true);

  const run = async (action: () => Promise<void>) => {
    setBusy(true);
    try {
      await action();
      await refresh();
    } catch (error) {
      fail(error);
    } finally {
      setBusy(false);
    }
  };

  const importList = (action: RuleAction) =>
    run(async () => {
      const outcome = await importRuleList(action);
      if (outcome.cancelled) return;
      const left = (Object.entries(outcome.ignored) as Array<[IgnoredBecause, number]>)
        .filter(([, count]) => count > 0)
        .map(([reason, count]) => `${count} ${t(REASONS[reason])}`);
      const summary = t("{n} rules imported.").replace("{n}", String(outcome.accepted))
        + (left.length ? ` ${t("Left out:")} ${left.join(", ")}.` : "");
      onToast(outcome.list ? t("Rule list imported") : t("Nothing imported"), summary, !outcome.list);
      if (outcome.list) onChanged();
    });

  // Recomputed as the rules change, so the answer never describes old rules.
  useEffect(() => {
    if (!destination.trim()) {
      setMatch(null);
      return;
    }
    let live = true;
    void matchRule(destination, routeBlock, routeDirect)
      .then((answer) => live && setMatch(answer))
      .catch(() => undefined);
    return () => {
      live = false;
    };
  }, [destination, routeBlock, routeDirect, lists]);

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <Label className="text-[13.5px]">{t("Imported lists")}</Label>
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" size="sm" disabled={busy} onClick={() => void importList("block")}>
            {t("Import never-send list")}
          </Button>
          <Button variant="outline" size="sm" disabled={busy} onClick={() => void importList("direct")}>
            {t("Import bypass list")}
          </Button>
        </div>
      </div>
      <p className="text-[12.5px] text-muted-foreground">
        {t("From a local file: plain domains, hosts files, addresses and CIDRs, or Clash rule lists. Up to 5,000 rules a list and 10,000 across the lists that are on.")}
      </p>
      {lists.length ? (
        <ul className="flex flex-col divide-y rounded-lg border">
          {lists.map((list) => (
            <li key={list.id} className="flex items-center gap-3 px-3 py-2">
              <Switch
                checked={list.enabled}
                disabled={busy}
                aria-label={list.name}
                onCheckedChange={(enabled) => void run(async () => {
                  await setRuleListEnabled(list.id, enabled);
                  onChanged();
                })}
              />
              <div className="min-w-0 flex-1">
                <div className="truncate text-[13px] font-medium">{list.name}</div>
                <div className="text-[12px] text-muted-foreground">
                  {t(list.action === "block" ? "Never send" : "Bypass the tunnel")} · {t("{n} rules").replace("{n}", String(list.count))}
                </div>
              </div>
              <Button
                variant="ghost"
                size="sm"
                disabled={busy}
                aria-label={t("Delete {name}").replace("{name}", list.name)}
                onClick={() => void run(async () => {
                  await deleteRuleList(list.id);
                  if (list.enabled) onChanged();
                })}
              >
                <Trash2 className="size-4" />
              </Button>
            </li>
          ))}
        </ul>
      ) : null}
      <div className="flex flex-col gap-2">
        <Label className="text-[13.5px]" htmlFor="rule-match">{t("Which rule does this destination meet?")}</Label>
        <Input
          id="rule-match"
          className="font-mono text-[12.5px]"
          placeholder="www.example.com"
          value={destination}
          onChange={(event) => setDestination(event.target.value)}
        />
        {match ? (
          <p className="text-[12.5px] text-muted-foreground">
            {match.action === "block"
              ? t("Never sent, by {rule}").replace("{rule}", match.rule ?? "")
              : match.action === "direct"
                ? t("Bypasses the tunnel, by {rule}").replace("{rule}", match.rule ?? "")
                : t("Goes through the tunnel: no rule names it.")}
            {" "}
            {t("Worked out from the rules alone, without looking the name up.")}
          </p>
        ) : null}
      </div>
    </div>
  );
}
