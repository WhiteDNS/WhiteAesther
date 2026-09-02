import { useEffect, useMemo, useRef, useState } from "react";
import { useT } from "@/core/useT";
import { CornerDownLeft, Search } from "lucide-react";
import { SETTINGS, type SectionId, searchSettings } from "./settingsIndex";

/**
 * Settings search.
 *
 * The header carried a "Search settings" box that only switched to Advanced,
 * which is worse than having no box at all: it names a thing the app does not
 * do. This is that box doing what it says.
 */
export function CommandPalette({
  open,
  onClose,
  onPick,
}: {
  open: boolean;
  onClose: () => void;
  onPick: (section: SectionId) => void;
}) {
  const t = useT();
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const input = useRef<HTMLInputElement>(null);
  const results = useMemo(() => searchSettings(query, t), [query, t]);

  useEffect(() => {
    if (!open) return;
    setQuery("");
    setActive(0);
    // Typing should start immediately; reaching for the mouse first defeats
    // the point of a keyboard shortcut.
    const focus = window.setTimeout(() => input.current?.focus(), 0);
    return () => window.clearTimeout(focus);
  }, [open]);

  useEffect(() => {
    setActive(0);
  }, [query]);

  if (!open) return null;

  const choose = (index: number) => {
    const entry = results[index];
    if (!entry) return;
    onPick(entry.section);
    onClose();
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center bg-background/70 pt-[12vh] backdrop-blur-sm"
      onClick={onClose}
      role="presentation"
    >
      <div
        className="surface w-full max-w-[540px] overflow-hidden rounded-xl border shadow-2xl"
        onClick={(event) => event.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-label="Search settings"
      >
        <div className="flex items-center gap-2.5 border-b px-3.5">
          <Search className="size-4 shrink-0 text-muted-foreground" />
          <input
            ref={input}
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Escape") onClose();
              if (event.key === "ArrowDown") {
                event.preventDefault();
                setActive((current) => Math.min(current + 1, results.length - 1));
              }
              if (event.key === "ArrowUp") {
                event.preventDefault();
                setActive((current) => Math.max(current - 1, 0));
              }
              if (event.key === "Enter") {
                event.preventDefault();
                choose(active);
              }
            }}
            placeholder={t("Search settings — try dns, kill switch, scan…")}
            className="h-12 w-full bg-transparent text-[14px] outline-none placeholder:text-muted-foreground"
          />
        </div>

        {results.length ? (
          <ul className="max-h-[320px] overflow-y-auto p-1.5">
            {results.map((entry, index) => (
              <li key={entry.label}>
                <button
                  type="button"
                  onMouseEnter={() => setActive(index)}
                  onClick={() => choose(index)}
                  className={[
                    "flex w-full items-center gap-3 rounded-lg px-2.5 py-2 text-start",
                    index === active ? "bg-primary/[0.11] text-foreground" : "text-muted-foreground",
                  ].join(" ")}
                >
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-[13.5px] font-medium text-foreground">
                      {t(entry.label)}
                    </span>
                    <span className="block truncate text-[11.5px] text-muted-foreground">
                      {t(entry.where)}
                    </span>
                  </span>
                  {index === active ? (
                    <CornerDownLeft className="size-3.5 shrink-0 text-primary" />
                  ) : null}
                </button>
              </li>
            ))}
          </ul>
        ) : (
          <p className="px-4 py-6 text-center text-[13px] text-muted-foreground">
            {t("Nothing matches")} “{query}”.
          </p>
        )}

        <div className="flex items-center justify-between border-t px-3.5 py-2 text-[11px] text-muted-foreground">
          <span>{t("Enter opens · ↑↓ moves · Esc closes")}</span>
          <span>{results.length} of {SETTINGS.length} settings</span>
        </div>
      </div>
    </div>
  );
}
