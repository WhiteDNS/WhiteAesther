import { useCallback, useSyncExternalStore } from "react";
import { type Language, getLanguage, subscribe, translate } from "./i18n";

/**
 * The current language, kept in step across every component that asks.
 *
 * A module-level store rather than a context provider: the language is one
 * value for the whole window, and threading a provider through would add a
 * wrapper to every test that renders a component in isolation.
 */
export function useLanguage(): Language {
  return useSyncExternalStore(subscribe, getLanguage, () => "en" as const);
}

/** `t("Tap to connect")` — the English sentence in, the reader's language out. */
export function useT(): (key: string) => string {
  const language = useLanguage();
  return useCallback((key: string) => translate(language, key), [language]);
}
