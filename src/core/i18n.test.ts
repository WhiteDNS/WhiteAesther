import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { DIRECTION, translate, translatedKeys } from "./i18n.ts";

test("an untranslated key reads as English, not as a broken label", () => {
  // The whole point of keying on the sentence: a gap in the dictionary is the
  // interface we already had, not "simple.headline.connected" on screen.
  assert.equal(translate("fa", "Something nobody has translated yet"), "Something nobody has translated yet");
  assert.equal(translate("en", "Tap to connect"), "Tap to connect");
  assert.equal(translate("fa", "Tap to connect"), "برای اتصال بزنید");
});

test("Persian is right to left and English is not", () => {
  // Read by applyLanguage to set the document direction; getting this backwards
  // mirrors the entire interface.
  assert.equal(DIRECTION.fa, "rtl");
  assert.equal(DIRECTION.en, "ltr");
});

test("no translation is left as an empty string", () => {
  // An empty value would silently blank a label rather than falling back,
  // because "" is a defined value.
  for (const key of translatedKeys()) {
    const value = translate("fa", key);
    assert.ok(value.trim().length > 0, `empty translation for: ${key}`);
    assert.notEqual(value, key, `untranslated placeholder left for: ${key}`);
  }
});

/** Every .ts/.tsx file under src, so the check cannot miss a new component. */
function sourceFiles(directory: string, found: string[] = []): string[] {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) sourceFiles(path, found);
    else if (/\.tsx?$/.test(entry.name) && !entry.name.endsWith(".test.ts")) found.push(path);
  }
  return found;
}

test("every string marked for translation has one", () => {
  // The other half of the drift check. Wrapping a string in t() and forgetting
  // to translate it is silent -- the fallback shows English and looks fine to
  // anyone reading in English, which is everyone who works on this.
  const missing = new Set<string>();
  for (const path of sourceFiles(join(import.meta.dirname, ".."))) {
    const source = readFileSync(path, "utf8");
    for (const [, key] of source.matchAll(/\bt\(\s*"((?:[^"\\]|\\.)*)"\s*\)/g)) {
      // Skip the ones fed a variable at runtime, like t(option.title): those
      // are checked by the entries they resolve to, which are in the dictionary
      // as plain strings.
      if (translate("fa", key) === key) missing.add(key);
    }
  }
  assert.deepEqual([...missing], [], `marked for translation but not translated: ${[...missing].join(" | ")}`);
});

test("every Persian entry still matches a string in the source", () => {
  // Keying on the English sentence buys a readable fallback and costs this:
  // editing the English silently orphans its translation, and the screen goes
  // back to English with nobody the wiser. This is the check that says so.
  const source = sourceFiles(join(import.meta.dirname, ".."))
    .filter((path) => !path.endsWith("i18n.ts"))
    .map((path) => readFileSync(path, "utf8"))
    .join("\n");

  const orphans = translatedKeys().filter((key) => !source.includes(key));
  assert.deepEqual(orphans, [], `translated strings no longer present in the interface: ${orphans.join(" | ")}`);
});
