/**
 * Persian and English, and the direction each is read in.
 *
 * Keyed by the English sentence rather than by an invented identifier
 * (`simple.headline.connected`). Two reasons. A key missing from the dictionary
 * falls back to itself, which is a correct English interface rather than a
 * screen full of dotted identifiers — so a half-finished translation degrades
 * into the thing we started with. And a translator reads the source sentence at
 * the point of use instead of chasing a name through two files.
 *
 * The cost is that editing an English string silently orphans its translation.
 * A test walks the source tree and fails on any orphan, which turns that from a
 * thing someone notices in production into a thing CI says out loud.
 *
 * No i18n library. For one language pair, react-i18next is a dependency and a
 * bundle for interpolation, plurals, namespaces and loaders we do not use —
 * this is a lookup and a listener.
 */

export type Language = "en" | "fa";

/** Right to left is a property of the language, so it is decided here. */
export const DIRECTION: Record<Language, "ltr" | "rtl"> = { en: "ltr", fa: "rtl" };

const STORAGE_KEY = "whiteaesther.language";

/**
 * Persian for everything a person meets before they ever open Advanced.
 *
 * Translated for sense, not word by word. "You're through" is an English idiom
 * that becomes nonsense carried across literally, and a status line nobody
 * understands is worse than an English one they can paste into a search.
 */
const FA: Record<string, string> = {
  // -- the shell -------------------------------------------------------------
  "Search settings": "جستجوی تنظیمات",
  Simple: "ساده",
  Advanced: "پیشرفته",
  "Advanced settings": "تنظیمات پیشرفته",
  Language: "زبان",
  "Traffic is blocked, not broken": "ترافیک مسدود شده، نه خراب",
  "The tunnel is down and your system proxy still points at it, so nothing leaves in the clear.":
    "تونل قطع است و پروکسی سیستم هنوز به آن اشاره می‌کند، پس هیچ چیزی بدون رمز خارج نمی‌شود.",
  "Restore my connection": "اتصال من را برگردان",
  "Restarted with permission": "با دسترسی لازم دوباره اجرا شد",
  "Full tunnel is ready. Press Connect when you want it.":
    "تونل کامل آماده است. هر وقت خواستید، اتصال را بزنید.",
  "Action failed": "انجام نشد",

  // -- the update notice -----------------------------------------------------
  "Get it": "دریافت",
  "Dismiss this update": "بستن این اطلاع",
  "is available": "منتشر شده است",
  "You are running": "نسخهٔ فعلی شما",
  "Opening this takes you to the download page.": "با باز کردن این، به صفحهٔ دانلود می‌روید.",
  "Connection restored": "اتصال برگردانده شد",
  "Your system proxy has been put back.": "پروکسی سیستم به حالت قبل برگشت.",

  // -- the orb and the headline ---------------------------------------------
  Connected: "متصل",
  Searching: "در حال جستجو",
  Stopped: "متوقف",
  "Tap to connect": "برای اتصال بزنید",
  "You're through": "راه باز شد",
  "Testing paths out": "در حال آزمودن راه‌های خروج",
  "Nothing got out": "هیچ راهی باز نشد",
  "Ready when you are": "هر وقت آماده بودید",
  "Testing paths out of this network.": "راه‌های خروج از این شبکه آزموده می‌شوند.",
  "Every path was refused.": "همهٔ راه‌ها بسته بودند.",
  "WhiteAesther finds a route that works here.":
    "وایت‌آستر خودش مسیری پیدا می‌کند که اینجا کار کند.",

  // -- the buttons -----------------------------------------------------------
  Connect: "اتصال",
  Disconnect: "قطع اتصال",
  Stop: "توقف",
  "Aether core not found": "هستهٔ Aether پیدا نشد",
  "Try again with Stealth": "دوباره با حالت مخفی",
  "Speed test": "تست سرعت",
  "Speed test failed": "تست سرعت انجام نشد",
  "Measuring…": "در حال اندازه‌گیری…",
  "Build a report": "ساخت گزارش",
  "Open Advanced": "باز کردن پیشرفته",

  // -- what the connection is doing -----------------------------------------
  Edge: "دروازه",
  Transport: "پروتکل",
  Latency: "تأخیر",
  Uptime: "مدت اتصال",
  "Round-trip through the tunnel": "زمان رفت و برگشت از تونل",
  "Measured every 5 s through the tunnel. Last 80 seconds.":
    "هر ۵ ثانیه از داخل تونل اندازه‌گیری می‌شود. ۸۰ ثانیهٔ اخیر.",
  "Taking the first measurement…": "در حال گرفتن اولین اندازه…",
  min: "کمینه",
  avg: "میانگین",
  max: "بیشینه",
  loss: "از دست‌رفته",
  now: "اکنون",

  // -- what the outside world sees ------------------------------------------
  "What websites see": "چیزی که سایت‌ها می‌بینند",
  "Checking…": "در حال بررسی…",
  "Through your node": "از نود شما",
  "Through the tunnel": "از تونل",
  "Not through the tunnel": "خارج از تونل",

  // -- the two switches ------------------------------------------------------
  "Keep me connected": "اتصال را نگه دار",
  "Reconnect automatically if the route drops": "اگر مسیر قطع شد، خودکار دوباره وصل شود",
  "Block traffic if the tunnel drops": "اگر تونل قطع شد، ترافیک را مسدود کن",
  "Apps fail closed. Disconnect to put the proxy back.":
    "برنامه‌ها به‌جای نشت، قطع می‌شوند. برای بازگرداندن پروکسی، اتصال را قطع کنید.",
  "Apps fail closed instead of leaking": "برنامه‌ها به‌جای نشت کردن، قطع می‌شوند",

  // -- while it is searching -------------------------------------------------
  "What it is trying": "کاری که در حال انجام است",
  "Device identity ready": "شناسهٔ دستگاه آماده شد",
  "Retries alternate the two MASQUE transports on their own. Nothing to do.":
    "تلاش‌های بعدی خودشان بین دو پروتکل MASQUE جابه‌جا می‌شوند. کاری لازم نیست.",

  // -- before it starts ------------------------------------------------------
  "What will happen": "چه اتفاقی می‌افتد",
  "The route is found for you. These are the settings it will start from.":
    "مسیر برای شما پیدا می‌شود. اتصال با این تنظیمات آغاز خواهد شد.",
  Protocol: "پروتکل",
  "Search depth": "عمق جستجو",
  Addresses: "نوع آدرس",
  "IPv4 and IPv6": "IPv4 و IPv6",
  Gateway: "دروازه",
  "found automatically": "خودکار پیدا می‌شود",
  pinned: "ثابت‌شده",
  "Local proxy": "پروکسی محلی",

  // -- when nothing worked ---------------------------------------------------
  "Three things to try, in order": "سه کار را به ترتیب امتحان کنید",
  Stealth: "مخفی",
  Aggressive: "تهاجمی",
  "IPv4 only": "فقط IPv4",

  // -- how far the tunnel reaches -------------------------------------------
  "This app only": "فقط همین برنامه",
  "Whole machine": "کل دستگاه",
  "Full tunnel": "تونل کامل",
  "Local proxy on {address}": "پروکسی محلی روی {address}",
  "Sets your system proxy": "پروکسی سیستم را تنظیم می‌کند",
  "Every app, even ones that ignore proxies":
    "همهٔ برنامه‌ها، حتی آن‌هایی که پروکسی را نادیده می‌گیرند",
  "Your system proxy is set, and will be put back when you disconnect.":
    "پروکسی سیستم تنظیم شده و با قطع اتصال به حالت قبل برمی‌گردد.",
  "Every app is captured through a network device, including the ones that ignore proxy settings.":
    "همهٔ برنامه‌ها از طریق یک کارت شبکه گرفته می‌شوند، حتی آن‌هایی که تنظیمات پروکسی را نادیده می‌گیرند.",

  // Split around the address rather than templated whole: Persian puts the
  // verb last, so one string with a {placeholder} would have pinned English
  // word order into the translation.
  "Point apps at": "برنامه‌ها را به آدرس",
  "to use it.": "وصل کنید",

  "or press": "یا بزنید",
  "no reply": "بی‌پاسخ",
  "testing gateways": "در حال آزمودن دروازه‌ها",
  Attempt: "تلاش",
  of: "از",
  "Retries alternate MASQUE H2 and H3 automatically, up to":
    "تلاش‌های بعدی خودکار بین MASQUE H2 و H3 جابه‌جا می‌شوند، تا",
  "attempts.": "بار.",
  "Switch search depth to": "عمق جستجو را بگذارید روی",
  "quieter probing, slower to connect": "آزمودن کم‌سروصداتر، اتصال کندتر",
  "Set addresses to": "نوع آدرس را بگذارید روی",
  "if this network handles IPv6 badly": "اگر این شبکه با IPv6 مشکل دارد",
  "Turn obfuscation up to": "مبهم‌سازی را ببرید روی",

  // The stored profile values the Idle card prints back. Translated because
  // they are shown to the reader, not because anything matches on them.
  turbo: "پرسرعت",
  balanced: "متعادل",
  thorough: "دقیق",
  stealth: "مخفی",
  ironclad: "حداکثری",

  // -- the command palette ---------------------------------------------------
  "Search settings — try dns, kill switch, scan…":
    "جستجوی تنظیمات — مثلاً dns یا kill switch یا scan…",
  "Nothing matches": "چیزی پیدا نشد",
};

const DICTIONARIES: Record<Language, Record<string, string>> = { en: {}, fa: FA };

/**
 * The English sentence, or its translation when one exists.
 *
 * An untranslated key returns itself, so a gap reads as English rather than as
 * a broken label.
 */
export function translate(language: Language, key: string): string {
  const value = DICTIONARIES[language][key];
  return value === undefined ? key : value;
}

/** Every key that has been given a Persian translation. */
export function translatedKeys(): string[] {
  return Object.keys(FA);
}

// ------------------------------------------------------- the live preference

function load(): Language {
  try {
    const stored = window.localStorage.getItem(STORAGE_KEY);
    if (stored === "fa" || stored === "en") return stored;
    // Nothing chosen yet: follow the machine. Someone whose computer is already
    // in Persian should not have to find a menu to be spoken to in Persian.
    return window.navigator.language?.toLowerCase().startsWith("fa") ? "fa" : "en";
  } catch {
    return "en";
  }
}

let current: Language = typeof window === "undefined" ? "en" : load();
const listeners = new Set<() => void>();

export function getLanguage(): Language {
  return current;
}

/** Applies the language to the document, so CSS and the browser agree with us. */
export function applyLanguage(language: Language): void {
  if (typeof document === "undefined") return;
  document.documentElement.lang = language;
  document.documentElement.dir = DIRECTION[language];
}

export function setLanguage(next: Language): void {
  if (next === current) return;
  current = next;
  try {
    window.localStorage.setItem(STORAGE_KEY, next);
  } catch {
    // A preference that cannot be stored still applies to this session.
  }
  applyLanguage(next);
  for (const listener of listeners) listener();
}

export function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}
