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

  // -- the Advanced screen ---------------------------------------------------
  // Reached through the primitives in panels.tsx rather than by a call at each
  // use site, so a control added later is translated by construction.
  "Settings sections": "بخش‌های تنظیمات",
  "Core": "هسته",
  "WhiteAesther": "وایت‌آستر",
  "This application. Source at github.com/WhiteDNS/WhiteAesther": "همین برنامه. کد منبع در github.com/WhiteDNS/WhiteAesther",
  "The connection engine, shipped as a binary and run by this app. Aether 1.8.0": "موتور اتصال، که به‌صورت یک فایل اجرایی همراه برنامه می‌آید و توسط آن اجرا می‌شود. Aether 1.8.0",
  "The second hop behind Exit chain, run as a separate program. Source at github.com/MetaCubeX/mihomo at tag v1.19.30": "پرش دوم پشت زنجیرهٔ خروج، که به‌عنوان یک برنامهٔ جدا اجرا می‌شود. کد منبع در github.com/MetaCubeX/mihomo، تگ v1.19.30",
  "Iran routing lists": "لیست‌های مسیریابی ایران",
  "The addresses and domains behind “Iranian sites bypass the tunnel”, bundled as data. Source at github.com/Chocolate4U/Iran-clash-rules": "آدرس‌ها و دامنه‌های پشت گزینهٔ «سایت‌های ایرانی از تونل خارج شوند»، که به‌صورت داده همراه برنامه‌اند. منبع: github.com/Chocolate4U/Iran-clash-rules",
  "Deeper searches take longer but survive stricter filtering.": "جستجوی عمیق‌تر بیشتر طول می‌کشد ولی از فیلترینگ سخت‌گیرتر عبور می‌کند.",
  "Turn off IPv6 where the network handles it badly.": "در شبکه‌هایی که IPv6 را درست هندل نمی‌کنند، خاموشش کنید.",
  "Reuse the last working edge": "استفادهٔ دوباره از آخرین دروازهٔ سالم",
  "Verify the cached gateway before scanning fresh.": "قبل از جستجوی تازه، دروازهٔ ذخیره‌شده را بررسی می‌کند.",
  "End-to-end data check": "بررسی عبور واقعی داده",
  "Expose the proxy only after a real tunnelled request succeeds.": "پروکسی فقط بعد از موفق شدن یک درخواست واقعی از داخل تونل، در دسترس قرار می‌گیرد.",
  "Resource profile": "میزان مصرف منابع",
  "How much concurrency the core gives the scan.": "هسته چقدر همزمانی به جستجو اختصاص می‌دهد.",
  "Validation deadline": "مهلت اعتبارسنجی",
  "sec": "ثانیه",
  "Startup deadline": "مهلت راه‌اندازی",
  "Reconnect delay": "فاصلهٔ اتصال مجدد",
  "Split the TLS opening": "تکه‌تکه کردن شروع TLS",
  "Fragment size": "اندازهٔ تکه",
  "Bytes per write, or a range like 16-32.": "تعداد بایت در هر نوبت نوشتن، یا یک بازه مثل 16-32.",
  "Fragment delay": "فاصلهٔ بین تکه‌ها",
  "Milliseconds between writes, or a range.": "میلی‌ثانیه بین هر نوبت نوشتن، یا یک بازه.",
  "Obfuscation profile": "پروفایل مبهم‌سازی",
  "Padding that makes tunnel traffic harder to fingerprint.": "پرکننده‌ای که تشخیص الگوی ترافیک تونل را سخت‌تر می‌کند.",
  "Try other obfuscation profiles": "امتحان کردن پروفایل‌های دیگر مبهم‌سازی",
  "On WireGuard, fall back through the other profiles when one finds nothing.": "روی WireGuard، اگر یک پروفایل چیزی پیدا نکرد، بقیه را هم امتحان می‌کند.",
  "WireGuard keepalive": "زنده‌نگه‌داری WireGuard",
  "How often to hold the UDP mapping open. Zero leaves it to the engine.": "هر چند وقت یک بار نگاشت UDP باز نگه داشته شود. صفر یعنی تصمیمش با موتور.",
  "Match domain rules on sniffed names": "تطبیق قوانین دامنه با نام استخراج‌شده",
  "Reads the host name from the first bytes of a connection, so rules written as domains still match when a program connects to a bare address. Off, those rules only match when a name was supplied.": "نام میزبان را از بایت‌های اول اتصال می‌خواند، پس قوانینی که به‌صورت دامنه نوشته شده‌اند وقتی برنامه‌ای مستقیم به یک آدرس وصل می‌شود هم تطبیق پیدا می‌کنند. خاموش که باشد، آن قوانین فقط وقتی کار می‌کنند که نام داده شده باشد.",
  "Register again if the identity is refused": "ثبت‌نام مجدد در صورت رد شدن شناسه",
  "Cloudflare sometimes stops accepting a saved device, and the handshake then succeeds while nothing passes. Off, the refusal is reported and the identity kept — which is what you want while diagnosing an account, and not otherwise.": "کلادفلر گاهی یک دستگاه ذخیره‌شده را دیگر قبول نمی‌کند، و آن وقت دست‌دادن موفق می‌شود ولی هیچ چیزی رد نمی‌شود. خاموش که باشد، رد شدن گزارش می‌شود و شناسه نگه داشته می‌شود — که همان چیزی است که موقع عیب‌یابی یک حساب می‌خواهید، و در بقیهٔ مواقع نه.",
  "off, auto, or base64": "off یا auto یا base64",
  "Hides the hostname where the upstream supports it.": "جایی که سرور بالادست پشتیبانی کند، نام میزبان را پنهان می‌کند.",
  "TLS groups": "گروه‌های TLS",
  "Core default": "پیش‌فرض هسته",
  "Key exchange groups to offer, comma separated.": "گروه‌های تبادل کلید که پیشنهاد می‌شوند، جداشده با کاما.",
  "Dial through a local proxy": "اتصال از طریق یک پروکسی محلی",
  "The endpoint search goes through it too, so it never reveals the address the tunnel hides.": "جستجوی دروازه هم از همین رد می‌شود، پس هیچ‌وقت آدرسی را که تونل پنهان می‌کند لو نمی‌دهد.",
  "How the gateway is chosen": "روش انتخاب دروازه",
  "Custom first spends one attempt on your address before searching. Custom only never searches.": "«اول دستی» یک تلاش را صرف آدرس شما می‌کند و بعد جستجو را شروع می‌کند. «فقط دستی» اصلاً جستجو نمی‌کند.",
  "Address": "آدرس",
  "HTTP/2 gateway": "دروازهٔ HTTP/2",
  "Automatic · IP:port": "خودکار · IP:port",
  "WireGuard endpoint": "نقطهٔ اتصال WireGuard",
  "Set the system proxy while connected": "تنظیم پروکسی سیستم در زمان اتصال",
  "Search again when a route drops. Off, a dead session stays dead, which is what you want while testing a network.": "وقتی مسیری قطع شد دوباره جستجو می‌کند. خاموش که باشد، نشست قطع‌شده قطع می‌ماند — که موقع تست یک شبکه همان را می‌خواهید.",
  "Applications fail rather than send traffic in the clear. Until a route comes back or you disconnect, this machine has no working proxy.": "برنامه‌ها به‌جای فرستادن ترافیک بدون رمز، خطا می‌دهند. تا وقتی مسیری برنگردد یا خودتان قطع نکنید، این دستگاه پروکسی سالمی ندارد.",
  "Proxy address": "آدرس پروکسی",
  "Where the SOCKS5 listener binds.": "جایی که شنوندهٔ SOCKS5 روی آن بالا می‌آید.",
  "DNS resolvers": "سرورهای DNS",
  "One to eight addresses, comma separated.": "یک تا هشت آدرس، جداشده با کاما.",
  "Iranian sites bypass the tunnel": "سایت‌های ایرانی از تونل خارج شوند",
  "Filtering only applies to traffic that looks like it left Iran, so these sites gain nothing from the tunnel and only pay for the exit's bandwidth. The list ships with the app and is not fetched.": "فیلترینگ فقط روی ترافیکی اعمال می‌شود که به‌نظر از ایران خارج شده، پس این سایت‌ها از تونل چیزی به دست نمی‌آورند و فقط پهنای باند نود خروج را مصرف می‌کنند. لیست همراه خود برنامه می‌آید و دانلود نمی‌شود.",
  "Never send": "هرگز فرستاده نشود",
  "Bypass the tunnel": "خارج از تونل",
  "Rules file": "فایل قوانین",
  "Optional absolute path": "مسیر کامل، اختیاری",
  "Read in addition to the rules above.": "علاوه بر قوانین بالا خوانده می‌شود.",
  "Share this connection on my network": "اشتراک این اتصال روی شبکهٔ من",
  "Port": "پورت",
  "Typed into the other device.": "همین را در دستگاه دیگر وارد می‌کنید.",
  "Username": "نام کاربری",
  "Optional.": "اختیاری.",
  "Password": "رمز عبور",
  "Team": "تیم",
  "team name": "نام تیم",
  "Email": "ایمیل",
  "Access client ID": "شناسهٔ کلاینت Access",
  "Access client secret": "کلید مخفی کلاینت Access",
  "Existing token": "توکن موجود",
  "Skips sign-in when you already hold one.": "اگر از قبل توکن دارید، مرحلهٔ ورود رد می‌شود.",
  "Send web traffic to Gateway": "فرستادن ترافیک وب به Gateway",
  "Applies the enrolled organisation's policy. Adds a hop, and permits its logging.": "سیاست سازمان ثبت‌شده را اعمال می‌کند. یک پرش اضافه می‌کند و اجازهٔ ثبت وقایع آن را می‌دهد.",
  "Profile name": "نام پروفایل",
  "Shown in reports so you can tell saved setups apart.": "در گزارش‌ها نمایش داده می‌شود تا تنظیمات ذخیره‌شده را از هم تشخیص دهید.",
  "Core executable": "فایل اجرایی هسته",
  "Auto-detect": "تشخیص خودکار",
  "Log detail": "جزئیات لاگ",
  "Connection state is read from info-level output, so info is the floor.": "وضعیت اتصال از خروجی سطح info خوانده می‌شود، پس info کف مجاز است.",
  "App and engine version": "نسخهٔ برنامه و موتور",
  "Always included — a report without it cannot be read.": "همیشه هست — گزارشی بدون آن قابل خواندن نیست.",
  "Operating system": "سیستم‌عامل",
  "Connection settings": "تنظیمات اتصال",
  "No Zero Trust credentials and no pinned address — only whether one is set.": "بدون اطلاعات ورود Zero Trust و بدون آدرس ثابت‌شده — فقط اینکه تنظیم شده یا نه.",
  "What the core and the supervisor did.": "کاری که هسته و ناظر انجام داده‌اند.",
  "Replace IP addresses": "جایگزینی آدرس‌های IP",
  "Swaps them for placeholders. Most problems can still be diagnosed.": "آن‌ها را با جای‌نگهدار عوض می‌کند. بیشتر مشکلات هنوز قابل تشخیص می‌مانند.",
  "both": "هر دو",
  "auto": "خودکار",
  "low": "کم",
  "medium": "متوسط",
  "high": "زیاد",
  "off": "خاموش",
  "light": "سبک",
  "firewall": "فایروال",
  "gfw": "GFW",
  "aggressive": "تهاجمی",
  "error": "خطا",
  "warn": "هشدار",
  "info": "اطلاعات",
  "debug": "اشکال‌زدایی",
  "trace": "ردیابی",
  "Route through a second hop": "عبور از یک پرش دوم",
  "Every node is dialled from inside the tunnel, so this network only ever sees Cloudflare.": "هر نود از داخل تونل شماره‌گیری می‌شود، پس این شبکه فقط کلادفلر را می‌بیند.",
  "Dial nodes through the tunnel": "شماره‌گیری نودها از داخل تونل",
  "Round-trip through the tunnel over the last eighty seconds": "زمان رفت و برگشت از تونل در هشتاد ثانیهٔ اخیر",

  // -- section headings, buttons and the paragraphs between them ---------
  // Reached through the primitives in panels.tsx rather than by a call at each
  // use site, so a control added later is translated by construction.
  "Retries alternate the two MASQUE transports automatically.": "تلاش‌های بعدی خودکار بین دو پروتکل MASQUE جابه‌جا می‌شوند.",
  "Search": "جستجو",
  "Anti-blocking": "ضد مسدودسازی",
  "Both cost a little on a healthy network and only matter on a filtered one.": "هر دو روی شبکهٔ سالم کمی هزینه دارند و فقط روی شبکهٔ فیلترشده به کار می‌آیند.",
  "Obfuscation applies to WireGuard; the TLS options are MASQUE H2 only.": "مبهم‌سازی مربوط به WireGuard است؛ گزینه‌های TLS فقط روی MASQUE H2 کار می‌کنند.",
  "Defeats filtering that reads only the first packet.": "فیلترینگی را که فقط بستهٔ اول را می‌خواند دور می‌زند.",
  "MASQUE H2 only — has no effect on the selected protocol.": "فقط MASQUE H2 — روی پروتکل انتخاب‌شده اثری ندارد.",
  "Pinned endpoint": "دروازهٔ ثابت‌شده",
  "One attempt goes here; if it fails the core searches instead and says so.": "یک تلاش به این آدرس می‌رود؛ اگر شکست بخورد، هسته جستجو را شروع می‌کند و همین را می‌گوید.",
  "Every attempt goes here. Nothing else is tried.": "همهٔ تلاش‌ها به این آدرس می‌روند. هیچ چیز دیگری امتحان نمی‌شود.",
  "A saved address is kept but not used while this is Automatic.": "آدرس ذخیره‌شده نگه داشته می‌شود ولی تا وقتی این گزینه روی خودکار است، استفاده نمی‌شود.",
  "Per-protocol overrides": "تنظیم جداگانه برای هر پروتکل",
  "Left empty, each protocol uses the pinned endpoint above or its own search.": "اگر خالی بماند، هر پروتکل از دروازهٔ ثابت بالا یا جستجوی خودش استفاده می‌کند.",
  "Reach": "دامنهٔ پوشش",
  "Local proxy and DNS": "پروکسی محلی و DNS",
  "Routing rules": "قوانین مسیریابی",
  "Blocked first, then direct; everything left over enters the tunnel. One rule per line.": "اول مسدودها، بعد مستقیم‌ها؛ هر چه بماند وارد تونل می‌شود. هر خط یک قانون.",
  "Share with other devices": "اشتراک با دستگاه‌های دیگر",
  "The port is opened while connected and closed when you disconnect.": "پورت در زمان اتصال باز می‌شود و با قطع اتصال بسته می‌شود.",
  "Connect first — there is nothing to share until the tunnel is carrying traffic.": "اول وصل شوید — تا وقتی تونل ترافیکی حمل نکند، چیزی برای اشتراک نیست.",
  "No sign-in: anyone on this network can use your tunnel": "بدون ورود: هر کسی روی این شبکه می‌تواند از تونل شما استفاده کند",
  "Open": "باز",
  "Not open": "بسته",
  "Apply to open the port.": "برای باز کردن پورت، «اعمال» را بزنید.",
  "Apply": "اعمال",
  "Sets the operating system's proxy settings.": "تنظیمات پروکسی سیستم‌عامل را اعمال می‌کند.",
  "Leave empty to stay on a personal WARP identity.": "خالی بگذارید تا روی شناسهٔ شخصی WARP بمانید.",
  "Core and profile": "هسته و پروفایل",
  "Save profile": "ذخیرهٔ پروفایل",
  "Report": "گزارش",
  "Raise the log detail, reproduce the problem, then build this.": "جزئیات لاگ را بالا ببرید، مشکل را دوباره ایجاد کنید، بعد این را بسازید.",
  "Copy": "کپی",
  "Save report": "ذخیرهٔ گزارش",
  "Change the address you appear from": "تغییر آدرسی که از آن دیده می‌شوید",
  "This network sees only Cloudflare, never your node's address. Needs the tunnel connected.": "این شبکه فقط کلادفلر را می‌بیند، هرگز آدرس نود شما را. نیاز دارد که تونل وصل باشد.",
  "Starting…": "در حال راه‌اندازی…",
  "Switched on, but not running.": "روشن است، ولی در حال اجرا نیست.",
  "Waiting for the tunnel. Turn off the switch above to run without it.": "منتظر تونل. برای اجرا بدون آن، کلید بالا را خاموش کنید.",
  "Start now": "همین حالا شروع کن",
  "The chain did not start": "زنجیره شروع نشد",
  "Configs pasted by hand": "کانفیگ‌های دستی",
  "Read when the chain starts, so they take effect once applied.": "موقع شروع زنجیره خوانده می‌شوند، پس بعد از اعمال کردن اثر می‌گذارند.",
  "Turn on “Route through a second hop” above to load nodes.": "برای بارگذاری نودها، «عبور از یک پرش دوم» را در بالا روشن کنید.",
  "Connect first, or turn off “Dial nodes through the tunnel”.": "اول وصل شوید، یا «شماره‌گیری نودها از داخل تونل» را خاموش کنید.",
  "The chain did not start. The reason is shown above.": "زنجیره شروع نشد. دلیلش در بالا نوشته شده.",
  "Subscriptions": "اشتراک‌ها",
  "No subscriptions yet.": "هنوز اشتراکی اضافه نشده.",
  "Add a subscription": "افزودن اشتراک",
  "Add": "افزودن",
  "Nodes": "نودها",
  "Refresh": "به‌روزرسانی",
  "Test": "تست",
  "In use": "در حال استفاده",
  "Use": "استفاده",
  "Enter opens · ↑↓ moves · Esc closes": "Enter باز می‌کند · ↑↓ جابه‌جا می‌شود · Esc می‌بندد",
  "Nothing answered on either transport. This network is filtering hard.": "هیچ‌کدام از دو پروتکل جوابی نداد. این شبکه سخت‌گیرانه فیلتر می‌کند.",
  "Enter a numeric address and port first.": "اول یک آدرس عددی و پورت وارد کنید.",
  "Find a gateway": "پیدا کردن دروازه",
  "Working": "در حال کار",
  "What will run": "چه چیزی اجرا می‌شود",
  "No events yet. Connect to populate this.": "هنوز رویدادی نیست. برای پر شدن، وصل شوید.",
  "What this is built on": "این برنامه بر چه چیزی ساخته شده",
  "Full notices": "متن کامل مجوزها",
  "Idle": "بی‌کار",
  "Live": "فعال",
  "Scan cancelled.": "جستجو لغو شد.",
  "Sets the WinINET proxy. Most apps follow it; some bring their own settings.": "پروکسی WinINET را تنظیم می‌کند. بیشتر برنامه‌ها از آن پیروی می‌کنند؛ بعضی تنظیمات خودشان را دارند.",
  "Sets the SOCKS proxy on every active network service.": "پروکسی SOCKS را روی هر سرویس شبکهٔ فعال تنظیم می‌کند.",
  "Sets the GNOME proxy. Desktops that ignore gsettings are unaffected.": "پروکسی GNOME را تنظیم می‌کند. میزکارهایی که gsettings را نادیده می‌گیرند تحت تأثیر قرار نمی‌گیرند.",
  "TCP. Survives networks that block UDP.": "TCP. از شبکه‌هایی که UDP را مسدود می‌کنند عبور می‌کند.",
  "QUIC. Lower overhead where UDP gets through.": "QUIC. جایی که UDP رد می‌شود، سربار کمتری دارد.",
  "UDP, with an obfuscation profile sweep.": "UDP، همراه با جستجو در پروفایل‌های مبهم‌سازی.",
  "Nested tunnel. Slower, harder to classify.": "تونل تودرتو. کندتر، ولی سخت‌تر قابل تشخیص.",
  "Connection": "اتصال",
  "Status": "وضعیت",
  "Routes & transports": "مسیرها و پروتکل‌ها",
  "Endpoint": "دروازه",
  "Exit chain": "زنجیرهٔ خروج",
  "System": "سیستم",
  "Traffic & DNS": "ترافیک و DNS",
  "Identity": "شناسه",
  "Support": "پشتیبانی",
  "Diagnostics": "عیب‌یابی",
  "Licences & notices": "مجوزها و اعلان‌ها",
  "What the core is doing right now.": "کاری که هسته همین الان انجام می‌دهد.",
  "How hard to search, what the tunnel rides on, and how it hides.": "چقدر سخت جستجو شود، تونل روی چه چیزی سوار شود، و چطور خودش را پنهان کند.",
  "Pin a specific gateway, or let the core find one.": "یک دروازهٔ مشخص را ثابت کنید، یا بگذارید هسته خودش پیدا کند.",
  "Send the tunnel's traffic on through a node of your own, so the address you appear from changes.": "ترافیک تونل را از یک نود متعلق به خودتان رد کنید، تا آدرسی که از آن دیده می‌شوید عوض شود.",
  "Where traffic goes once the tunnel is up.": "ترافیک بعد از بالا آمدن تونل کجا می‌رود.",
  "Cloudflare Zero Trust enrolment.": "ثبت‌نام در Cloudflare Zero Trust.",
  "The core executable, logging, and a report you can hand to someone.": "فایل اجرایی هسته، ثبت وقایع، و گزارشی که می‌توانید به کسی بدهید.",
  "What WhiteAesther is built on, under what terms, and where to get the source.": "وایت‌آستر بر چه چیزی ساخته شده، تحت چه شرایطی، و کد منبع از کجا گرفته می‌شود.",

  // -- labels the settings search shows and matches on ----------------------
  "Live event log": "لاگ زندهٔ رویدادها",
  "Round-trip chart": "نمودار رفت و برگشت",
  "Timeouts": "مهلت‌ها",
  "Endpoint scanner": "جستجوگر دروازه",
  "Local proxy address": "آدرس پروکسی محلی",
  "Where the source lives": "کد منبع کجاست",

  "Missing": "پیدا نشد",
  "Put back on disconnect. If the app is killed rather than closed, the next launch restores it.": "با قطع اتصال به حالت قبل برمی‌گردد. اگر برنامه به‌جای بسته شدن کشته شود، اجرای بعدی آن را برمی‌گرداند.",
  "Tests real MASQUE gateways over": "دروازه‌های واقعی MASQUE را روی",
  "and ranks them by round-trip time. Nothing is connected until you pick one.": "تست می‌کند و بر اساس زمان رفت و برگشت رتبه‌بندی می‌کند. تا وقتی یکی را انتخاب نکنید، هیچ اتصالی برقرار نمی‌شود.",
  "Recent events (up to": "رویدادهای اخیر (حداکثر",
  "Scan": "جستجو کن",
  "Test pinned": "تست آدرس ثابت",
  "Automatic": "خودکار",
  "Custom first": "اول دستی",
  "Custom only": "فقط دستی",
  // -- the long paragraphs -------------------------------------------------
  // Reached through the primitives in panels.tsx rather than by a call at each
  // use site, so a control added later is translated by construction.
  "Opens a proxy on this machine that phones, televisions and anything else on the same network can point at. They go out through whatever is carrying traffic here — the second hop when one is running, the tunnel when it is not.": "روی این دستگاه یک پروکسی باز می‌کند که گوشی، تلویزیون و هر چیز دیگری روی همین شبکه می‌تواند به آن وصل شود. آن‌ها از همان مسیری خارج می‌شوند که ترافیک اینجا از آن می‌رود — پرش دوم اگر در حال اجرا باشد، و خود تونل اگر نباشد.",
  "The client secret and the token are held in memory and passed to the core through its environment. Neither is written to the profile on disk, and neither appears in a diagnostics report. The team, client ID and email are saved with the profile on this device.": "کلید مخفی کلاینت و توکن فقط در حافظه نگه داشته می‌شوند و از طریق متغیرهای محیطی به هسته داده می‌شوند. هیچ‌کدام روی دیسک در پروفایل نوشته نمی‌شوند و هیچ‌کدام در گزارش عیب‌یابی نمی‌آیند. نام تیم، شناسهٔ کلاینت و ایمیل همراه پروفایل روی این دستگاه ذخیره می‌شوند.",
  "The tunnel hides your traffic but keeps your country — Cloudflare places you near where you already are. Sending it on through a node of your own is what changes that.": "تونل ترافیک شما را پنهان می‌کند ولی کشورتان را نگه می‌دارد — کلادفلر شما را نزدیک همان جایی می‌گذارد که هستید. فرستادن ترافیک از یک نود متعلق به خودتان، همان چیزی است که این را عوض می‌کند.",
  "One per line. vless, vmess, trojan, ss, hysteria2 and tuic are all understood as they are — nothing needs converting first.": "هر خط یکی. vless و vmess و trojan و ss و hysteria2 و tuic همگی به همان شکلی که هستند خوانده می‌شوند — لازم نیست چیزی را اول تبدیل کنید.",
  "Kept up to date automatically. A subscription link is a credential — anyone holding it can use your nodes.": "خودکار به‌روز نگه داشته می‌شود. لینک اشتراک یک اطلاعات محرمانه است — هر کسی که آن را داشته باشد می‌تواند از نودهای شما استفاده کند.",
  "Every measurement here travels the tunnel, so a figure means the node works from behind it — and a failure means it does not. A node marked in amber is not broken and was not measured: hover it to read why this build cannot use it, and what to change.": "هر اندازه‌گیری اینجا از داخل تونل انجام می‌شود، پس یک عدد یعنی نود از پشت تونل کار می‌کند — و شکست یعنی کار نمی‌کند. نودی که زرد علامت خورده خراب نیست و اصلاً اندازه‌گیری نشده: نشانگر را رویش نگه دارید تا بخوانید چرا این نسخه نمی‌تواند از آن استفاده کند و چه چیزی باید عوض شود.",
  "The core is launched with these arguments. Zero Trust secrets go through the environment and are not shown here.": "هسته با این آرگومان‌ها اجرا می‌شود. اطلاعات محرمانهٔ Zero Trust از طریق متغیرهای محیطی می‌روند و اینجا نمایش داده نمی‌شوند.",

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
