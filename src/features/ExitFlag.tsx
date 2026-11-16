import { useEffect, useState } from "react";

// Windows draws flag emoji as two letters, so the flags are bundled SVGs. One
// small module per country, loaded only for the country actually on screen.
const FLAGS = import.meta.glob<string>("/node_modules/country-flag-icons/string/3x2/[A-Z][A-Z].js", {
  import: "default",
});

function loaderFor(country: string) {
  return FLAGS[`/node_modules/country-flag-icons/string/3x2/${country.toUpperCase()}.js`];
}

/** Whether a flag exists for this code. Cloudflare's XX (unknown) and T1 (Tor) have none. */
export function hasFlag(country: string | undefined): country is string {
  return !!country && /^[A-Za-z]{2}$/.test(country) && !!loaderFor(country);
}

export function ExitFlag({ country }: { country: string }) {
  const [svg, setSvg] = useState<string | null>(null);

  useEffect(() => {
    let disposed = false;
    setSvg(null);
    void loaderFor(country)?.().then((next) => { if (!disposed) setSvg(next); });
    return () => { disposed = true; };
  }, [country]);

  return (
    <div className="grid h-[34px] w-[40px] shrink-0 place-items-center">
      {svg ? (
        <img
          src={`data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`}
          alt=""
          className="h-[26px] w-[39px] rounded-[5px] object-cover shadow-[0_1px_3px_rgba(0,0,0,0.45)] ring-1 ring-white/15"
        />
      ) : (
        <div className="h-[26px] w-[39px] animate-pulse rounded-[5px] bg-muted" />
      )}
    </div>
  );
}

/** "Thailand" or "تایلند" for TH; the code itself when the name is unknown. */
export function countryName(country: string, language: string): string {
  try {
    return new Intl.DisplayNames([language], { type: "region" }).of(country.toUpperCase()) ?? country;
  } catch {
    return country;
  }
}
