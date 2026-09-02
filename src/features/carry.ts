import { Globe, Laptop, Layers, type LucideIcon } from "lucide-react";

/**
 * The one decision a normal user makes: how far the tunnel reaches.
 *
 * Named for what the person gets, not for the mechanism — "whole machine"
 * rather than "system proxy", because nobody opens this app wanting to
 * configure a proxy.
 */
export type CarryMode = "app" | "system" | "tun";

export interface CarryOption {
  id: CarryMode;
  title: string;
  detail: string;
  icon: LucideIcon;
  /** Set while the engine work behind full-tunnel is outstanding. */
  disabled?: boolean;
  disabledReason?: string;
}

export const CARRY_OPTIONS: CarryOption[] = [
  {
    id: "app",
    title: "This app only",
    // Filled in from the address traffic is actually carried on. A literal
    // here was wrong twice over: it ignored a changed port, and once a second
    // hop was carrying it named the tunnel, so anything pointed at it went out
    // past the hop and kept the old exit address.
    detail: "Local proxy on {address}",
    icon: Laptop,
  },
  {
    id: "system",
    title: "Whole machine",
    detail: "Sets your system proxy",
    icon: Globe,
  },
  {
    id: "tun",
    title: "Full tunnel",
    detail: "Every app, even ones that ignore proxies",
    icon: Layers,
  },
];

/**
 * Which of the three the profile currently describes.
 *
 * Full tunnel wins when both are set: it is the stronger of the two, and a
 * system proxy left over from before is not what the person chose last.
 */
export function carryFromProfile(systemProxy: boolean, fullTunnel = false): CarryMode {
  if (fullTunnel) return "tun";
  return systemProxy ? "system" : "app";
}

/**
 * Where applications have to point to get what this mode promises.
 *
 * `carryAddress` is the chain's listener when a second hop is running and the
 * tunnel's otherwise — never the configured SOCKS port on its own, which stops
 * being the right answer the moment a hop is added in front of it.
 */
export function describeCarry(
  mode: CarryMode,
  carryAddress: string,
  t: (key: string) => string = (key) => key,
): string {
  if (mode === "system") return t("Your system proxy is set, and will be put back when you disconnect.");
  if (mode === "tun") {
    return t("Every app is captured through a network device, including the ones that ignore proxy settings.");
  }
  // The address is the sentence's object, so the two halves are translated
  // around it rather than as one string with a placeholder -- Persian puts the
  // verb last, and a single template would have pinned English word order.
  return `${t("Point apps at")} ${carryAddress} ${t("to use it.")}`;
}

/** Fills the option's address placeholder, if it has one. */
export function carryDetail(
  option: CarryOption,
  carryAddress: string,
  t: (key: string) => string = (key) => key,
): string {
  return t(option.detail).replace("{address}", carryAddress);
}
