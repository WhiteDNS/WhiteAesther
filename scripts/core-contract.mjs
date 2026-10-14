export const REQUIRED_COMMANDS = ["scan-only", "scan-limit", "test-endpoint", "export-identity", "import-identity", "check-options"];
export const REQUIRED_FEATURES = ["h2-ech", "h3-ech", "tls-ciphers", "tls-groups", "disable-grease", "enroll-address", "ech-dns", "ech-domain", "wg-over-masque", "verified", "scan-diversity", "history-8", "certificate-pinning"];

export function validateCoreContract(version, capabilities, expected) {
  if (version !== `aether ${expected.version}` || capabilities.schema !== 1 || capabilities.version !== expected.version) throw new Error(`Expected Aether ${expected.version}, got ${version}`);
  if (capabilities.revision !== expected.revision || !/^[a-f0-9]{40}$/.test(expected.revision)) throw new Error(`Core revision mismatch: expected ${expected.revision}, got ${capabilities.revision}`);
  for (const [key, required] of [["commands", REQUIRED_COMMANDS], ["features", REQUIRED_FEATURES]]) {
    for (const item of required) if (!capabilities[key]?.includes(item)) throw new Error(`Core is missing desktop ${key}: ${item}`);
  }
}

export function binaryArchitecture(bytes) {
  if (bytes[0] === 0x4d && bytes[1] === 0x5a) {
    const offset = bytes.readUInt32LE(0x3c);
    if (bytes.toString("ascii", offset, offset + 4) !== "PE\0\0") throw new Error("Invalid PE header");
    const machine = bytes.readUInt16LE(offset + 4);
    return machine === 0x8664 ? "x86_64" : machine === 0xaa64 ? "arm64" : "unknown";
  }
  if (bytes.toString("ascii", 0, 4) === "\x7fELF") {
    const machine = bytes[5] === 1 ? bytes.readUInt16LE(18) : bytes.readUInt16BE(18);
    return machine === 62 ? "x86_64" : machine === 183 ? "arm64" : "unknown";
  }
  if (bytes.readUInt32LE(0) === 0xfeedfacf) {
    const cpu = bytes.readUInt32LE(4);
    return cpu === 0x01000007 ? "x86_64" : cpu === 0x0100000c ? "arm64" : "unknown";
  }
  throw new Error("Core is not a supported PE, ELF or Mach-O executable");
}

// Read the PE import directory, rather than searching arbitrary executable strings.
export function windowsImports(bytes) {
  if (bytes[0] !== 0x4d || bytes[1] !== 0x5a) return [];
  const pe = bytes.readUInt32LE(0x3c);
  const optional = pe + 24;
  const magic = bytes.readUInt16LE(optional);
  const directory = optional + (magic === 0x20b ? 112 : magic === 0x10b ? 96 : 0);
  if (directory === optional) throw new Error("Unsupported PE optional header");
  const sections = optional + bytes.readUInt16LE(pe + 20);
  const count = bytes.readUInt16LE(pe + 6);
  const fileOffset = (rva) => {
    for (let index = 0; index < count; index++) {
      const section = sections + index * 40;
      const start = bytes.readUInt32LE(section + 12);
      const length = Math.max(bytes.readUInt32LE(section + 8), bytes.readUInt32LE(section + 16));
      if (rva >= start && rva < start + length) return bytes.readUInt32LE(section + 20) + rva - start;
    }
    throw new Error("PE import address is outside its sections");
  };
  const rva = bytes.readUInt32LE(directory + 8);
  if (!rva) return [];
  const start = fileOffset(rva);
  const imports = [];
  for (let descriptor = start; descriptor + 20 <= bytes.length; descriptor += 20) {
    const name = bytes.readUInt32LE(descriptor + 12);
    if (!name) break;
    const at = fileOffset(name);
    const end = bytes.indexOf(0, at);
    if (end < 0) throw new Error("Unterminated PE import name");
    imports.push(bytes.toString("ascii", at, end));
  }
  return imports;
}

export function checkWindowsRuntime(bytes) {
  const imports = windowsImports(bytes);
  const external = imports.filter(name => /^(?:msvcp|vcruntime|msvcr)\d/i.test(name));
  if (external.length) throw new Error(`Core needs unbundled VC runtime DLLs (${external.join(", ")}); build Windows with -C target-feature=+crt-static`);
  return imports;
}
