import { test } from "node:test";
import assert from "node:assert/strict";
import { validateCoreContract, REQUIRED_COMMANDS, REQUIRED_FEATURES, binaryArchitecture } from "./core-contract.mjs";

test("staging rejects old, dirty, wrong-revision and incomplete cores", () => {
  const expected = { version: "2.3.0", revision: "a".repeat(40), patchset: "restricted-networks-v1" };
  const cap = { ...expected, schema: 1, commands: REQUIRED_COMMANDS, features: REQUIRED_FEATURES };
  assert.doesNotThrow(() => validateCoreContract("aether 2.3.0", cap, expected));
  for (const bad of [{ ...cap, patchset: undefined }, { ...cap, revision: "b".repeat(40) }, { ...cap, revision: cap.revision + "-dirty" }, { ...cap, features: [] }, { ...cap, commands: [] }]) assert.throws(() => validateCoreContract("aether 2.3.0", bad, expected));
  assert.throws(() => validateCoreContract("aether 2.0.0", cap, expected));
});

test("native headers determine the packaged architecture", () => {
  const pe = Buffer.alloc(128); pe.write("MZ"); pe.writeUInt32LE(64, 0x3c); pe.write("PE\0\0", 64); pe.writeUInt16LE(0x8664, 68);
  assert.equal(binaryArchitecture(pe), "x86_64");
  pe.writeUInt16LE(0xaa64, 68); assert.equal(binaryArchitecture(pe), "arm64");
  const elf = Buffer.alloc(64); elf.write("\x7fELF"); elf[5] = 1; elf.writeUInt16LE(183, 18); assert.equal(binaryArchitecture(elf), "arm64");
  const macho = Buffer.alloc(32); macho.writeUInt32LE(0xfeedfacf); macho.writeUInt32LE(0x01000007, 4); assert.equal(binaryArchitecture(macho), "x86_64");
});
