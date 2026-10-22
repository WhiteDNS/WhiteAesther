import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildCoreCommand } from './command.ts';
import { DEFAULT_PROFILE } from '../types.ts';

test('TLS options reach the command in order and inactive ECH overrides stay stored', () => {
  const profile = { ...DEFAULT_PROFILE, tlsCiphers: 'ECDHE-RSA-AES128-GCM-SHA256', tlsGroups: 'X25519:P-256:P-384', disableGrease: true, enrollAddress: '203.0.113.10:443', ech: 'auto', echResolver: 'tcp://1.1.1.1:53', echDomain: 'keys.example' };
  const command = buildCoreCommand(profile);
  for (const flag of ['--tls-ciphers', '--tls-groups', '--disable-grease', '--enroll-address', '--ech-dns', '--ech-domain']) assert.ok(command.includes(flag), flag);
  assert.ok(command.includes('X25519:P-256:P-384'));
  const off = buildCoreCommand({ ...profile, ech: 'off' });
  assert.ok(off.includes("--ech 'off'")); assert.ok(!off.includes('--ech-dns')); assert.ok(!off.includes('--ech-domain'));
  assert.equal(profile.echResolver, 'tcp://1.1.1.1:53');
});

test('nested transports and zero keepalive agree with the backend contract', () => {
  for (const [protocol, flag] of [['mim', '--mim'], ['gool', '--gool'], ['wom', '--wg-over-masque']] as const) {
    const command = buildCoreCommand({ ...DEFAULT_PROFILE, protocol, keepaliveSecs: 0 });
    assert.ok(command.startsWith(`aether ${flag} `));
    assert.ok(!command.includes('--keepalive'));
    assert.equal(command.includes('--h2'), protocol !== 'gool');
  }
});

test('the adaptive bootstrap receives a custom resolver without mistaking it for ECH data', () => {
  const command = buildCoreCommand({ ...DEFAULT_PROFILE, ech: null, echResolver: 'tcp://1.1.1.1:53' });
  assert.ok(command.includes("--ech-dns 'tcp://1.1.1.1:53'"));
  assert.ok(!command.includes('--ech tcp://'));
});
