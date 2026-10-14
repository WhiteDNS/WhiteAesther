import { test, expect } from '@playwright/test';
import { DEFAULT_PROFILE, IDLE_SNAPSHOT } from '../src/types';
import { execFileSync } from 'node:child_process';

test.beforeEach(async ({ page }) => {
  await page.context().grantPermissions(['clipboard-read', 'clipboard-write']);
  await page.exposeFunction('validateCoreOptions', (profile: typeof DEFAULT_PROFILE) => {
    if (!process.env.WHITEAESTHER_TEST_CORE) return { ok: true };
    const args = ['--check-options'];
    for (const [flag, value] of [['--tls-groups', profile.tlsGroups], ['--tls-ciphers', profile.tlsCiphers], ['--enroll-address', profile.enrollAddress]]) {
      if (value?.trim()) args.push(flag!, value.trim());
    }
    if (profile.disableGrease) args.push('--disable-grease');
    if (profile.ech?.trim() && profile.ech.trim().toLowerCase() !== 'off') {
      args.push('--ech', profile.ech.trim(), '--ech-dns', profile.echResolver?.trim() || 'https://1.1.1.1/dns-query');
      if (profile.echDomain?.trim()) args.push('--ech-domain', profile.echDomain.trim());
    }
    return JSON.parse(execFileSync(process.env.WHITEAESTHER_TEST_CORE, args, { encoding: 'utf8', timeout: 10_000, windowsHide: true }));
  });
  await page.addInitScript(({ defaults, idle }) => {
    localStorage.setItem('whiteaesther.mode', 'advanced');
    const state = window as any;
    state.testPendingSaves = [];
    state.testSavedProfiles = [];
    state.testHoldSave = false;
    state.__TAURI_EVENT_PLUGIN_INTERNALS__ = { unregisterListener() {} };
    state.__TAURI_INTERNALS__ = {
      transformCallback: () => 1,
      invoke: async (command: string, args: any) => {
        if (command === 'load_profile') return JSON.parse(localStorage.getItem('test-stored-profile') || 'null') || { ...defaults, autoRoute: false };
        if (command === 'core_status') return idle;
        if (command === 'core_logs') return [];
        if (command === 'runtime_info') return { os: 'windows', arch: 'x86_64' };
        if (command === 'probe_core') return { available: true, path: 'aether.exe', version: 'aether 2.3.0', message: 'Ready' };
        if (command === 'carriers_available') return ['aether', 'psiphon', 'tor'];
        if (command === 'save_profile') {
          state.testSavedProfiles.push(args.profile);
          if (state.testHoldSave) await new Promise(resolve => state.testPendingSaves.push(resolve));
          const check = await state.validateCoreOptions(args.profile);
          if (!check.ok) throw new Error(check.error);
          const profile = structuredClone(args.profile);
          profile.accessClientSecret = null; profile.accessToken = null;
          localStorage.setItem('test-stored-profile', JSON.stringify(profile));
          return profile;
        }
        if (command === 'psiphon_status') return { state: 'idle', availableRegions: [] };
        if (command === 'tor_status') return { state: 'idle', bootstrap: 0 };
        if (command === 'lan_share_status') return { running: false, address: null, open: false };
        if (command.startsWith('plugin:event|')) return 1;
        return false;
      },
    };
  }, { defaults: DEFAULT_PROFILE, idle: IDLE_SNAPSHOT });
  await page.goto('/');
  await page.getByRole('button', { name: 'Routes & transports', exact: true }).click();
  await expect(page.getByLabel('TLS groups', { exact: true })).toBeVisible();
});

const fields = [
  ['TLS 1.2 cipher suites', 'ECDHE-RSA-AES128-GCM-SHA256', 'tlsCiphers'],
  ['TLS groups', 'X25519:P-256:P-384', 'tlsGroups'],
  ['WARP registration address', '203.0.113.10:443', 'enrollAddress'],
  ['ECH resolver', 'https://1.1.1.1/dns-query', 'echResolver'],
  ['ECH key domain', 'cloudflare-ech.com', 'echDomain'],
];
for (const [label, text, key] of fields) {
  test(`${label}: typing, old Save, paste, clear and reload`, async ({ page }) => {
    const input = page.getByLabel(label, { exact: true });
    await input.fill('');
    for (const character of text) await input.pressSequentially(character);
    await expect(input).toHaveValue(text);
    await page.evaluate(() => { (window as any).testHoldSave = true; });
    await page.getByRole('button', { name: 'Save profile', exact: true }).click();
    await expect.poll(() => page.evaluate(() => (window as any).testPendingSaves.length)).toBe(1);
    await input.fill(text + ':new-edit');
    await page.evaluate(() => { const s = window as any; s.testHoldSave = false; s.testPendingSaves.shift()(); });
    await expect(page.getByText('Profile saved', { exact: true })).toBeVisible();
    await expect(input).toHaveValue(text + ':new-edit');
    await input.press('ControlOrMeta+A');
    await input.press('Backspace');
    await expect(input).toHaveValue('');
    await page.evaluate(value => navigator.clipboard.writeText(value), text);
    await input.press('ControlOrMeta+V');
    await expect(input).toHaveValue(text);
    await page.getByRole('button', { name: 'Save profile', exact: true }).click();
    await expect.poll(() => page.evaluate(k => JSON.parse(localStorage.getItem('test-stored-profile') || '{}')[k], key)).toBe(text);
    await page.reload();
    await page.getByRole('button', { name: 'Routes & transports', exact: true }).click();
    await expect(page.getByLabel(label, { exact: true })).toHaveValue(text);
  });
}

test('queued Saves persist the newest draft and do not overwrite its text', async ({ page }) => {
  const input = page.getByLabel('TLS groups', { exact: true });
  await input.fill('X25519');
  await page.evaluate(() => { (window as any).testHoldSave = true; });
  await page.getByRole('button', { name: 'Save profile', exact: true }).click();
  await expect.poll(() => page.evaluate(() => (window as any).testPendingSaves.length)).toBe(1);
  await input.fill('X25519:P-256');
  await page.getByRole('button', { name: 'Save profile', exact: true }).click();
  expect(await page.evaluate(() => (window as any).testSavedProfiles.length)).toBe(1);
  await page.evaluate(() => { const s = window as any; s.testHoldSave = false; s.testPendingSaves.shift()(); });
  await expect.poll(() => page.evaluate(() => JSON.parse(localStorage.getItem('test-stored-profile') || '{}').tlsGroups)).toBe('X25519:P-256');
  await expect(input).toHaveValue('X25519:P-256');
});

test('an actual core validation error keeps the text for correction', async ({ page }) => {
  test.skip(!process.env.WHITEAESTHER_TEST_CORE, 'Requires the built native core');
  const input = page.getByLabel('TLS 1.2 cipher suites', { exact: true });
  await input.fill('INVALID-WHITEAESTHER-CIPHER');
  await page.getByRole('button', { name: 'Save profile', exact: true }).click();
  await expect(page.getByText('Action failed', { exact: true })).toBeVisible();
  await expect(input).toHaveValue('INVALID-WHITEAESTHER-CIPHER');
  await input.fill('ECDHE-RSA-AES128-GCM-SHA256');
  await page.getByRole('button', { name: 'Save profile', exact: true }).click();
  await expect.poll(() => page.evaluate(() => JSON.parse(localStorage.getItem('test-stored-profile') || '{}').tlsCiphers)).toBe('ECDHE-RSA-AES128-GCM-SHA256');
});
