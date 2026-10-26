import { test, expect } from '@playwright/test';
import { DEFAULT_PROFILE, IDLE_SNAPSHOT } from '../src/types';

test.beforeEach(async ({ page }) => {
  await page.route('https://api.github.com/**', route => route.fulfill({ status: 503, body: '' }));
  await page.addInitScript(({ profile, idle }) => {
    localStorage.setItem('whiteaesther.mode', 'simple');
    localStorage.setItem('whiteaesther.language', 'en');
    const state = window as any;
    state.testSavedProfile = null;
    state.__TAURI_EVENT_PLUGIN_INTERNALS__ = { unregisterListener() {} };
    state.__TAURI_INTERNALS__ = {
      transformCallback: () => 1,
      invoke: async (command: string, args: any) => {
        if (command === 'load_profile') return profile;
        if (command === 'core_status') return {
          ...idle, state: 'connected', transport: 'wireguard', endpoint: 'NL',
          latencyMs: 258, startedAt: Date.now() - 70_000,
        };
        if (command === 'core_logs') return [];
        if (command === 'runtime_info') return { os: 'windows', arch: 'x86_64' };
        if (command === 'probe_core') return { available: true, path: 'aether.exe', version: 'aether 2.3.0', message: 'Ready' };
        if (command === 'probe_latency') return 258;
        if (command === 'chain_status') return { running: false, address: null };
        if (command === 'exit_info') return { ip: '203.0.113.10', country: 'NL', warp: true, chained: false };
        if (command === 'save_profile') { state.testSavedProfile = args.profile; return args.profile; }
        if (command === 'set_system_proxy') return false;
        if (command.startsWith('plugin:event|')) return 1;
        return false;
      },
    };
  }, { profile: DEFAULT_PROFILE, idle: IDLE_SNAPSHOT });
});

for (const viewport of [{ width: 1366, height: 715 }, { width: 1100, height: 560 }, { width: 1340, height: 860 }]) {
  test(`connected controls remain reachable at ${viewport.width}x${viewport.height}`, async ({ page }) => {
    await page.setViewportSize(viewport);
    await page.goto('/');
    await expect(page.getByRole('img', { name: 'Round-trip through the tunnel over the last eighty seconds' })).toBeVisible();

    const scroller = page.locator('main > div');
    const picker = page.getByRole('button', { name: /This app only/ });
    const switches = page.getByRole('switch');
    // The picker must follow all connection settings instead of covering them.
    const controlsBottom = await switches.last().evaluate(el => el.getBoundingClientRect().bottom);
    const pickerTop = await picker.evaluate(el => el.getBoundingClientRect().top);
    expect(pickerTop).toBeGreaterThan(controlsBottom);

    const footerBefore = await page.locator('footer').boundingBox();
    if (viewport.height < 800) {
      await expect.poll(() => scroller.evaluate(el => el.scrollHeight - el.clientHeight)).toBeGreaterThan(0);
      await page.mouse.move(viewport.width - 60, 260);
      await page.mouse.wheel(0, 2000);
      await expect.poll(() => scroller.evaluate(el => el.scrollTop)).toBeGreaterThan(0);
    }
    await expect(picker).toBeInViewport({ ratio: 1 });
    await expect(switches.last()).toBeInViewport({ ratio: 1 });
    await switches.last().click();
    await expect(switches.last()).toBeChecked();
    await expect.poll(() => page.evaluate(() => (window as any).testSavedProfile?.killSwitch)).toBe(true);
    expect(await page.locator('footer').boundingBox()).toEqual(footerBefore);
    expect(await page.evaluate(() => document.documentElement.scrollHeight)).toBe(viewport.height);
  });
}
