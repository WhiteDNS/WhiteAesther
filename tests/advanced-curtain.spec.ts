import { test, expect, type Page } from '@playwright/test';
import { DEFAULT_PROFILE, IDLE_SNAPSHOT } from '../src/types';

async function boot(page: Page, language: 'en' | 'fa') {
  await page.route('https://api.github.com/**', route => route.fulfill({ status: 503, body: '' }));
  await page.addInitScript(({ profile, idle, language }) => {
    // Only on first load, so a reload shows whatever the app remembered.
    if (!localStorage.getItem('whiteaesther.mode')) localStorage.setItem('whiteaesther.mode', 'simple');
    localStorage.setItem('whiteaesther.language', language);
    const state = window as any;
    state.__TAURI_EVENT_PLUGIN_INTERNALS__ = { unregisterListener() {} };
    state.__TAURI_INTERNALS__ = {
      transformCallback: () => 1,
      invoke: async (command: string) => {
        if (command === 'load_profile') return profile;
        if (command === 'core_status') return idle;
        if (command === 'core_logs') return [];
        if (command === 'runtime_info') return { os: 'windows', arch: 'x86_64' };
        if (command === 'probe_core') return { available: true, path: 'aether.exe', version: 'aether 2.4.0', message: 'Ready' };
        if (command === 'chain_status') return { running: false, address: null };
        if (command.startsWith('plugin:event|')) return 1;
        return false;
      },
    };
  }, { profile: DEFAULT_PROFILE, idle: IDLE_SNAPSHOT, language });
  await page.setViewportSize({ width: 1366, height: 768 });
  await page.goto('/');
}

const tab = (page: Page) => page.locator('main button[aria-expanded]');

test('the tab opens the curtain, Escape closes it, and the choice survives a reload', async ({ page }) => {
  await boot(page, 'en');
  await expect(tab(page)).toHaveAttribute('aria-expanded', 'false');
  await expect(page.locator('main [inert]')).toHaveCount(1);

  await tab(page).click();
  await expect(tab(page)).toHaveAttribute('aria-expanded', 'true');
  await expect(page.locator('main [inert]')).toHaveCount(0);
  await expect(page.getByRole('navigation', { name: 'Settings sections' })).toBeVisible();
  // The connect box stays on screen beside the open settings.
  await expect(page.locator('aside')).toBeInViewport({ ratio: 1 });

  await page.reload();
  await expect(tab(page)).toHaveAttribute('aria-expanded', 'true');

  await page.keyboard.press('Escape');
  await expect(tab(page)).toHaveAttribute('aria-expanded', 'false');
});

test('settings search opens the curtain on the chosen section', async ({ page }) => {
  await boot(page, 'en');
  await page.keyboard.press('Control+k');
  await page.getByRole('dialog', { name: 'Search settings' }).locator('input').fill('event log');
  await page.keyboard.press('Enter');
  await expect(tab(page)).toHaveAttribute('aria-expanded', 'true');
  await expect(page.getByRole('heading', { level: 2, name: 'Status' })).toBeVisible();
});

test('Escape inside the settings search closes only the search', async ({ page }) => {
  await boot(page, 'en');
  await tab(page).click();
  await page.keyboard.press('Control+k');
  await expect(page.getByRole('dialog', { name: 'Search settings' }).locator('input')).toBeFocused();
  await page.keyboard.press('Escape');
  await expect(page.getByRole('dialog', { name: 'Search settings' })).toHaveCount(0);
  await expect(tab(page)).toHaveAttribute('aria-expanded', 'true');
});

test('Persian mirrors the layout: tab on the right, connect box on the left', async ({ page }) => {
  await boot(page, 'fa');
  await expect(page.locator('html')).toHaveAttribute('dir', 'rtl');
  const tabBox = await tab(page).boundingBox();
  const asideBox = await page.locator('aside').boundingBox();
  expect(tabBox!.x).toBeGreaterThan(asideBox!.x);
  await tab(page).click();
  await expect(page.locator('main nav')).toBeInViewport();
});
