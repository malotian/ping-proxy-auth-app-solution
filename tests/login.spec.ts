import { test, expect } from '@playwright/test';


test('login.with.username',async ({ page }) => {

  // 1. Go to initial URL
  await page.goto('https://app.lab.com:3000/login');

  // 2. Wait for the page to load or become idle
  await page.waitForLoadState('networkidle');

  // 3. Wait for the callbacks panel to appear
  await page.waitForSelector('div[data-testid="callbacks_panel"]');

  // 4. Fill in username
  await page.getByTestId('fr-field-callback_1').getByTestId('input-').click();
  await page.getByTestId('fr-field-callback_1').getByTestId('input-').fill('playwright');
  await page.getByTestId('fr-field-callback_1').getByTestId('input-').press('Tab');

  // 5. Fill in password and press Enter
  await page.getByTestId('fr-field-callback_2').getByTestId('input-').fill('P@$$w0rd@123');
  await page.getByTestId('fr-field-callback_2').getByTestId('input-').press('Enter');

  // 6. Wait for the final page or known URL pattern
  await page.waitForURL('https://app.lab.com:3000/**');

  // 7. Check for the cookie on the application domain
  const appCookies = await page.context().cookies();
  const appCookieNames = appCookies.map((cookie) => cookie.name);
  expect(appCookieNames).toContain('COOKIE_STAPLES_SESSION');

  const authSessionCookie = appCookies.find((c) => c.name === 'COOKIE_STAPLES_SESSION');
  expect(authSessionCookie).toBeDefined();
  expect(authSessionCookie?.value?.length).toBeGreaterThan(0);

  // 8. Check for the 'session-jwt' cookie on the openam-simeio2-demo domain
  const pingCookies = await page.context().cookies('https://openam-simeio2-demo.forgeblocks.com/');
  const pingPersistantSessionCookie = pingCookies.find((cookie) => cookie.name === 'session-jwt');
  expect(pingPersistantSessionCookie).toBeDefined();
  expect(pingPersistantSessionCookie?.value).toBeTruthy();

  // 9. Validate final page elements
  await expect(page.getByText('"AccessToken"')).toBeVisible();
  await expect(page.getByText('"RefreshToken"')).toBeVisible();
  await expect(page.getByText('"RememberMe"')).toBeVisible();
  await expect(page.getByText('"StateID"')).toBeVisible();
  await expect(page.getByText('"TargetUrl"')).toBeVisible();
  await expect(page.locator('andypf-json-viewer')).toContainText('"staples-kid"');
  await expect(page.getByText('"OriginalAccessToken"')).toBeVisible();
  await expect(page.getByText('"OriginalIdToken"')).toBeVisible();
  await expect(page.getByText('"OriginalRefreshToken"')).toBeVisible();
});

test('login.with.email', async ({ page }) => {

  // 1. Go to initial URL
  await page.goto('https://app.lab.com:3000/login');

  // 2. Wait for the page to load or become idle
  await page.waitForLoadState('networkidle');

  // 3. Wait for the callbacks panel to appear
  await page.waitForSelector('div[data-testid="callbacks_panel"]');

  // 4. Fill in username (email)
  await page.getByTestId('fr-field-callback_1').getByTestId('input-').click();
  await page.getByTestId('fr-field-callback_1').getByTestId('input-').fill('playwright@playwright.com');
  await page.getByTestId('fr-field-callback_1').getByTestId('input-').press('Tab');

  // 5. Fill in password and press Enter
  await page.getByTestId('fr-field-callback_2').getByTestId('input-').fill('P@$$w0rd@123');
  await page.getByTestId('fr-field-callback_2').getByTestId('input-').press('Enter');

  // 6. Wait for the final page or known URL pattern
  await page.waitForURL('https://app.lab.com:3000/**');

  // 7. Check for the cookie on the application domain
  const appCookies = await page.context().cookies();
  const appCookieNames = appCookies.map((cookie) => cookie.name);
  expect(appCookieNames).toContain('COOKIE_STAPLES_SESSION');

  const authSessionCookie = appCookies.find((c) => c.name === 'COOKIE_STAPLES_SESSION');
  expect(authSessionCookie).toBeDefined();
  expect(authSessionCookie?.value?.length).toBeGreaterThan(0);

  // 8. Check for the 'session-jwt' cookie on the openam-simeio2-demo domain
  const pingCookies = await page.context().cookies('https://openam-simeio2-demo.forgeblocks.com/');
  const pingPersistantSessionCookie = pingCookies.find((cookie) => cookie.name === 'session-jwt');
  expect(pingPersistantSessionCookie).toBeDefined();
  expect(pingPersistantSessionCookie?.value).toBeTruthy();

  // 9. Validate final page elements
  await expect(page.getByText('"AccessToken"')).toBeVisible();
  await expect(page.getByText('"RefreshToken"')).toBeVisible();
  await expect(page.getByText('"RememberMe"')).toBeVisible();
  await expect(page.getByText('"StateID"')).toBeVisible();
  await expect(page.getByText('"TargetUrl"')).toBeVisible();
  await expect(page.locator('andypf-json-viewer')).toContainText('"staples-kid"');
  await expect(page.getByText('"OriginalAccessToken"')).toBeVisible();
  await expect(page.getByText('"OriginalIdToken"')).toBeVisible();
  await expect(page.getByText('"OriginalRefreshToken"')).toBeVisible();
});
