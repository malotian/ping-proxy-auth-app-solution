import { test, expect } from '@playwright/test';


test('login.with.username', async ({ page }) => {
  // 1. Go to initial URL
  await page.goto('https://app.lab.com:3000/login');
  
  // 2. Optionally wait for the page to be idle (or fully loaded) if needed
  await page.waitForLoadState('networkidle');

  // 3. After redirection, wait for the callbacks panel to appear
  await page.waitForSelector('div[data-testid="callbacks_panel"]');

  // 4. Fill in username
  await page.getByTestId('fr-field-callback_1').getByTestId('input-').click();
  await page.getByTestId('fr-field-callback_1').getByTestId('input-').fill('playwright');
  await page.getByTestId('fr-field-callback_1').getByTestId('input-').press('Tab');

  // 5. Fill in password and press Enter
  await page.getByTestId('fr-field-callback_2').getByTestId('input-').fill('P@$$w0rd@123');
  await page.getByTestId('fr-field-callback_2').getByTestId('input-').press('Enter');

  await expect(page.getByText('"AccessToken"')).toBeVisible();
  await expect(page.getByText('"RefreshToken"')).toBeVisible();
  await expect(page.getByText('"RememberMe"')).toBeVisible();
  await expect(page.getByText('"StateID"')).toBeVisible();
  await expect(page.getByText('"RememberMe"')).toBeVisible();
  await expect(page.getByText('"TargetUrl"')).toBeVisible();
  await expect(page.locator('andypf-json-viewer')).toContainText('"staples-kid"');
  await expect(page.getByText('"OriginalAccessToken"')).toBeVisible();
  await expect(page.getByText('"OriginalIdToken"')).toBeVisible();
  await expect(page.getByText('"OriginalRefreshToken"')).toBeVisible();
});

test('login.with.email', async ({ page }) => {
  // 1. Go to initial URL
  await page.goto('https://app.lab.com:3000/login');
  
  // 2. Optionally wait for the page to be idle (or fully loaded) if needed
  await page.waitForLoadState('networkidle');

  // 3. After redirection, wait for the callbacks panel to appear
  await page.waitForSelector('div[data-testid="callbacks_panel"]');

  // 4. Fill in username
  await page.getByTestId('fr-field-callback_1').getByTestId('input-').click();
  await page.getByTestId('fr-field-callback_1').getByTestId('input-').fill('playwright@playwright.com');
  await page.getByTestId('fr-field-callback_1').getByTestId('input-').press('Tab');

  // 5. Fill in password and press Enter
  await page.getByTestId('fr-field-callback_2').getByTestId('input-').fill('P@$$w0rd@123');
  await page.getByTestId('fr-field-callback_2').getByTestId('input-').press('Enter');

  await expect(page.getByText('"AccessToken"')).toBeVisible();
  await expect(page.getByText('"RefreshToken"')).toBeVisible();
  await expect(page.getByText('"RememberMe"')).toBeVisible();
  await expect(page.getByText('"StateID"')).toBeVisible();
  await expect(page.getByText('"RememberMe"')).toBeVisible();
  await expect(page.getByText('"TargetUrl"')).toBeVisible();
  await expect(page.locator('andypf-json-viewer')).toContainText('"staples-kid"');
  await expect(page.getByText('"OriginalAccessToken"')).toBeVisible();
  await expect(page.getByText('"OriginalIdToken"')).toBeVisible();
  await expect(page.getByText('"OriginalRefreshToken"')).toBeVisible();
});

