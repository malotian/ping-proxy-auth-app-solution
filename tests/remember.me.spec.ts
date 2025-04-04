// auth-code-impersonation-refresh.spec.ts
import { test, expect } from '@playwright/test';
import axios from 'axios';
import qs from 'qs';

require('dotenv').config();

// CONFIGURATION
const openidConfigUrl = 'https://openam-simeio2-demo.forgeblocks.com/am/oauth2/bravo/.well-known/openid-configuration';
const subjectClientId = 'staples_tier_a_app_client_id';
const subjectClientSecret = 'ystaples_tier_a_app_client_secret';
const actorClientId = 'staples_tier_a_app_actor_client_id';
const actorClientSecret = 'staples_tier_a_app_actor_client_secret';
const redirectUri = 'https://app.lab.com:3000/callback';
const userName = 'hdhanjal';
const userPassword = 'Infosys@123';

test('Auth Code → Impersonation → Refresh', async ({ page }) => {
  // Step 1: Fetch OIDC config
  const { data: openidConfig } = await axios.get(openidConfigUrl);
  const authUrl = openidConfig.authorization_endpoint;
  const tokenUrl = openidConfig.token_endpoint;

  // Step 2: Construct auth URL
  const state = 'xyz123';
  const nonce = 'abc456';
  const scope = 'openid profile offline_access';

  const fullAuthUrl = `${authUrl}?` + qs.stringify({
    client_id: subjectClientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope,
    state,
    nonce,
  });

  // Step 3: Automate login with Playwright
  await page.goto(fullAuthUrl);

  await page.fill('input[name="username"]', userName);
  await page.fill('input[name="password"]', userPassword);
  await page.click('button[type="submit"]');

  // Optional: consent screen
  if (await page.locator('button:has-text("Allow")').isVisible()) {
    await page.click('button:has-text("Allow")');
  }

  // Step 4: Capture auth code from redirect
  await page.waitForURL(`${redirectUri}?*`);
  const redirectedUrl = new URL(page.url());
  const authCode = redirectedUrl.searchParams.get('code');
  expect(authCode).not.toBeNull();

  console.log('🔑 Authorization Code:', authCode);

  // Step 5: Exchange auth code for token
  const tokenRes = await axios.post(tokenUrl, qs.stringify({
    grant_type: 'authorization_code',
    code: authCode,
    redirect_uri: redirectUri,
    client_id: subjectClientId,
    client_secret: subjectClientSecret,
  }), {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  });

  const subjectAccessToken = tokenRes.data.access_token;
  console.log('🎟️ Subject Access Token:', subjectAccessToken);

  // Step 6: Token Exchange (impersonation)
  const impersonationRes = await axios.post(tokenUrl, qs.stringify({
    grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
    subject_token: subjectAccessToken,
    subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
    client_id: actorClientId,
    client_secret: actorClientSecret,
    scope: 'openid profile offline_access',
  }), {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  });

  const impersonatedAccessToken = impersonationRes.data.access_token;
  const impersonatedRefreshToken = impersonationRes.data.refresh_token;

  console.log('🧑‍🎤 Impersonated Access Token:', impersonatedAccessToken);
  console.log('♻️ Impersonated Refresh Token:', impersonatedRefreshToken);

  expect(impersonatedAccessToken).not.toBeNull();
  expect(impersonatedRefreshToken).not.toBeNull();

  // Step 7: Refresh token request
  const refreshRes = await axios.post(tokenUrl, qs.stringify({
    grant_type: 'refresh_token',
    refresh_token: impersonatedRefreshToken,
    client_id: actorClientId,
    client_secret: actorClientSecret,
  }), {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  });

  const newAccessToken = refreshRes.data.access_token;
  console.log('🔄 Refreshed Access Token:', newAccessToken);

  expect(newAccessToken).not.toBeNull();
});
