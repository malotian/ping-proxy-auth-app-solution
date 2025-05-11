// auth-code-impersonation-refresh.spec.ts
import { test, expect, Page } from '@playwright/test';
import axios from 'axios';
import qs from 'qs';
import fs from 'fs';
import https from 'https';
import { parse } from 'url';
import crypto from 'crypto';

// ---------- CONFIGURATION ----------
const config = {
  ping: {
    baseUrl: 'https://openam-staplesciam-use4-dev.id.forgerock.io',
    realm: 'alpha',
  },
  clients: {
    regular: {
      clientId: 'staples_dotcom_application_client_id',
      clientSecret: 'staples_dotcom_application_client_secret',
    },
    rememberMe: {
      clientId: 'staples_dotcom_application_remember_me_client_id',
      clientSecret: 'staples_dotcom_application_remember_me_client_secret',
    },
  },
  redirectUri: 'https://app-127-0-0-1.sslip.io:3000/callback',
  server: {
    host: '0.0.0.0',
    port: 3000,
  },
};

// Permutations of loginType, rememberMe, jumpUrl, showGuest
const testCases = [
  // email scenarios
  { loginType: 'email', identifier: 'playwright@staples.com', password: 'P@$$w0rd@123', rememberMe: true, jumpUrl: 'https://www.staples.com/checkout', showGuest: true },
  { loginType: 'email', identifier: 'playwright@staples.com', password: 'P@$$w0rd@123', rememberMe: true, jumpUrl: 'https://www.staples.com/checkout', showGuest: false },
  { loginType: 'email', identifier: 'playwright@staples.com', password: 'P@$$w0rd@123', rememberMe: false, jumpUrl: undefined, showGuest: true },
  { loginType: 'email', identifier: 'playwright@staples.com', password: 'P@$$w0rd@123', rememberMe: false, jumpUrl: undefined, showGuest: false },
  // username scenarios
  { loginType: 'username', identifier: 'playwright', password: 'P@$$w0rd@123', rememberMe: true, jumpUrl: 'https://www.staples.com/checkout', showGuest: true },
  { loginType: 'username', identifier: 'playwright', password: 'P@$$w0rd@123', rememberMe: true, jumpUrl: 'https://www.staples.com/checkout', showGuest: false },
  { loginType: 'username', identifier: 'playwright', password: 'P@$$w0rd@123', rememberMe: false, jumpUrl: undefined, showGuest: true },
  { loginType: 'username', identifier: 'playwright', password: 'P@$$w0rd@123', rememberMe: false, jumpUrl: undefined, showGuest: false },
];

let server: https.Server & { capturedAuthCode?: string };

// ---------- SERVER LIFECYCLE ----------
test.beforeAll(() => {
  console.log(`\n🌐 Starting HTTPS callback server on ${config.server.host}:${config.server.port}`);
  server = https.createServer(
    { key: fs.readFileSync('certs/key.pem'), cert: fs.readFileSync('certs/cert.pem') },
    (req, res) => {
      console.log(`🔔 Received HTTP request: ${req.method} ${req.url}`);
      const urlObj = parse(req.url || '', true);
      if (urlObj.pathname === '/callback' && urlObj.query.code) {
        server.capturedAuthCode = urlObj.query.code as string;
        console.log(`✅ Captured auth code: ${server.capturedAuthCode}`);
        res.writeHead(200).end('OK');
      } else {
        console.log(`⚠️  Unhandled request path or missing code: ${urlObj.pathname}`);
        res.writeHead(404).end();
      }
    }
  ).listen(config.server.port, config.server.host, () =>
    console.log(`🛡️  Callback server listening at https://${config.server.host}:${config.server.port}/callback`)
  );
});

test.afterAll(() => {
  console.log('🛑 Shutting down callback server');
  server.close();
});

// ---------- HELPERS ----------
async function fetchOpenIDConfig() {
  const url = `${config.ping.baseUrl}/am/oauth2/${config.ping.realm}/.well-known/openid-configuration`;
  console.log(`\n📡 Fetching OpenID configuration from: ${url}`);
  const res = await axios.get(url);
  console.log(`✅ OpenID config fetched: authorization_endpoint=${res.data.authorization_endpoint}`);
  return res.data;
}

function buildAuthUrl(authEndpoint: string, tc: typeof testCases[0]) {
  console.log(`\n🔐 Building auth URL for loginType=${tc.loginType}, rememberMe=${tc.rememberMe}, jumpUrl=${tc.jumpUrl}`);
  const state = crypto.randomBytes(16).toString('hex');
  const nonce = crypto.randomBytes(16).toString('hex');
  const params: Record<string, any> = {
    client_id: config.clients.regular.clientId,
    redirect_uri: config.redirectUri,
    response_type: 'code',
    scope: 'openid profile email',
    state,
    nonce,
    showGuest: tc.showGuest,
    acr_values: '__staples_h_device_profile'
  };
  if (tc.jumpUrl) {
    params.jumpUrl = tc.jumpUrl;
    console.log(`➡️  Including jumpUrl param: ${tc.jumpUrl}`);
  }
  const url = `${authEndpoint}?${qs.stringify(params)}`;
  console.log(`🌍 Full auth URL: ${url}`);
  return url;
}

async function loginAndCaptureCode(
  page: Page,
  authUrl: string,
  tc: typeof testCases[0]
): Promise<{ authCode: string; transactionId?: string }> {

  console.log(`\n🚀 Navigating to Auth URL and performing login for ${tc.identifier}`);
  server.capturedAuthCode = undefined;
  let transactionId: string | undefined;

  // Attach response listener to capture transaction ID from /authenticate endpoint
  page.on('response', async (response) => {
    const url = response.url();
    if (url.includes('/authenticate')) {
      const header = response.headers()['x-forgerock-transactionid'];
      if (header) {
        transactionId = header;
        console.log(`🆔 Captured x-forgerock-transactionid: ${transactionId}`);
      }
    }
  });

  await page.goto(authUrl);

  if (tc.showGuest) {
    await expect(page.getByRole('link', { name: 'Shop as Guest' })).toBeVisible();
    await expect(page.locator('#go-back-link')).toContainText('Return to Cart');
    await expect(page.getByRole('link', { name: 'Return to Cart' })).toBeVisible();
  } else {
    await expect(page.getByRole('link', { name: 'Shop as Guest' })).toBeHidden();
    await expect(page.locator('#go-back-link')).toContainText('Continue Shopping');
    await expect(page.getByRole('link', { name: 'Continue Shopping' })).toBeVisible();
  }

  console.log('⌨️  Filling identifier and password');
  await page.getByTestId('fr-field-callback_1').getByTestId('input-').fill(tc.identifier);
  await page.getByTestId('fr-field-callback_2').getByTestId('input-').fill(tc.password);

  if (!tc.rememberMe) {
    console.log('🗑️  Unchecking Remember Me');
    await page.getByTestId('fr-field-Keep me logged in').locator('label').click();
  }

  console.log('↩️  Submitting credentials');
  await page.getByTestId('fr-field-callback_2').getByTestId('input-').press('Enter');

  console.log('⏳ Waiting for callback to capture auth code');
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('Timeout waiting for auth code')), 15000);
    const interval = setInterval(() => {
      if (server.capturedAuthCode) {
        clearTimeout(timeout);
        clearInterval(interval);
        resolve({
          authCode: server.capturedAuthCode,
          transactionId,
        });
      }
    }, 500);
  });
}

async function exchangeAuthCode(tokenEndpoint: string, code: string) {
  console.log(`\n🔁 Exchanging auth code at: ${tokenEndpoint}`);
  const res = await axios.post(
    tokenEndpoint,
    qs.stringify({
      grant_type: 'authorization_code',
      code,
      redirect_uri: config.redirectUri,
      client_id: config.clients.regular.clientId,
      client_secret: config.clients.regular.clientSecret,
    }),
    { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
  );
  console.log(`✅ Token response received: ${JSON.stringify(res.data, null, 2)}`);
  return res.data;
}

async function exchangeToken(tokenEndpoint: string, data: Record<string, any>) {
  console.log(`🔄 Exchanging token with payload: ${JSON.stringify(data)}`);
  const res = await axios.post(tokenEndpoint, qs.stringify(data), { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
  console.log(`✅ Exchange response: ${JSON.stringify(res.data, null, 2)}`);
  return res.data;
}

function decodeJwt(token: string, label: string) {
  const parts = token.split('.');
  if (parts.length !== 3) {
    console.warn(`[JWT] Invalid format for ${label}`);
    return;
  }
  try {
    const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString('utf8'));
    // Append payload.exp and calculate expiration date
    const exp = payload.exp;
    const expDate = exp ? new Date(exp * 1000) : null;
    console.log(
      `🔍 [JWT] Decoded ${label}:`,
      payload,
      exp != null ? `| exp: ${exp} | expDate: ${expDate?.toUTCString()} (${expDate?.toISOString()})` : ''
    );
    if (exp) {
      console.log(`⏰ [JWT] Expiration: ${expDate?.toUTCString()} (${expDate?.toISOString()})`);
    }
  } catch (err) {
    console.error(`[JWT] Failed to decode ${label}:`, err);
  }
}

async function assertCookie(page: Page) {
  console.log('🍪 Checking session-jwt cookie');
  const cookies = await page.context().cookies(config.ping.baseUrl);
  const session = cookies.find(c => c.name === 'session-jwt');
  console.log(`🔑 Retrieved cookies: ${JSON.stringify(cookies)}`);
  expect(session).toBeDefined();
  expect(session?.value).toBeTruthy();
}

// ---------- PARAMETRIZED TESTS ----------
for (const tc of testCases) {
  test(`Auth Flow | ${tc.loginType} | rememberMe=${tc.rememberMe} | jumpUrl=${tc.jumpUrl ?? 'none'} | showGuest=${tc.showGuest}`, async ({ page }) => {
    console.log(`\n🎬 Starting test case: ${JSON.stringify(tc)}`);
    const openid = await fetchOpenIDConfig();
    const authUrl = buildAuthUrl(openid.authorization_endpoint, tc);
    const tokenUrl = openid.token_endpoint;

    const { authCode, transactionId } = await loginAndCaptureCode(page, authUrl, tc);
    console.log(`✅ Received auth code: ${authCode}`);
    console.log(`📎 Transaction ID: ${transactionId ?? 'Not found'}`);
    expect(authCode).toBeTruthy();

    const tokenRes = await exchangeAuthCode(tokenUrl, authCode);
    // decode regular tokens
    decodeJwt(tokenRes.access_token, 'Regular Access Token');
    decodeJwt(tokenRes.refresh_token, 'Regular Refresh Token');
    decodeJwt(tokenRes.id_token, 'Regular ID Token');

    // assert regular tokens
    expect(tokenRes.access_token).toBeTruthy();
    expect(tokenRes.refresh_token).toBeTruthy();
    expect(tokenRes.id_token).toBeTruthy();

    // rememberMe assertion
    console.log(`🔒 Asserting rememberMe flag: expected=${tc.rememberMe}`);
    if (tc.rememberMe) {
      expect(tokenRes.remember_me).toBe('true');
    } else {
      expect(tokenRes.remember_me === 'false' || tokenRes.remember_me === undefined).toBe(true);
    }

    // jumpUrl assertion
    console.log(`🚀 Asserting jumpUrl: expected=${tc.jumpUrl}`);

    if (tc.jumpUrl) {
      expect(tokenRes.jump_url).toBe(tc.jumpUrl);
    } else {
      expect(tokenRes).not.toHaveProperty('jump_url');
    }

    // conditional RememberMe token exchange & extended refresh assert
    if (tc.rememberMe && tokenRes.remember_me === 'true') {
      console.log('🛡️ Performing RememberMe token exchange for extended session');
      const rm = await exchangeToken(tokenUrl, {
        grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
        subject_token: tokenRes.access_token,
        subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
        client_id: config.clients.rememberMe.clientId,
        client_secret: config.clients.rememberMe.clientSecret,
        scope: 'transfer openid email profile',
      });
      // decode RememberMe tokens
      decodeJwt(rm.access_token, 'RememberMe Access Token');
      decodeJwt(rm.refresh_token, 'RememberMe Refresh Token');
      //decodeJwt(rm.id_token, 'RememberMe ID Token');

      // assert RememberMe tokens
      expect(rm.access_token).toBeTruthy();
      expect(rm.refresh_token).toBeTruthy();
      //expect(rm.id_token).toBeTruthy();

      // assert extended refresh token TTL (~180 days)
      const payload = JSON.parse(Buffer.from(rm.refresh_token.split('.')[1], 'base64').toString('utf8'));
      const now = Math.floor(Date.now() / 1000);
      const ttl = payload.exp - now;
      console.log(`⏳ RememberMe Refresh Token TTL (seconds): ${ttl}`);
      expect(ttl).toBeGreaterThan(15500000); // ~180 days

      console.log('🔄 Performing RememberMe token refresh');
      const ref = await exchangeToken(tokenUrl, {
        grant_type: 'refresh_token',
        refresh_token: rm.refresh_token,
        client_id: config.clients.rememberMe.clientId,
        client_secret: config.clients.rememberMe.clientSecret,
      });
      // decode refreshed RememberMe tokens
      decodeJwt(ref.access_token, 'Refreshed RememberMe Access Token');
      decodeJwt(ref.id_token, 'Refreshed RememberMe ID Token');

      // assert refreshed RememberMe tokens
      expect(ref.access_token).toBeTruthy();
      expect(ref.id_token).toBeTruthy();

      await assertCookie(page);
    } else {
      console.log('⚠️ Skipping RememberMe extended flows');
    }

    console.log(`✅✅ Test completed for: ${JSON.stringify(tc)}`);
  });
}
