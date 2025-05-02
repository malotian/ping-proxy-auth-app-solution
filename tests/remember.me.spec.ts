// auth-code-impersonation-refresh.spec.ts
import { test, expect } from '@playwright/test';
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
  rememberMe: true,
  loginFromCheckout: true,
  jumpUrl: 'https://www.staples.com/checkout',
};

const openidConfigUrl = `${config.ping.baseUrl}/am/oauth2/${config.ping.realm}/.well-known/openid-configuration`;

// ---------- UTILITIES ----------
function decodeJwt(token: string, label: string) {
  const parts = token.split('.');
  if (parts.length !== 3) {
    console.warn(`[JWT] Invalid format for ${label}`);
    return;
  }
  try {
    const payloadStr = Buffer.from(parts[1], 'base64').toString('utf-8');
    const payload = JSON.parse(payloadStr);
    console.log(`\n🔍 [JWT] Decoded Payload for ${label}:\n${JSON.stringify(payload, null, 2)}`);

    if (payload.exp) {
      const expDate = new Date(payload.exp * 1000);
      console.log(`⏰ [JWT] Expiration: ${expDate.toUTCString()} (${expDate.toISOString()})`);
    }
  } catch (err) {
    console.error(`[JWT] Failed to decode ${label}:`, err);
  }
}

// ---------- MAIN TEST ----------
test('🔁 Full Auth Flow: Auth Code ➝ Impersonation ➝ Refresh ➝ Cookie Validation (Conditional)', async ({ page }) => {
  let capturedAuthCode = '';

  console.log(`\n🚀 Starting test with config:`);
  console.log(JSON.stringify(config, null, 2));

  // Start HTTPS server for redirect handling
  console.log(`\n🌐 Setting up HTTPS listener on https://${config.server.host}:${config.server.port}/callback`);
  const server = https.createServer({
    key: fs.readFileSync('certs/key.pem'),
    cert: fs.readFileSync('certs/cert.pem'),
  }, (req, res) => {
    const parsedUrl = parse(req.url ?? '', true);
    if (parsedUrl.pathname === '/callback' && parsedUrl.query.code) {
      capturedAuthCode = parsedUrl.query.code as string;
      console.log(`✅ Received auth code: ${capturedAuthCode}`);
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('Authentication successful. You can close this window.');
      server.close(() => console.log('🛑 HTTPS server closed'));
    } else {
      res.writeHead(404).end('Not Found');
    }
  });

  await new Promise<void>((resolve) => server.listen(config.server.port, config.server.host, resolve));

  // Fetch OpenID config
  console.log(`\n📡 Fetching OpenID configuration from:\n${openidConfigUrl}`);
  const { data: openidConfig } = await axios.get(openidConfigUrl);
  //console.log(`✅ OpenID Config:\n${JSON.stringify(openidConfig, null, 2)}`);

  const authUrl = openidConfig.authorization_endpoint;
  const tokenUrl = openidConfig.token_endpoint;

  console.log(`\n🔐 Auth Endpoint: ${authUrl}`);
  console.log(`🔑 Token Endpoint: ${tokenUrl}`);

  // Construct auth URL
  const state = crypto.randomBytes(16).toString('hex');
  const nonce = crypto.randomBytes(16).toString('hex');
  const fullAuthUrl = `${authUrl}?${qs.stringify({
    client_id: config.clients.regular.clientId,
    redirect_uri: config.redirectUri,
    response_type: 'code',
    scope: 'openid profile email',
    state,
    nonce,
    ...(config.jumpUrl ? { jumpUrl: config.jumpUrl } : {}),
    ...(config.loginFromCheckout ? { showGuest: true } : {})
  })}`;

  console.log(`\n🌍 Navigating to Auth URL:\n${fullAuthUrl}`);
  await page.goto(fullAuthUrl);
  await page.getByTestId('fr-field-callback_1').getByTestId('input-').fill('playwright');
  await page.getByTestId('fr-field-callback_2').getByTestId('input-').fill('P@$$w0rd@123');

  if (!config.rememberMe) {
    //uncheck box if we are not testing rember me
    await page.getByTestId('fr-field-Keep me logged in').locator('label').click();
  }
  await page.getByTestId('fr-field-callback_2').getByTestId('input-').press('Enter');

  // Wait for redirect capture
  console.log(`\n⏳ Waiting for redirect with auth code...`);
  await new Promise<void>((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('Timeout waiting for auth code')), 15000);
    const interval = setInterval(() => {
      if (capturedAuthCode) {
        clearTimeout(timeout);
        clearInterval(interval);
        resolve();
      }
    }, 500);
  });

  expect(capturedAuthCode).not.toBe('');

  // Exchange auth code for tokens
  console.log(`\n🔁 Exchanging auth code for tokens at:\n${tokenUrl}`);
  const tokenRes = await axios.post(tokenUrl, qs.stringify({
    grant_type: 'authorization_code',
    code: capturedAuthCode,
    redirect_uri: config.redirectUri,
    client_id: config.clients.regular.clientId,
    client_secret: config.clients.regular.clientSecret,
  }), {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  });

  console.log(`✅ Token Response:\n${JSON.stringify(tokenRes.data, null, 2)}`);

  const {
    access_token: regularAccessToken,
    refresh_token: regularRefreshToken,
    id_token: regularIdToken,
    remember_me: rememberMe,
  } = tokenRes.data;

  decodeJwt(regularAccessToken, 'Regular Access Token');
  decodeJwt(regularRefreshToken, 'Regular Refresh Token');
  decodeJwt(regularIdToken, 'Regular ID Token');

  expect(regularAccessToken).toBeTruthy();
  expect(regularRefreshToken).toBeTruthy();
  expect(regularIdToken).toBeTruthy();

  console.log(`rememberMe: ${rememberMe}`);

  if (!config.rememberMe) {
    expect(rememberMe === 'false' || rememberMe === undefined).toBe(true);
  } else {
    expect(rememberMe).toBe('true');
  }

  if (rememberMe === 'true') {
    // Impersonation (token exchange)
    console.log(`\n🔁 Performing token exchange for RememberMe client...`);
    const impersonationRes = await axios.post(tokenUrl, qs.stringify({
      grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
      subject_token: regularAccessToken,
      subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
      client_id: config.clients.rememberMe.clientId,
      client_secret: config.clients.rememberMe.clientSecret,
      scope: 'transfer openid email profile',
    }), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    });

    console.log(`✅ Impersonation Token Response:\n${JSON.stringify(impersonationRes.data, null, 2)}`);

    const {
      access_token: rememberMeAccessToken,
      refresh_token: rememberMeRefreshToken,
      id_token: rememberMeIdToken,
    } = impersonationRes.data;

    decodeJwt(rememberMeAccessToken, 'RememberMe Access Token');
    decodeJwt(rememberMeRefreshToken, 'RememberMe Refresh Token');

    expect(rememberMeAccessToken).toBeTruthy();
    expect(rememberMeRefreshToken).toBeTruthy();

    // Refresh RememberMe token
    console.log(`\n🔄 Refreshing RememberMe token...`);
    const refreshRes = await axios.post(tokenUrl, qs.stringify({
      grant_type: 'refresh_token',
      refresh_token: rememberMeRefreshToken,
      client_id: config.clients.rememberMe.clientId,
      client_secret: config.clients.rememberMe.clientSecret,
    }), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    });

    console.log(`✅ Refresh Token Response:\n${JSON.stringify(refreshRes.data, null, 2)}`);

    const {
      access_token: refreshedAccessToken,
      id_token: refreshedIdToken,
    } = refreshRes.data;

    decodeJwt(refreshedAccessToken, 'Refreshed RememberMe Access Token');
    decodeJwt(refreshedIdToken, 'Refreshed RememberMe ID Token');

    expect(refreshedAccessToken).toBeTruthy();
    expect(refreshedIdToken).toBeTruthy();

    // Validate persistent cookie
    console.log(`\n🍪 Checking for session-jwt cookie on domain: ${config.ping.baseUrl}`);
    const cookies = await page.context().cookies(config.ping.baseUrl);
    const sessionCookie = cookies.find(c => c.name === 'session-jwt');

    console.log(`✅ Cookie found:\n${JSON.stringify(sessionCookie, null, 2)}`);
    expect(sessionCookie).toBeDefined();
    expect(sessionCookie?.value).toBeTruthy();
  } else {
    console.log(`⚠️ remember_me is false or not set — skipping impersonation, refresh, and cookie check.`);
  }

  console.log(`\n✅✅ Flow completed successfully.`);
});
