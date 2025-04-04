// auth-code-impersonation-refresh.spec.ts
import { test, expect } from '@playwright/test';
import axios from 'axios';
import qs from 'qs';
import fs from 'fs';
import https from 'https';
import { parse } from 'url';
import crypto from 'crypto';

const openidConfigUrl = 'https://openam-simeio2-demo.forgeblocks.com/am/oauth2/bravo/.well-known/openid-configuration';
const regularClientId = 'staples_tier_a_app_client_id';
const regularClientSecret = 'staples_tier_a_app_client_secret';
const rememberMeClientId = 'staples_tier_a_app_actor_client_id';
const rememberMeClientSecret = 'staples_tier_a_app_actor_client_secret';
const redirectUri = 'https://app.lab.com:3000/callback';
const PORT = 3000;
const HOST = '0.0.0.0';

// Helper to decode JWT
function decodeJwt(token: string, label: string) {
  const parts = token.split('.');
  if (parts.length !== 3) {
    console.warn(`Invalid JWT format for ${label}`);
    return;
  }
  try {
    const payloadStr = Buffer.from(parts[1], 'base64').toString('utf-8');
    const payload = JSON.parse(payloadStr);

    console.log(`Decoded ${label} Payload:`);
    console.log(JSON.stringify(payload, null, 2));

    if (payload.exp) {
      const expDate = new Date(payload.exp * 1000); // exp is in seconds
      console.log(`Expiration (exp): ${expDate.toUTCString()} (${expDate.toISOString()})`);
    }
  } catch (err) {
    console.error(`Failed to decode JWT for ${label}:`, err);
  }
}


test('Auth Code to Impersonation to Refresh (Verbose Logging)', async ({ page, browser }) => {
  let capturedAuthCode = '';

  console.log('Starting HTTPS listener for redirect...');
  const server = https.createServer({
    key: fs.readFileSync('certs/key.pem'),
    cert: fs.readFileSync('certs/cert.pem'),
  }, (req, res) => {
    const parsedUrl = parse(req.url ?? '', true);
    if (parsedUrl.pathname === '/callback' && parsedUrl.query.code) {
      capturedAuthCode = parsedUrl.query.code as string;
      console.log('Received auth code via redirect:', capturedAuthCode);

      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('Authentication successful. You can close this window.');

      server.close(() => console.log('HTTPS server closed'));
    } else {
      res.writeHead(404);
      res.end('Not Found');
    }
  });

  await new Promise<void>((resolve) => server.listen(PORT, HOST, resolve));
  console.log(`Listening at https://${HOST}:${PORT}/callback`);

  console.log('Fetching OpenID Connect configuration...');
  const { data: openidConfig } = await axios.get(openidConfigUrl);
  const authUrl = openidConfig.authorization_endpoint;
  const tokenUrl = openidConfig.token_endpoint;
  console.log('Authorization Endpoint:', authUrl);
  console.log('Token Endpoint:', tokenUrl);

  const state = crypto.randomBytes(16).toString('base64').replace(/[^a-zA-Z0-9]/g, '');
  const nonce = crypto.randomBytes(16).toString('base64').replace(/[^a-zA-Z0-9]/g, '');
  const scope = 'openid';

  const fullAuthUrl = `${authUrl}?` + qs.stringify({
    client_id: regularClientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope,
    state,
    nonce,
  });

  console.log('Navigating to auth URL...');
  await page.goto(fullAuthUrl);
  await page.getByTestId('fr-field-callback_1').getByTestId('input-').fill('playwright');
  await page.getByTestId('fr-field-callback_2').getByTestId('input-').fill('P@$$w0rd@123');
  await page.getByTestId('fr-field-callback_2').getByTestId('input-').press('Enter');

  console.log('Waiting for auth code from redirect...');
  await new Promise<void>((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('Timeout waiting for auth code')), 15000);
    const checkInterval = setInterval(() => {
      if (capturedAuthCode) {
        clearTimeout(timeout);
        clearInterval(checkInterval);
        resolve();
      }
    }, 500);
  });

  expect(capturedAuthCode).not.toBe('');

  console.log('Exchanging auth code for token (Regular Client)...');
  const tokenRes = await axios.post(tokenUrl, qs.stringify({
    grant_type: 'authorization_code',
    code: capturedAuthCode,
    redirect_uri: redirectUri,
    client_id: regularClientId,
    client_secret: regularClientSecret,
  }), {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  });

  const regularClientAccessToken = tokenRes.data.access_token;
  console.log('Regular Client Access Token:', regularClientAccessToken);
  decodeJwt(regularClientAccessToken, 'RegularClient Access Token');

  const regularClientRefreshToken = tokenRes.data.refresh_token;
  console.log('Regular Client Refresh Token:', regularClientRefreshToken);
  decodeJwt(regularClientRefreshToken, 'RegularClient Refresh Token');

  console.log('Exchanging token for RememberMe Client...');
  const impersonationRes = await axios.post(tokenUrl, qs.stringify({
    grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
    subject_token: regularClientAccessToken,
    subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
    client_id: rememberMeClientId,
    client_secret: rememberMeClientSecret,
    scope: 'transfer openid',
  }), {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  });

  const rememberMeClientAccessToken = impersonationRes.data.access_token;
  const rememberMeClientRefreshToken = impersonationRes.data.refresh_token;

  console.log('RememberMe Client Access Token:', rememberMeClientAccessToken);
  decodeJwt(rememberMeClientAccessToken, 'RememberMeClient Access Token');

  console.log('RememberMe Client Refresh Token:', rememberMeClientRefreshToken);
  decodeJwt(rememberMeClientRefreshToken, 'RememberMeClient Refresh Token');

  expect(rememberMeClientAccessToken).not.toBeNull();
  expect(rememberMeClientRefreshToken).not.toBeNull();

  console.log('Refreshing RememberMe Client token...');
  const refreshRes = await axios.post(tokenUrl, qs.stringify({
    grant_type: 'refresh_token',
    refresh_token: rememberMeClientRefreshToken,
    client_id: rememberMeClientId,
    client_secret: rememberMeClientSecret,
  }), {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  });

  const refreshedRememberMeClientAccessToken = refreshRes.data.access_token;
  console.log('Refreshed RememberMe Client Access Token:', refreshedRememberMeClientAccessToken);
  decodeJwt(refreshedRememberMeClientAccessToken, 'Refreshed RememberMeClient Access Token');

  expect(refreshedRememberMeClientAccessToken).not.toBeNull();

  console.log('Flow complete: Auth Code to Impersonation to Refresh');
});
