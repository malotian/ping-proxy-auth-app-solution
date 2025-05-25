// auth-code-impersonation-refresh.spec.ts
import { test, expect, Page } from '@playwright/test';
import axios from 'axios';
import qs from 'qs';
import fs from 'fs';
import https from 'https';
import { parse, URL } from 'url';
import crypto from 'crypto';
import path from 'path';

// ---------- CONFIGURATION ----------
const config = {
  usePKCE: false, // New flag to control PKCE usage
  ping: {
    baseUrl: 'https://identity-qe.staples.com',
    realm: 'alpha',
  },
  clients: {
    regular: {
      clientId: 'staples_dotcom_application_client_id',
      clientSecret: 'staples_dotcom_application_client_secret', // Will not be used for auth code grant / PAR (if PKCE is true)
    },
    keepMeLoggedIn: {
      clientId: 'staples_dotcom_application_remember_me_client_id',
      clientSecret: 'staples_dotcom_application_remember_me_client_secret',
    },
  },
  redirectUri: 'https://app-127-0-0-1.sslip.io:3000/callback',
  server: { host: '0.0.0.0', port: 3000 },
  monitoringApi: {
    baseUrl: 'https://identity-qe.staples.com/monitoring/logs',
    apiKey: '61d244ee890a4aae6d97f033f905eda2',
    apiSecret: '38ffee277dc1be87248724aead9e690b08245e97d759826eef1462017d4e9694',
    source: 'am-everything',
    pageSize: 1000,
  },
  logsDir: 'test-logs',
  logQueueFile: path.join('test-logs', 'log_fetch_queue.json'),
};

interface TestCase {
  loginType: 'email' | 'username';
  identifier: string;
  password: string;
  keepMeLoggedIn: boolean;
  jumpUrl?: string;
  showGuest: boolean;
  acrValue?: string;
  newUsername?: string;
  newEmail?: string;
}

const testCases: TestCase[] = [
  // Standard email login
  {
    loginType: 'username',
    identifier: 'playwright',
    password: 'P@$$w0rd@123',
    keepMeLoggedIn: true,
    jumpUrl: 'https://www.staples.com/checkout',
    showGuest: true,
  },
  {
    loginType: 'email',
    identifier: 'playwright@staples.com',
    password: 'P@$$w0rd@123',
    keepMeLoggedIn: true,
    jumpUrl: 'https://www.staples.com/checkout',
    showGuest: true,
  },
  // Change-Username flow (user must already be logged in)
  {
    loginType: 'email',
    identifier: 'playwright2@staples.com',
    password: 'P@$$w0rd@123',
    keepMeLoggedIn: false,
    showGuest: false,
    acrValue: 'Staples_ChangeUsername',
    newUsername: `pw_new_user_${Date.now()}@staples-test.com`,
    newEmail: `pw_new_email_${Date.now()}@staples-test.com`,
  },
];

let server: https.Server & { capturedAuthCode?: string };
let capturedTransactionIds: string[] = [];

interface LogFetchTask {
  testTitle: string;
  transactionId: string;
}

// Helper to wipe cookies if needed
async function clearAllCookiesForConfigDomain(page: Page) {
  const targetUrl = config.ping.baseUrl;
  if (!targetUrl) return;
  console.log(`🧼 Clearing cookies for ${targetUrl}`);
  await page.context().clearCookies();
}

// ---------- SERVER LIFECYCLE ----------
test.beforeAll(async () => {
  console.log(`🌐 Starting HTTPS callback server on ${config.server.host}:${config.server.port}`);
  if (!fs.existsSync(config.logsDir)) {
    fs.mkdirSync(config.logsDir, { recursive: true });
    console.log(`📂 Created logs directory: ${config.logsDir}`);
  }
  fs.writeFileSync(config.logQueueFile, JSON.stringify([]), 'utf-8');
  console.log(`📋 Initialized log queue at ${config.logQueueFile}`);

  server = https.createServer(
    {
      key: fs.readFileSync('certs/key.pem'),
      cert: fs.readFileSync('certs/cert.pem'),
    },
    (req, res) => {
      console.log(`🔔 Callback request: ${req.method} ${req.url}`);
      const urlObj = parse(req.url || '', true);
      if (urlObj.pathname === '/callback' && urlObj.query.code) {
        server.capturedAuthCode = urlObj.query.code as string;
        console.log(`✅ Captured auth code: ${server.capturedAuthCode}`);
        res.writeHead(200).end('OK');
      } else {
        console.log(`⚠️  Ignored path or missing code: ${urlObj.pathname}`);
        res.writeHead(404).end();
      }
    }
  ).listen(config.server.port, config.server.host, () =>
    console.log(`🛡️  Server listening at https://${config.server.host}:${config.server.port}/callback`)
  );
});

test.afterAll(async () => {
  console.log('🛑 Shutting down callback server');
  await new Promise<void>(r => server.close(() => r()));
  console.log('🚪 Server stopped');
});

test.beforeEach(async ({ page }, testInfo) => {
  // Only clear cookies if not running Change_Username, so that ACR test can reuse session
  if (!testInfo.title.includes('ACR=Staples_ChangeUsername')) {
    await clearAllCookiesForConfigDomain(page);
  }
  capturedTransactionIds = [];
});

// ---------- OIDC & PKCE HELPERS ----------
async function fetchOpenIDConfig() {
  const url = `${config.ping.baseUrl}/am/oauth2/${config.ping.realm}/.well-known/openid-configuration`;
  console.log(`📡 Fetching OIDC config from ${url}`);
  const res = await axios.get(url);
  return res.data;
}

function generateRandomString(length: number): string {
  const possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
  const bytes = crypto.randomBytes(length);
  return Array.from(bytes)
    .map(b => possible[b % possible.length])
    .join('');
}

function sha256(buf: string | Buffer) {
  return crypto.createHash('sha256').update(buf).digest();
}

function base64URLEncode(buf: Buffer) {
  return buf.toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

interface PkceCodes {
  code_verifier: string;
  code_challenge: string;
  code_challenge_method: 'S256';
}

function generatePkceChallenge(): PkceCodes {
  const verifier = generateRandomString(128);
  return {
    code_verifier: verifier,
    code_challenge: base64URLEncode(sha256(verifier)),
    code_challenge_method: 'S256',
  };
}

async function introspectToken(
  introspectionEndpoint: string,
  token: string,
  clientId: string,
  clientSecret: string,
  token_type_hint: string
  // label: string = 'Token' // Parameter removed
) {
  if (!introspectionEndpoint) {
    console.warn(`[Introspection] Introspection endpoint not configured. Skipping.`); // Removed label from log
    return null;
  }
  if (!token) {
    console.warn(`[Introspection] No token provided. Skipping introspection.`); // Removed label from log
    return null;
  }
  console.log(`\n🧐 Introspecting token at ${introspectionEndpoint}`); // Removed label from log
  try {
    const payload = {
      token: token,
      client_id: clientId,
      client_secret: clientSecret, // Introspection often requires client auth
      token_type_hint: token_type_hint, // Optional, but good practice
    };
    const res = await axios.post(introspectionEndpoint, qs.stringify(payload), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    });
    // console.log(`🔬 [Introspection] Raw result for ${label}:`, res.data); // Removed internal raw result log
    return res.data; // Return raw data
  } catch (error: any) {
    console.error(`🔥 [Introspection] Error introspecting token:`, error.response?.data || error.message); // Removed label from log
    return null;
  }
}

async function fetchUserInfo(userInfoEndpoint: string, accessToken: string /*, label: string = 'User' */) { // Parameter removed
  if (!userInfoEndpoint) {
    console.warn(`[UserInfo] UserInfo endpoint not configured. Skipping.`); // Removed label from log
    return null;
  }
  if (!accessToken) {
    console.warn(`[UserInfo] No access token provided. Skipping UserInfo fetch.`); // Removed label from log
    return null;
  }
  console.log(`\n🧑 Fetching UserInfo from ${userInfoEndpoint}`); // Removed label from log
  try {
    const res = await axios.get(userInfoEndpoint, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    // console.log(`ℹ️ [UserInfo] Raw result for ${label}:`, res.data); // Removed internal raw result log
    return res.data; // Return raw data
  } catch (error: any) {
    console.error(`🔥 [UserInfo] Error fetching UserInfo:`, error.response?.data || error.message); // Removed label from log
    return null;
  }
}

// Build the authorization URL, returns PKCE verifier if PKCE is used
async function buildAuthUrl(
  authEndpoint: string,
  tc: TestCase
): Promise<{ authUrl: string; codeVerifier?: string }> { // codeVerifier is now optional
  console.log(`\n🔐 Building auth URL (ACR=${tc.acrValue ?? 'none'}, PKCE=${config.usePKCE})`);
  const state = crypto.randomBytes(16).toString('hex');
  const nonce = crypto.randomBytes(16).toString('hex');
  let codeVerifierToReturn: string | undefined;

  const params: Record<string, any> = {
    client_id: config.clients.regular.clientId,
    redirect_uri: config.redirectUri,
    response_type: 'code',
    scope: 'openid profile email write',
    state,
    nonce,
  };

  if (config.usePKCE) {
    const pkce = generatePkceChallenge();
    codeVerifierToReturn = pkce.code_verifier;
    params.code_challenge = pkce.code_challenge;
    params.code_challenge_method = pkce.code_challenge_method;
    console.log('    🛡️ Building standard auth URL with PKCE');
  } else {
    console.log('    🛡️ Building standard auth URL without PKCE (will use client_secret at token endpoint)');
    // No PKCE params added if config.usePKCE is false
  }


  if (!tc.acrValue) {
    params.showGuest = tc.showGuest;
    if (tc.jumpUrl) params.jumpUrl = tc.jumpUrl;
  }
  if (tc.acrValue) params.acr_values = tc.acrValue;

  const url = `${authEndpoint}?${qs.stringify(params)}`;
  console.log(`    🌍 Standard auth URL: ${url}`);
  return { authUrl: url, codeVerifier: codeVerifierToReturn };
}

// Navigate, fill forms (including geolocation), capture code + TID
async function loginAndCaptureCode(
  page: Page,
  authUrl: string,
  tc: TestCase
): Promise<{ authCode: string; transactionId?: string }> {
  console.log(`\n🚀 Navigating to ${authUrl}`);
  server.capturedAuthCode = undefined;
  capturedTransactionIds = [];

  page.on('response', async (response) => {
    const url = response.url();
    if (url.includes('/authenticate')) {
      const header = response.headers()['x-forgerock-transactionid'];
      if (header) {
        console.log(`🆔 Captured x-forgerock-transactionid: ${header}`);
        capturedTransactionIds.push(header);
      }
    }
  });

  // Grant & set a fixed geo-location so behavior is deterministic
  await page.context().grantPermissions(['geolocation'], { origin: config.ping.baseUrl });
  await page.context().setGeolocation({ latitude: 37.7749, longitude: -122.4194 });

  await page.goto(authUrl);

  if (tc.acrValue === 'Staples_ChangeUsername') {
    // ---- Change-Username flow ----
    expect(tc.newUsername).toBeDefined();
    expect(tc.newEmail).toBeDefined();

    // Step 1: current password
    const pwInput = page.getByTestId('input-');
    await expect(pwInput).toBeVisible({ timeout: 15000 });
    await pwInput.fill(tc.password);
    await pwInput.press('Enter');

    // Step 2: new username
    const unInput = page.getByTestId('input-');
    await expect(unInput).toBeVisible({ timeout: 15000 });
    await unInput.fill(tc.newUsername!);
    await unInput.press('Enter');

  } else {
    // ---- Standard login flow ----
    if (tc.showGuest) {
      await expect(page.getByRole('link', { name: 'Shop as Guest' })).toBeVisible();
      await expect(page.locator('#go-back-link')).toContainText('Return to Cart');
    } else {
      await expect(page.getByRole('link', { name: 'Shop as Guest' })).toBeHidden();
      await expect(page.locator('#go-back-link')).toContainText('Continue Shopping');
    }

    await page.getByTestId('fr-field-callback_1').getByTestId('input-').fill(tc.identifier);
    await page.getByTestId('fr-field-callback_2').getByTestId('input-').fill(tc.password);
    if (!tc.keepMeLoggedIn) {
      await page.getByTestId('fr-field-Keep me logged in').locator('label').click();
    }
    await page.getByTestId('fr-field-callback_2').getByTestId('input-').press('Enter');
  }

  // Wait up to 15s for callback server to capture code
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('Timeout waiting for auth code')), 15000);
    const polling = setInterval(() => {
      if (server.capturedAuthCode) {
        clearTimeout(timeout);
        clearInterval(polling);
        const baseTid = capturedTransactionIds.length
          ? getBaseTransactionId(capturedTransactionIds[0])
          : undefined;
        resolve({ authCode: server.capturedAuthCode!, transactionId: baseTid });
      }
    }, 500);
  });
}

async function exchangeAuthCode(tokenEndpoint: string, code: string, codeVerifier?: string) { // codeVerifier is now optional
  console.log(`\n🔁 Exchanging code at ${tokenEndpoint} (PKCE=${config.usePKCE})`);
  const payload: any = {
    grant_type: 'authorization_code',
    code,
    redirect_uri: config.redirectUri,
    client_id: config.clients.regular.clientId, // Uses 'regular' client
  };

  if (config.usePKCE) {
    if (!codeVerifier) {
      // This should not happen if buildAuthUrl correctly returns a verifier when usePKCE is true
      console.error('🔥 PKCE is enabled, but no code_verifier was provided to exchangeAuthCode.');
      throw new Error('PKCE enabled, but code_verifier is missing for token exchange.');
    }
    payload.code_verifier = codeVerifier;
    console.log('    🔑 Using PKCE verifier');
    // For PKCE, client_secret is typically NOT sent for public clients.
    // If 'regular' client is confidential AND uses PKCE, it might send client_secret.
    // The current code (and common practice for public clients) omits it.
  } else {
    // Standard authorization_code flow for a confidential client (requires client_secret)
    payload.client_secret = config.clients.regular.clientSecret;
    console.log('    🔑 Using client_secret (PKCE is false)');
  }

  const res = await axios.post(tokenEndpoint, qs.stringify(payload), {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  });
  console.log(`✅ Token response: ${JSON.stringify(res.data)}`);
  return res.data;
}

function decodeJwt(token: string, label: string) {
  if (!token) {
    console.warn(`[JWT] Token for ${label} is undefined or empty. Skipping decoding.`);
    return null; // Return null if token is not present
  }
  const parts = token.split('.');
  if (parts.length !== 3) {
    console.warn(`[JWT] Invalid format for ${label}`);
    return null;
  }
  try {
    const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString('utf8'));
    const exp = payload.exp;
    const expDate = exp ? new Date(exp * 1000) : null;
    console.log(`🔍 [JWT] Decoded ${label}:`, payload);
    if (exp) {
      console.log(`⏰ [JWT] Expiration: ${expDate?.toUTCString()} (${expDate?.toISOString()})`);
    }
    return payload; // Return decoded payload
  } catch (err) {
    console.error(`[JWT] Failed to decode ${label}:`, err);
    return null;
  }
}

function getBaseTransactionId(fullTid: string): string {
  const m = fullTid.match(/^([a-f0-9-]+)(?:-[a-z]+-\d+)?$/i);
  return m ? m[1] : fullTid;
}

function appendTaskToLogQueue(task: LogFetchTask) {
  let tasks: LogFetchTask[] = [];
  if (fs.existsSync(config.logQueueFile)) {
    const txt = fs.readFileSync(config.logQueueFile, 'utf-8').trim();
    tasks = txt ? JSON.parse(txt) : [];
  }
  tasks.push(task);
  fs.writeFileSync(config.logQueueFile, JSON.stringify(tasks, null, 2), 'utf-8');
  console.log(`📝 Queued log fetch for TID ${task.transactionId}`);
}

// ---------- PARAMETRIZED TESTS ----------
for (const tc of testCases) {
  const segments = [
    'Auth Flow',
    tc.acrValue ? `ACR=${tc.acrValue}` : `LoginType=${tc.loginType}`,
    `PKCE=${config.usePKCE}`, // Added PKCE status to test name
    `keepMeLoggedIn=${tc.keepMeLoggedIn}`,
  ];
  if (!tc.acrValue) {
    segments.push(`jumpUrl=${tc.jumpUrl ?? 'none'}`, `showGuest=${tc.showGuest}`);
  }

  test(segments.join(' | '), async ({ page }, testInfo) => {
    console.log(`\n🎬 Starting test: ${tc.acrValue ?? tc.loginType} (PKCE: ${config.usePKCE})`);

    const openid = await fetchOpenIDConfig();
    const tokenUrl = openid.token_endpoint;
    const userinfoUrl = openid.userinfo_endpoint;
    const introspectionUrl = openid.introspection_endpoint;

    let seedTokens; // Reset seed tokens for each test
    // If Change-Username, first do a standard login so ACR will see an existing session
    if (tc.acrValue === 'Staples_ChangeUsername') {
      console.log('🔏 Seeding session with standard login');
      const standardTc: TestCase = { ...tc, acrValue: undefined };
      const { authUrl: loginUrl, codeVerifier: seedCodeVerifier } = await buildAuthUrl(openid.authorization_endpoint, standardTc);
      const { authCode: seedAuthCode } = await loginAndCaptureCode(page, loginUrl, standardTc);

      if (seedAuthCode) {
        seedTokens = await exchangeAuthCode(tokenUrl, seedAuthCode, seedCodeVerifier); // Pass optional seedCodeVerifier
        if (seedTokens && seedTokens.access_token) {
          decodeJwt(seedTokens.access_token, 'Seed Access Token');
          decodeJwt(seedTokens.id_token, 'Seed ID Token');

          const seedIdTokenIntro = await introspectToken(
            introspectionUrl,
            seedTokens.id_token,
            config.clients.regular.clientId,
            config.clients.regular.clientSecret, // Using regular client's secret for its tokens
            "id_token"
            // 'Seed ID Token' // Label removed
          );
          if (seedIdTokenIntro) {
            console.log(`🔬 [Introspection] Raw result for Seed ID Token:`, seedIdTokenIntro);
          }


          const seedAccessTokenIntro = await introspectToken(
            introspectionUrl,
            seedTokens.access_token,
            config.clients.regular.clientId,
            config.clients.regular.clientSecret, // Using regular client's secret for its tokens
            "access_token"
            // 'Seed Access Token' // Label removed
          );
          if (seedAccessTokenIntro) {
            console.log(`🔬 [Introspection] Raw result for Seed Access Token:`, seedAccessTokenIntro);
          }

          console.log('Seed User Access Token:', seedTokens.access_token);
          const seedUserInfo = await fetchUserInfo(userinfoUrl, seedTokens.access_token /*, 'Seed User' */); // Label removed
          if (seedUserInfo) {
            console.log(`ℹ️ [UserInfo] Raw result for Seed User:`, seedUserInfo);
          }
        }
      }
    }

    // Now invoke the real flow (standard or ACR)
    const { authUrl, codeVerifier } = await buildAuthUrl(openid.authorization_endpoint, tc);
    const { authCode, transactionId } = await loginAndCaptureCode(page, authUrl, tc);
    expect(authCode).toBeTruthy();

    // Exchange for tokens & assertions
    const tokens = await exchangeAuthCode(tokenUrl, authCode, codeVerifier); // Pass optional codeVerifier
    decodeJwt(tokens.access_token, 'Access Token');
    decodeJwt(tokens.id_token, 'ID Token');
    expect(tokens.access_token).toBeTruthy();
    expect(tokens.id_token).toBeTruthy();
    if (!tc.acrValue) expect(tokens.refresh_token).toBeTruthy();

    if (tokens && tokens.id_token) {
      const mainIdTokenIntro = await introspectToken(
        introspectionUrl,
        tokens.id_token,
        config.clients.regular.clientId,
        config.clients.regular.clientSecret, // Using regular client's secret for its tokens
        "id_token"
        // 'Main ID Token' // Label removed
      );
      if (mainIdTokenIntro) {
        console.log(`🔬 [Introspection] Raw result for Main ID Token:`, mainIdTokenIntro);
      }
    }

    if (tokens && tokens.access_token) {
      const mainAccessTokenIntro = await introspectToken(
        introspectionUrl,
        tokens.access_token,
        config.clients.regular.clientId,
        config.clients.regular.clientSecret, // Using regular client's secret for its tokens
        "access_token"
        // 'Main Access Token' // Label removed
      );
      if (mainAccessTokenIntro) {
        console.log(`🔬 [Introspection] Raw result for Main Access Token:`, mainAccessTokenIntro);
      }

      console.log('Main User Access Token:', tokens.access_token);
      const mainUserInfo = await fetchUserInfo(userinfoUrl, tokens.access_token /*, 'Main User' */); // Label removed
      if (mainUserInfo) {
        console.log(`ℹ️ [UserInfo] Raw result for Main User:`, mainUserInfo);
      }
    }

    // This block seems redundant as it re-introspects and re-fetches seed user info.
    // However, I will keep it as per "don't change comments or anything else" and to match the original structure.
    // If it was intended to re-validate after the main flow, the state might have changed (e.g. if tokens were revoked).
    if (seedTokens && seedTokens.id_token) {
      const seedIdTokenIntroAgain = await introspectToken(introspectionUrl,
        seedTokens.id_token,
        config.clients.regular.clientId,
        config.clients.regular.clientSecret, // Using regular client's secret for its tokens
        "id_token"
        // 'Seed ID Token' // Label removed
      );
      if (seedIdTokenIntroAgain) {
        console.log(`🔬 [Introspection] Raw result for Seed ID Token (re-check):`, seedIdTokenIntroAgain);
      }
    }

    if (seedTokens && seedTokens.access_token) {
      const seedAccessTokenIntroAgain = await introspectToken(
        introspectionUrl,
        seedTokens.access_token,
        config.clients.regular.clientId,
        config.clients.regular.clientSecret, // Using regular client's secret for its tokens
        "access_token"
        // 'Seed Access Token' // Label removed
      );
      if (seedAccessTokenIntroAgain) {
        console.log(`🔬 [Introspection] Raw result for Seed Access Token (re-check):`, seedAccessTokenIntroAgain);
      }

      console.log('Seed User Access Token:', seedTokens.access_token);
      const seedUserInfoAgain = await fetchUserInfo(userinfoUrl, seedTokens.access_token /*, 'Seed User' */); // Label removed
      if (seedUserInfoAgain) {
        console.log(`ℹ️ [UserInfo] Raw result for Seed User (re-check):`, seedUserInfoAgain);
      }
    }

    // Verify the username change succeeded
    if (tc.acrValue === 'Staples_ChangeUsername') {
      const idPayload = JSON.parse(Buffer.from(tokens.id_token.split('.')[1], 'base64').toString('utf8'));
      expect(idPayload.user_name).toBe(tc.newUsername);
      console.log(`🏅 user_name was updated to ${tc.newUsername}`);
    }

    // Queue logs for later retrieval
    if (transactionId) {
      appendTaskToLogQueue({ testTitle: testInfo.title, transactionId });
    }

    console.log(`✅ Test finished: ${testInfo.title}`);
  });
}