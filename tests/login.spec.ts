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
  tags?: string[]; // Optional tags for categorization
  loginType: 'email' | 'username';
  identifier: string;
  password: string;
  keepMeLoggedIn: boolean;
  jumpUrl?: string;
  showGuest: boolean;
  acrValue?: string;
  newUsername?: string;
  newEmail?: string;
  secondNewUsername?: string; // Added for second change
  secondNewEmail?: string;    // Added for second change
}

const testCases: TestCase[] = [
  // Standard email login
  {
    tags:['login'],    
    loginType: 'username',
    identifier: 'playwright',
    password: 'P@$$w0rd@123',
    keepMeLoggedIn: true,
    jumpUrl: 'https://www.staples.com/checkout',
    showGuest: true,
  },
  {
    tags:['login'],
    loginType: 'email',
    identifier: 'playwright@staples.com',
    password: 'P@$$w0rd@123',
    keepMeLoggedIn: true,
    jumpUrl: 'https://www.staples.com/checkout',
    showGuest: true,
  },
  // ChangeUsername flow (user must already be logged in)
  {
    tags:['ChangeUsername'],
    loginType: 'email',
    identifier: 'playwright2@staples.com', // Initial identifier for seeding session
    password: 'P@$$w0rd@123',
    keepMeLoggedIn: false,
    showGuest: false,
    acrValue: '__staples_h_a_change_user_name',
    newUsername: `pw_first_new_user_${Date.now()}@staples-test.com`,  // First new username
    newEmail: `pw_first_new_email_${Date.now()}@staples-test.com`,    // First new email
    secondNewUsername: `pw_second_new_user_${Date.now()}@staples-test.com`, // Second new username
    secondNewEmail: `pw_second_new_email_${Date.now()}@staples-test.com`,   // Second new email
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
  if (!testInfo.title.includes('ACR=__staples_h_a_change_user_name')) {
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
  capturedTransactionIds = []; // Reset for each login attempt

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

    // --- SET COOKIE AND MODIFY URL BEFORE NAVIGATION ---
  const urlObject = new URL(authUrl);
  const cookieDomain = urlObject.hostname;
  const traceIdValue = crypto.randomUUID();

  const cookieToSet = {
    name: 'staples-cookie-trace-id', // Or just 'traceId' if that's preferred
    value: traceIdValue,
    domain: cookieDomain,
    path: '/',
    secure: urlObject.protocol === 'https:',
    httpOnly: true,
  };

  console.log(`🍪 Setting cookie: Name='${cookieToSet.name}', Value='${cookieToSet.value}', Domain='${cookieToSet.domain}'`);
  await page.context().addCookies([cookieToSet]);

  const queryStringParamName = 'staples-querystring-trace-id';
  urlObject.searchParams.set(queryStringParamName, traceIdValue);

  const modifiedAuthUrl = urlObject.href; // This is the URL to navigate to

  console.log(`🔗 Modified Auth URL with trace ID: ${modifiedAuthUrl}`);

  await page.goto(modifiedAuthUrl); // Use the modified URL here

  if (tc.tags?.includes('ChangeUsername')) {
    // ---- ChangeUsername flow ----
    expect(tc.newUsername).toBeDefined();
    expect(tc.newEmail).toBeDefined(); // Though not used in form, good to ensure data is present

    // Step 1: current password
    const pwInput = page.getByTestId('input-');
    await expect(pwInput).toBeVisible({ timeout: 15000 });
    await pwInput.fill(tc.password);
    await pwInput.press('Enter');

    // Step 2: new username
    const unInput = page.getByTestId('input-'); // Assumes same test-id for new username field
    await expect(unInput).toBeVisible({ timeout: 15000 });
    await unInput.fill(tc.newUsername!); // This will fill with tc.newUsername or tc.secondNewUsername depending on the call
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
    const timeout = setTimeout(() => reject(new Error('Timeout waiting for auth code')), 20000);
    const polling = setInterval(() => {
      if (server.capturedAuthCode) {
        clearTimeout(timeout);
        clearInterval(polling);
        const baseTid = capturedTransactionIds.length
          ? getBaseTransactionId(capturedTransactionIds[0]) // Get TID from the most recent login attempt
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
  if (tc.tags?.includes('ChangeUsername') && tc.secondNewUsername) {
    segments.push(`doubleChange=true`);
  }


  test(segments.join(' | '), async ({ page }, testInfo) => {
    console.log(`\n🎬 Starting test: ${tc.acrValue ?? tc.loginType} (PKCE: ${config.usePKCE})`);

    const openid = await fetchOpenIDConfig();
    const tokenUrl = openid.token_endpoint;
    const userinfoUrl = openid.userinfo_endpoint;
    const introspectionUrl = openid.introspection_endpoint;

    let seedTokens: any; // Reset seed tokens for each test
    let seedIdTokenPayload: any;
    let seedAccessTokenPayload: any;
    let seedSubFromToken: string | undefined;

    // If ChangeUsername, first do a standard login so ACR will see an existing session
    if (tc.tags?.includes('ChangeUsername')) {
      console.log('🔏 Seeding session with standard login');
      // For seed, use the original identifier, not newUsername/newEmail etc.
      const standardTc: TestCase = {
          ...tc, // Copy base properties
          acrValue: undefined, // Standard login, no ACR
          newUsername: undefined, // Not used for seed login
          newEmail: undefined, // Not used for seed login
          secondNewUsername: undefined, // Not used for seed login
          secondNewEmail: undefined, // Not used for seed login
          // Keep tc.identifier (original email/username for seed login)
          // Keep tc.password
          // Keep tc.keepMeLoggedIn for seed phase if needed (current ACR tc has it false)
          showGuest: false, // Typically not shown for programmatic seed
          jumpUrl: undefined, // No jump for seed
      };
      const { authUrl: loginUrl, codeVerifier: seedCodeVerifier } = await buildAuthUrl(openid.authorization_endpoint, standardTc);
      const { authCode: seedAuthCode } = await loginAndCaptureCode(page, loginUrl, standardTc);

      if (seedAuthCode) {
        seedTokens = await exchangeAuthCode(tokenUrl, seedAuthCode, seedCodeVerifier); // Pass optional seedCodeVerifier
        expect(seedTokens).toBeTruthy();
        expect(seedTokens.access_token).toBeTruthy();
        expect(seedTokens.id_token).toBeTruthy();

        if (seedTokens && seedTokens.access_token) {
          seedAccessTokenPayload = decodeJwt(seedTokens.access_token, 'Seed Access Token');
          seedIdTokenPayload = decodeJwt(seedTokens.id_token, 'Seed ID Token');
          expect(seedAccessTokenPayload).toBeTruthy();
          expect(seedIdTokenPayload).toBeTruthy();
          seedSubFromToken = seedAccessTokenPayload.sub;


          const seedIdTokenIntro = await introspectToken(
            introspectionUrl,
            seedTokens.id_token,
            config.clients.regular.clientId,
            config.clients.regular.clientSecret, // Using regular client's secret for its tokens
            "id_token"
          );
          if (seedIdTokenIntro) {
            console.log(`🔬 [Introspection] Raw result for Seed ID Token:`, seedIdTokenIntro);
            expect(seedIdTokenIntro.active).toBe(false); // ID Tokens often show as inactive on introspection
          }


          const seedAccessTokenIntro = await introspectToken(
            introspectionUrl,
            seedTokens.access_token,
            config.clients.regular.clientId,
            config.clients.regular.clientSecret, // Using regular client's secret for its tokens
            "access_token"
          );
          if (seedAccessTokenIntro) {
            console.log(`🔬 [Introspection] Raw result for Seed Access Token:`, seedAccessTokenIntro);
            expect(seedAccessTokenIntro.active).toBe(true);
            expect(seedAccessTokenIntro.client_id).toBe(config.clients.regular.clientId);
            expect(seedAccessTokenIntro.sub).toBe(seedSubFromToken);
            expect(seedAccessTokenIntro.username).toBe(seedSubFromToken); // Or user_id, depending on IdP
            expect(seedAccessTokenIntro.exp).toBeGreaterThan(Date.now() / 1000);
          }

          console.log('Seed User Access Token:', seedTokens.access_token);
          const seedUserInfo = await fetchUserInfo(userinfoUrl, seedTokens.access_token);
          if (seedUserInfo) {
            console.log(`ℹ️ [UserInfo] Raw result for Seed User:`, seedUserInfo);
            expect(seedUserInfo.sub).toBe(seedSubFromToken);
            expect(seedUserInfo.email).toBe(standardTc.identifier); // Seed user has original email
            if (seedIdTokenPayload) { // Username in UserInfo should match what was in the ID token from seed
                expect(seedUserInfo.user_name).toBe(seedIdTokenPayload.user_name);
            }
          }
        }
      }
    }

    // Now invoke the real flow (standard or FIRST ACR)
    console.log(`\n🎬🎬 Initiating main operation (Login or First ACR: ${tc.acrValue ?? tc.loginType}) using identifier: ${tc.identifier} and newUsername: ${tc.newUsername}`);
    const { authUrl, codeVerifier } = await buildAuthUrl(openid.authorization_endpoint, tc); // Uses original `tc` for first ACR or standard login
    const { authCode, transactionId: mainOpTransactionId } = await loginAndCaptureCode(page, authUrl, tc); // Uses original `tc`
    expect(authCode).toBeTruthy();

    // Exchange for tokens & assertions (for the FIRST change or standard login)
    const mainOpTokens = await exchangeAuthCode(tokenUrl, authCode, codeVerifier); // Pass optional codeVerifier

    const mainOpIdTokenDecoded = decodeJwt(mainOpTokens.id_token, 'ID Token (Main Op/First Change)');
    const mainOpAccessTokenDecoded = decodeJwt(mainOpTokens.access_token, 'Access Token (Main Op/First Change)');
    expect(mainOpTokens.access_token).toBeTruthy();
    expect(mainOpTokens.id_token).toBeTruthy();
    if (!tc.acrValue) expect(mainOpTokens.refresh_token).toBeTruthy();
    else expect(mainOpTokens.refresh_token).toBeTruthy();

    expect(mainOpIdTokenDecoded).toBeTruthy();
    expect(mainOpAccessTokenDecoded).toBeTruthy();
    const mainOpSubFromToken = mainOpAccessTokenDecoded.sub;


    if (mainOpTokens && mainOpTokens.id_token) {
      const mainOpIdTokenIntro = await introspectToken(
        introspectionUrl,
        mainOpTokens.id_token,
        config.clients.regular.clientId,
        config.clients.regular.clientSecret,
        "id_token"
      );
      if (mainOpIdTokenIntro) {
        console.log(`🔬 [Introspection] Raw result for Main Op ID Token:`, mainOpIdTokenIntro);
        expect(mainOpIdTokenIntro.active).toBe(false);
      }
    }

    if (mainOpTokens && mainOpTokens.access_token) {
      const mainOpAccessTokenIntro = await introspectToken(
        introspectionUrl,
        mainOpTokens.access_token,
        config.clients.regular.clientId,
        config.clients.regular.clientSecret,
        "access_token"
      );
      if (mainOpAccessTokenIntro) {
        console.log(`🔬 [Introspection] Raw result for Main Op Access Token:`, mainOpAccessTokenIntro);
        expect(mainOpAccessTokenIntro.active).toBe(true);
        expect(mainOpAccessTokenIntro.client_id).toBe(config.clients.regular.clientId);
        if (tc.tags?.includes('ChangeUsername') && seedSubFromToken) {
             expect(mainOpAccessTokenIntro.sub).toBe(seedSubFromToken);
             expect(mainOpAccessTokenIntro.username).toBe(seedSubFromToken); // Assuming username in AT introspection is sub
        } else {
            expect(mainOpAccessTokenIntro.sub).toBeDefined();
            expect(mainOpAccessTokenIntro.username).toBeDefined();
        }
        expect(mainOpAccessTokenIntro.exp).toBeGreaterThan(Date.now() / 1000);
      }

      console.log('Main Op Access Token:', mainOpTokens.access_token);
      const mainOpUserInfo = await fetchUserInfo(userinfoUrl, mainOpTokens.access_token);
      if (mainOpUserInfo) {
        console.log(`ℹ️ [UserInfo] Raw result for Main Op User:`, mainOpUserInfo);
        if (tc.tags?.includes('ChangeUsername') && seedSubFromToken) {
            expect(mainOpUserInfo.sub).toBe(seedSubFromToken);
        } else {
            expect(mainOpUserInfo.sub).toBeDefined();
        }

        if (tc.tags?.includes('ChangeUsername')) {
            expect(mainOpUserInfo.user_name).toBe(tc.newUsername); // After 1st change
            //expect(mainOpUserInfo.email).toBe(tc.newEmail);       // After 1st change
        } else { // Standard login
            expect(mainOpUserInfo.email).toBe(tc.identifier);
            if (mainOpIdTokenDecoded) {
                expect(mainOpUserInfo.user_name).toBe(mainOpIdTokenDecoded.user_name);
            }
        }
      }
    }

    // --- SECOND USERNAME CHANGE (if applicable) ---
    let secondChangeTokens: any;
    let secondChangeIdTokenDecoded: any;
    let secondChangeAccessTokenDecoded: any;

    if (tc.tags?.includes('ChangeUsername') && tc.secondNewUsername) {
        console.log(`\n🔄🔄 Initiating second username change to ${tc.secondNewUsername} (from ${tc.newUsername})`);

        // Prepare TestCase data for the second ACR invocation
        // The session is already established and reflects the first username change.
        // loginAndCaptureCode will use `newUsername` from this object to fill the form.
        const secondChangeTcData: TestCase = {
            ...tc, // Base on original tc to carry over password, etc.
            identifier: tc.newUsername!, // The "current" username of the user for IdP context, if needed by IdP before ACR form.
            newUsername: tc.secondNewUsername, // This is the target for the *second* change
            newEmail: tc.secondNewEmail,       // This is the target email for the *second* change
            acrValue: '__staples_h_a_change_user_name', // Crucial: still an ACR flow
            // Reset other params not relevant for pure ACR on second round
            jumpUrl: undefined,
            showGuest: false,
            secondNewUsername: undefined, // Prevent recursion if this object were reused
            secondNewEmail: undefined,
        };
        console.log(`   Data for second change: newUsername=${secondChangeTcData.newUsername}, newEmail=${secondChangeTcData.newEmail}`);

        const { authUrl: secondAuthUrl, codeVerifier: secondCodeVerifier } = await buildAuthUrl(openid.authorization_endpoint, secondChangeTcData);
        const { authCode: secondAuthCode, transactionId: secondChangeTransactionId } = await loginAndCaptureCode(page, secondAuthUrl, secondChangeTcData);
        expect(secondAuthCode).toBeTruthy();

        secondChangeTokens = await exchangeAuthCode(tokenUrl, secondAuthCode, secondCodeVerifier);
        secondChangeIdTokenDecoded = decodeJwt(secondChangeTokens.id_token, 'ID Token (Second Change)');
        secondChangeAccessTokenDecoded = decodeJwt(secondChangeTokens.access_token, 'Access Token (Second Change)');

        expect(secondChangeTokens.access_token).toBeTruthy();
        expect(secondChangeTokens.id_token).toBeTruthy();
        expect(secondChangeTokens.refresh_token).toBeTruthy(); // Assuming refresh token is still issued

        expect(secondChangeIdTokenDecoded).toBeTruthy();
        expect(secondChangeAccessTokenDecoded).toBeTruthy();

        // Assertions for the second change
        if (secondChangeIdTokenDecoded) {
            expect(secondChangeIdTokenDecoded.user_name).toBe(tc.secondNewUsername);
            expect(secondChangeIdTokenDecoded.acr).toBe('__staples_h_a_change_user_name');
        }
        console.log(`🏅 (Second Change) user_name in ID token verified as ${tc.secondNewUsername}`);

        // Introspect and UserInfo for second change tokens
        if (secondChangeTokens && secondChangeTokens.id_token) {
            const secondChangeIdTokenIntro = await introspectToken(
                introspectionUrl,
                secondChangeTokens.id_token,
                config.clients.regular.clientId,
                config.clients.regular.clientSecret,
                "id_token"
              );
              if (secondChangeIdTokenIntro) {
                console.log(`🔬 [Introspection] Raw result for Second Change ID Token:`, secondChangeIdTokenIntro);
                expect(secondChangeIdTokenIntro.active).toBe(false);
              }
        }
        if (secondChangeTokens && secondChangeTokens.access_token) {
            const secondChangeAccessTokenIntro = await introspectToken(
                introspectionUrl,
                secondChangeTokens.access_token,
                config.clients.regular.clientId,
                config.clients.regular.clientSecret,
                "access_token"
              );
              if (secondChangeAccessTokenIntro) {
                console.log(`🔬 [Introspection] Raw result for Second Change Access Token:`, secondChangeAccessTokenIntro);
                expect(secondChangeAccessTokenIntro.active).toBe(true);
                expect(secondChangeAccessTokenIntro.client_id).toBe(config.clients.regular.clientId);
                expect(secondChangeAccessTokenIntro.sub).toBe(seedSubFromToken); // Sub should remain constant
                expect(secondChangeAccessTokenIntro.username).toBe(seedSubFromToken); // Assuming username in AT is sub
                expect(secondChangeAccessTokenIntro.exp).toBeGreaterThan(Date.now() / 1000);
              }

            const secondChangeUserInfo = await fetchUserInfo(userinfoUrl, secondChangeTokens.access_token);
            if (secondChangeUserInfo) {
                console.log(`ℹ️ [UserInfo] Raw result for User (after Second Change):`, secondChangeUserInfo);
                expect(secondChangeUserInfo.sub).toBe(seedSubFromToken); // Sub should remain constant
                expect(secondChangeUserInfo.user_name).toBe(tc.secondNewUsername); // Username reflects second change
            }
        }

        if (secondChangeTransactionId) {
            appendTaskToLogQueue({ testTitle: `${testInfo.title} (Second Change)`, transactionId: secondChangeTransactionId });
        }
    }


    // Re-check seed tokens if they exist
    if (seedTokens && seedTokens.id_token) {
      const seedIdTokenIntroAgain = await introspectToken(introspectionUrl,
        seedTokens.id_token,
        config.clients.regular.clientId,
        config.clients.regular.clientSecret,
        "id_token"
      );
      if (seedIdTokenIntroAgain) {
        console.log(`🔬 [Introspection] Raw result for Seed ID Token (re-check):`, seedIdTokenIntroAgain);
        expect(seedIdTokenIntroAgain.active).toBe(false);
      }
    }

    if (seedTokens && seedTokens.access_token) {
      const seedAccessTokenIntroAgain = await introspectToken(
        introspectionUrl,
        seedTokens.access_token,
        config.clients.regular.clientId,
        config.clients.regular.clientSecret,
        "access_token"
      );
      if (seedAccessTokenIntroAgain) {
        console.log(`🔬 [Introspection] Raw result for Seed Access Token (re-check):`, seedAccessTokenIntroAgain);
        expect(seedAccessTokenIntroAgain.active).toBe(true);
        expect(seedAccessTokenIntroAgain.client_id).toBe(config.clients.regular.clientId);
        expect(seedAccessTokenIntroAgain.sub).toBe(seedSubFromToken);
        expect(seedAccessTokenIntroAgain.exp).toBeGreaterThan(Date.now() / 1000);
      }

      console.log('Seed User Access Token (re-check):', seedTokens.access_token);
      const seedUserInfoAgain = await fetchUserInfo(userinfoUrl, seedTokens.access_token);
      if (seedUserInfoAgain) {
        console.log(`ℹ️ [UserInfo] Raw result for Seed User (re-check):`, seedUserInfoAgain);
        expect(seedUserInfoAgain.sub).toBe(seedSubFromToken);

        // UserInfo reflects the *current* state of the user, so it should show the *latest* username/email
        if (tc.tags?.includes('ChangeUsername')) {
            if (tc.secondNewUsername) { // If a second change happened
                expect(seedUserInfoAgain.user_name).toBe(tc.secondNewUsername);
                
                //expect(seedUserInfoAgain.email).toBe(tc.secondNewEmail);
            } else { // Only the first change happened
                expect(seedUserInfoAgain.user_name).toBe(tc.newUsername);
                //expect(seedUserInfoAgain.email).toBe(tc.newEmail);
            }
        } else if (seedIdTokenPayload) { // Fallback to original seed username if not a change username flow
            expect(seedUserInfoAgain.user_name).toBe(seedIdTokenPayload.user_name);
            expect(seedUserInfoAgain.email).toBe(tc.identifier); // Original seed email
        }
      }
    }

    // Verify the username change succeeded (final state)
    if (tc.tags?.includes('ChangeUsername')) {
      if (tc.secondNewUsername && secondChangeIdTokenDecoded) {
          // If second change happened, the ID token from that flow has the final username
          expect(secondChangeIdTokenDecoded.user_name).toBe(tc.secondNewUsername);
          expect(secondChangeIdTokenDecoded.acr).toBe('__staples_h_a_change_user_name');
          console.log(`🏅 Final user_name was confirmed as ${tc.secondNewUsername} (after second change)`);
      } else if (mainOpIdTokenDecoded) {
          // Only first change happened (or no secondNewUsername was provided)
          expect(mainOpIdTokenDecoded.user_name).toBe(tc.newUsername);
          if (mainOpIdTokenDecoded) {
              expect(mainOpIdTokenDecoded.acr).toBe('__staples_h_a_change_user_name');
          }
          console.log(`🏅 Final user_name was confirmed as ${tc.newUsername} (after first change)`);
      }
    }

    // Queue logs for the main/first operation's transaction
    if (mainOpTransactionId) {
      appendTaskToLogQueue({ testTitle: testInfo.title, transactionId: mainOpTransactionId });
    }

    console.log(`✅ Test finished: ${testInfo.title}`);
  });
}