// auth-code-impersonation-refresh.spec.ts
import { test, expect, Page } from '@playwright/test';
import axios from 'axios';
import qs from 'qs';
import fs from 'fs';
import https from 'https';
import { parse, URL } from 'url'; // Added URL for hostname extraction
import crypto from 'crypto';
import path from 'path'; // Added for path manipulation

// ---------- CONFIGURATION ----------
const config = {
  ping: {
    baseUrl: 'https://identity-qe.staples.com', // Domain to clear cookies for
    realm: 'alpha',

    usePAR: false, // << SET THIS TO true TO TEST PAR, false FOR STANDARD FLOW >>
    parEndpoint: 'https://identity-qe.staples.com/am/oauth2/realms/root/realms/alpha/par', // Example PAR endpoint
  },
  clients: {
    regular: {
      clientId: 'staples_dotcom_application_client_id',
      clientSecret: 'staples_dotcom_application_client_secret',
    },
    keepMeLoggedIn: {
      clientId: 'staples_dotcom_application_remember_me_client_id',
      clientSecret: 'staples_dotcom_application_remember_me_client_secret',
    },
  },
  redirectUri: 'https://app-127-0-0-1.sslip.io:3000/callback',
  server: {
    host: '0.0.0.0',
    port: 3000,
  },
  monitoringApi: { // Added for monitoring API
    baseUrl: 'https://identity-qe.staples.com/monitoring/logs',
    apiKey: '61d244ee890a4aae6d97f033f905eda2',
    apiSecret: '38ffee277dc1be87248724aead9e690b08245e97d759826eef1462017d4e9694',
    source: 'am-everything',
    pageSize: 1000,
  },
  logsDir: 'test-logs', // Added for storing logs
  logQueueFile: path.join('test-logs', 'log_fetch_queue.json'), // File to store pending log tasks
};

// Permutations of loginType, keepMeLoggedIn, jumpUrl, showGuest
const testCases = [
  // email scenarios
  { loginType: 'email', identifier: 'playwright@staples.com', password: 'P@$$w0rd@123', keepMeLoggedIn: true, jumpUrl: 'https://www.staples.com/checkout', showGuest: true },
  { loginType: 'email', identifier: 'playwright@staples.com', password: 'P@$$w0rd@123', keepMeLoggedIn: false, jumpUrl: undefined, showGuest: false },
  // username scenarios
  { loginType: 'username', identifier: 'playwright', password: 'P@$$w0rd@123', keepMeLoggedIn: true, jumpUrl: 'https://www.staples.com/checkout', showGuest: true },
  { loginType: 'username', identifier: 'playwright', password: 'P@$$w0rd@123', keepMeLoggedIn: false, jumpUrl: undefined, showGuest: false },
];

let server: https.Server & { capturedAuthCode?: string };
let capturedTransactionIds: string[] = []; // To store all captured transaction IDs per test

interface LogFetchTask {
  testTitle: string;
  transactionId: string;
}

// ---------- COOKIE CLEARING HELPER ----------
async function clearAllCookiesForConfigDomain(page: Page) {
  const targetUrl = config.ping.baseUrl;
  if (!targetUrl) {
    console.warn('config.ping.baseUrl is not defined. Cannot clear cookies.');
    return;
  }
  console.log(`Clearing all cookies for the current browser context (which affects all domains).`);
  await page.context().clearCookies();
  console.log(`All cookies for the current browser context have been cleared.`);
}

// ---------- SERVER LIFECYCLE ----------
test.beforeAll(async () => { // Made async for potential future needs
  console.log(`\n🌐 Starting HTTPS callback server on ${config.server.host}:${config.server.port}`);
  if (!fs.existsSync(config.logsDir)) {
    fs.mkdirSync(config.logsDir, { recursive: true });
    console.log(`📂 Created base logs directory: ${config.logsDir}`);
  }
  try {
    fs.writeFileSync(config.logQueueFile, JSON.stringify([]), 'utf-8'); // Start with an empty array
    console.log(`📋 Initialized/Cleared log queue file: ${config.logQueueFile}`);
  } catch (err) {
    console.error(`❌ Error initializing log queue file ${config.logQueueFile}:`, err);
  }

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

test.afterAll(async () => { // Made async
  console.log('🛑 Shutting down callback server');
  await new Promise<void>(resolve => server.close(() => resolve()));
  console.log('🚪 Callback server shut down.');
});

test.beforeEach(async ({ page }) => { // Made async to await cookie clearing
  console.log('\n🧼 Clearing cookies and resetting captured transaction IDs for new test.');
  await clearAllCookiesForConfigDomain(page);
  capturedTransactionIds = []; // Reset for each test case
});

// ---------- HELPERS ----------
async function fetchOpenIDConfig() {
  const url = `${config.ping.baseUrl}/am/oauth2/${config.ping.realm}/.well-known/openid-configuration`;
  console.log(`\n📡 Fetching OpenID configuration from: ${url}`);
  const res = await axios.get(url);
  console.log(`✅ OpenID config fetched: authorization_endpoint=${res.data.authorization_endpoint}, pushed_authorization_request_endpoint=${res.data.pushed_authorization_request_endpoint}`);
  return res.data;
}

function generateRandomString(length: number): string {
  const possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
  const randomBytes = crypto.randomBytes(length);
  let result = "";
  for (let i = 0; i < length; i++) {
    result += possible.charAt(randomBytes[i] % possible.length);
  }
  return result;
}

function sha256(buffer: string | Buffer): Buffer {
  return crypto.createHash("sha256").update(buffer).digest();
}

function base64URLEncode(str: Buffer): string {
  return str.toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

interface PkceCodes {
  code_verifier: string;
  code_challenge: string;
  code_challenge_method: "S256";
}

function generatePkceChallenge(): PkceCodes {
  const verifier = generateRandomString(128);
  const challenge = base64URLEncode(sha256(verifier));
  return {
    code_verifier: verifier,
    code_challenge: challenge,
    code_challenge_method: "S256"
  };
}

// MODIFIED: buildAuthUrl to handle PAR and return codeVerifier
async function buildAuthUrl(
  authEndpoint: string, // Standard authorization endpoint
  tc: typeof testCases[0]
): Promise<{ authUrl: string; codeVerifier?: string }> {
  console.log(`\n🔐 Building auth URL for loginType=${tc.loginType}, keepMeLoggedIn=${tc.keepMeLoggedIn}, jumpUrl=${tc.jumpUrl}, usePAR=${config.ping.usePAR}`);
  const state = crypto.randomBytes(16).toString('hex');
  const nonce = crypto.randomBytes(16).toString('hex');
  let codeVerifierToReturn: string | undefined;

  if (config.ping.usePAR && config.ping.parEndpoint) {
    console.log('    🚀 Using Pushed Authorization Request (PAR) with PKCE');
    const pkce = generatePkceChallenge();
    codeVerifierToReturn = pkce.code_verifier;

    const parPayload: Record<string, any> = {
      client_id: config.clients.regular.clientId,
      client_secret: config.clients.regular.clientSecret,
      response_type: 'code',
      scope: 'openid profile email write',
      redirect_uri: config.redirectUri,
      code_challenge: pkce.code_challenge,
      code_challenge_method: pkce.code_challenge_method,
      //acr_values: '__staples_h_device_profile'
    };

    try {
      console.log(`    ➡️  Pushing to PAR endpoint: ${config.ping.parEndpoint}`);
      const loggableParPayload = { ...parPayload, client_secret: '********' };
      console.log(`    📋 PAR Payload: ${JSON.stringify(loggableParPayload)}`);
      const parResponse = await axios.post(
        config.ping.parEndpoint,
        qs.stringify(parPayload),
        { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
      );

      const { request_uri, expires_in } = parResponse.data;
      if (!request_uri) {
        throw new Error('PAR response did not include request_uri');
      }
      console.log(`    ✅ PAR successful: request_uri=${request_uri}, expires_in=${expires_in}`);

      const paramsForAuthorize: Record<string, any> = {
        client_id: config.clients.regular.clientId,
        request_uri: request_uri,
        //acr_values: '__staples_h_device_profile',
      };
      if (tc.jumpUrl) paramsForAuthorize.jumpUrl = tc.jumpUrl;
      if (tc.showGuest) paramsForAuthorize.showGuest = tc.showGuest;
      const finalAuthUrl = `${authEndpoint}?${qs.stringify(paramsForAuthorize)}`;
      console.log(`    🌍 Full auth URL (via PAR): ${finalAuthUrl}`);
      return { authUrl: finalAuthUrl, codeVerifier: codeVerifierToReturn };
    } catch (error: any) {
      console.error('    ❌ PAR request failed:', error.response?.data || error.message);
      console.warn('    ⚠️ Falling back to standard authorization flow due to PAR failure. PKCE might not be applied in this fallback.');
    }
  }

  // Standard (non-PAR) flow or PAR fallback
  console.log('    🛡️ Using standard authorization flow (PKCE not applied in this path unless manually added)');
  const params: Record<string, any> = {
    client_id: config.clients.regular.clientId,
    redirect_uri: config.redirectUri,
    response_type: 'code',
    scope: 'openid profile email',
    state,
    nonce,
    showGuest: tc.showGuest,
    //acr_values: '__staples_h_device_profile'
  };
  if (tc.jumpUrl) params.jumpUrl = tc.jumpUrl;

  const standardAuthUrl = `${authEndpoint}?${qs.stringify(params)}`;
  console.log(`    🌍 Full auth URL (standard): ${standardAuthUrl}`);
  return { authUrl: standardAuthUrl, codeVerifier: codeVerifierToReturn };
}

async function loginAndCaptureCode(
  page: Page,
  authUrl: string,
  tc: typeof testCases[0]
): Promise<{ authCode: string; transactionId?: string }> {
  console.log(`\n🚀 Navigating to Auth URL and performing login for ${tc.identifier}`);
  server.capturedAuthCode = undefined;
  capturedTransactionIds = [];

  // Attach response listener to capture transaction ID headers
  page.on('response', async (response) => {
    const url = response.url();
    if (url.includes('/authenticate') || url.includes('/sessions?_action=logout')) {
      const header = response.headers()['x-forgerock-transactionid'];
      if (header) {
        console.log(`🆔 Captured x-forgerock-transactionid: ${header} from ${url}`);
        capturedTransactionIds.push(header);
      }
    }
  });

  page.context().grantPermissions(['geolocation'], {
    origin: config.ping.baseUrl
  });

  // (optional) stub a location so that JS `navigator.geolocation.getCurrentPosition()` returns data
  page.context().setGeolocation({ latitude: 37.7749, longitude: -122.4194 });


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

  if (!tc.keepMeLoggedIn) {
    console.log('🗑️  Unchecking Keep Me Logged In');
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
        const baseTransactionId = capturedTransactionIds.length > 0
          ? getBaseTransactionId(capturedTransactionIds[0])
          : undefined;
        resolve({ authCode: server.capturedAuthCode!, transactionId: baseTransactionId });
      }
    }, 500);
  });
}

async function exchangeAuthCode(
  tokenEndpoint: string,
  code: string,
  codeVerifier?: string
) {
  console.log(`\n🔁 Exchanging auth code at: ${tokenEndpoint}`);
  const payload: Record<string, any> = {
    grant_type: 'authorization_code',
    code,
    redirect_uri: config.redirectUri,
    client_id: config.clients.regular.clientId,
    client_secret: config.clients.regular.clientSecret,
  };
  if (codeVerifier) {
    payload.code_verifier = codeVerifier;
    console.log('    🔑 Including code_verifier in token exchange.');
  } else {
    console.log('    ⚠️ No code_verifier provided for token exchange (PKCE not used).');
  }
  const res = await axios.post(
    tokenEndpoint,
    qs.stringify(payload),
    { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
  );
  console.log(`✅ Token response received: ${JSON.stringify(res.data, null, 2)}`);
  return res.data;
}

async function exchangeToken(tokenEndpoint: string, data: Record<string, any>) {
  console.log(`🔄 Exchanging token with payload: ${JSON.stringify(data)}`);
  const res = await axios.post(
    tokenEndpoint,
    qs.stringify(data),
    { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
  );
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
    const exp = payload.exp;
    const expDate = exp ? new Date(exp * 1000) : null;
    console.log(`🔍 [JWT] Decoded ${label}:`, payload);
    if (exp) {
      console.log(`⏰ [JWT] Expiration: ${expDate?.toUTCString()} (${expDate?.toISOString()})`);
    }
  } catch (err) {
    console.error(`[JWT] Failed to decode ${label}:`, err);
  }
}

function getBaseTransactionId(fullTransactionId: string): string | undefined {
  const match = fullTransactionId.match(/^([a-f0-9-]+)(?:-request-\d+|-logout-\d+)?$/i);
  return match ? match[1] : undefined;
}

function appendTaskToLogQueue(task: LogFetchTask) {
  try {
    let tasks: LogFetchTask[] = [];
    if (fs.existsSync(config.logQueueFile)) {
      const fileContent = fs.readFileSync(config.logQueueFile, 'utf-8');
      if (fileContent.trim()) {
        tasks = JSON.parse(fileContent);
        if (!Array.isArray(tasks)) tasks = [];
      }
    }
    tasks.push(task);
    fs.writeFileSync(config.logQueueFile, JSON.stringify(tasks, null, 2), 'utf-8');
    console.log(`📝 Appended task for TID ${task.transactionId} (Test: "${task.testTitle}") to ${config.logQueueFile}`);
  } catch (err) {
    console.error(`❌ Error appending task to log queue file ${config.logQueueFile}:`, err);
  }
}

// ---------- PARAMETRIZED TESTS ----------
for (const tc of testCases) {
  test(`Auth Flow | ${tc.loginType} | PAR=${config.ping.usePAR} | keepMeLoggedIn=${tc.keepMeLoggedIn} | jumpUrl=${tc.jumpUrl ?? 'none'} | showGuest=${tc.showGuest}`, async ({ page }, testInfo) => {
    console.log(`\n🎬 Starting test case: ${JSON.stringify(tc)} | PAR enabled: ${config.ping.usePAR}`);
    const openid = await fetchOpenIDConfig();
    const tokenUrl = openid.token_endpoint;

    const { authUrl, codeVerifier } = await buildAuthUrl(openid.authorization_endpoint, tc);
    if (codeVerifier) {
      console.log(`    🔑 PKCE code_verifier generated (will be used in token exchange)`);
    } else if (config.ping.usePAR) {
      console.warn(`    ⚠️ PAR was enabled, but no code_verifier returned. Check PAR response.`);
    }

    let mainTransactionId: string | undefined;

    try {
      const { authCode, transactionId } = await loginAndCaptureCode(page, authUrl, tc);
      mainTransactionId = transactionId;
      console.log(`✅ Received auth code: ${authCode}`);
      console.log(`📎 Main Transaction ID for logs: ${mainTransactionId ?? 'Not found'}`);
      expect(authCode).toBeTruthy();

      const regularTokenResponse = await exchangeAuthCode(tokenUrl, authCode, codeVerifier);
      // decode regular tokens
      decodeJwt(regularTokenResponse.access_token, 'Regular Access Token');
      decodeJwt(regularTokenResponse.refresh_token, 'Regular Refresh Token');
      decodeJwt(regularTokenResponse.id_token, 'Regular ID Token');

      // assert regular tokens
      expect(regularTokenResponse.access_token).toBeTruthy();
      expect(regularTokenResponse.refresh_token).toBeTruthy();
      expect(regularTokenResponse.id_token).toBeTruthy();

      // keepMeLoggedIn assertion
      console.log(`🔒 Asserting keepMeLoggedIn flag: expected=${tc.keepMeLoggedIn}`);
      if (tc.keepMeLoggedIn) {
        expect(regularTokenResponse.keep_me_logged_in).toBe('true');
      } else {
        expect(regularTokenResponse.keep_me_logged_in === 'false' ||
               regularTokenResponse.keep_me_logged_in === undefined).toBe(true);
      }

      // jumpUrl assertion
      console.log(`🚀 Asserting jumpUrl: expected=${tc.jumpUrl}`);
      if (tc.jumpUrl) {
        expect(regularTokenResponse.jump_url).toBe(tc.jumpUrl);
      } else {
        expect(regularTokenResponse).not.toHaveProperty('jump_url');
      }

      // conditional KeepMeLoggedIn flows
      if (tc.keepMeLoggedIn && regularTokenResponse.keep_me_logged_in === 'true') {
        console.log('🛡️ Performing KeepMeLoggedIn token exchange for extended session');
        const keepMeLoggedInResponse = await exchangeToken(tokenUrl, {
          grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
          subject_token: regularTokenResponse.access_token,
          subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
          client_id: config.clients.keepMeLoggedIn.clientId,
          client_secret: config.clients.keepMeLoggedIn.clientSecret,
          scope: 'transfer openid email profile',
        });
        // decode KeepMeLoggedIn tokens
        decodeJwt(keepMeLoggedInResponse.access_token, 'KeepMeLoggedIn Access Token');
        decodeJwt(keepMeLoggedInResponse.refresh_token, 'KeepMeLoggedIn Refresh Token');

        // assert KeepMeLoggedIn tokens
        expect(keepMeLoggedInResponse.access_token).toBeTruthy();
        expect(keepMeLoggedInResponse.refresh_token).toBeTruthy();

        // assert extended refresh token TTL (~180 days)
        const payload = JSON.parse(Buffer.from(keepMeLoggedInResponse.refresh_token.split('.')[1], 'base64').toString('utf8'));
        const now = Math.floor(Date.now() / 1000);
        const ttl = payload.exp - now;
        console.log(`⏳ KeepMeLoggedIn Refresh Token TTL (seconds): ${ttl}`);
        expect(ttl).toBeGreaterThan(15500000);

        console.log('🔄 Performing KeepMeLoggedIn token refresh');
        const refreshedKeepMeLoggedInResponse = await exchangeToken(tokenUrl, {
          grant_type: 'refresh_token',
          refresh_token: keepMeLoggedInResponse.refresh_token,
          client_id: config.clients.keepMeLoggedIn.clientId,
          client_secret: config.clients.keepMeLoggedIn.clientSecret,
        });
        decodeJwt(refreshedKeepMeLoggedInResponse.access_token, 'Refreshed KeepMeLoggedIn Access Token');
        decodeJwt(refreshedKeepMeLoggedInResponse.id_token, 'Refreshed KeepMeLoggedIn ID Token');

        // assert refreshed tokens
        expect(refreshedKeepMeLoggedInResponse.access_token).toBeTruthy();
        expect(refreshedKeepMeLoggedInResponse.id_token).toBeTruthy();

        console.log('🍪 Checking session-jwt and trusted-device cookies');
        const cookies = await page.context().cookies(config.ping.baseUrl);
        console.log(`🔑 Retrieved cookies: ${JSON.stringify(cookies)}`);

        const sessionCookie = cookies.find(c => c.name === 'session-jwt');
        console.log(`🍪 session-jwt cookie: ${JSON.stringify(sessionCookie)}`);
        expect(sessionCookie).toBeDefined();
        expect(sessionCookie?.value).toBeTruthy();

        const trustedDeviceCookie = cookies.find(c => c.name === 'fr-trusted-device-identifier');
        console.log(`🍪 fr-trusted-device-identifier cookie: ${JSON.stringify(trustedDeviceCookie)}`);
        expect(trustedDeviceCookie).toBeDefined();
        expect(trustedDeviceCookie?.value).toBeTruthy();
      } else {
        console.log('⚠️ Skipping KeepMeLoggedIn extended flows');
      }
    } finally {
      let idToLog: string | undefined = mainTransactionId;
      if (!idToLog && capturedTransactionIds.length > 0) {
        const firstBaseId = getBaseTransactionId(capturedTransactionIds[0]);
        if (firstBaseId) {
          console.warn(`⚠️ Main transaction ID not explicitly set for "${testInfo.title}", using first captured base ID: ${firstBaseId} for log collection.`);
          idToLog = firstBaseId;
        } else {
          console.error(`❌ Could not determine a base transaction ID to collect for "${testInfo.title}".`);
        }
      }

      if (idToLog) {
        appendTaskToLogQueue({ testTitle: testInfo.title, transactionId: idToLog });
      } else {
        console.error(`❌ No transaction ID to add to log fetching queue for test "${testInfo.title}".`);
      }
    }

    console.log(`✅✅ Test completed for: ${JSON.stringify(tc)}`);
  });
}
