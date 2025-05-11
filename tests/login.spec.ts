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
    baseUrl: 'https://openam-staplesciam-use4-dev.id.forgerock.io', // Domain to clear cookies for
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
  monitoringApi: { // Added for monitoring API
    baseUrl: 'https://openam-staplesciam-use4-dev.id.forgerock.io/monitoring/logs',
    apiKey: '61d244ee890a4aae6d97f033f905eda2',
    apiSecret: '38ffee277dc1be87248724aead9e690b08245e97d759826eef1462017d4e9694',
    source: 'am-everything',
    pageSize: 1000,
  },
  logsDir: 'test-logs', // Added for storing logs
  logQueueFile: path.join('test-logs', 'log_fetch_queue.json'), // File to store pending log tasks
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
let capturedTransactionIds: string[] = []; // To store all captured transaction IDs per test

interface LogFetchTask {
  testTitle: string;
  transactionId: string;
}
// let allLogFetchTasks: LogFetchTask[] = []; // Store all transaction IDs to fetch logs for // Replaced by file queue


// ---------- COOKIE CLEARING HELPER ----------
async function clearAllCookiesForConfigDomain(page: Page) {
  const targetUrl = config.ping.baseUrl;
  if (!targetUrl) {
    console.warn('config.ping.baseUrl is not defined. Cannot clear cookies.');
    return;
  }
  // While page.context().clearCookies() clears all cookies for the context,
  // to be more precise for a specific domain as requested:
  console.log(`Clearing all cookies for the current browser context (which affects all domains).`);
  await page.context().clearCookies();
  // Playwright's `clearCookies()` clears cookies for the entire context.
  // If you need to be extremely precise and only clear for a specific domain (though clearCookies() is generally sufficient for test isolation):
  // const cookies = await page.context().cookies([targetUrl]);
  // for (const cookie of cookies) {
  //   // Construct a new cookie object with an expiry date in the past.
  //   // This method is more complex and usually not needed if context.clearCookies() is used.
  // }
  console.log(`All cookies for the current browser context have been cleared.`);
}


// ---------- SERVER LIFECYCLE ----------
test.beforeAll(async () => { // Made async for potential future needs
  console.log(`\n🌐 Starting HTTPS callback server on ${config.server.host}:${config.server.port}`);
  if (!fs.existsSync(config.logsDir)) {
    fs.mkdirSync(config.logsDir, { recursive: true });
    console.log(`📂 Created base logs directory: ${config.logsDir}`);
  }
  // Initialize/clear the log queue file at the beginning of the test suite
  try {
    fs.writeFileSync(config.logQueueFile, JSON.stringify([]), 'utf-8'); // Start with an empty array
    console.log(`📋 Initialized/Cleared log queue file: ${config.logQueueFile}`);
  } catch (err) {
    console.error(`❌ Error initializing log queue file ${config.logQueueFile}:`, err);
    // Depending on severity, you might want to throw err or handle it
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
  await new Promise<void>(resolve => server.close(() => resolve())); // Ensure server is fully closed
  console.log('🚪 Callback server shut down.');
  // Log queue file processing is handled by the 'Fetch All Collected Logs' test in a separate file.
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
  // transactionId is now managed by capturedTransactionIds array

  // Attach response listener to capture transaction ID from /authenticate endpoint
  page.on('response', async (response) => {
    const url = response.url();
    if (url.includes('/authenticate') || url.includes('/sessions?_action=logout')) { // Capture for auth and logout
      const header = response.headers()['x-forgerock-transactionid'];
      if (header) {
        console.log(`🆔 Captured x-forgerock-transactionid: ${header} from ${url}`);
        capturedTransactionIds.push(header);
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
        // Resolve with the first captured transactionId's base, if available
        const baseTransactionId = capturedTransactionIds.length > 0
            ? getBaseTransactionId(capturedTransactionIds[0])
            : undefined;
        resolve({
          authCode: server.capturedAuthCode as string, // Ensure it's a string
          transactionId: baseTransactionId,
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
      payload
    );
    if (exp) {
      console.log(`⏰ [JWT] Expiration: ${expDate?.toUTCString()} (${expDate?.toISOString()})`);
    }
  } catch (err) {
    console.error(`[JWT] Failed to decode ${label}:`, err);
  }
}

// ---------- LOG FETCHING HELPERS (NEW - only those needed by auth flows) ----------
function getBaseTransactionId(fullTransactionId: string): string | undefined {
  // Extracts the part before "-request-" or "-logout-" or returns if no suffix
  const match = fullTransactionId.match(/^([a-f0-9-]+)(?:-request-\d+|-logout-\d+)?$/i);
  return match ? match[1] : undefined;
}

// Helper to append a task to the queue file
function appendTaskToLogQueue(task: LogFetchTask) {
  try {
    let tasks: LogFetchTask[] = [];
    if (fs.existsSync(config.logQueueFile)) {
      const fileContent = fs.readFileSync(config.logQueueFile, 'utf-8');
      if (fileContent.trim() !== '') { // Ensure file is not empty before parsing
        try {
            tasks = JSON.parse(fileContent);
            if (!Array.isArray(tasks)) { // Basic validation that it's an array
                console.warn(`⚠️ Log queue file ${config.logQueueFile} does not contain a valid JSON array. Re-initializing for this append.`);
                tasks = []; // If not an array, start fresh for this operation
            }
        } catch (parseError) {
            console.error(`❌ Error parsing log queue file ${config.logQueueFile}. Re-initializing for this append. Error:`, parseError);
            tasks = []; // Re-initialize if parsing fails
        }
      }
    }
    tasks.push(task);
    fs.writeFileSync(config.logQueueFile, JSON.stringify(tasks, null, 2), 'utf-8'); // Pretty print for readability
    console.log(`📝 Appended task for TID ${task.transactionId} (Test: "${task.testTitle}") to ${config.logQueueFile}`);
  } catch (err) {
    console.error(`❌ Error appending task to log queue file ${config.logQueueFile}:`, err);
  }
}


// ---------- PARAMETRIZED TESTS ----------
for (const tc of testCases) {
  test(`Auth Flow | ${tc.loginType} | rememberMe=${tc.rememberMe} | jumpUrl=${tc.jumpUrl ?? 'none'} | showGuest=${tc.showGuest}`, async ({ page }, testInfo) => { // Added testInfo
    console.log(`\n🎬 Starting test case: ${JSON.stringify(tc)}`);
    const openid = await fetchOpenIDConfig();
    const authUrl = buildAuthUrl(openid.authorization_endpoint, tc);
    const tokenUrl = openid.token_endpoint;

    // Test case specific variables
    let mainTransactionId: string | undefined;

    try { // Wrap test logic in try-finally to ensure log fetching
        const { authCode, transactionId } = await loginAndCaptureCode(page, authUrl, tc);
        mainTransactionId = transactionId; // Store the primary transaction ID for log fetching
        console.log(`✅ Received auth code: ${authCode}`);
        console.log(`📎 Main Transaction ID for logs: ${mainTransactionId ?? 'Not found'}`);
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


        console.log('🍪 Checking session-jwt cookie');
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
        console.log('⚠️ Skipping RememberMe extended flows');
        }
    } finally {
        // Log fetching is no longer done here. Instead, we collect the info.
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
            // allLogFetchTasks.push({ testTitle: testInfo.title, transactionId: idToLog }); // Old way
            // console.log(`📝 Added transaction ID ${idToLog} from test "${testInfo.title}" to log fetching queue.`); // Old way
            appendTaskToLogQueue({ testTitle: testInfo.title, transactionId: idToLog });
        } else {
            console.error(`❌ No transaction ID to add to log fetching queue for test "${testInfo.title}".`);
        }
    }

    console.log(`✅✅ Test completed for: ${JSON.stringify(tc)}`);
  });
}

// ---------- FINAL TEST CASE FOR LOG FETCHING (MOVED TO fetch-logs.spec.ts) ----------
// The 'Fetch All Collected Logs' test case and its specific helpers (fetchAndSaveLogs, sanitizeTestName)
// have been moved to a separate file: fetch-logs.spec.ts