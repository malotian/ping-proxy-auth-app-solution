import { test, expect, Page, TestInfo } from '@playwright/test';
import fs from 'fs';
import path from 'path';

// ---------- CONFIGURATION ----------
const config = {
  ping: {
    baseUrl: 'https://identity-qe.staples.com',
  },
  logsDir: 'test-logs',
  logQueueFile: path.join('test-logs', 'log-fetch-queue.json'),
};

// ---------- TEST CASES (NEW STRUCTURE) ----------
interface TestCase {
  name: string;
  journey: {
    realm: string;
    authIndexType: string;
    authIndexValue: string;
  };
}

const testCases: TestCase[] = [
  {
    name: 'Test-SendEmailForgotPassword',
    journey: {
      realm: '/alpha',
      authIndexType: 'service',
      authIndexValue: '__staples_h_user_util_lib_test',
    },
  },
  // Add more test cases here as needed
];

// Array to store captured full transaction IDs for the current test
let capturedFullTransactionIdsForCurrentTest: string[] = [];

// Interface for the individual log entry
interface LogFetchEntry {
  testTitle: string;
  transactionId: string;
}

// ---------- HELPER FUNCTIONS ----------

function getBaseTransactionId(fullTid: string): string {
  if (!fullTid) return '';
  const match = fullTid.match(/^([a-f0-9-]+)(?:-[a-z]+-\d+)?$/i);
  return match ? match[1] : fullTid;
}

function initializeLogging() {
  if (!fs.existsSync(config.logsDir)) {
    fs.mkdirSync(config.logsDir, { recursive: true });
    console.log(`📂 Created logs directory: ${config.logsDir}`);
  }
  if (!fs.existsSync(config.logQueueFile) || fs.readFileSync(config.logQueueFile, 'utf-8').trim() === '') {
    fs.writeFileSync(config.logQueueFile, JSON.stringify([]), 'utf-8');
    console.log(`📋 Initialized log queue at ${config.logQueueFile}`);
  }
}

async function clearAllCookiesForConfigDomain(page: Page) {
  const targetUrl = config.ping.baseUrl;
  if (!targetUrl) {
    console.warn('⚠️ Cookie clearing: config.ping.baseUrl not set. Skipping.');
    return;
  }
  console.log(`🧼 Clearing cookies for ${targetUrl}`);
  try {
    await page.context().clearCookies();
    console.log(`🍪 Cookies cleared for the current browser context.`);
  } catch (error) {
    console.error(`🔥 Error clearing cookies:`, error);
  }
}

function setupTransactionIdCapture(page: Page) {
  page.removeAllListeners('response');
  page.on('response', async (response) => {
    const url = response.url();
    const urlWithoutQuery = url.split('?')[0];
    if (
      urlWithoutQuery.endsWith('/json/realms/root/realms/alpha/authenticate') ||
      urlWithoutQuery.endsWith('/json/realms/root/realms/bravo/authenticate') ||
      urlWithoutQuery.includes('/XUI/')
    ) {
      const header = response.headers()['x-forgerock-transactionid'];
      if (header && !capturedFullTransactionIdsForCurrentTest.includes(header)) {
        console.log(`🆔 Captured FULL x-forgerock-transactionid: ${header} from ${url}`);
        capturedFullTransactionIdsForCurrentTest.push(header);
      }
    }
  });
  console.log('📡 Transaction ID capture listener set up.');
}

function appendEntryToLogQueue(entry: LogFetchEntry) {
  let entries: LogFetchEntry[] = [];
  if (fs.existsSync(config.logQueueFile)) {
    const fileContent = fs.readFileSync(config.logQueueFile, 'utf-8').trim();
    if (fileContent) {
      try {
        const parsedContent = JSON.parse(fileContent);
        entries = Array.isArray(parsedContent) ? parsedContent : [];
      } catch (e) {
        console.error(`Error parsing log file ${config.logQueueFile}. Initializing with new entry.`, e);
        entries = [];
      }
    }
  }
  entries.push(entry);
  try {
    fs.writeFileSync(config.logQueueFile, JSON.stringify(entries, null, 2), 'utf-8');
    console.log(`📝 Queued log for test "${entry.testTitle}", Base TID: ${entry.transactionId} to ${config.logQueueFile}`);
  } catch (e) {
    console.error(`🔥 Error writing to log file ${config.logQueueFile}:`, e);
  }
}

// ---------- TEST LIFECYCLE ----------
test.beforeAll(async () => {
  initializeLogging();
});

test.beforeEach(async ({ page }) => {
  await clearAllCookiesForConfigDomain(page);
  capturedFullTransactionIdsForCurrentTest = [];
  setupTransactionIdCapture(page);
});

test.afterEach(async ({ }, testInfo: TestInfo) => {
  if (capturedFullTransactionIdsForCurrentTest.length > 0) {
    console.log(`🧾 Logging individual base TIDs for test: "${testInfo.title}"`);
    for (const fullTid of capturedFullTransactionIdsForCurrentTest) {
      const baseTid = getBaseTransactionId(fullTid);
      if (baseTid) {
        appendEntryToLogQueue({
          testTitle: testInfo.title,
          transactionId: baseTid,
        });
      } else {
        console.warn(`⚠️ Could not extract base TID from: ${fullTid}`);
      }
    }
  } else {
    console.log(`🤔 No transaction IDs were captured for test: "${testInfo.title}". Not writing to log file.`);
  }
  console.log(`🏁 Test finished: "${testInfo.title}". Final captured FULL TIDs for this test:`, capturedFullTransactionIdsForCurrentTest);
});

// ---------- PARAMETRIZED TESTS ----------
test.describe('Invoke', () => {
  for (const { name, journey } of testCases) {
    test(`Invoke Journey: "${name}"`, async ({ page }) => {
      // Build the URL from journey parameters
      const url = `${config.ping.baseUrl}/am/XUI/?realm=${encodeURIComponent(journey.realm)}&authIndexType=${encodeURIComponent(journey.authIndexType)}&authIndexValue=${encodeURIComponent(journey.authIndexValue)}#/`;

      console.log(`🚀 [${name}] Navigating to: ${url}`);

      await page.goto(url);

      await page.waitForTimeout(3000);

      if (capturedFullTransactionIdsForCurrentTest.length > 0) {
        console.log(`✅ [${name}] Captured FULL Transaction IDs:`, capturedFullTransactionIdsForCurrentTest);
      } else {
        console.warn(`⚠️ [${name}] No transaction IDs captured. Check endpoint filters or network activity.`);
      }

      expect(capturedFullTransactionIdsForCurrentTest.length).toBeGreaterThan(0);

      capturedFullTransactionIdsForCurrentTest.forEach((tid, idx) => {
        const baseTid = getBaseTransactionId(tid);
        console.log(`   [${name}] #${idx + 1}: Base Transaction ID: ${baseTid}`);
      });
    });
  }
});