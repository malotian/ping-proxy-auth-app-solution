import { test, expect, Page, TestInfo } from '@playwright/test';
import fs from 'fs';
import path from 'path';

// ---------- CONFIGURATION ----------
const config = {
  ping: {
    baseUrl: 'https://identity-qe.staples.com', // Used for cookie clearing domain
  },
  logsDir: 'test-logs', // << CHANGED to be consistent with logQueueFile
  logQueueFile: path.join('test-logs', 'log_fetch_queue.json'), // Using the same file name as your complex example
};

// Array to store captured full transaction IDs for the current test
let capturedFullTransactionIdsForCurrentTest: string[] = [];

// Interface for the individual log entry (similar to LogFetchTask)
interface LogFetchEntry {
  testTitle: string;
  transactionId: string; // This will store the BASE transaction ID
}

// ---------- HELPER FUNCTIONS ----------

/**
 * Extracts the base part of a Forgerock transaction ID.
 * Example: "a1b2c3d4-e5f6-7890-1234-abcdef012345-authenticate-1" -> "a1b2c3d4-e5f6-7890-1234-abcdef012345"
 * @param fullTid The full transaction ID string.
 * @returns The base transaction ID or the original string if no match.
 */
function getBaseTransactionId(fullTid: string): string {
  if (!fullTid) return ''; // Handle null or undefined input
  const match = fullTid.match(/^([a-f0-9-]+)(?:-[a-z]+-\d+)?$/i);
  return match ? match[1] : fullTid;
}

/**
 * Ensures the log directory exists and initializes the log file if it doesn't.
 */
function initializeLogging() {
  if (!fs.existsSync(config.logsDir)) {
    fs.mkdirSync(config.logsDir, { recursive: true });
    console.log(`📂 Created logs directory: ${config.logsDir}`);
  }
  // Initialize with an empty array if the file doesn't exist or is empty
  if (!fs.existsSync(config.logQueueFile) || fs.readFileSync(config.logQueueFile, 'utf-8').trim() === '') {
    fs.writeFileSync(config.logQueueFile, JSON.stringify([]), 'utf-8');
    console.log(`📋 Initialized log queue at ${config.logQueueFile}`);
  }
}

/**
 * Clears all cookies for the domain specified in config.ping.baseUrl.
 */
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

/**
 * Sets up a listener to capture x-forgerock-transactionid from responses.
 * @param page The Playwright Page object.
 */
function setupTransactionIdCapture(page: Page) {
  page.removeAllListeners('response'); // Clear previous listeners

  page.on('response', async (response) => {
    const url = response.url();
    // Adjust this filter if your TIDs come from different paths
    if (url.includes('/authenticate') || url.includes('/json/realms') || url.includes('/XUI/')) {
      const header = response.headers()['x-forgerock-transactionid'];
      if (header) {
        if (!capturedFullTransactionIdsForCurrentTest.includes(header)) {
          console.log(`🆔 Captured FULL x-forgerock-transactionid: ${header} from ${url}`);
          capturedFullTransactionIdsForCurrentTest.push(header);
        }
      }
    }
  });
  console.log('📡 Transaction ID capture listener set up.');
}

/**
 * Appends a single log entry (with base TID) to the log queue file.
 * @param entry The log entry to append.
 */
function appendEntryToLogQueue(entry: LogFetchEntry) {
  let entries: LogFetchEntry[] = [];
  if (fs.existsSync(config.logQueueFile)) {
    const fileContent = fs.readFileSync(config.logQueueFile, 'utf-8').trim();
    if (fileContent) {
      try {
        const parsedContent = JSON.parse(fileContent);
        // Ensure it's an array
        if (Array.isArray(parsedContent)) {
            entries = parsedContent;
        } else {
            console.warn(`Log file ${config.logQueueFile} does not contain a valid JSON array. Re-initializing.`);
            entries = []; // Reset if not an array
        }
      } catch (e) {
        console.error(`Error parsing log file ${config.logQueueFile}. Initializing with new entry.`, e);
        entries = []; // Reset if parsing fails
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
  capturedFullTransactionIdsForCurrentTest = []; // Reset for the current test
  setupTransactionIdCapture(page);
});

test.afterEach(async ({}, testInfo: TestInfo) => {
  if (capturedFullTransactionIdsForCurrentTest.length > 0) {
    console.log(`🧾 Logging individual base TIDs for test: "${testInfo.title}"`);
    for (const fullTid of capturedFullTransactionIdsForCurrentTest) {
      const baseTid = getBaseTransactionId(fullTid);
      if (baseTid) { // Ensure baseTid is not empty
        appendEntryToLogQueue({
          testTitle: testInfo.title, // You might want to add more context if needed
          transactionId: baseTid,    // Log the base transaction ID
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


// ---------- TEST ----------
test('Navigate and capture base transaction IDs to file', async ({ page }) => {
  const targetUrl = 'https://identity-qe.staples.com/am/XUI/?realm=/alpha&authIndexType=service&authIndexValue=__staples_h_1kosmos#/';
  console.log(`🚀 Navigating to ${targetUrl}`);

  await page.goto(targetUrl);

  try {
    await page.waitForSelector('input[type="text"], input[type="email"], input[type="password"]', { timeout: 1500 });
    console.log('✅ Page loaded, input field found.');
  } catch (e) {
    console.warn('⚠️ Page or specific element might not have fully loaded as expected, or no input field found, but proceeding.');
  }

  await page.waitForTimeout(1000); // Use with caution

  console.log('📄 Captured FULL Transaction IDs during this test execution:', capturedFullTransactionIdsForCurrentTest);
  if (capturedFullTransactionIdsForCurrentTest.length > 0) {
    console.log('🎉 Successfully captured transaction IDs during execution.');
  } else {
    console.warn('🤔 No transaction IDs were captured during execution. Check URL filter or network activity.');
  }

  // Example assertion:
  // await expect(page).toHaveTitle(/Sign In|Identity Cloud|Staples Identity/);
});