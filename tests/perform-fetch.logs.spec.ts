// fetch-logs.spec.ts
import { test } from '@playwright/test';
import axios from 'axios';
import fs from 'fs';
import path from 'path';

// ---------- CONFIGURATION (Subset for Log Fetching) ----------
const config = {
  monitoringApi: {
    baseUrl: 'https://identity-qe.staples.com/monitoring/logs',
    apiKey: '61d244ee890a4aae6d97f033f905eda2',
    apiSecret: '38ffee277dc1be87248724aead9e690b08245e97d759826eef1462017d4e9694',
    source: 'am-everything',
    pageSize: 1000,
  },
  logsDir: 'test-logs', // Added for storing logs
  logQueueFile: path.join('test-logs', 'log_fetch_queue.json'), // File to store pending log tasks
};

interface LogFetchTask {
  testTitle: string;
  transactionId: string;
}

// ---------- LOG FETCHING HELPERS (NEW) ----------
function sanitizeTestName(testName: string): string {
  return testName
    .replace(/Auth Flow \| /g, '')
    .replace(/ \| /g, '_')
    .replace(/keepMeLoggedIn=/g, 'rm-')
    .replace(/jumpUrl=/g, 'ju-')
    .replace(/showGuest=/g, 'sg-')
    .replace(/[^a-zA-Z0-9_.-]/g, '') // Remove invalid chars
    .slice(0, 100); // Limit length
}

async function fetchAndSaveLogs(testName: string, baseTransactionId: string) {
  const sanitizedName = sanitizeTestName(testName);
  const testLogDir = path.join(config.logsDir, sanitizedName);

  if (!fs.existsSync(testLogDir)) {
    fs.mkdirSync(testLogDir, { recursive: true });
    console.log(`📂 Created test case log directory: ${testLogDir}`);
  }

  const logFileName = `${baseTransactionId}.json`;
  const logFilePath = path.join(testLogDir, logFileName);

  console.log(`\n📜 Fetching logs for transaction ID: ${baseTransactionId} (Test: ${sanitizedName})`);
  const logApiUrl = `${config.monitoringApi.baseUrl}?source=${config.monitoringApi.source}&transactionId=${baseTransactionId}&_pageSize=${config.monitoringApi.pageSize}&_prettyPrint=true`;

  try {
    const response = await axios.request({
      method: 'get',
      maxBodyLength: Infinity,
      url: logApiUrl,
      headers: {
        'x-api-key': config.monitoringApi.apiKey,
        'x-api-secret': config.monitoringApi.apiSecret,
      }
    });
    fs.writeFileSync(logFilePath, JSON.stringify(response.data, null, 2));
    console.log(`💾 Logs saved to: ${logFilePath} (Test: ${sanitizedName})`);
  } catch (error: any) {
    console.error(`❌ Error fetching or saving logs for ${baseTransactionId} (Test: ${sanitizedName}):`);
    if (error.response) {
      console.error(`   Status: ${error.response.status}`);
      console.error(`   Data: ${JSON.stringify(error.response.data)}`);
    } else {
      console.error(`   Error: ${error.message}`);
    }
    // Optionally save the error to a file
    fs.writeFileSync(path.join(testLogDir, `${baseTransactionId}-ERROR.txt`), `Error fetching logs for ${testName}:\n${error.stack || error}`);
  }
}

// Helper function to get a formatted timestamp
function getFormattedTimestamp(): string {
  const now = new Date();
  const dd = String(now.getDate()).padStart(2, '0');
  const mm = String(now.getMonth() + 1).padStart(2, '0'); // January is 0!
  const yyyy = now.getFullYear();
  const hh = String(now.getHours()).padStart(2, '0');
  const min = String(now.getMinutes()).padStart(2, '0');
  const ss = String(now.getSeconds()).padStart(2, '0');
  return `${dd}-${mm}-${yyyy}-${hh}-${min}-${ss}`;
}

// ---------- FINAL TEST CASE FOR LOG FETCHING ----------
test('Fetch All Collected Logs', async () => {
  console.log(`\n📜 Starting to fetch logs based on queue file: ${config.logQueueFile}`);

  // Ensure the base logs directory exists, as beforeAll is not run for this file
  if (!fs.existsSync(config.logsDir)) {
    fs.mkdirSync(config.logsDir, { recursive: true });
    console.log(`📂 Created base logs directory (from fetch-logs): ${config.logsDir}`);
  }

  let tasksToFetch: LogFetchTask[] = [];
  if (fs.existsSync(config.logQueueFile)) {
    try {
      const fileContent = fs.readFileSync(config.logQueueFile, 'utf-8');
      if (fileContent.trim() !== '') { // Handle empty or whitespace-only file
          tasksToFetch = JSON.parse(fileContent);
          if (!Array.isArray(tasksToFetch)) {
              console.error(`❌ Log queue file ${config.logQueueFile} does not contain a valid JSON array. Skipping log fetch.`);
              tasksToFetch = []; // Prevent processing if not an array
          }
      }
    } catch (err) {
      console.error(`❌ Error reading or parsing log queue file ${config.logQueueFile}:`, err);
      // Optionally, decide not to proceed if the file is corrupt, e.g., return;
      return;
    }
  }

  if (tasksToFetch.length === 0) {
    console.log('🤷 No logs to fetch from queue file.');
    return;
  }
  console.log(`📄 Found ${tasksToFetch.length} tasks in queue file.`);

  // Optional: Add a small delay here if logs are not immediately available on the server
  // after all functional tests have completed.
  // const initialDelayMs = 5000; // 5 seconds
  // console.log(`⏳ Waiting ${initialDelayMs / 1000} seconds before starting log fetching process...`);
  // await new Promise(resolve => setTimeout(resolve, initialDelayMs));

  for (const task of tasksToFetch) {
    console.log(`\n➡️  Fetching logs for test: "${task.testTitle}", Transaction ID: ${task.transactionId}`);
    try {
      // You might want a small delay between fetches if the API is rate-limited
      // await new Promise(resolve => setTimeout(resolve, 500)); // 0.5 second delay
      await fetchAndSaveLogs(task.testTitle, task.transactionId);
    } catch (error) {
      // Log the error but continue with other tasks
      console.error(`❌❌ Critical error during fetchAndSaveLogs for ${task.transactionId} (Test: ${task.testTitle}):`, error);
    }
  }
  console.log('✅ All scheduled log fetching tasks from file have been processed.');

  // Archive the queue file after processing with the specified timestamp format
  try {
    if (fs.existsSync(config.logQueueFile)) { // Check if file exists before trying to rename
        const timestamp = getFormattedTimestamp();
        const processedQueueFile = `${config.logQueueFile}_${timestamp}.processed`;
        fs.renameSync(config.logQueueFile, processedQueueFile);
        console.log(`📦 Renamed log queue file to: ${processedQueueFile}`);
    } else {
        console.log(`ℹ️ Log queue file ${config.logQueueFile} not found, so no renaming needed.`);
    }
  } catch (err) {
    console.error(`⚠️ Error archiving log queue file ${config.logQueueFile}:`, err);
  }
  // The following line is now superseded by the try-catch block above
  // console.log(`ℹ️ Log queue file ${config.logQueueFile} was not cleared or archived as per request.`);
});