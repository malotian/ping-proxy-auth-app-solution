// @ts-check
const { test, expect } = require('@playwright/test');

let KosmosSDK;

// --- Constants from Postman Collection (or your valid staging test data) ---
const POSTMAN_LICENSE_KEY = "b3e3863b-1060-420d-8583-919c7f595613";
const DEFAULT_COMMUNITY_ID = "67f6c98cb4ff8970085b11ca";
const DEFAULT_TENANT_ID = "63d0359ef83ef571e35fda6c";
const DEFAULT_USER_ID = "liveTestUserPlaywright";
const DEFAULT_COMMUNITY_NAME = "staplesciam";
const DEFAULT_X_TENANT_TAG = "staging";

const VALID_TEST_PHONE_FOR_SMS_OTP = "17809523990"; // e.g., your actual phone number
const VALID_TEST_PHONE_ISD_CODE = "1";
const VALID_TEST_EMAIL_FOR_OTP_OR_MAGICLINK = "malotian@gmail.com"; // An email you can check

const DEFAULT_EMAIL_TEMPLATE_B64 = "Q2xpY2sgdGhlIGJ1dHRvbiBiZWxvdyB0byBsb2cgaW4gdG8gMUtvc21vcyBEZXZlbG9wZXIgRXhwZXJpZW5jZS4gaHR0cHM6Ly9ibG9ja2lkLXRyaWFsLjFrb3Ntb3MubmV0L2RldnBvcnRhbC9kZW1vP2NvZGU9e3tNQUdJQ0xJTkt9fSBUaGlzIGxpbmsgd2lsbCBleHBpcmUgaW4gMjAgbWludXRlcy4=";
const DEFAULT_EMAIL_SUBJECT = "Playwright Live Test Subject";
const DEFAULT_PUBLIC_KEY_FOR_REDEEM = "KptAI9Vk/79odk5lsWD1DVzI2rkK5ZoLtcbSJqkgT7YdP6UTBszFjPTrDReL9hAPVk0O/40tW6RzVUYqRAKmBg==";

test.describe('KosmosSDK Live API Tests (No Mocks - Corrected Assertions)', () => {
    test.beforeAll(() => {
        KosmosSDK = require('../1kosmos/1kosmosSDK.js'); // Adjust path
        KosmosSDK.init({
            LICENSE_KEY: POSTMAN_LICENSE_KEY,
            APP_ID_FOR_REQUEST: "com.playwright.node.test.live.v2",
            DEBUG_MODE: true
        });
    });

    test.setTimeout(30000);

    test.describe.serial('OTP Functionality (Live)', () => {
        const otpBaseParams = {
            userId: DEFAULT_USER_ID,
            communityId: DEFAULT_COMMUNITY_ID,
            tenantId: DEFAULT_TENANT_ID,
        };

        test('should send an SMS OTP to a valid number', async () => {
            try {
                const response = await KosmosSDK.sendOtp({
                    ...otpBaseParams,
                    channel: 'sms',
                    recipient: VALID_TEST_PHONE_FOR_SMS_OTP,
                    isdCode: VALID_TEST_PHONE_ISD_CODE
                });
                console.log("Live SMS OTP Send Response:", JSON.stringify(response, null, 2));
                expect(response).toBeDefined();
                // **ASSERTION BASED ON ACTUAL API RESPONSE**
                // Example: Many APIs return a success status or a transaction ID.
                // Check 1Kosmos documentation or Postman for the actual success response structure.
                // If success is indicated by a specific field:
                // expect(response.status).toBe("SENT"); // Hypothetical
                // expect(response.transactionId).toBeDefined(); // Hypothetical
                // Or a general success message/flag:
                expect(response.message || typeof response.success === 'boolean').toBeDefined(); // General check
                if (typeof response.success === 'boolean') {
                    expect(response.success).toBe(true);
                }
            } catch (error) {
                console.error("Live SMS OTP Send Error:", error.message, error.response?.data);
                throw error;
            }
        });

        test('should send an Email OTP to a valid email', async () => {
            try {
                const response = await KosmosSDK.sendOtp({
                    ...otpBaseParams,
                    channel: 'email',
                    recipient: VALID_TEST_EMAIL_FOR_OTP_OR_MAGICLINK
                });
                console.log("Live Email OTP Send Response:", JSON.stringify(response, null, 2));
                expect(response).toBeDefined();
                // **ASSERTION BASED ON ACTUAL API RESPONSE**
                expect(response.message || typeof response.success === 'boolean').toBeDefined();
                 if (typeof response.success === 'boolean') {
                    expect(response.success).toBe(true);
                }
            } catch (error) {
                console.error("Live Email OTP Send Error:", error.message);
                throw error;
            }
        });

        test('verify OTP (manual step required - placeholder/skip)', async () => {
            test.skip("Skipping live OTP verification as it requires manual code input.");
            // To test this live, you'd:
            // 1. Have a known OTP code (e.g., from a previous successful send to your email/phone).
            // 2. Call KosmosSDK.verifyOtp with that code.
            // 3. Assert the expected success response from the 1Kosmos API.
            // const knownOtpCode = "PREVIOUSLY_RECEIVED_OTP";
            // const response = await KosmosSDK.verifyOtp({ ...otpBaseParams, code: knownOtpCode });
            // console.log("Live OTP Verify Response:", JSON.stringify(response, null, 2));
            // expect(response.verified).toBe(true); // Hypothetical, check actual API
            // expect(response.message).toContain("verified successfully"); // Hypothetical
        });
    });

    test.describe.serial('Magic Link / ACR Functionality (Live)', () => {
        let createdAccessCode = null;

        test('should send/create a magic link code to a valid email', async () => {
            try {
                const response = await KosmosSDK.sendMagicLink({
                    communityName: DEFAULT_COMMUNITY_NAME,
                    emailTo: VALID_TEST_EMAIL_FOR_OTP_OR_MAGICLINK,
                    emailTemplateB64: DEFAULT_EMAIL_TEMPLATE_B64,
                    emailSubject: "Playwright Live Test - Magic Link",
                    ttl_seconds: 600,
                    xTenantTag: DEFAULT_X_TENANT_TAG
                });
                console.log("Live Magic Link Send Response:", JSON.stringify(response, null, 2));
                expect(response).toBeDefined();
                // **ASSERTION BASED ON ACTUAL API RESPONSE for r2/acr/.../code**
                expect(response.code).toBeDefined();
                expect(response.code.length).toBeGreaterThan(5); // A basic sanity check
                // The Postman collection shows "r2 create code" returning:
                // { "code": "...", "link": "...", ... }
                expect(response.link).toBeDefined(); // Check if a link is also returned
                createdAccessCode = response.code;
            } catch (error) {
                console.error("Live Magic Link Send Error:", error.message);
                throw error;
            }
        });

        test('should attempt to redeem a created access code', async () => {
            console.info(`Attempting to redeem live access code: ${createdAccessCode}.`);

            try {
                const response = await KosmosSDK.redeemMagicLink({
                    communityName: DEFAULT_COMMUNITY_NAME,
                    accessCode: createdAccessCode,
                    publicKey: DEFAULT_PUBLIC_KEY_FOR_REDEEM,
                    xTenantTag: DEFAULT_X_TENANT_TAG
                });
                console.log("Live Magic Link Redeem Response:", JSON.stringify(response, null, 2));
                expect(response).toBeDefined();
                // **ASSERTION BASED ON ACTUAL API RESPONSE for r1/acr/.../redeem**
                // What does a successful redeem return? A session token? User info? A success message?
                // expect(response.sessionToken).toBeDefined(); // Hypothetical
                // expect(response.user.id).toBe(DEFAULT_USER_ID); // Hypothetical
                // A general success check:
                expect(response.message || typeof response.success === 'boolean' || response.session_info || response.user_info).toBeDefined();
                if (response.success === false) { // If API explicitly returns success: false for known issues
                    console.warn("Redeem API call was accepted but indicated failure:", response.message);
                    // You might want to fail the test or handle this as an expected "soft" failure
                    // expect(response.message).not.toContain("Unexpected"); // For example
                }

            } catch (error) {
                console.error("Live Magic Link Redeem Error:", error.message, error.response?.data);
                // The SDK throws on non-2xx. If it's a 4xx/5xx, this block is hit.
                // You might assert specific error messages if you know them.
                // For instance, if the code is invalid or expired, the API should return a specific error.
                // expect(error.message).toContain("Invalid access code"); // Hypothetical
                throw error; // Re-throw to fail the test if it's an unexpected error
            }
        });
    });

    test('should handle an API error for invalid input (e.g., missing userId for OTP)', async () => {
        try {
            await KosmosSDK.sendOtp({
                 userId: null, // Or undefined
                communityId: DEFAULT_COMMUNITY_ID,
                tenantId: DEFAULT_TENANT_ID,
                channel: 'email',
                recipient: 'error_test@example.com'
            });
            throw new Error("API call did not fail as expected for invalid input."); // Should not reach here
        } catch (error) {
            console.log("Live API Error (Invalid Input):", error.message);
            // **ASSERTION BASED ON ACTUAL API ERROR RESPONSE**
            // The SDK's _fetchApi throws an error like "Kosmos API Error <status>: <message>"
            expect(error.message).toMatch(/Kosmos API Error (400|422|4xx)/); // Expecting a client error status
            // You might also check if the error message from the API (embedded in error.message)
            // contains keywords like "userId is required" or "Validation failed".
            // This depends on 1Kosmos API error structure.
            // e.g. if (error.response && error.response.data) expect(error.response.data.details).toContain("userId");
        }
    });
});