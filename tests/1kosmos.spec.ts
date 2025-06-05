// @ts-check
const { test, expect } = require('@playwright/test');

let KosmosSDK;

// --- Constants ---
const POSTMAN_LICENSE_KEY = "b3e3863b-1060-420d-8583-919c7f595613";
const DEFAULT_COMMUNITY_ID = "67f6c98cb4ff8970085b11ca";
const DEFAULT_TENANT_ID = "63d0359ef83ef571e35fda6c";
const DEFAULT_USER_ID = "liveTestUserPlaywrightV3"; // Use a unique user ID if needed
const DEFAULT_COMMUNITY_NAME = "staplesciam";
const DEFAULT_X_TENANT_TAG = "staging";

const VALID_TEST_PHONE_FOR_SMS_OTP = "17809523990"; // Ensure this is a real, accessible number for testing
const VALID_TEST_PHONE_ISD_CODE = "1";
const VALID_TEST_EMAIL_FOR_OTP_OR_MAGICLINK = "malotian@gmail.com"; // An email you can check

const DEFAULT_EMAIL_TEMPLATE_B64 = "Q2xpY2sgdGhlIGJ1dHRvbiBiZWxvdyB0byBsb2cgaW4gdG8gMUtvc21vcyBEZXZlbG9wZXIgRXhwZXJpZW5jZS4gaHR0cHM6Ly9ibG9ja2lkLXRyaWFsLjFrb3Ntb3MubmV0L2RldnBvcnRhbC9kZW1vP2NvZGU9e3tNQUdJQ0xJTkt9fSBUaGlzIGxpbmsgd2lsbCBleHBpcmUgaW4gMjAgbWludXRlcy4=";
const DEFAULT_EMAIL_SUBJECT = "Playwright Live Test Subject V3";
const DEFAULT_PUBLIC_KEY_FOR_REDEEM = "KptAI9Vk/79odk5lsWD1DVzI2rkK5ZoLtcbSJqkgT7YdP6UTBszFjPTrDReL9hAPVk0O/40tW6RzVUYqRAKmBg==";

test.describe('KosmosSDK API Tests (Updated Assertions)', () => {
    test.beforeAll(() => {
        KosmosSDK = require('../1kosmos/1kosmos.sdk.js'); // Adjust path as needed
        KosmosSDK.init({
            LICENSE_KEY: POSTMAN_LICENSE_KEY,
            APP_ID_FOR_REQUEST: "com.playwright.node.test.live.v3",
            DEBUG_MODE: true, // Enable SDK debug logs for more insight
            TENANT_TAG: DEFAULT_X_TENANT_TAG, // Set default tenant tag
            COMMUNITY_NAME: DEFAULT_COMMUNITY_NAME // Set default community name
        });
    });

    test.setTimeout(35000); // Increased timeout slightly for live API calls

    test.describe.serial('OTP Functionality (Live)', () => {
        const OTPBaseParams = {
            userId: DEFAULT_USER_ID,
            communityId: DEFAULT_COMMUNITY_ID,
            tenantId: DEFAULT_TENANT_ID,
        };

        test('Send SMS OTP', async () => {
            try {
                const response = await KosmosSDK.sendOTP({
                    ...OTPBaseParams,
                    channel: 'sms',
                    recipient: VALID_TEST_PHONE_FOR_SMS_OTP,
                    isdCode: VALID_TEST_PHONE_ISD_CODE
                });
                console.log("Live SMS OTP Send Response:", JSON.stringify(response, null, 2));

                expect(response).toBeDefined();
                expect(response.success).toBe(true);
                expect(response.status).toBe(202); // 1Kosmos OTP generate returns 202 Accepted
                expect(response.message).toBe("Operation successful."); // SDK's success message
                expect(response.data).toBeDefined();
                expect(response.data.messageId).toMatch(/[a-f0-9\-]{36}/i); // UUID format for messageId
                expect(response.data.info).toBe("OTP request accepted");

            } catch (error) {
                console.error("Live SMS OTP Send Test Error:", error);
                throw error; // Re-throw to fail the test if an unexpected error occurs
            }
        });

        test('Send Email OTP', async () => {
            try {
                const response = await KosmosSDK.sendOTP({
                    ...OTPBaseParams,
                    channel: 'email',
                    recipient: VALID_TEST_EMAIL_FOR_OTP_OR_MAGICLINK
                });
                console.log("Live Email OTP Send Response:", JSON.stringify(response, null, 2));

                expect(response).toBeDefined();
                expect(response.success).toBe(true);
                expect(response.status).toBe(202); // Expecting 202 Accepted for email OTP as well
                expect(response.message).toBe("Operation successful.");
                expect(response.data).toBeDefined();
                expect(response.data.messageId).toMatch(/[a-f0-9\-]{36}/i);
                expect(response.data.info).toBe("OTP request accepted");

            } catch (error) {
                console.error("Live Email OTP Send Test Error:", error);
                throw error;
            }
        });

        test('verify OTP (manual step required - placeholder/skip)', async () => {
            test.skip(true, "Skipping live OTP verification as it requires manual code input.");
            // To test this live:
            // 1. Send an OTP (e.g., in a previous step or manually).
            // 2. Get the actual OTP code.
            // 3. Call KosmosSDK.verifyOTP with that code.
            // const knownOTPCode = "ACTUAL_RECEIVED_OTP"; // Replace with real OTP
            // try {
            //     const response = await KosmosSDK.verifyOTP({ ...OTPBaseParams, code: knownOTPCode });
            //     console.log("Live OTP Verify Response:", JSON.stringify(response, null, 2));
            //     expect(response.success).toBe(true);
            //     expect(response.status).toBe(200); // Or whatever success status verify OTP returns
            //     // Add assertions for response.data based on actual API for successful verification
            //     // e.g., expect(response.data.verified).toBe(true);
            // } catch (error) {
            //     console.error("Live OTP Verify Test Error:", error);
            //     throw error;
            // }
        });
    });

    test.describe.serial('Magic Link / ACR Functionality (Live)', () => {
        let createdAccessCode = null;

        test('Send Magic link code', async () => {
            try {
                const response = await KosmosSDK.sendMagicLink({
                    // communityName: DEFAULT_COMMUNITY_NAME, // Uses SDK default
                    // xTenantTag: DEFAULT_X_TENANT_TAG, // Uses SDK default
                    emailTo: VALID_TEST_EMAIL_FOR_OTP_OR_MAGICLINK,
                    emailTemplateB64: DEFAULT_EMAIL_TEMPLATE_B64,
                    emailSubject: "Playwright Live Test - Magic Link V3",
                    ttl_seconds: 600
                });
                console.log("Live Magic Link Send Response:", JSON.stringify(response, null, 2));

                expect(response).toBeDefined();
                expect(response.success).toBe(true);
                expect(response.status).toBe(200); // Assuming 200 OK for successful code creation
                expect(response.message).toBe("Operation successful.");
                expect(response.data).toBeDefined();
                expect(response.data.code).toBeDefined();
                expect(response.data.code.length).toBeGreaterThan(5);
                expect(response.data.link).toBeDefined();
                expect(response.data.link).toContain(response.data.code);

                createdAccessCode = response.data.code;
                console.log("Created Magic Link Access Code:", createdAccessCode);
            } catch (error) {
                console.error("Live Magic Link Send Test Error:", error);
                throw error;
            }
        });

        test('should attempt to redeem a created access code', async () => {
            expect(createdAccessCode, "Access code must be created in the previous step").not.toBeNull();
            console.info(`Attempting to redeem live access code: ${createdAccessCode}.`);

            // It might take a moment for the code to be active after creation.
            // Adding a small delay, though ideally the API should be instantly consistent.
            await new Promise(resolve => setTimeout(resolve, 2000));


            try {
                const response = await KosmosSDK.redeemMagicLink({
                    // communityName: DEFAULT_COMMUNITY_NAME, // Uses SDK default
                    accessCode: createdAccessCode,
                    publicKey: DEFAULT_PUBLIC_KEY_FOR_REDEEM,
                    // xTenantTag: DEFAULT_X_TENANT_TAG // Uses SDK default
                });
                console.log("Live Magic Link Redeem Response:", JSON.stringify(response, null, 2));

                expect(response).toBeDefined();
                expect(response.success).toBe(true);
                expect(response.status).toBe(200); // Assuming 200 OK for successful redeem
                expect(response.message).toBe("Operation successful.");
                expect(response.data).toBeDefined();
                // Add assertions based on the actual successful redeem response structure from 1Kosmos
                // e.g., expect(response.data.session_info).toBeDefined();
                // e.g., expect(response.data.user_info.id).toBe(DEFAULT_USER_ID); // If applicable
                // For the provided Postman, a successful redeem might return user_info, session_info, etc.
                expect(response.data.user_info || response.data.session_info).toBeDefined();


            } catch (error) {
                console.error("Live Magic Link Redeem Test Error:", error);
                // If the code has already been redeemed or expired, this will be an API error.
                // Check the error details to understand why it failed.
                expect(error.isApiError).toBe(true);
                // Example: If code is invalid/expired, you might expect a specific status
                // expect(error.status).toBe(400); // Or 404, 410 etc.
                // expect(error.data.message).toContain("Invalid or expired code"); // Check API specific message
                throw error; // Re-throw to fail the test if it's unexpected
            }
        });
    });

    test('should handle an API error for invalid input (e.g., verifyOTP with invalid code format)', async () => {
        try {
            await KosmosSDK.verifyOTP({
                userId: DEFAULT_USER_ID,
                communityId: DEFAULT_COMMUNITY_ID,
                tenantId: DEFAULT_TENANT_ID,
                code: "INVALID_CODE_FORMAT_VERY_LONG" // Invalid OTP that API should reject
            });
            throw new Error("API call did not fail as expected for invalid OTP format."); // Should not reach here
        } catch (error) {
            console.log("Live API Error Test (Invalid Input) Caught:", JSON.stringify({
                message: error.message,
                isApiError: error.isApiError,
                status: error.status,
                data: error.data
            }, null, 2));

            expect(error.isApiError).toBe(true);
            expect(error.status).toBeOneOf([400, 422]); // Common client error statuses
            expect(error.message).toMatch(/Kosmos API Error:/);
            expect(error.data).toBeDefined();
            // Check specific error message from API if known, e.g.,
            // expect(error.data.message || error.data.error).toMatch(/invalid OTP|validation failed/i);
        }
    });

    test('should handle a Client Validation error for missing required parameters', async () => {
        try {
            await KosmosSDK.sendOTP({
                // userId: DEFAULT_USER_ID, // Intentionally missing
                communityId: DEFAULT_COMMUNITY_ID,
                tenantId: DEFAULT_TENANT_ID,
                channel: 'email',
                recipient: 'client_error_test@example.com'
            });
            throw new Error("SDK call did not throw client validation error as expected.");
        } catch (error) {
            console.log("Client Validation Error Test Caught:", JSON.stringify({
                message: error.message,
                isApiError: error.isApiError
            }, null, 2));

            expect(error.isApiError).toBe(false);
            expect(error.message).toMatch(/\[KosmosSDK Client Validation\] Missing required parameters for sendOTP/);
        }
    });
});