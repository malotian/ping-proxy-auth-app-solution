// File: KosmosSDK.js

/**
 * @file KosmosSDK.js
 * @description A JavaScript library for interacting with 1Kosmos APIs.
 * Inspired by the "library script" concept for reusability.
 */

const KosmosSDK = (function () {
    'use strict';

    // --- Default Configuration (can be overridden by init) ---
    let _config = {
        BASE_URL: "https://staging.1kosmos.net",
        LICENSE_KEY: "b3e3863b-1060-420d-8583-919c7f595613", // WARNING: See security note below
        APP_ID_FOR_REQUEST: "com.javascript.sdk.example",
        NO_ECDSA: "true",
        DEBUG_MODE: false // Set to true for more console logging
    };

    // --- Internal Helper Functions ---

    /**
     * Logs messages if debug mode is enabled.
     * @param {...any} args - Arguments to log.
     */
    function _debugLog(...args) {
        if (_config.DEBUG_MODE) {
            console.log('[KosmosSDK DEBUG]', ...args);
        }
    }

    /**
     * Generates a request ID string in the format expected by 1Kosmos.
     * @returns {string} The generated request ID.
     */
    function _generateRequestId() {
        const date = new Date();
        const current_time = Math.round(date.getTime() / 1000);
        let uuid;

        if (typeof crypto !== 'undefined' && crypto.randomUUID) {
            uuid = crypto.randomUUID();
        } else if (typeof require !== 'undefined') { // For Node.js
            try {
                const cryptoNode = require('crypto');
                uuid = cryptoNode.randomUUID();
            } catch (e) {
                console.warn("[KosmosSDK] Node.js crypto.randomUUID not available. Falling back. Consider 'uuid' package.");
                uuid = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
            }
        } else {
            console.warn("[KosmosSDK] crypto.randomUUID not available. Falling back. This is not a true UUID.");
            uuid = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
        }

        const requestIdObj = {
            ts: current_time,
            appid: _config.APP_ID_FOR_REQUEST,
            uuid: uuid
        };
        const requestIdStr = JSON.stringify(requestIdObj).replace(/"/g, "'");
        _debugLog('Generated Request ID:', requestIdStr);
        return requestIdStr;
    }

    /**
     * Core function to make API calls.
     * @param {string} endpoint - The API endpoint path.
     * @param {string} method - HTTP method.
     * @param {object} [body=null] - The request body.
     * @param {object} [additionalHeaders={}] - Additional headers.
     * @returns {Promise<object>} The JSON response from the API.
     * @throws {Error} If the API call fails or returns an error.
     */
    async function _fetchApi(endpoint, method, body = null, additionalHeaders = {}) {
        const url = `${_config.BASE_URL}${endpoint}`;
        const requestId = _generateRequestId();

        const headers = {
            "Content-Type": "application/json",
            "licensekey": _config.LICENSE_KEY,
            "requestid": requestId,
            "noecdsa": _config.NO_ECDSA,
            ...additionalHeaders
        };

        const options = {
            method: method,
            headers: headers,
        };

        if (body) {
            options.body = JSON.stringify(body);
        }

        _debugLog(`Calling API: ${method} ${url}`, 'Headers:', headers, 'Body:', body);

        try {
            const response = await fetch(url, options);
            const responseText = await response.text();

            _debugLog(`API Response Status: ${response.status}`, 'Response Text:', responseText);

            if (!response.ok) {
                let errorData;
                try {
                    errorData = JSON.parse(responseText);
                } catch (e) {
                    errorData = { message: responseText || response.statusText, status: response.status };
                }
                const errorMessage = errorData.message || JSON.stringify(errorData);
                throw new Error(`Kosmos API Error ${response.status}: ${errorMessage}`);
            }

            if (!responseText) {
                return { success: true, status: response.status, message: "Operation successful, no content returned." };
            }
            return JSON.parse(responseText);

        } catch (error) {
            console.error(`[KosmosSDK] Error in _fetchApi for ${method} ${url}:`, error);
            throw error; // Re-throw the error to be handled by the caller
        }
    }

    // --- Public API ---
    const publicApi = {};

    /**
     * Initializes the KosmosSDK with custom configuration.
     * @param {object} userConfig - Configuration object.
     * @param {string} [userConfig.BASE_URL] - The base URL for 1Kosmos APIs.
     * @param {string} [userConfig.LICENSE_KEY] - Your 1Kosmos license key.
     * @param {string} [userConfig.APP_ID_FOR_REQUEST] - Custom app ID for requests.
     * @param {boolean} [userConfig.DEBUG_MODE] - Enable debug logging.
     */
    publicApi.init = function (userConfig = {}) {
        _config = { ..._config, ...userConfig };
        _debugLog("KosmosSDK initialized with config:", _config);
        // SECURITY WARNING:
        if (typeof window !== 'undefined' && _config.LICENSE_KEY === "b3e3863b-1060-420d-8583-919c7f595613") {
            console.warn(
                "[KosmosSDK] SECURITY WARNING: You are using the default/example LICENSE_KEY in a client-side environment. " +
                "This key should be kept secret and ideally used from a backend server. " +
                "Exposing it client-side is a security risk."
            );
        }
    };

    /**
     * Generates and sends an OTP.
     * @param {object} params - Parameters for sending OTP.
     * @param {string} params.userId - User's identifier.
     * @param {string} params.communityId - Community identifier.
     * @param {string} params.tenantId - Tenant identifier.
     * @param {'sms' | 'voice' | 'email'} params.channel - The OTP delivery channel.
     * @param {string} params.recipient - Phone number (for sms/voice) or email address.
     * @param {string} [params.isdCode='1'] - ISD code for phone number.
     * @returns {Promise<object>} API response.
     */
    publicApi.sendOtp = async function ({ userId, communityId, tenantId, channel, recipient, isdCode = '1' }) {
        const body = {
            userId,
            communityId,
            tenantId
        };

        if (channel === 'sms') {
            body.smsTo = recipient;
            body.smsISDCode = isdCode;
        } else if (channel === 'voice') {
            body.voiceTo = recipient;
            body.voiceISDCode = isdCode;
        } else if (channel === 'email') {
            body.emailTo = recipient;
        } else {
            throw new Error("[KosmosSDK] Invalid OTP channel. Use 'sms', 'voice', or 'email'.");
        }
        return _fetchApi("/api/r2/otp/generate", "POST", body);
    };

    /**
     * Verifies an OTP.
     * @param {object} params - Parameters for verifying OTP.
     * @param {string} params.userId - User's identifier.
     * @param {string} params.communityId - Community identifier.
     * @param {string} params.tenantId - Tenant identifier.
     * @param {string} params.code - The OTP code to verify.
     * @returns {Promise<object>} API response.
     */
    publicApi.verifyOtp = async function ({ userId, communityId, tenantId, code }) {
        const body = {
            userId,
            communityId,
            tenantId,
            code
        };
        return _fetchApi("/api/r2/otp/verify", "POST", body);
    };

    /**
     * Creates an access code and triggers sending a magic link email.
     * @param {object} params - Parameters for sending magic link.
     * @param {string} params.communityName - The name of the community (e.g., "staplesciam").
     * @param {string} params.emailTo - Email address to send the magic link.
     * @param {string} params.emailTemplateB64 - Base64 encoded email template (with {{MAGICLINK}} placeholder).
     * @param {string} params.emailSubject - Subject of the email.
     * @param {number} [params.ttl_seconds=700] - Time-to-live for the code in seconds.
     * @param {string} [params.xTenantTag="staging"] - The X-TenantTag header value.
     * @returns {Promise<object>} API response, which should include the generated 'code'.
     */
    publicApi.sendMagicLink = async function ({ communityName, emailTo, emailTemplateB64, emailSubject, ttl_seconds = 700, xTenantTag = "staging" }) {
        const body = {
            createdby: "javascript-sdk",
            version: "v0",
            type: "verification_link",
            emailTo,
            ttl_seconds,
            emailTemplateB64,
            emailSubject
        };
        const additionalHeaders = { "X-TenantTag": xTenantTag };
        const endpoint = `/api/r2/acr/community/${encodeURIComponent(communityName)}/code`;
        return _fetchApi(endpoint, "PUT", body, additionalHeaders);
    };

    /**
     * Redeems an access code (from a magic link).
     * @param {object} params - Parameters for redeeming magic link.
     * @param {string} params.communityName - The name of the community.
     * @param {string} params.accessCode - The access code to redeem.
     * @param {string} params.publicKey - Base64 encoded public key of the client/user.
     * @param {string} [params.xTenantTag="staging"] - The X-TenantTag header value.
     * @returns {Promise<object>} API response.
     */
    publicApi.redeemMagicLink = async function ({ communityName, accessCode, publicKey, xTenantTag = "staging" }) {
        const body = {}; // Empty body as per Postman collection
        const additionalHeaders = {
            "X-TenantTag": xTenantTag,
            "publickey": publicKey
        };
        const endpoint = `/api/r1/acr/community/${encodeURIComponent(communityName)}/${encodeURIComponent(accessCode)}/redeem`;
        return _fetchApi(endpoint, "POST", body, additionalHeaders);
    };

    return publicApi;
})();

// For CommonJS environments (like Node.js)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = KosmosSDK;
}
// If you want to make it a global variable in browsers (not recommended for larger apps, use modules)
// else if (typeof window !== 'undefined') {
//     window.KosmosSDK = KosmosSDK;
// }