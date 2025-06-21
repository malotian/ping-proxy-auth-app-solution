// File: KosmosSDK.js

/**
 * @file KosmosSDK.js
 * @description A JavaScript library for interacting with 1Kosmos APIs.
 * Structured for environments that use an 'exports' object for defining public members.
 * Pure Vanilla JavaScript version without crypto.
 * Refactored for Mozilla Rhino 1.7.14 (ES5 compatibility).
 */

// --- Default Configuration (internal, modified by exported init function) ---
var _config = {
    BASE_URL: "https://staging.1kosmos.net",
    LICENSE_KEY: "b3e3863b-1060-420d-8583-919c7f595613", // WARNING: See security note below
    APP_ID_FOR_REQUEST: "com.javascript.sdk.example",
    NO_ECDSA: "true",
    TENANT_TAG: "staging", // Default X-TenantTag
    COMMUNITY_NAME: "staplesciam" // Default community name
};

var _logger;
// --- Internal Helper Functions (not exported) ---

/**
 * Generates a request ID string in the format expected by 1Kosmos.
 * Uses a Math.random-based fallback for UUID generation.
 * @returns {string} The generated request ID.
 */
function _generateRequestId() {
    var date = new Date();
    var current_time = Math.round(date.getTime() / 1000);
    var uuid;

    // Assuming _logger is initialized by the time this function is called.
    _logger.warn("[KosmosSDK] Using a Math.random-based fallback for UUID generation. This is not cryptographically secure.");

    uuid = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
        var r = Math.random() * 16 | 0, v = c === 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });

    var requestIdObj = {
        ts: current_time,
        appid: _config.APP_ID_FOR_REQUEST,
        uuid: uuid
    };
    var requestIdStr = JSON.stringify(requestIdObj).replace(/"/g, "'");

    _logger.debug('[KosmosSDK] Generated Request ID (using fallback UUID): {}', requestIdStr);
    return requestIdStr;
}

/**
 * Core function to make API calls. It NEVER throws an exception.
 * It returns a single, consistent result object where `ok` indicates success.
 *
 * @param {string} endpoint - The API endpoint path.
 * @param {string} method - HTTP method.
 * @param {object} [body] - The request body. Optional.
 * @param {object} [additionalHeaders] - Additional headers. Optional.
 * @returns {object} A consistent, detailed result object for success or any failure.
 */
function _fetchApi(endpoint, method, body, additionalHeaders) {
    var url = _config.BASE_URL + endpoint;
    var requestId = _generateRequestId();

    // --- Setup request options ---
    var headers = {
        "Content-Type": "application/json",
        "licensekey": _config.LICENSE_KEY,
        "requestid": requestId,
        "noecdsa": _config.NO_ECDSA
    };
    if (additionalHeaders) {
        for (var key in additionalHeaders) {
            if (additionalHeaders.hasOwnProperty(key)) {
                headers[key] = additionalHeaders[key];
            }
        }
    }
    var options = { method: method, headers: headers };
    if (body) {
        options.body = JSON.stringify(body);
    }
    
    _logger.debug('[KosmosSDK] Calling API: {} {}', method, url);

    try {
        var response = httpClient.send(url, options).get();

        // --- Initialize a consistent result object ---
        var result = {
            ok: false, // The single source of truth for success
            status: 0,
            statusText: "",
            message: "",
            json: null,
            text: null,
            headers: null,
            error: null,
            rawResponse: response
        };

        if (!response) {
            result.message = "HTTP Client Error: Did not receive a response object.";
            result.error = result.message;
            _logger.error("[KosmosSDK] " + result.message);
            return result;
        }

        // --- Populate the result directly from the response ---
        result.ok = response.ok;
        result.status = response.status;
        result.statusText = response.statusText;
        result.headers = response.headers;
        
        // Safely assign response body content, skipping for 204 No Content
        if (result.status !== 204) {
             result.text = response.text();
             // Assuming .json() is a safe call in this environment
             result.json = response.json();
        }
        
        // --- Set final message based on outcome ---
        if (result.ok) {
            result.message = "Operation successful" + (result.status === 204 ? ", no content returned." : ".");
        } else {
            result.message = "API Error: " + result.status + " " + result.statusText;
            result.error = result.message;
            _logger.error("[KosmosSDK] " + result.message + " | Body: " + (result.text || "Empty"));
        }

        return result;

    } catch (e) {
        // --- Catches client-side exceptions (network, etc.) ---
        _logger.error("[KosmosSDK] Unhandled exception during API call: " + (e.message || e));
        return {
            ok: false, status: 0, statusText: "Client Exception",
            message: "An unhandled exception occurred: " + (e.message || e),
            json: null, text: null, headers: null,
            error: e, rawResponse: null
        };
    }
}

/**
 * (ES5 Compatible)
 * Transforms a PingIdentity-style log message template and parameters
 * into an array of arguments suitable for console methods (e.g., console.log).
 * It replaces '{}' placeholders with '%o' (a versatile console format specifier).
 *
 * @param {string} messageTemplate - The log message template with '{}' placeholders.
 *                                   Additional arguments will be treated as parameters for placeholders.
 * @returns {Array<any>} An array where the first element is the modified template string,
 *                       followed by the parameters.
 */
function _kosmosSdkFormatPingStyleForConsole(messageTemplate) {
    var params = [];
    for (var i = 1; i < arguments.length; i++) {
        params.push(arguments[i]);
    }

    var template = String(messageTemplate || "");
    var consoleTemplate = template.replace(/\{}/g, "%o");

    var consoleArgs = [consoleTemplate];
    for (var j = 0; j < params.length; j++) {
        consoleArgs.push(params[j]);
    }

    return consoleArgs;
}


/**
 * (ES5 Compatible)
 * Initializes the KosmosSDK with custom configuration and sets up a logger.
 * This function must be called before any other SDK function to ensure proper setup.
 * It merges user-provided configuration with the SDK's defaults and either adopts a
 * provided global `logger` object or creates a console-based fallback.
 *
 * @param {object} [userConfig] - Optional. An object containing configuration properties to override SDK defaults.
 * @param {string} [userConfig.BASE_URL] - The base URL for the 1Kosmos API (e.g., "https://staging.1kosmos.net").
 * @param {string} [userConfig.LICENSE_KEY] - The license key for API authentication.
 * @param {string} [userConfig.APP_ID_FOR_REQUEST] - An identifier for the application making the requests.
 * @param {string} [userConfig.NO_ECDSA] - A flag (as a string, e.g., "true") to disable ECDSA.
 * @param {string} [userConfig.TENANT_TAG] - The default X-TenantTag header value.
 * @param {string} [userConfig.COMMUNITY_NAME] - The default community name used in API calls.
 */
function init(userConfig) {
    userConfig = userConfig || {};
    var key;
    for (key in userConfig) {
        if (userConfig.hasOwnProperty(key) && _config.hasOwnProperty(key)) {
            _config[key] = userConfig[key];
        }
    }

    if (typeof logger !== 'undefined' && logger &&
        typeof logger.debug === 'function' &&
        typeof logger.info === 'function' &&
        typeof logger.warn === 'function' &&
        typeof logger.error === 'function') {
        _logger = logger;
        _logger.info("[KosmosSDK] Using provided global logger.");
    } else {
        if (typeof console !== 'undefined' && typeof console.log === 'function') {
            console.log("[KosmosSDK INIT] Global 'logger' not found or incomplete. Creating a console-based fallback 'logger'.");
        }

        _logger = {
            debug: function (messageTemplate) {
                if (typeof console !== 'undefined' && (typeof console.debug === 'function' || typeof console.log === 'function')) {
                    var consoleArgs = _kosmosSdkFormatPingStyleForConsole.apply(null, arguments);
                    var finalArgs = ['[KosmosSDK DEBUG] ' + consoleArgs[0]];
                    for (var i = 1; i < consoleArgs.length; i++) {
                        finalArgs.push(consoleArgs[i]);
                    }
                    (console.debug || console.log).apply(console, finalArgs);
                }
            },
            info: function (messageTemplate) {
                if (typeof console !== 'undefined' && (typeof console.info === 'function' || typeof console.log === 'function')) {
                    var consoleArgs = _kosmosSdkFormatPingStyleForConsole.apply(null, arguments);
                    var finalArgs = ['[KosmosSDK INFO] ' + consoleArgs[0]];
                    for (var i = 1; i < consoleArgs.length; i++) {
                        finalArgs.push(consoleArgs[i]);
                    }
                    (console.info || console.log).apply(console, finalArgs);
                }
            },
            warn: function (messageTemplate) {
                if (typeof console !== 'undefined' && typeof console.warn === 'function') {
                    var consoleArgs = _kosmosSdkFormatPingStyleForConsole.apply(null, arguments);
                    var finalArgs = ['[KosmosSDK WARN] ' + consoleArgs[0]];
                    for (var i = 1; i < consoleArgs.length; i++) {
                        finalArgs.push(consoleArgs[i]);
                    }
                    console.warn.apply(console, finalArgs);
                }
            },
            error: function (messageTemplate) {
                if (typeof console !== 'undefined' && typeof console.error === 'function') {
                    var consoleArgs = _kosmosSdkFormatPingStyleForConsole.apply(null, arguments);
                    var finalArgs = ['[KosmosSDK ERROR] ' + consoleArgs[0]];
                    for (var i = 1; i < consoleArgs.length; i++) {
                        finalArgs.push(consoleArgs[i]);
                    }
                    console.error.apply(console, finalArgs);
                }
            }
        };
        _logger.info("[KosmosSDK] Console-based fallback logger created and is now active.");
    }

    if (typeof window !== 'undefined' && _config.LICENSE_KEY === "b3e3863b-1060-420d-8583-919c7f595613") {
        _logger.warn(
            "SECURITY WARNING: You are using the default/example LICENSE_KEY in a client-side environment. " +
            "This key should be kept secret and ideally used from a backend server. " +
            "Exposing it client-side is a security risk."
        );
    }
    _logger.debug("[KosmosSDK] Initialized with config: {}", JSON.stringify(_config));
}

/**
 * Generates an OTP and sends it to a user via a specified channel (SMS, voice, or email).
 * This function builds the request and calls the 1Kosmos /otp/generate API endpoint.
 *
 * @param {object} params - The parameters for the OTP generation request.
 * @param {string} params.userId - The unique identifier for the user.
 * @param {string} params.communityId - The identifier for the community the user belongs to.
 * @param {string} params.tenantId - The identifier for the tenant associated with the user.
 * @param {string} params.channel - The delivery channel for the OTP. Must be 'sms', 'voice', or 'email'.
 * @param {string} params.recipient - The destination for the OTP (e.g., a phone number for SMS/voice, or an email address).
 * @param {string} [params.isdCode='1'] - The International Subscriber Dialing code, required for 'sms' and 'voice' channels. Defaults to '1'.
 * @returns {object} A consistent result object. `ok: true` on success. On failure (client validation or API error), `ok: false` with details.
 */
function sendOTP(params) {
    params = params || {};
    var userId = params.userId;
    var communityId = params.communityId;
    var tenantId = params.tenantId;
    var channel = params.channel;
    var recipient = params.recipient;
    var isdCode = params.isdCode === undefined ? '91' : params.isdCode;

    if (!userId || !communityId || !tenantId || !channel || !recipient) {
        var errorMessage1 = "[KosmosSDK Client Validation] Missing required parameters for sendOTP: userId, communityId, tenantId, channel, recipient are required.";
        _logger.warn("[KosmosSDK Client Validation] Missing required parameters for sendOTP. Provided params: {}", JSON.stringify(params));
        return {
            ok: false, status: 0, statusText: "Client Validation Error",
            message: errorMessage1,
            json: null, text: null, headers: null,
            error: errorMessage1, rawResponse: null
        };
    }

    var body = {
        userId: userId,
        communityId: communityId,
        tenantId: tenantId
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
        var errorMessage2 = "[KosmosSDK Client Validation] Invalid OTP channel. Use 'sms', 'voice', or 'email'.";
        _logger.warn("[KosmosSDK Client Validation] Invalid OTP channel: {}. Provided params: {}", channel, JSON.stringify(params));
        return {
            ok: false, status: 0, statusText: "Client Validation Error",
            message: errorMessage2,
            json: null, text: null, headers: null,
            error: errorMessage2, rawResponse: null
        };
    }
    _logger.debug("[KosmosSDK] sendOTP: Calling API with body: {}", JSON.stringify(body));
    return _fetchApi("/api/r2/otp/generate", "POST", body);
}

/**
 * Verifies a user-provided One-Time Password (OTP) against the 1Kosmos service.
 * This function calls the /otp/verify API endpoint.
 *
 * @param {object} params - The parameters for the OTP verification request.
 * @param {string} params.userId - The unique identifier for the user.
 * @param {string} params.communityId - The identifier for the community the user belongs to.
 * @param {string} params.tenantId - The identifier for the tenant associated with the user.
 * @param {string} params.code - The OTP code that the user entered.
 * @returns {object} A consistent result object. `ok: true` on success. On failure (client validation or API error), `ok: false` with details.
 */
function verifyOTP(params) {
    params = params || {};
    var userId = params.userId;
    var communityId = params.communityId;
    var tenantId = params.tenantId;
    var code = params.code;

    if (!userId || !communityId || !tenantId || !code) {
        var errorMessage = "[KosmosSDK Client Validation] Missing required parameters for verifyOTP: userId, communityId, tenantId, code are required.";
        _logger.warn("[KosmosSDK Client Validation] Missing required parameters for verifyOTP. Provided params: {}", JSON.stringify(params));
        return {
            ok: false, status: 0, statusText: "Client Validation Error",
            message: errorMessage,
            json: null, text: null, headers: null,
            error: errorMessage, rawResponse: null
        };
    }
    var body = {
        userId: userId,
        communityId: communityId,
        tenantId: tenantId,
        code: code
    };
    _logger.debug("[KosmosSDK] verifyOTP: Calling API with body: {}", JSON.stringify(body));
    return _fetchApi("/api/r2/otp/verify", "POST", body);
}

/**
 * Creates an access code and triggers the sending of a magic link email to a user.
 * This function constructs a request for the /acr/community/{communityName}/code API endpoint.
 * The magic link allows for passwordless authentication or verification.
 *
 * @param {object} params - The parameters required to create and send the magic link.
 * @param {string} params.emailTo - The recipient's email address.
 * @param {string} params.emailTemplateB64 - A Base64-encoded HTML template for the email body. The template
 *   must contain a placeholder for the magic link, which the backend will replace.
 * @param {string} params.emailSubject - The subject line for the magic link email.
 * @param {string} [params.communityName] - The name of the community. If not provided, the default from the SDK configuration is used.
 * @param {number} [params.ttl_seconds=700] - The time-to-live for the magic link in seconds. Defaults to 700.
 * @param {string} [params.xTenantTag] - The tenant tag for the request. If not provided, the default from the SDK configuration is used.
 * @returns {object} A consistent result object. `ok: true` on success. On failure (client validation or API error), `ok: false` with details.
 */
/**
 * Creates an access code and triggers the sending of a magic link email to a user.
 * This function constructs a request for the /acr/community/{communityName}/code API endpoint.
 * The magic link allows for passwordless authentication or verification.
 * If emailTemplateB64 or emailSubject are null or undefined, they are omitted from the request body.
 *
 * @param {object} params - The parameters required to create and send the magic link.
 * @param {string} params.emailTo - The recipient's email address.
 * @param {string} [params.emailTemplateB64] - A Base64-encoded HTML template for the email body. The template
 *   must contain a placeholder for the magic link, which the backend will replace.
 * @param {string} [params.emailSubject] - The subject line for the magic link email.
 * @param {string} [params.communityName] - The name of the community. If not provided, the default from the SDK configuration is used.
 * @param {number} [params.ttl_seconds=700] - The time-to-live for the magic link in seconds. Defaults to 700.
 * @param {string} [params.xTenantTag] - The tenant tag for the request. If not provided, the default from the SDK configuration is used.
 * @returns {object} A consistent result object. `ok: true` on success. On failure (client validation or API error), `ok: false` with details.
 */
function sendMagicLink(params) {
    params = params || {};
    var communityName = params.communityName;
    var emailTo = params.emailTo;
    var emailTemplateB64 = params.emailTemplateB64;
    var emailSubject = params.emailSubject;
    var ttl_seconds = params.ttl_seconds === undefined ? 700 : params.ttl_seconds;
    var xTenantTag = params.xTenantTag;

    if (!emailTo) {
        var errorMessage = "[KosmosSDK Client Validation] Missing required parameter for sendMagicLink (emailTo).";
        _logger.warn("[KosmosSDK Client Validation] Missing required parameter for sendMagicLink. Provided params: {}", JSON.stringify(params));
        return {
            ok: false, status: 0, statusText: "Client Validation Error",
            message: errorMessage,
            json: null, text: null, headers: null,
            error: errorMessage, rawResponse: null
        };
    }
    var targetCommunityName = communityName || _config.COMMUNITY_NAME;
    var targetTenantTag = xTenantTag || _config.TENANT_TAG;

    var body = {
        createdby: "javascript-sdk",
        version: "v0",
        type: "verification_link",
        emailTo: emailTo,
        ttl_seconds: ttl_seconds
    };
    if (emailTemplateB64 != null) {
        body.emailTemplateB64 = emailTemplateB64;
    }
    if (emailSubject != null) {
        body.emailSubject = emailSubject;
    }

    var additionalHeaders = { "X-TenantTag": targetTenantTag };
    var endpoint = "/api/r2/acr/community/" + encodeURIComponent(targetCommunityName) + "/code";

    var loggableBody = {
        createdby: body.createdby,
        version: body.version,
        type: body.type,
        emailTo: body.emailTo,
        ttl_seconds: body.ttl_seconds,
        emailSubject: body.emailSubject,
        emailTemplateB64: body.emailTemplateB64 ? "OMITTED_FOR_LOG" : undefined
    };
    _logger.debug("[KosmosSDK] sendMagicLink: Calling API for community '{}', tenantTag '{}', endpoint '{}', body: {}",
        targetCommunityName, targetTenantTag, endpoint, JSON.stringify(loggableBody));
    return _fetchApi(endpoint, "PUT", body, additionalHeaders);
}

/**
 * Redeems an access code obtained from a magic link to complete a verification or authentication flow.
 * This function calls the /acr/community/{communityName}/{accessCode}/redeem API endpoint.
 *
 * @param {object} params - The parameters required to redeem the magic link's access code.
 * @param {string} params.accessCode - The unique code from the magic link URL that is being redeemed.
 * @param {string} params.publicKey - The public key of the user's device or browser, which may be used
 *   to associate the device with the user's identity.
 * @param {string} [params.communityName] - The name of the community. Defaults to the value in `_config.COMMUNITY_NAME`.
 * @param {string} [params.xTenantTag] - The tenant tag for the request. Defaults to the value in `_config.TENANT_TAG`.
 * @returns {object} A consistent result object. `ok: true` on success. On failure (client validation or API error), `ok: false` with details.
 */
function redeemMagicLink(params) {
    params = params || {};
    var communityName = params.communityName;
    var accessCode = params.accessCode;
    var publicKey = params.publicKey;
    var xTenantTag = params.xTenantTag;

    if (!accessCode || !publicKey) {
        var errorMessage = "[KosmosSDK Client Validation] Missing required parameters for redeemMagicLink (accessCode, publicKey).";
        _logger.warn("[KosmosSDK Client Validation] Missing required parameters for redeemMagicLink. Provided params: {}", JSON.stringify(params));
        return {
            ok: false, status: 0, statusText: "Client Validation Error",
            message: errorMessage,
            json: null, text: null, headers: null,
            error: errorMessage, rawResponse: null
        };
    }
    var targetCommunityName = communityName || _config.COMMUNITY_NAME;
    var targetTenantTag = xTenantTag || _config.TENANT_TAG;

    var body = {};
    var additionalHeaders = {
        "X-TenantTag": targetTenantTag,
        "publickey": publicKey
    };
    var endpoint = "/api/r1/acr/community/" + encodeURIComponent(targetCommunityName) + "/" + encodeURIComponent(accessCode) + "/redeem";
    _logger.debug("[KosmosSDK] redeemMagicLink: Calling API for community '{}', tenantTag '{}', accessCode '{}', endpoint '{}'",
        targetCommunityName, targetTenantTag, accessCode, endpoint);
    return _fetchApi(endpoint, "POST", body, additionalHeaders);
}


// --- Exports ---
if (typeof exports === 'undefined') {
    // var exports = {}; // This line is usually not needed if the environment provides 'exports'.
}

exports.init = init;
exports.sendOTP = sendOTP;
exports.verifyOTP = verifyOTP;
exports.sendMagicLink = sendMagicLink;
exports.redeemMagicLink = redeemMagicLink;