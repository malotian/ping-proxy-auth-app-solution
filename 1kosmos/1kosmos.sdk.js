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
 * Core function to make API calls.
 * @param {string} endpoint - The API endpoint path.
 * @param {string} method - HTTP method.
 * @param {object} [body] - The request body. Optional.
 * @param {object} [additionalHeaders] - Additional headers. Optional.
 * @returns {Promise<object>}
 */
function _fetchApi(endpoint, method, body, additionalHeaders) {
    body = body || null;
    additionalHeaders = additionalHeaders || {};

    var url = _config.BASE_URL + endpoint;
    var requestId = _generateRequestId();

    var baseHeaders = {
        "Content-Type": "application/json",
        "licensekey": _config.LICENSE_KEY,
        "requestid": requestId,
        "noecdsa": _config.NO_ECDSA
    };

    var headers = {};
    var key;
    for (key in baseHeaders) {
        if (baseHeaders.hasOwnProperty(key)) {
            headers[key] = baseHeaders[key];
        }
    }
    for (key in additionalHeaders) {
        if (additionalHeaders.hasOwnProperty(key)) {
            headers[key] = additionalHeaders[key];
        }
    }

    var options = {
        method: method,
        headers: headers
    };

    var requestBodyStr = null;
    if (body && Object.keys(body).length > 0) {
        requestBodyStr = JSON.stringify(body);
        options.body = requestBodyStr;
    } else if (method === 'POST' || method === 'PUT' || method === 'PATCH') {
        requestBodyStr = JSON.stringify({});
        options.body = requestBodyStr;
    }

    _logger.debug('[KosmosSDK] Calling API: {} {} Headers: {} Request Body: {}', method, url, JSON.stringify(headers), requestBodyStr);

    try {
        var response = httpClient.send(url, options).get();
        _logger.debug('[KosmosSDK] API Response Status: {} Response Text: {}', statusCode, responseText);

        if (!response){
            var error = new Error('Kosmos API Error: Kosmos API request failed"');
            error.status = response.status;
            error.data = "response is null or undefined";
            error.message = "Kosmos API request failed: response is null or undefined";
            error.isApiError = true;
            _logger.error('[KosmosSDK] API Error Prepared: status={} data={} message={}', error.status, JSON.stringify(error.data), error.message);
            throw error;
        }

        var statusCode = response.status;
        var responseText = response.text(); // Use response.text() to get the full body as a string
        var responseJson = response.json(); 

        // Check for non-successful status codes (e.g., 4xx, 5xx)
        if (statusCode < 200 || statusCode >= 300) {
            var errorData;
            var apiErrorMessage = "Kosmos API request failed";
            throw error;
        }

        // Handle successful responses
        if (statusCode === 204 || !responseText) {
            _logger.debug("[KosmosSDK] Successful (204 No Content or empty body)");
            return {
                success: true,
                status: statusCode,
                data: null,
                message: "Operation successful, no content returned."
            };
        }

        try {
            // Attempt to parse the successful response as JSON
            var parsedData = JSON.parse(responseText);
            _logger.debug("[KosmosSDK] Successful (JSON response): {}", JSON.stringify(parsedData));
            return {
                success: true,
                status: statusCode,
                data: parsedData,
                message: "Operation successful."
            };
        } catch (e) {
            // If it's not JSON, return the raw text
            _logger.debug("[KosmosSDK] Successful (Non-JSON response): {}", responseText);
            return {
                success: true,
                status: statusCode,
                data: responseText,
                message: "Operation successful, non-JSON data returned."
            };
        }
    } catch (error) {
        // This outer catch handles both API errors thrown above and underlying client/network errors
        if (error.isApiError) {
            _logger.error('[KosmosSDK] Re-throwing structured API error for {} {}: status={} data={} message={}', method, url, error.status, JSON.stringify(error.data), error.message);
            throw error;
        }

        var clientErrorMessage = '[KosmosSDK] Network or client-side error for ' + method + ' ' + url + '.';
        if (error.message) {
             clientErrorMessage = '[KosmosSDK] Client Error for ' + method + ' ' + url + ': ' + error.message;
        }

        var clientError = new Error(clientErrorMessage);
        clientError.isApiError = false;
        clientError.data = error;
        var originalErrorDataString = error instanceof Error ? error.toString() : JSON.stringify(error);
        _logger.error('[KosmosSDK] Client-side/Network Error Prepared for {} {}: message={}, originalErrorData={}', method, url, clientError.message, originalErrorDataString);
        throw clientError;
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
 * Initializes the KosmosSDK with custom configuration and sets up the SDK's logger.
 * This function MUST be called before any other SDK function.
 *
 * @param {object} userConfig - Configuration object.
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
 * Generates and sends an OTP.
 * @param {object} params - Parameters for sending OTP.
 * @param {string} params.userId
 * @param {string} params.communityId
 * @param {string} params.tenantId
 * @param {string} params.channel - 'sms', 'voice', or 'email'
 * @param {string} params.recipient - Phone number or email address
 * @param {string} [params.isdCode='1'] - ISD code for phone numbers
 * @returns {Promise<object>}
 */
function sendOTP(params) {
    params = params || {};
    var userId = params.userId;
    var communityId = params.communityId;
    var tenantId = params.tenantId;
    var channel = params.channel;
    var recipient = params.recipient;
    var isdCode = params.isdCode === undefined ? '1' : params.isdCode;

    if (!userId || !communityId || !tenantId || !channel || !recipient) {
        var clientValidationError1 = new Error("[KosmosSDK Client Validation] Missing required parameters for sendOTP: userId, communityId, tenantId, channel, recipient are required.");
        clientValidationError1.isApiError = false;
        _logger.warn("[KosmosSDK Client Validation] Missing required parameters for sendOTP. Provided params: {}", JSON.stringify(params));
        return Promise.reject(clientValidationError1);
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
        var clientValidationError2 = new Error("[KosmosSDK Client Validation] Invalid OTP channel. Use 'sms', 'voice', or 'email'.");
        clientValidationError2.isApiError = false;
        _logger.warn("[KosmosSDK Client Validation] Invalid OTP channel: {}. Provided params: {}", channel, JSON.stringify(params));
        return Promise.reject(clientValidationError2);
    }
    _logger.debug("[KosmosSDK] sendOTP: Calling API with body: {}", JSON.stringify(body));
    return _fetchApi("/api/r2/otp/generate", "POST", body);
}

/**
 * Verifies an OTP.
 * @param {object} params - Parameters for verifying OTP.
 * @param {string} params.userId
 * @param {string} params.communityId
 * @param {string} params.tenantId
 * @param {string} params.code - The OTP code
 * @returns {Promise<object>}
 */
function verifyOTP(params) {
    params = params || {};
    var userId = params.userId;
    var communityId = params.communityId;
    var tenantId = params.tenantId;
    var code = params.code;

    if (!userId || !communityId || !tenantId || !code) {
        var clientError = new Error("[KosmosSDK Client Validation] Missing required parameters for verifyOTP: userId, communityId, tenantId, code are required.");
        clientError.isApiError = false;
        _logger.warn("[KosmosSDK Client Validation] Missing required parameters for verifyOTP. Provided params: {}", JSON.stringify(params));
        return Promise.reject(clientError);
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
 * Creates an access code and triggers sending a magic link email.
 * @param {object} params - Parameters for sending magic link.
 * @param {string} [params.communityName] - Optional community name, defaults to _config.COMMUNITY_NAME
 * @param {string} params.emailTo
 * @param {string} params.emailTemplateB64 - Base64 encoded email template
 * @param {string} params.emailSubject
 * @param {number} [params.ttl_seconds=700] - Time to live for the link
 * @param {string} [params.xTenantTag] - Optional X-TenantTag, defaults to _config.TENANT_TAG
 * @returns {Promise<object>}
 */
function sendMagicLink(params) {
    params = params || {};
    var communityName = params.communityName;
    var emailTo = params.emailTo;
    var emailTemplateB64 = params.emailTemplateB64;
    var emailSubject = params.emailSubject;
    var ttl_seconds = params.ttl_seconds === undefined ? 700 : params.ttl_seconds;
    var xTenantTag = params.xTenantTag;

    if (!emailTo || !emailTemplateB64 || !emailSubject) {
        var clientError = new Error("[KosmosSDK Client Validation] Missing required parameters for sendMagicLink (emailTo, emailTemplateB64, emailSubject).");
        clientError.isApiError = false;
        _logger.warn("[KosmosSDK Client Validation] Missing required parameters for sendMagicLink. Provided params: {}", JSON.stringify(params));
        return Promise.reject(clientError);
    }
    var targetCommunityName = communityName || _config.COMMUNITY_NAME;
    var targetTenantTag = xTenantTag || _config.TENANT_TAG;

    var body = {
        createdby: "javascript-sdk",
        version: "v0",
        type: "verification_link",
        emailTo: emailTo,
        ttl_seconds: ttl_seconds,
        emailTemplateB64: emailTemplateB64,
        emailSubject: emailSubject
    };
    var additionalHeaders = { "X-TenantTag": targetTenantTag };
    var endpoint = "/api/r2/acr/community/" + encodeURIComponent(targetCommunityName) + "/code";

    var loggableBody = {
        createdby: body.createdby,
        version: body.version,
        type: body.type,
        emailTo: body.emailTo,
        ttl_seconds: body.ttl_seconds,
        emailSubject: body.emailSubject,
        emailTemplateB64: "OMITTED_FOR_LOG"
    };
    _logger.debug("[KosmosSDK] sendMagicLink: Calling API for community '{}', tenantTag '{}', endpoint '{}', body: {}",
        targetCommunityName, targetTenantTag, endpoint, JSON.stringify(loggableBody));
    return _fetchApi(endpoint, "PUT", body, additionalHeaders);
}

/**
 * Redeems an access code (from a magic link).
 * @param {object} params - Parameters for redeeming magic link.
 * @param {string} [params.communityName] - Optional community name, defaults to _config.COMMUNITY_NAME
 * @param {string} params.accessCode
 * @param {string} params.publicKey
 * @param {string} [params.xTenantTag] - Optional X-TenantTag, defaults to _config.TENANT_TAG
 * @returns {Promise<object>}
 */
function redeemMagicLink(params) {
    params = params || {};
    var communityName = params.communityName;
    var accessCode = params.accessCode;
    var publicKey = params.publicKey;
    var xTenantTag = params.xTenantTag;

    if (!accessCode || !publicKey) {
        var clientError = new Error("[KosmosSDK Client Validation] Missing required parameters for redeemMagicLink (accessCode, publicKey).");
        clientError.isApiError = false;
        _logger.warn("[KosmosSDK Client Validation] Missing required parameters for redeemMagicLink. Provided params: {}", JSON.stringify(params));
        return Promise.reject(clientError);
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