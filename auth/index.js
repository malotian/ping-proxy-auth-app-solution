require("dotenv").config();
const express =require("express");
const axios = require("axios");
const cookieParser = require("cookie-parser");
const { v4: uuidv4 } = require("uuid");
const crypto = require("crypto");
const config = require("./config");
const qs = require("qs");
const jwt = require("jsonwebtoken");
const { generateKeyPairSync } = require("crypto");
const forge = require("node-forge");
const winston = require("winston");

const app = express();
app.use(express.json());
app.use(cookieParser());

// Extremely verbose logger setup
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || "debug",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(({ level, message, timestamp, ...meta }) => {
      return `${timestamp} [${level.toUpperCase()}] ${message}${
        Object.keys(meta).length ? " " + JSON.stringify(meta) : ""
      }`;
    })
  ),
  transports: [new winston.transports.Console()],
});

// Attach correlationId and log incoming request details
app.use((req, res, next) => {
  req.correlationId = req.headers["proxy-correlation-id"] || uuidv4(); // Ensure correlationId always exists
  const clientIp = req.headers["x-forwarded-for"]?.split(",")[0].trim() ||
                   req.socket?.remoteAddress || "Unknown"; // Use req.socket for newer Node/Express
  logger.info("Auth Service received request", {
    correlationId: req.correlationId,
    method: req.method,
    url: req.originalUrl,
    clientIp
  });
  next();
});

// In-memory session store (for demonstration only)
const sessionStore = {};

// Generate RSA Key Pair and prepare JWKS endpoint
const { privateKey, publicKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});
const forgeKey = forge.pki.publicKeyFromPem(publicKey);
const n = Buffer.from(forgeKey.n.toByteArray()).toString("base64url");
const e = Buffer.from(forgeKey.e.toByteArray()).toString("base64url");

app.get("/.well-known/jwks.json", (req, res) => {
  logger.info("Serving JWKS endpoint", { correlationId: req.correlationId });
  res.json({
    keys: [
      {
        kty: "RSA",
        kid: "staples-kid", // Consistent Key ID
        use: "sig",
        alg: "RS256",
        n: n,
        e: e,
      },
    ],
  });
});

// Function: Compute device fingerprint based on IP and User-Agent
function computeDeviceFingerPrint(context, secretKey = null) {
  if (!context || !context.ip || !context.userAgent) {
    logger.warn("Missing ip or userAgent for fingerprint computation", { context });
    throw new Error("Missing required context fields: ip and userAgent");
  }

  const fingerprintComponents = { ip: context.ip, userAgent: context.userAgent };
  const fingerprintData = JSON.stringify(fingerprintComponents);
  let fingerprint;

  if (secretKey) {
    fingerprint = crypto.createHmac("sha256", secretKey).update(fingerprintData).digest("hex");
  } else {
    fingerprint = crypto.createHash("sha256").update(fingerprintData).digest("hex");
  }

  logger.debug("Computed DeviceID (fingerprint)", { fingerprint, components: fingerprintComponents });
  return fingerprint;
}

// Utility functions to check token states
function isAccessTokenExpired(session) {
  // In real scenarios, decode session.AccessToken and check its 'exp' claim
  // For now, placeholder:
  if (session && session.AccessToken === "expired") return true; // For testing
  if (session && session.AccessToken) {
    try {
      const decoded = jwt.decode(session.AccessToken);
      return decoded.exp * 1000 < Date.now();
    } catch (e) {
      logger.warn("Failed to decode access token for expiry check", { error: e.message, SessionID: session.SessionID });
      return true; // Treat as expired if undecodable
    }
  }
  return true; // No access token means it's effectively expired/missing
}

function isRefreshTokenValid(session) {
  // In real scenarios, implement proper validation (e.g., check against a revocation list or its own expiry if applicable)
  return session && session.RefreshToken && session.RefreshToken !== "invalid";
}

// Function: Build StaplesJWT from session details
function buildStaplesJWT(session) {
  // Ensure sensitive data like code_verifier is not in the JWT payload unless intended
  const payload = { ...session };
  delete payload.code_verifier; // PKCE verifier should not be in the JWT
  delete payload.StateID;       // State should not be in JWT
  delete payload.NonceID;       // Nonce should not be in JWT

  logger.debug("Building StaplesJWT payload", { payload, SessionID: session.SessionID });
  const token = jwt.sign(payload, privateKey, {
    algorithm: "RS256",
    expiresIn: "1h",
    keyid: "staples-kid", // Matches kid in JWKS
  });
  logger.info("StaplesJWT generated successfully", { SessionID: session.SessionID });
  return token;
}

async function refreshTokenThrice(refreshToken, correlationId) {
  let latestRefreshResponse = null;

  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      logger.info(`Attempt ${attempt}: Refreshing token`, { correlationId });

      const refreshResponse = await axios.post(
        config.idaasAccessTokenEndpoint,
        qs.stringify({
          grant_type: "refresh_token",
          refresh_token: refreshToken,
          client_id: config.idaasKeepMeLoggedInClientID, // Assuming KMLI client for refresh, or use main client_id
          client_secret: config.idaasKeepMeLoggedInClientSecret, // Same as above
        }),
        { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
      );

      latestRefreshResponse = refreshResponse; // Store the successful response
      logger.info(`Attempt ${attempt}: Token refresh successful`, {correlationId, responseStatus: refreshResponse.status});
      // Check if data actually contains tokens before breaking
      if (refreshResponse.data && refreshResponse.data.access_token) {
        break; // Success, no need for more attempts
      } else {
        logger.warn(`Attempt ${attempt}: Token refresh response did not contain access_token`, {correlationId, responseData: refreshResponse.data});
        // Don't break if a retry might help, but typically IdP returns error or no token on failure.
        // For now, if no access_token, it's effectively a failure for this attempt.
        // If this was the last attempt, latestRefreshResponse will reflect this.
      }
    } catch (refreshError) {
      logger.warn(`Attempt ${attempt}: Token refresh failed with HTTP error`, {
        correlationId,
        error: refreshError.response ? {status: refreshError.response.status, data: refreshError.response.data } : refreshError.message,
      });
      if (attempt === 3 || (refreshError.response && refreshError.response.status !== 500)) { // Don't retry client errors
          break; // Break on error, especially if it's a client error or last attempt
      }
      // Optional: add a delay before retrying
      // await new Promise(resolve => setTimeout(resolve, 1000 * attempt));
    }
  }
  return latestRefreshResponse; // This will be the last attempt's response or the first successful one
}

function generateRandomString(length) {
  return crypto.randomBytes(Math.ceil(length / 2)).toString("hex").slice(0, length); // More secure random
}

function sha256(buffer) {
  return crypto.createHash("sha256").update(buffer).digest();
}

function base64URLEncode(str) {
  return str.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function generatePkceChallenge() {
  const verifier = generateRandomString(128);
  const challenge = base64URLEncode(sha256(Buffer.from(verifier, 'utf8')));// Ensure buffer for sha256
  return { code_verifier: verifier, code_challenge: challenge, code_challenge_method: "S256" };
}

// Helper function to initiate redirect to IDP
async function initiateIdpRedirect(req, res, targetUrlStr, deviceId, acrValue = null) {
  const correlationId = req.correlationId;
  logger.info(`Initiating IDP redirect`, { correlationId, targetUrl: targetUrlStr, deviceId, acrValue });

  const newSessionId = uuidv4();
  const stateId      = uuidv4();
  const nonceId      = uuidv4(); // OIDC Nonce

  const preAuthSession = {
    StateID:     stateId,
    NonceID:     nonceId,
    FingerPrint: deviceId,
    TargetUrl:   targetUrlStr, // The original URL the user intended to access
  };

  const pkce = generatePkceChallenge();
  preAuthSession.code_verifier = pkce.code_verifier; // Store verifier for callback
  logger.debug("Created pre-auth session object with PKCE", { correlationId, newSessionId, preAuthSession });

  const txnId = 'app-txn-' + uuidv4();
  const params = new URLSearchParams({
    client_id:             config.idaasClientID,
    redirect_uri:          config.appCallbackEndpoint,
    scope:                 config.scope,
    response_type:         config.response_type, // e.g., "code"
    state:                 stateId,
    nonce:                 nonceId,
    txn_id:                txnId,
    code_challenge:        pkce.code_challenge,
    code_challenge_method: pkce.code_challenge_method
  });

  if (acrValue) {
    params.append('acr_values', acrValue);
    params.append('prompt', 'login');
    params.append('service', 'ChangeUsername');
    
  }

  const authnUrl = `${config.idaasAuthorizeEndpoint}?${params.toString()}`;
  logger.debug("Constructed authnUrl", { correlationId, authnUrl });

  sessionStore[newSessionId] = preAuthSession;
  logger.info("Saved new pre-auth session to store", { correlationId, newSessionId });

  return res.json({
    adviceHeaders: {
      HTTP_STAPLES_AUTHN_URL:    authnUrl,
      HTTP_STAPLES_COOKIE_VALUE: newSessionId // Proxy should set this cookie
    }
  });
}


app.post("/advice", async (req, res) => {
  const { url: targetUrlStr, cookies = {}, ip, userAgent } = req.body;
  const correlationId = req.correlationId;

  logger.info("Entering /advice handler", { correlationId, rawBody: { url: targetUrlStr, cookies: Object.keys(cookies), ip, userAgent } });

  let deviceId;
  try {
    deviceId = computeDeviceFingerPrint({ ip, userAgent });
  } catch (err) {
    logger.error("Failed to compute device fingerprint", { correlationId, error: err.message, ip, userAgent });
    return res.status(400).json({ error: "Invalid device context: " + err.message });
  }

  let targetUrlObject;
  try {
    targetUrlObject = new URL(targetUrlStr);
  } catch (e) {
    logger.error("Invalid target URL provided", { correlationId, url: targetUrlStr, error: e.message });
    return res.status(400).json({ error: "Invalid target URL" });
  }
  logger.debug("Parsed target URL", { correlationId, url: targetUrlStr, pathname: targetUrlObject.pathname });

  const sessionId = cookies["COOKIE_STAPLES_SESSION"];
  let session = sessionId ? sessionStore[sessionId] : null;
  logger.debug("Session status", { correlationId, sessionId, sessionFound: !!session });

  const isCallback = targetUrlObject.pathname.endsWith("/callback") && targetUrlObject.searchParams.has("code");
  const isChangeUsernameRequest = targetUrlObject.pathname.endsWith("/change-username");

  logger.info("Request context", { correlationId, isCallback, isChangeUsernameRequest, targetPath: targetUrlObject.pathname });

  // ── 1. CALLBACK FLOW ──
  if (isCallback) {
    if (!session) {
      logger.error("Callback received but no session found for sessionId. Cannot process PKCE.", { correlationId, sessionIdFromCookie: sessionId });
      // Potentially redirect to login again or show an error page.
      // For now, let's force a new login by falling through after clearing any invalid session id.
      // Or, more directly, initiate a new login.
      return initiateIdpRedirect(req, res, config.defaultRedirectUrl || "/", deviceId, null); // Redirect to a safe default
    }
    logger.info("Entering CALLBACK flow", { correlationId, sessionId });

    if (session.FingerPrint !== deviceId) {
      logger.warn("Fingerprint mismatch in CALLBACK flow. Invalidating session.", {
        correlationId, sessionId, expected: session.FingerPrint, actual: deviceId
      });
      delete sessionStore[sessionId];
      return initiateIdpRedirect(req, res, config.defaultRedirectUrl || "/", deviceId, null); // Force new login
    }

    const code = targetUrlObject.searchParams.get("code");
    const returnedState = targetUrlObject.searchParams.get("state");

    if (!session.StateID || session.StateID !== returnedState) {
      logger.error("State mismatch in CALLBACK flow. Potential CSRF. Invalidating session.", {
        correlationId, sessionId, expected: session.StateID, actual: returnedState
      });
      delete sessionStore[sessionId];
      return initiateIdpRedirect(req, res, config.defaultRedirectUrl || "/", deviceId, null); // Force new login
    }
    logger.debug("State verified in CALLBACK flow", { correlationId, sessionId });

    const tokenReqPayload = {
      grant_type: "authorization_code",
      code: code,
      redirect_uri: config.appCallbackEndpoint, // Must match what was sent in authz request
      client_id: config.idaasClientID,
      client_secret: config.idaasClientSecret,
    };
    if (session.code_verifier) {
      tokenReqPayload.code_verifier = session.code_verifier;
    } else {
      logger.warn("Missing code_verifier in session for PKCE token exchange", { correlationId, sessionId });
      // This likely indicates a problem or a non-PKCE flow somehow reaching here with a session.
    }

    try {
      logger.debug("Exchanging code for tokens", { correlationId, sessionId, client_id: tokenReqPayload.client_id });
      const tokenResponse = await axios.post(
        config.idaasAccessTokenEndpoint,
        qs.stringify(tokenReqPayload),
        { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
      );
      const tokenData = tokenResponse.data;
      logger.info("Successfully exchanged code for tokens", { correlationId, sessionId });

      // OIDC: Validate ID token signature, issuer, audience, nonce, expiry.
      // For now, assuming tokenData.id_token is valid if present.
      // The Nonce in ID token should match session.NonceID.

      const finalSession = {
        SessionID:      sessionId, // Keep SessionID for reference if needed by buildStaplesJWT
        AccessToken:    tokenData.access_token,
        IdToken:        tokenData.id_token,
        RefreshToken:   tokenData.refresh_token,
        KeepMeLoggedIn: !!tokenData.keep_me_logged_in, // Or however KMLI is indicated
        FingerPrint:    session.FingerPrint, // Preserve fingerprint
        TargetUrl:      session.TargetUrl,   // Preserve original target URL
        // UserInfo: could be fetched here using access_token if needed
      };
      sessionStore[sessionId] = finalSession; // Update session in store
      logger.debug("Session updated with tokens", { correlationId, sessionId });

      const staplesJwt = buildStaplesJWT(finalSession);
      logger.info("StaplesJWT created, callback flow complete.", { correlationId, sessionId });
      return res.json({
        adviceHeaders: {
          HTTP_STAPLES_JWT: staplesJwt,
          HTTP_STAPLES_COOKIE_VALUE: sessionId,
          // Optionally, instruct proxy to redirect to finalSession.TargetUrl
          // HTTP_STAPLES_REDIRECT_TARGET: finalSession.TargetUrl
        }
      });
    } catch (err) {
      logger.error("Token exchange failed in CALLBACK flow", {
        correlationId, sessionId,
        error: err.response ? { status: err.response.status, data: err.response.data } : err.message
      });
      delete sessionStore[sessionId]; // Clean up session on failure
      return initiateIdpRedirect(req, res, config.defaultRedirectUrl || "/", deviceId, null); // Force new login on error
    }
  } // End CALLBACK flow

  // ── 2. CHANGE USERNAME REQUEST FLOW ──
  if (isChangeUsernameRequest) {
    logger.info("Entering CHANGE-USERNAME flow (redirect to IdP with acr_values)", { correlationId, targetUrl: targetUrlStr });
    // This always initiates a fresh login sequence with specific acr_values.
    // targetUrlStr is the /change-username URL itself.
    return initiateIdpRedirect(req, res, targetUrlStr, deviceId, 'Staples_ChangeUsername');
  }

  // ── 3. EXISTING-SESSION PROCESSING (Not a callback, not a change-username initiation) ──
  if (session) {
    logger.info("Processing existing session", { correlationId, sessionId });
    if (session.FingerPrint !== deviceId) {
      logger.warn("Fingerprint mismatch for existing session; invalidating.", {
        correlationId, sessionId, expected: session.FingerPrint, actual: deviceId
      });
      delete sessionStore[sessionId];
      session = null; // Fall through to new login
    } else {
      logger.debug("Fingerprint verified for existing session", { correlationId, sessionId });
      if (session.AccessToken && !isAccessTokenExpired(session)) {
        logger.info("Access token valid for existing session; issuing StaplesJWT.", { correlationId, sessionId });
        const staplesJwt = buildStaplesJWT(session);
        return res.json({
          adviceHeaders: {
            HTTP_STAPLES_JWT: staplesJwt,
            HTTP_STAPLES_COOKIE_VALUE: sessionId
          }
        });
      }

      logger.info("Access token expired or missing for existing session.", { correlationId, sessionId });
      if (isRefreshTokenValid(session)) {
        logger.info("Attempting token refresh for existing session.", { correlationId, sessionId });
        try {
          const refreshRes = await refreshTokenThrice(session.RefreshToken, correlationId);
          if (refreshRes && refreshRes.data && refreshRes.data.access_token) {
            logger.info("Token refresh successful.", { correlationId, sessionId });
            session.AccessToken = refreshRes.data.access_token;
            if (refreshRes.data.id_token) session.IdToken = refreshRes.data.id_token;
            if (refreshRes.data.refresh_token) session.RefreshToken = refreshRes.data.refresh_token; // Handle refresh token rotation
            sessionStore[sessionId] = session; // Persist updated session

            const staplesJwt = buildStaplesJWT(session);
            return res.json({
              adviceHeaders: {
                HTTP_STAPLES_JWT: staplesJwt,
                HTTP_STAPLES_COOKIE_VALUE: sessionId
              }
            });
          } else {
            logger.warn("Token refresh attempt did not yield a new access token.", { correlationId, sessionId, responseStatus: refreshRes ? refreshRes.status : 'N/A'});
          }
        } catch (err) {
          logger.error("Token refresh attempt failed with an error.", { correlationId, sessionId, error: err.message });
        }
      } else {
        logger.warn("Refresh token invalid or missing; cannot refresh.", { correlationId, sessionId });
      }

      // If refresh failed or not possible, invalidate session
      logger.warn("Invalidating session due to failed/impossible refresh or expired token.", { correlationId, sessionId });
      delete sessionStore[sessionId];
      session = null; // Fall through to new login
    }
  } // End existing session processing

  // ── 4. NEW-LOGIN FLOW (Default) ──
  // Reached if no session, session invalidated, or unhandled case.
  logger.info("Entering NEW-LOGIN flow (redirect to IdP).", { correlationId, reason: session === null ? "No valid session" : "Unhandled existing session state" });
  // targetUrlStr is the original URL the user was trying to access.
  return initiateIdpRedirect(req, res, targetUrlStr, deviceId, null); // Standard login, no specific acr_value
});

// Start Auth service
app.listen(config.port, "0.0.0.0", () => {
  logger.info(`Auth service listening on port ${config.port}.`);
  logger.debug("Configuration in use (sensitive values might be masked or omitted from log in production):", {
      idaasAccessTokenEndpoint: config.idaasAccessTokenEndpoint,
      idaasAuthorizeEndpoint: config.idaasAuthorizeEndpoint,
      appCallbackEndpoint: config.appCallbackEndpoint,
      scope: config.scope,
      // Avoid logging client secrets directly here
  });
});