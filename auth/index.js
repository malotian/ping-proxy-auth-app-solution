require("dotenv").config();
const express = require("express");
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
  req.correlationId = req.headers["proxy-correlation-id"] || "N/A";
  const clientIp = req.headers["x-forwarded-for"]?.split(",")[0].trim() ||
                   req.connection?.remoteAddress || "Unknown";
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
        kid: "staples-kid",
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
  // In real scenarios, implement actual expiry checks
  return session.AccessToken === "expired";
}

function isRefreshTokenValid(session) {
  // In real scenarios, implement proper validation of RefreshToken
  return session.RefreshToken && session.RefreshToken !== "invalid";
}

// Function: Build StaplesJWT from session details
function buildStaplesJWT(session) {
  const payload = session;

  logger.debug("Building StaplesJWT payload", { payload });
  const token = jwt.sign(payload, privateKey, {
    algorithm: "RS256",
    expiresIn: "1h",
    keyid: "staples-kid",
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
          client_id: config.idaasKeepMeLoggedInClientID,
          client_secret: config.idaasKeepMeLoggedInClientSecret,
        }),
        { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
      );

      latestRefreshResponse = refreshResponse;
      logger.info(`Attempt ${attempt}: Token refresh successful`, {correlationId, refreshResponse: refreshResponse.data});
    } catch (refreshError) {
      logger.warn(`Attempt ${attempt}: Token refresh failed`, {
        correlationId,
        error: refreshError
      });
      break; // optional: break on first failure or allow retries
    }
  }

  return latestRefreshResponse;
}

// Helper function to generate a random string for the code_verifier
function generateRandomString(length) {
  let text = "";
  const possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
  for (let i = 0; i < length; i++) {
    text += possible.charAt(Math.floor(Math.random() * possible.length));
  }
  return text;
}

// Helper function to generate SHA256 hash and Base64URL encode it
function sha256(buffer) {
  return crypto.createHash("sha256").update(buffer).digest();
}

function base64URLEncode(str) {
  return str.toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

// Main function to generate PKCE challenge
function generatePkceChallenge() {
  const verifier = generateRandomString(128); // code_verifier: min 43, max 128 chars
  const challenge = base64URLEncode(sha256(verifier)); // code_challenge
  return {
    code_verifier: verifier,
    code_challenge: challenge,
    code_challenge_method: "S256"
  };
}

app.post("/advice", async (req, res) => {
  const { url, cookies = {}, ip, userAgent } = req.body;
  const correlationId = req.correlationId;

  logger.info("Entering /advice handler", {
    correlationId,
    rawBody: req.body
  });

  // 1) Compute device fingerprint
  let deviceId;
  try {
    deviceId = computeDeviceFingerPrint({ ip, userAgent });
    logger.debug("Computed device fingerprint", { correlationId, deviceId, ip, userAgent });
  } catch (err) {
    logger.error("Failed to compute device fingerprint", { correlationId, error: err.message });
    return res.status(400).json({ error: "Invalid device context" });
  }

  // 2) Parse URL & extract sessionId from cookie
  const ctxUrl = new URL(url);
  logger.debug("Parsed request URL", { correlationId, url, pathname: ctxUrl.pathname, search: ctxUrl.search });

  const sessionId = cookies["COOKIE_STAPLES_SESSION"];
  logger.debug("Extracted sessionId from cookie", { correlationId, sessionId });

  let session = sessionId ? sessionStore[sessionId] : null;
  logger.debug("Loaded session from store", { correlationId, hasSession: !!session });

  const isCallback = ctxUrl.pathname.endsWith("/callback") && ctxUrl.searchParams.has("code");
  logger.info("Determined callback status", { correlationId, isCallback });

  // ── CALLBACK FLOW ──
  if (session && isCallback) {
    logger.info("Entering CALLBACK flow", { correlationId, sessionId });

    // 3) Fingerprint check
    if (session.FingerPrint !== deviceId) {
      logger.warn("Fingerprint mismatch in CALLBACK flow", {
        correlationId,
        expected: session.FingerPrint,
        actual: deviceId
      });
      return res.status(401).json({ error: "Fingerprint mismatch" });
    }
    logger.debug("Fingerprint verified in CALLBACK flow", { correlationId });

    // 4) Exchange code → tokens
    const code = ctxUrl.searchParams.get("code");
    const tokenReq = {
      grant_type:    "authorization_code",
      code,
      client_id:     config.idaasClientID,
      client_secret: config.idaasClientSecret,
      redirect_uri:  config.appCallbackEndpoint,
    };
    logger.debug("Built token request payload", { correlationId, tokenReq: { ...tokenReq, client_secret: '***' } });

    if (session.code_verifier) {
      tokenReq.code_verifier = session.code_verifier;
      logger.debug("Added PKCE code_verifier to token request", { correlationId, code_verifier: session.code_verifier });
    }

    try {
      const { data } = await axios.post(
        config.idaasAccessTokenEndpoint,
        qs.stringify(tokenReq),
        { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
      );
      logger.info("Received token response", {
        correlationId,
        tokens: { access_token: '***', id_token: '***', refresh_token: '***' }
      });

      // 5) Mutate the same session object
      Object.assign(session, {
        SessionID:      sessionId,
        AccessToken:    data.access_token,
        IdToken:        data.id_token,
        RefreshToken:   data.refresh_token,
        KeepMeLoggedIn: !!data.keep_me_logged_in
      });
      logger.debug("Updated session object after token exchange", { correlationId, session });

      const staplesJwt = buildStaplesJWT(session);
      logger.info("Built StaplesJWT and completing CALLBACK flow", { correlationId, SessionID: sessionId });

      return res.json({
        adviceHeaders: {
          HTTP_STAPLES_JWT:          staplesJwt,
          HTTP_STAPLES_COOKIE_VALUE: sessionId
        }
      });
    } catch (err) {
      logger.error("Token exchange failed in CALLBACK flow", {
        correlationId,
        error: err.response ? err.response.data : err.message
      });
      return res.status(500).json({ error: "Token exchange failed" });
    }
  }

  // ── EXISTING-SESSION FLOW ──
  if (session && !isCallback) {
    logger.info("Entering EXISTING-SESSION flow", { correlationId, sessionId });
    if (session.FingerPrint !== deviceId) {
      logger.warn("Fingerprint mismatch in EXISTING-SESSION flow; invalidating session", {
        correlationId,
        expected: session.FingerPrint,
        actual: deviceId
      });
      delete sessionStore[sessionId];
      session = null;
    } else {
      logger.debug("Fingerprint verified in EXISTING-SESSION flow", { correlationId });
    }
  }

  // 6) If session valid & access token still good → re-issue JWT
  if (session && session.AccessToken && !isAccessTokenExpired(session)) {
    logger.info("Existing session is valid; issuing JWT", { correlationId, sessionId });
    const staplesJwt = buildStaplesJWT(session);
    return res.json({
      adviceHeaders: {
        HTTP_STAPLES_JWT:          staplesJwt,
        HTTP_STAPLES_COOKIE_VALUE: sessionId
      }
    });
  }

  // 7) If expired but refreshable → attempt refresh
  if (session && isAccessTokenExpired(session) && isRefreshTokenValid(session)) {
    logger.info("Access token expired; attempting refresh", { correlationId, sessionId });
    try {
      const refreshRes = await refreshTokenThrice(session.RefreshToken, correlationId);
      if (refreshRes?.data) {
        logger.info("Refresh token call succeeded", { correlationId });
        Object.assign(session, {
          AccessToken:  refreshRes.data.access_token,
          IdToken:      refreshRes.data.id_token,
          RefreshToken: refreshRes.data.refresh_token || session.RefreshToken
        });
        logger.debug("Updated session after refresh", { correlationId, session });

        const staplesJwt = buildStaplesJWT(session);
        return res.json({
          adviceHeaders: {
            HTTP_STAPLES_JWT:          staplesJwt,
            HTTP_STAPLES_COOKIE_VALUE: sessionId
          }
        });
      }
    } catch (err) {
      logger.error("Token refresh failed", { correlationId, error: err.message });
    }

    logger.warn("Failed to refresh token; invalidating session", { correlationId, sessionId });
    delete sessionStore[sessionId];
    session = null;
  }

  // ── NEW-LOGIN FLOW (PKCE ALWAYS) ──
  logger.info("Entering NEW-LOGIN flow with PKCE", { correlationId });

  // a) Generate new sessionId & nonces
  const newSessionId = uuidv4();
  const stateId      = uuidv4();
  const nonceId      = uuidv4();
  const preAuth      = {
    StateID:     stateId,
    NonceID:     nonceId,
    FingerPrint: deviceId,
    TargetUrl:   url
  };
  logger.debug("Created pre-auth session object", { correlationId, newSessionId, preAuth });

  // b) Generate PKCE challenge/verifier
  const pkce = generatePkceChallenge();
  preAuth.code_verifier = pkce.code_verifier;
  logger.debug("Generated PKCE challenge", { correlationId, pkce });

  // c) Build authorize URL with PKCE parameters
  const txnId = 'app-txn-' + uuidv4();
  const params = new URLSearchParams({
    client_id:             config.idaasClientID,
    redirect_uri:          config.appCallbackEndpoint,
    scope:                 config.scope,
    response_type:         config.response_type,
    state:                 stateId,
    nonce:                 nonceId,
    txn_id:                txnId,
    code_challenge:        pkce.code_challenge,
    code_challenge_method: pkce.code_challenge_method
  });
  const authnUrl = `${config.idaasAuthorizeEndpoint}?${params}`;
  logger.debug("Constructed authnUrl with PKCE", { correlationId, authnUrl });

  // d) Persist the preAuth session under newSessionId
  sessionStore[newSessionId] = preAuth;
  logger.info("Saved new pre-auth session to store", { correlationId, newSessionId });

  // e) Return the redirect URL + only the sessionId cookie
  return res.json({
    adviceHeaders: {
      HTTP_STAPLES_AUTHN_URL:    authnUrl,
      HTTP_STAPLES_COOKIE_VALUE: newSessionId
    }
  });
});


// ... (app.listen and any other remaining code) ...

// Start Auth service with detailed startup logging
app.listen(config.port, "0.0.0.0", () => {
  logger.info(`Auth service listening on port ${config.port}`);
});
