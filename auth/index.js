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
          client_id: config.idaasRememberClientID,
          client_secret: config.idaasRememberClientSecret,
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

// Main authentication advice route following sequence diagram
app.post("/advice", async (req, res) => {
  const correlationId = req.correlationId;
  logger.info("Received /advice request", { correlationId, body: req.body });

  try {
    // Extract context from request body as passed from TierA/NGINX
    const context = req.body;
    // Compute device fingerprint (DeviceID)
    const deviceId = computeDeviceFingerPrint(context);
    logger.info("Device fingerprint computed", { correlationId, deviceId });

    // Extract URL and cookies from context for further processing
    const contextUrl = new URL(context.url);
    const cookies = context.cookies || {};
    const cookieSessionValue = cookies["COOKIE_STAPLES_SESSION"];
    logger.debug("Extracted cookie and URL info", { correlationId, cookieSessionValue, pathname: contextUrl.pathname });

    // Determine if the request is a callback from PING (i.e., URL ends with /callback with a code parameter)
    const isCallbackRequest = contextUrl.pathname.endsWith("/callback") && contextUrl.searchParams.has("code");
    logger.info("Is callback request?", { correlationId, isCallbackRequest });

    let session = null;

    if (cookieSessionValue) {
      // There is a session cookie present
      if (isCallbackRequest) {
        // --- Callback Flow ---
        logger.info("Callback flow initiated: Parsing session cookie", { correlationId });
        let parsedCookie;
        try {
          parsedCookie = JSON.parse(cookieSessionValue);
          logger.debug("Parsed COOKIE_STAPLES_SESSION from callback", { correlationId, parsedCookie });
        } catch (e) {
          logger.warn("Failed to parse COOKIE_STAPLES_SESSION during callback", { correlationId, error: e.message });
          return res.status(400).json({ error: "Invalid session cookie format" });
        }
        const { StateID, NonceID, FingerPrint, TargetUrl} = parsedCookie;

        logger.info("Extracted StateID, NonceID, and FingerPrint from cookie", { correlationId, StateID, NonceID, FingerPrint, TargetUrl});

        // Validate device fingerprint against the one in cookie
        if (FingerPrint !== deviceId) {
          logger.warn("FingerPrint mismatch detected in callback", { correlationId, expected: deviceId, received: FingerPrint });
          return res.status(401).json({ error: "FingerPrint mismatch. Re-authenticate required." });
        }
        logger.info("FingerPrint match confirmed in callback", { correlationId });

        // Exchange authorization code for tokens with PING (idaas)
        try {
          logger.info("Exchanging authorization code for tokens with PING", { correlationId, code: contextUrl.searchParams.get("code") });
          const tokenResponse = await axios.post(
            config.idaasAccessTokenEndpoint,
            qs.stringify({
              grant_type: "authorization_code",
              code: contextUrl.searchParams.get("code"),
              client_id: config.idaasClientID,
              client_secret: config.idaasClientSecret,
              redirect_uri: config.appCallbackEnpoint,
            }),
            { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
          );
          logger.info("Token exchange successful", { correlationId, tokenResponse: tokenResponse.data });
          let finalTokenResponse = tokenResponse;

          // If remember_me flag is true, make an additional token exchange call
          if (tokenResponse.data.remember_me) {
            let tokenResponseRememberMe = await axios.post(
              config.idaasAccessTokenEndpoint,
              qs.stringify({
                grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
                scope: "transfer openid",
                client_id: config.idaasRememberClientID,
                client_secret: config.idaasRememberClientSecret,
                subject_token: tokenResponse.data.access_token,
                subject_token_type: "urn:ietf:params:oauth:token-type:access_token"
              }),
              { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
            );
            logger.info("Token exchange (remember_me) successful", {correlationId, tokenResponseRememberMe: tokenResponseRememberMe.data});
            tokenResponseRememberMe.data.remember_me = true;

            finalTokenResponse.data.access_token = tokenResponseRememberMe.data.access_token;
            finalTokenResponse.data.id_token = tokenResponseRememberMe.data.id_token;
            finalTokenResponse.data.remember_me = true;


            // multi refresh test
            // const latestRefreshTokenResponseRemeberMe = await refreshTokenThrice(
            //   tokenResponseRememberMe.data.refresh_token,
            //   correlationId
            // );          

            // if (latestRefreshTokenResponseRemeberMe?.data?.access_token) {
            //   finalTokenResponse.data.access_token = latestRefreshTokenResponseRemeberMe.data.access_token;
            // }
            
            // if (latestRefreshTokenResponseRemeberMe?.data?.id_token) {
            //   finalTokenResponse.data.id_token = latestRefreshTokenResponseRemeberMe.data.id_token;
            // }
          }

          // Generate new SessionID and update session store (PersistenceStore)
          const newSessionId = uuidv4();
          session = {
            SessionID: newSessionId,
            AccessToken: finalTokenResponse.data.access_token,
            IdToken: finalTokenResponse.data.id_token,
            RefreshToken: finalTokenResponse.data.refresh_token,
            FingerPrint: deviceId,
            RememberMe: finalTokenResponse.data.remember_me || false,
            StateID,
            NonceID,
            TargetUrl,
            ...(tokenResponse.data.remember_me
              ? {
                  OriginalAccessToken: tokenResponse.data.access_token,
                  OriginalIdToken:    tokenResponse.data.id_token,
                  OriginalRefreshToken: tokenResponse.data.refresh_token,
                }
              : {}),
            
          };

          sessionStore[newSessionId] = session;
          logger.info("Session record updated in PersistenceStore", { correlationId, SessionID: newSessionId, session });

          // Build JWT for the authenticated session
          const jwtToken = buildStaplesJWT(session);
          logger.info("Callback processing completed successfully", { correlationId });
          return res.json({
            adviceHeaders: {
              HTTP_STAPLES_JWT: jwtToken,
              HTTP_STAPLES_COOKIE_VALUE: newSessionId,
            },
          });
        } catch (error) {
          logger.error("Token exchange failed during callback", { correlationId, error: error.message });
          return res.status(500).json({ error: "Token exchange failed" });
        }
      } else {
        // --- Non-Callback Flow with existing session cookie ---
        logger.info("Non-callback flow: Treating session cookie as SessionID", { correlationId, sessionCookie: cookieSessionValue });
        const sessionId = cookieSessionValue;
        session = sessionStore[sessionId];
        if (session) {
          logger.info("Session record found in PersistenceStore", { correlationId, SessionID: sessionId, session });
          // Validate fingerprint from session against current DeviceID
          if (session.FingerPrint !== deviceId) {
            logger.warn("FingerPrint mismatch detected in session lookup", { correlationId, expected: deviceId, stored: session.FingerPrint });
            session = null;
          } else if (isAccessTokenExpired(session)) {
            logger.info("AccessToken expired; attempting to refresh token", { correlationId, SessionID: sessionId });
            if (isRefreshTokenValid(session)) {
              try {
                logger.info("Refreshing tokens using RefreshToken", { correlationId, SessionID: sessionId });
                const refreshResponse = await axios.post(config.idaasRenewUrl, { refreshToken: session.RefreshToken });
                session.AccessToken = refreshResponse.data.access_token;
                session.IdToken = refreshResponse.data.id_token;
                session.RefreshToken = refreshResponse.data.refresh_token;
                session.RememberMe = refreshResponse.data.remember_me || false;
                session.FingerPrint = deviceId; // Update fingerprint if needed
                logger.info("Session successfully refreshed", { correlationId, SessionID: sessionId, session });
              } catch (err) {
                logger.error("Token refresh failed", { correlationId, SessionID: sessionId, error: err.message });
                session = null;
              }
            } else {
              logger.warn("RefreshToken invalid; re-authentication required", { correlationId, SessionID: sessionId });
              session = null;
            }
          } else {
            logger.info("Existing session is valid with unexpired AccessToken", { correlationId, SessionID: sessionId });
          }
        } else {
          logger.warn("No session record found for provided SessionID", { correlationId, SessionID: sessionId });
        }
      }
    }

    // Validate session and issue JWT if AccessToken is valid
    if (session && session.AccessToken) {
      logger.info("Session valid. Proceeding to generate JWT", { correlationId, SessionID: session.SessionID });
      const jwtToken = buildStaplesJWT(session);
      logger.info("JWT built and session authenticated", { correlationId, RememberMe: session.RememberMe });
      return res.json({
        adviceHeaders: {
          HTTP_STAPLES_JWT: jwtToken,
          HTTP_STAPLES_COOKIE_VALUE: session.SessionID,
        },
      });
    }

    // No valid session available: Initiate new authentication flow
    logger.info("No valid session available. Initiating new authentication flow", { correlationId });
    const stateId = uuidv4();
    const nonceId = uuidv4();
    logger.debug("Generated new GUIDs for StateID and NonceID", { correlationId, StateID: stateId, NonceID: nonceId });

    // Compose COOKIE_STAPLES_SESSION_VALUE with null tokens and current DeviceID
    const sessionCookiePayload = {
      StateID: stateId,
      NonceID: nonceId,
      FingerPrint: deviceId,
      AccessToken: null,
      IdToken: null,
      RefreshToken: null,
      TargetUrl: context.url
    };
    logger.info("Composed new COOKIE_STAPLES_SESSION payload", { correlationId, sessionCookiePayload });

    // Compose PING Authentication URL with required parameters
    const authnParams = new URLSearchParams({
      client_id: config.idaasClientID,
      redirect_uri: config.appCallbackEnpoint,
      scope: config.scope,
      response_type: config.response_type,
      state: stateId,
      nonce: nonceId,
      //acr_values: config.acrValues,
    });
    const authnUrl = `${config.idaasAuthorizeEndpoint}?${authnParams.toString()}`;
    logger.info("Constructed PING Authentication URL", { correlationId, authnUrl });

    // Advise NGINX/TierA to set authentication headers accordingly
    return res.json({
      adviceHeaders: {
        HTTP_STAPLES_AUTHN_URL: authnUrl,
        HTTP_STAPLES_COOKIE_VALUE: JSON.stringify(sessionCookiePayload),
      },
    });
  } catch (err) {
    logger.error("Error processing /advice", {
      correlationId,
      error: err.message,
      stack: err.stack,
    });
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

// Start Auth service with detailed startup logging
app.listen(config.port, "0.0.0.0", () => {
  logger.info(`Auth service listening on port ${config.port}`);
});
