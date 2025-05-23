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
      return `${timestamp} [${level.toUpperCase()}] ${message}${Object.keys(meta).length ? " " + JSON.stringify(meta) : ""
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
      logger.info(`Attempt ${attempt}: Token refresh successful`, { correlationId, refreshResponse: refreshResponse.data });
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


function parseSessionCookie(cookieValue) {
  let parsed;
  try {
    parsed = JSON.parse(cookieValue);
  } catch (err) {
    throw new Error(`Invalid session cookie JSON: ${err.message}`);
  }

  const {
    StateID,
    NonceID,
    FingerPrint,
    TargetUrl
  } = parsed;

  if (!StateID || !NonceID || !FingerPrint || !TargetUrl) {
    throw new Error('Session cookie is missing one or more required fields');
  }

  // Extract optional PKCE verifier
  const code_verifier = parsed.hasOwnProperty('code_verifier')
    ? parsed.code_verifier
    : undefined;

  return { StateID, NonceID, FingerPrint, TargetUrl, code_verifier };
}


function parseSessionCookie(cookieValue) {
  let parsed;
  try {
    parsed = JSON.parse(cookieValue);
  } catch (err) {
    throw new Error(`Invalid session cookie JSON: ${err.message}`);
  }

  // Safely extract all possible fields using hasOwnProperty
  const SessionID = parsed.hasOwnProperty('SessionID') ? parsed.SessionID : undefined;
  const AccessToken = parsed.hasOwnProperty('AccessToken') ? parsed.AccessToken : undefined;
  const IdToken = parsed.hasOwnProperty('IdToken') ? parsed.IdToken : undefined;
  const RefreshToken = parsed.hasOwnProperty('RefreshToken') ? parsed.RefreshToken : undefined;
  const FingerPrint = parsed.hasOwnProperty('FingerPrint') ? parsed.FingerPrint : undefined;
  const KeepMeLoggedIn = parsed.hasOwnProperty('KeepMeLoggedIn') ? parsed.KeepMeLoggedIn : undefined;
  const StateID = parsed.hasOwnProperty('StateID') ? parsed.StateID : undefined;
  const NonceID = parsed.hasOwnProperty('NonceID') ? parsed.NonceID : undefined;
  const TargetUrl = parsed.hasOwnProperty('TargetUrl') ? parsed.TargetUrl : undefined;
  const code_verifier = parsed.hasOwnProperty('code_verifier') ? parsed.code_verifier : undefined;

  return {
    SessionID,
    AccessToken,
    IdToken,
    RefreshToken,
    FingerPrint,
    KeepMeLoggedIn,
    StateID,
    NonceID,
    TargetUrl,
    code_verifier
  };
}

// ... (all existing code and imports before app.post("/advice")) ...
// ... (sessionStore, logger, helper functions like computeDeviceFingerPrint, buildStaplesJWT, etc. remain as they are) ...
// ... (PKCE helper functions defined above or imported) ...

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
    var NonceID = null;
    var FingerPrint = null;
    var TargetUrl = null;
    var code_verifier = null;

    if (cookieSessionValue) {
      // There is a session cookie present
      if (isCallbackRequest) {
        // --- Callback Flow ---
        logger.info("Callback flow initiated: Parsing session cookie", { correlationId, cookieSessionValue });
        let parsedCookie;
        try {
          session = parseSessionCookie(cookieSessionValue);
          logger.debug("Parsed COOKIE_STAPLES_SESSION from callback", { correlationId, parsedCookie });
          logger.info("Extracted StateID, NonceID, FingerPrint, TargetUrl, and code_verifier from cookie", { correlationId, StateID, NonceID, FingerPrint, TargetUrl, hasCodeVerifier: !!code_verifier });
        } catch (e) {
          if (sessionStore[cookieSessionValue] != null) {
            logger.info("Session cookie found in session store", { correlationId, cookieSessionValue });
            session = sessionStore[cookieSessionValue];
            // StateID = session.StateID;
            // NonceID = session.NonceID;
            FingerPrint = session.FingerPrint;
            //TargetUrl = session.TargetUrl;
            code_verifier = session.hasOwnProperty('code_verifier') ? session.code_verifier : undefined;
            logger.info("Extracted StateID, NonceID, FingerPrint, TargetUrl, and code_verifier from session store", { correlationId, FingerPrint, TargetUrl, hasCodeVerifier: !!code_verifier });
          }
          else {
            logger.warn("Session cookie also not found in session store", { correlationId, cookieSessionValue });
            return res.status(401).json({ error: "Invalid session cookie or format" });
          }
        }

        // Validate device fingerprint against the one in cookie
        if (FingerPrint !== deviceId) {
          logger.warn("FingerPrint mismatch detected in callback", { correlationId, expected: deviceId, received: FingerPrint });
          return res.status(401).json({ error: "FingerPrint mismatch. Re-authenticate required." });
        }
        logger.info("FingerPrint match confirmed in callback", { correlationId });

        // Exchange authorization code for tokens with PING (idaas)
        try {
          logger.info("Exchanging authorization code for tokens with PING", { correlationId, code: contextUrl.searchParams.get("code") });

          // --- PKCE MODIFICATION: Add code_verifier to token request if present ---
          const tokenRequestBody = {
            grant_type: "authorization_code",
            code: contextUrl.searchParams.get("code"),
            client_id: config.idaasClientID,
            client_secret: config.idaasClientSecret,
            redirect_uri: config.appCallbackEndpoint,
          };
          if (code_verifier) { // Only add if PKCE was used (verifier was stored)
            tokenRequestBody.code_verifier = code_verifier;
            logger.debug("Adding code_verifier to token exchange request", { correlationId });
          }

          const tokenResponse = await axios.post(
            config.idaasAccessTokenEndpoint,
            qs.stringify(tokenRequestBody), // Use the constructed body
            { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
          );
          logger.info("Token exchange successful", { correlationId, tokenResponse: tokenResponse.data });
          let finalTokenResponse = tokenResponse;

          // If keep_me_logged_in flag is true, make an additional token exchange call
          if (tokenResponse.data.keep_me_logged_in) {
            // ... (Keep Me Logged In logic remains the same) ...
            let tokenResponseKeepMeLoggedIn = await axios.post(
              config.idaasAccessTokenEndpoint,
              qs.stringify({
                grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
                scope: "transfer openid",
                client_id: config.idaasKeepMeLoggedInClientID,
                client_secret: config.idaasKeepMeLoggedInClientSecret,
                subject_token: tokenResponse.data.access_token,
                subject_token_type: "urn:ietf:params:oauth:token-type:access_token"
              }),
              { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
            );
            logger.info("Token exchange (keep_me_logged_in) successful", { correlationId, tokenResponseKeepMeLoggedIn: tokenResponseKeepMeLoggedIn.data });
            finalTokenResponse.data.access_token = tokenResponseKeepMeLoggedIn.data.access_token;
            finalTokenResponse.data.id_token = tokenResponseKeepMeLoggedIn.data.id_token;
            finalTokenResponse.data.refresh_token = tokenResponseKeepMeLoggedIn.data.refresh_token;
            finalTokenResponse.data.keep_me_logged_in = true;

            // multi refresh test
            // const latestRefreshTokenResponseRemeberMe = await refreshTokenThrice(
            //   tokenResponseKeepMeLoggedIn.data.refresh_token,
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
            KeepMeLoggedIn: finalTokenResponse.data.keep_me_logged_in || false,
            StateID,
            NonceID,
            TargetUrl,
            ...(tokenResponse.data.keep_me_logged_in
              ? {
                OriginalAccessToken: tokenResponse.data.access_token,
                OriginalIdToken: tokenResponse.data.id_token,
                OriginalRefreshToken: tokenResponse.data.refresh_token,
              }
              : {}),

          };

          sessionStore[newSessionId] = session;
          logger.info("Session record updated in PersistenceStore", { correlationId, SessionID: newSessionId });

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
          logger.error("Token exchange failed during callback", { correlationId, error: error.response ? error.response.data : error.message });
          return res.status(500).json({ error: "Token exchange failed" });
        }
      }


      else {
        // --- Non-Callback Flow with existing session cookie ---
        // ... (This section remains largely the same as your previous version) ...
        logger.info("Non-callback flow: Treating session cookie as SessionID", { correlationId, sessionCookie: cookieSessionValue });
        const sessionId = cookieSessionValue;
        session = sessionStore[sessionId];
        if (session) {
          logger.info("Session record found in PersistenceStore", { correlationId, SessionID: sessionId });
          if (session.FingerPrint !== deviceId) {
            logger.warn("FingerPrint mismatch detected in session lookup", { correlationId, expected: deviceId, stored: session.FingerPrint });
            delete sessionStore[sessionId];
            session = null;
          } else if (isAccessTokenExpired(session)) {
            logger.info("AccessToken expired; attempting to refresh token", { correlationId, SessionID: sessionId });
            if (isRefreshTokenValid(session)) {
              try {
                logger.info("Refreshing tokens using RefreshToken", { correlationId, SessionID: sessionId });
                const latestRefreshResponse = await refreshTokenThrice(session.RefreshToken, correlationId);
                if (latestRefreshResponse && latestRefreshResponse.data) {
                  session.AccessToken = latestRefreshResponse.data.access_token;
                  session.IdToken = latestRefreshResponse.data.id_token;
                  if (latestRefreshResponse.data.refresh_token) {
                    session.RefreshToken = latestRefreshResponse.data.refresh_token;
                  }
                  session.FingerPrint = deviceId;
                  sessionStore[sessionId] = session;
                  logger.info("Session successfully refreshed", { correlationId, SessionID: sessionId });
                } else {
                  logger.warn("Token refresh attempt did not yield new tokens or failed. Invalidating session.", { correlationId, SessionID: sessionId });
                  delete sessionStore[sessionId];
                  session = null;
                }
              } catch (err) {
                logger.error("Token refresh failed. Invalidating session.", { correlationId, SessionID: sessionId, error: err.message });
                delete sessionStore[sessionId];
                session = null;
              }
            } else {
              logger.warn("RefreshToken invalid; re-authentication required. Invalidating session.", { correlationId, SessionID: sessionId });
              delete sessionStore[sessionId];
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

    var sessionExist = session && session.AccessToken && !isAccessTokenExpired(session);
    const isChangeUsername = contextUrl.pathname.endsWith("/change-username");
    const isChangePassword = contextUrl.pathname.endsWith("/change-password");

    // Validate session and issue JWT if AccessToken is valid
    if (sessionExist) {

      logger.info("Session is valid.");


      var acrValues = null;
      if (isChangePassword) {
        // --- Change Password Flow ---
        logger.info("Change password flow initiated", { correlationId });
        acrValues = "UpdatePassword";

      } else if (isChangeUsername) {
        // --- Change Username Flow ---
        logger.info("Change username flow initiated", { correlationId });
        acrValues = "Staples_ChangeUsername";
      }
      else {
        logger.info("Session valid. Proceeding to generate JWT", { correlationId, SessionID: session.SessionID });
        const jwtToken = buildStaplesJWT(session);
        logger.info("JWT built and session authenticated", { correlationId, KeepMeLoggedIn: session.KeepMeLoggedIn });
        return res.json({
          adviceHeaders: {
            HTTP_STAPLES_JWT: jwtToken,
            HTTP_STAPLES_COOKIE_VALUE: session.SessionID,
          },
        });
      }
    }

    // No valid session available: Initiate new authentication flow
    if (!isChangeUsername && !isChangePassword) {
      logger.info("No valid session available. Initiating new authentication flow", { correlationId });
    }
    const stateId = uuidv4();
    const nonceId = uuidv4();
    const txnId = 'app-txn-' + uuidv4();
    logger.debug("Generated new GUIDs for StateID and NonceID", { correlationId, StateID: stateId, NonceID: nonceId });

    // --- PKCE MODIFICATION: Prepare sessionCookiePayload in advance to include code_verifier if PKCE is used ---
    const sessionCookiePayload = {
      StateID: stateId,
      NonceID: nonceId,
      FingerPrint: deviceId,
      AccessToken: null,
      IdToken: null,
      RefreshToken: null,
      TargetUrl: context.url
    };
    // code_verifier will be added to sessionCookiePayload if PAR with PKCE is successful

    let authnUrl;

    if (config.usePAR && config.idaasParEndpoint && config.idaasClientID && config.idaasClientSecret) {
      logger.info("Attempting Pushed Authorization Request (PAR) with PKCE", { correlationId });
      try {
        // --- PKCE MODIFICATION: Generate PKCE challenge ---
        const pkce = generatePkceChallenge();
        logger.debug("Generated PKCE challenge", { correlationId, method: pkce.code_challenge_method });

        const parPayload = {
          client_id: config.idaasClientID,
          redirect_uri: config.appCallbackEndpoint,
          scope: "write",
          response_type: config.response_type,
          // --- PKCE MODIFICATION: Add challenge to PAR payload ---
          code_challenge: pkce.code_challenge,
          code_challenge_method: pkce.code_challenge_method,
        };

        const parFullPayload = { ...parPayload, client_secret: config.idaasClientSecret };

        const parResponse = await axios.post(
          config.idaasParEndpoint,
          qs.stringify(parFullPayload),
          { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
        );

        const { request_uri, expires_in } = parResponse.data;
        if (!request_uri) {
          logger.error("PAR response did not include request_uri. Falling back to standard flow.", { correlationId, response: parResponse.data });
        } else {
          logger.info("PAR successful", { correlationId, request_uri, expires_in });
          const authnParamsPAR = new URLSearchParams({
            client_id: config.idaasClientID,
            request_uri: request_uri,
            response_type: config.response_type,
            redirect_uri: config.appCallbackEndpoint,
            ...acrValues ? { acr_values: acrValues } : {},
          });
          authnUrl = `${config.idaasAuthorizeEndpoint}?${authnParamsPAR.toString()}`;
          // --- PKCE MODIFICATION: Store code_verifier in the cookie payload ---
          sessionCookiePayload.code_verifier = pkce.code_verifier;
          logger.debug("Stored code_verifier in session cookie payload for later use", { correlationId });
        }
      } catch (parError) {
        logger.error("Pushed Authorization Request (PAR) failed. Falling back to standard authorization flow.", {
          correlationId,
          error: parError.response ? parError.response.data : parError.message,
        });
      }
    }

    if (!authnUrl) { // If PAR not used, or PAR failed
      if (config.usePAR) {
        logger.warn("PAR was enabled but failed or did not produce a request_uri, using standard authorization flow (without PKCE for this fallback example, unless added separately).", { correlationId });
      }
      // Standard flow (original code, could also add PKCE here if desired for non-PAR flow)
      const authnParams = new URLSearchParams({
        client_id: config.idaasClientID,
        redirect_uri: config.appCallbackEndpoint,
        scope: config.scope,
        response_type: config.response_type,
        state: stateId,
        nonce: nonceId,
        txn_id: txnId,
        ...acrValues ? { acr_values: acrValues } : {},
        // Note: If you want PKCE for non-PAR flow as well, generate and add here,
        // and store code_verifier in sessionCookiePayload.
        // const pkce = generatePkceChallenge();
        // authnParams.set('code_challenge', pkce.code_challenge);
        // authnParams.set('code_challenge_method', pkce.code_challenge_method);
        // sessionCookiePayload.code_verifier = pkce.code_verifier;
      });
      authnUrl = `${config.idaasAuthorizeEndpoint}?${authnParams.toString()}`;
    }

    logger.info("Composed COOKIE_STAPLES_SESSION payload with potentially code_verifier", { correlationId, sessionCookiePayload: Object.keys(sessionCookiePayload) }); // Log keys to avoid logging sensitive data
    logger.info("Constructed PING Authentication URL", { correlationId, authnUrl, usingPAR: authnUrl.includes("request_uri="), usingPKCE: !!sessionCookiePayload.code_verifier });

    return res.json({
      adviceHeaders: {
        HTTP_STAPLES_AUTHN_URL: authnUrl,
        HTTP_STAPLES_COOKIE_VALUE: JSON.stringify(sessionCookiePayload)
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

// ... (app.listen and any other remaining code) ...

// Start Auth service with detailed startup logging
app.listen(config.port, "0.0.0.0", () => {
  logger.info(`Auth service listening on port ${config.port}`);
});
