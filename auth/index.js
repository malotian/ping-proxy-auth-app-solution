require('dotenv').config();
const express = require('express');
const axios = require('axios');
const cookieParser = require('cookie-parser');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const config = require('./config');
const qs = require('qs');
const jwt = require("jsonwebtoken");
const { generateKeyPairSync } = require("crypto");
const forge = require("node-forge");
const winston = require('winston');

const app = express();
app.use(express.json());
app.use(cookieParser());

// Create a Winston logger with timestamp and structured output.
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    // Custom format: [timestamp] [LEVEL] message {optional meta}
    winston.format.printf(({ level, message, timestamp, ...meta }) => {
      return `${timestamp} [${level.toUpperCase()}] ${message}${Object.keys(meta).length ? ' ' + JSON.stringify(meta) : ''}`;
    })
  ),
  transports: [new winston.transports.Console()]
});

// Middleware to attach a unique correlationId from the proxy header (or default).
app.use((req, res, next) => {
  req.correlationId = req.headers['proxy-correlation-id'] || 'N/A';
  logger.info('Incoming request', {
    correlationId: req.correlationId,
    method: req.method,
    url: req.originalUrl,
    ip: req.headers['x-forwarded-for']?.split(',')[0].trim() || req.connection?.remoteAddress || 'Unknown'
  });
  next();
});

// In-memory persistence store (for demo purposes)
const sessionStore = {};

// Generate RSA Key Pair
const { privateKey, publicKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

// Convert Public Key to JWKS Format
const forgeKey = forge.pki.publicKeyFromPem(publicKey);
const n = Buffer.from(forgeKey.n.toByteArray()).toString("base64url");
const e = Buffer.from(forgeKey.e.toByteArray()).toString("base64url");

// Serve JWKS endpoint correctly
app.get("/.well-known/jwks.json", (req, res) => {
  logger.info('Serving JWKS endpoint');
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

/**
 * Compute a device fingerprint based on IP and User-Agent.
 */
function computeDeviceFingerprint(context, secretKey = null) {
  try {
    // Validate required context properties.
    if (!context || !context.ip || !context.userAgent) {
      throw new Error("Missing required context fields: ip and userAgent");
    }

    // Build a structured fingerprint object.
    const fingerprintComponents = {
      ip: context.ip,
      userAgent: context.userAgent
      // Optionally add other stable properties like screen resolution or timezone.
    };

    // Canonicalize the data using JSON.stringify.
    const fingerprintData = JSON.stringify(fingerprintComponents);
    logger.debug("Fingerprint data prepared", { fingerprintData });

    let fingerprint;

    // Use HMAC with a secret key if provided for extra security.
    if (secretKey) {
      fingerprint = crypto
        .createHmac("sha256", secretKey)
        .update(fingerprintData)
        .digest("hex");
      logger.debug("Computed fingerprint using HMAC", { fingerprint });
    } else {
      fingerprint = crypto
        .createHash("sha256")
        .update(fingerprintData)
        .digest("hex");
      logger.debug("Computed fingerprint using SHA-256", { fingerprint });
    }

    // Log at info level the final fingerprint.
    logger.info("DeviceFingerprint computed", { fingerprint });
    return fingerprint;
  } catch (error) {
    logger.error("Error computing device fingerprint", { error });
    throw error;
  }
}


/**
 * Dummy check: determines if the access token is expired.
 */
function isAccessTokenExpired(session) {
  return session.AccessToken === "expired";
}

/**
 * Dummy check: determines if the refresh token is valid.
 */
function isRefreshTokenValid(session) {
  return session.RefreshToken && session.RefreshToken !== "invalid";
}

/**
 * Dummy function to build a JWT from session details.
 */
function buildStaplesJWT(session) {
  return jwt.sign(session, privateKey, {
    algorithm: "RS256",
    expiresIn: "1h",
    keyid: "staples-kid", // Ensure keyid matches JWKS kid
  });
}

/**
 * /advice endpoint: Called by NGINX with full HTTP request context.
 */
app.post("/advice", async (req, res) => {
  const correlationId = req.correlationId;
  try {
    logger.info("Received request at /advice", { correlationId });

    // Using req.body as the context.
    const context = req.body;
    logger.info("Context received", { correlationId, context });

    // Step 1: Compute device fingerprint
    const deviceId = computeDeviceFingerprint(context);
    logger.info("Computed Device Fingerprint", { correlationId, deviceId });

    let sessionUUID = context.cookies && context.cookies["COOKIE_STAPLES_SESSION"];
    if (sessionUUID) {
      logger.info("Found COOKIE_STAPLES_SESSION", { correlationId, sessionUUID });
    } else {
      logger.info("COOKIE_STAPLES_SESSION not found", { correlationId });
    }

    let session = sessionUUID ? sessionStore[sessionUUID] : null;
    const contextUrl = new URL(context.url);

    if (session) {
      logger.info("Session found", { correlationId, sessionUUID });
      if (session.FingerPrint !== deviceId) {
        logger.warn("Fingerprint mismatch! Possible session hijacking", { correlationId, sessionUUID });
        session = null;
      } else if (contextUrl.searchParams.has("code") && contextUrl.pathname.endsWith("/callback")) {
        logger.info("Authorization code received", { correlationId });
        const data = qs.stringify({
          grant_type: "authorization_code",
          code: contextUrl.searchParams.get("code"),
          client_id: config.idaasClientID,
          client_secret: config.idaasClientSecret,
          redirect_uri: config.appCallbackEnpoint,
        });

        const tokenConfig = {
          method: "post",
          maxBodyLength: Infinity,
          url: config.idaasAccessTokenEndpoint,
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          data,
        };

        try {
          const idaasResponse = await axios.request(tokenConfig);
          logger.info("IDAAS token exchange successful", { correlationId, response: idaasResponse.data });

          session.AccessToken = idaasResponse.data.access_token;
          session.IdToken = idaasResponse.data.id_token;
          session.RefreshToken = idaasResponse.data.refresh_token;
          session.FingerPrint = deviceId;
          if (idaasResponse.data.rememberMe) session.rememberMe = true;

          logger.info("Session updated after token exchange", { correlationId, session });
          const staplesJWT = buildStaplesJWT(session);
          logger.info("Created staplesJWT", { correlationId, staplesJWT });
          return res.json({ adviceHeaders: { HTTP_STAPLES_JWT: staplesJWT } });
        } catch (error) {
          logger.error("Error exchanging token", { correlationId, sessionUUID, error: error.message });
          return res.status(500).json({ error: error.message });
        }
      } else if (isAccessTokenExpired(session)) {
        logger.info("Access token expired", { correlationId, sessionUUID });
        if (isRefreshTokenValid(session)) {
          try {
            logger.info("Attempting to refresh access token", { correlationId, sessionUUID });
            const idaasResponse = await axios.post(config.idaasRenewUrl, {
              refreshToken: session.RefreshToken,
            });
            session.AccessToken = idaasResponse.data.access_token;
            session.IdToken = idaasResponse.data.id_token;
            session.RefreshToken = idaasResponse.data.refresh_token;
            session.FingerPrint = deviceId;
            logger.info("Access token refreshed successfully", { correlationId, session });
          } catch (err) {
            logger.error("Error refreshing token", { correlationId, sessionUUID, error: err.message });
            session = null;
          }
        } else {
          logger.warn("Refresh token invalid, requiring re-authentication", { correlationId, sessionUUID });
          session = null;
        }
      }
    } else {
      logger.info("No valid session found, initiating authentication flow", { correlationId });
    }

    // Step 5: Generate response headers for NGINX.
    let adviceHeaders = {};
    if (session && session.AccessToken) {
      logger.info("Valid session found; generating JWT", { correlationId, sessionUUID });
      let staplesJWT = buildStaplesJWT(session);
      if (session.rememberMe) {
        // Optionally add additional information if needed.
        staplesJWT.remember_me = true;
      }
      adviceHeaders = {
        HTTP_STAPLES_JWT: staplesJWT.token || staplesJWT, // Adjust according to your JWT structure
        HTTP_STAPLES_UUID: sessionUUID,
      };
    } else {
      sessionUUID = uuidv4();
      const state = uuidv4();
      const nonce = uuidv4();

      sessionStore[sessionUUID] = {
        SessionUUID: sessionUUID,
        AccessToken: null,
        IdToken: null,
        RefreshToken: null,
        FingerPrint: deviceId,
        nonce: nonce,
      };

      logger.info("Initiating new authentication flow", { correlationId, sessionUUID });
      const authParams = new URLSearchParams({
        client_id: config.idaasClientID,
        redirect_uri: config.appCallbackEnpoint,
        scope: config.scope,
        response_type: config.response_type,
        state: state,
        nonce: nonce,
        acr_values: config.acrValues,
      });
      const authnUrl = `${config.idaasAuthorizeEndpoint}?${authParams.toString()}`;
      logger.info("Generated authentication URL", { correlationId, authnUrl });

      adviceHeaders = {
        HTTP_STAPLES_AUTHN_URL: authnUrl,
        HTTP_STAPLES_UUID: sessionUUID,
      };
    }

    logger.info("Sending response headers to NGINX", { correlationId, adviceHeaders });
    res.json({ adviceHeaders });
  } catch (error) {
    logger.error("Error in /advice endpoint", { correlationId, error: error.message, stack: error.stack });
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.listen(config.port, "0.0.0.0", () => {
  logger.info(`Auth service listening on port ${config.port}`);
});
