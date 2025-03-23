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

// Logger setup
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || "info",
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

// Attach correlationId
app.use((req, res, next) => {
  req.correlationId = req.headers["proxy-correlation-id"] || "N/A";
  logger.info("Incoming request", {
    correlationId: req.correlationId,
    method: req.method,
    url: req.originalUrl,
    ip:
      req.headers["x-forwarded-for"]?.split(",")[0].trim() ||
      req.connection?.remoteAddress ||
      "Unknown",
  });
  next();
});

// In-memory store (demo only)
const sessionStore = {};

// RSA Key Pair and JWKS
const { privateKey, publicKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});
const forgeKey = forge.pki.publicKeyFromPem(publicKey);
const n = Buffer.from(forgeKey.n.toByteArray()).toString("base64url");
const e = Buffer.from(forgeKey.e.toByteArray()).toString("base64url");

app.get("/.well-known/jwks.json", (req, res) => {
  logger.info("Serving JWKS endpoint");
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

// Device fingerprint function
function computeDeviceFingerprint(context, secretKey = null) {
  if (!context || !context.ip || !context.userAgent) {
    throw new Error("Missing required context fields: ip and userAgent");
  }

  const fingerprintComponents = {
    ip: context.ip,
    userAgent: context.userAgent,
  };

  const fingerprintData = JSON.stringify(fingerprintComponents);
  let fingerprint;

  if (secretKey) {
    fingerprint = crypto
      .createHmac("sha256", secretKey)
      .update(fingerprintData)
      .digest("hex");
  } else {
    fingerprint = crypto
      .createHash("sha256")
      .update(fingerprintData)
      .digest("hex");
  }

  logger.info("DeviceFingerprint computed", { fingerprint });
  return fingerprint;
}

function isAccessTokenExpired(session) {
  return session.AccessToken === "expired";
}

function isRefreshTokenValid(session) {
  return session.RefreshToken && session.RefreshToken !== "invalid";
}

function buildStaplesJWT(session) {
  const payload = {
    AccessToken: session.AccessToken,
    IdToken: session.IdToken,
    SessionID: session.SessionID,
    RememberMe: session.RememberMe || false, // ✅ INCLUDED AS PER SPEC
  };

  return jwt.sign(payload, privateKey, {
    algorithm: "RS256",
    expiresIn: "1h",
    keyid: "staples-kid",
  });
}

app.post("/advice", async (req, res) => {
  const correlationId = req.correlationId;

  try {
    const context = req.body;
    logger.info("Received /advice request", { correlationId, context });

    const deviceId = computeDeviceFingerprint(context);
    const contextUrl = new URL(context.url);
    const cookies = context.cookies || {};
    const cookieSessionValue = cookies["COOKIE_STAPLES_SESSION"];

    const isCallbackRequest =
      contextUrl.pathname.endsWith("/callback") &&
      contextUrl.searchParams.has("code");

    let session = null;

    if (isCallbackRequest) {
      // CASE: Callback from Ping with JSON-formatted cookie
      let parsed;
      try {
        parsed = JSON.parse(cookieSessionValue);
      } catch (e) {
        logger.warn("Invalid COOKIE_STAPLES_SESSION format in callback", {
          correlationId,
          error: e.message,
        });
        return res.status(400).json({ error: "Invalid session cookie format" });
      }

      const { StateID, NonceID, FingerPrint: cookieFingerprint } = parsed;

      logger.info("Parsed COOKIE_STAPLES_SESSION (callback)", {
        correlationId,
        StateID,
        NonceID,
        cookieFingerprint,
      });

      if (cookieFingerprint !== deviceId) {
        logger.warn("Fingerprint mismatch during callback", { correlationId });
        return res.status(401).json({ error: "Fingerprint mismatch. Re-authenticate required." });
      }

      try {
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

        const newSessionId = uuidv4();

        session = {
          SessionID: newSessionId,
          AccessToken: tokenResponse.data.access_token,
          IdToken: tokenResponse.data.id_token,
          RefreshToken: tokenResponse.data.refresh_token,
          FingerPrint: deviceId,
          RememberMe: tokenResponse.data.remember_me || false,
          StateID,
          NonceID,
        };

        sessionStore[newSessionId] = session;

        const jwtToken = buildStaplesJWT(session);

        return res.json({
          adviceHeaders: {
            HTTP_STAPLES_JWT: jwtToken,
            HTTP_STAPLES_COOKIE_VALUE: newSessionId,
          },
        });
      } catch (error) {
        logger.error("Token exchange failed", {
          correlationId,
          error: error.message,
        });
        return res.status(500).json({ error: "Token exchange failed" });
      }
    }

    // Non-callback flow — treat cookie as UUID for session lookup
    if (cookieSessionValue) {
      const sessionId = cookieSessionValue;
      session = sessionStore[sessionId];

      if (session) {
        if (session.FingerPrint !== deviceId) {
          logger.warn("Fingerprint mismatch", { correlationId });
          session = null;
        } else if (isAccessTokenExpired(session)) {
          if (isRefreshTokenValid(session)) {
            try {
              const refreshResponse = await axios.post(config.idaasRenewUrl, {
                refreshToken: session.RefreshToken,
              });

              session.AccessToken = refreshResponse.data.access_token;
              session.IdToken = refreshResponse.data.id_token;
              session.RefreshToken = refreshResponse.data.refresh_token;
              session.RememberMe = refreshResponse.data.remember_me || false;
              session.FingerPrint = deviceId;

              logger.info("Session refreshed", { correlationId });
            } catch (err) {
              logger.error("Token refresh failed", {
                correlationId,
                error: err.message,
              });
              session = null;
            }
          } else {
            logger.warn("Invalid refresh token", { correlationId });
            session = null;
          }
        }
      }
    }

    // If session is valid and AccessToken exists, issue JWT
    if (session && session.AccessToken) {
      const jwtToken = buildStaplesJWT(session);
      return res.json({
        adviceHeaders: {
          HTTP_STAPLES_JWT: jwtToken,
          HTTP_STAPLES_COOKIE_VALUE: session.SessionID,
        },
      });
    }

    // No valid session — initiate authentication (no sessionStore write)
    const stateId = uuidv4();
    const nonceId = uuidv4();

    const sessionCookiePayload = {
      StateID: stateId,
      NonceID: nonceId,
      FingerPrint: deviceId,
    };

    const authnParams = new URLSearchParams({
      client_id: config.idaasClientID,
      redirect_uri: config.appCallbackEnpoint,
      scope: config.scope,
      response_type: config.response_type,
      state: stateId,
      nonce: nonceId,
      acr_values: config.acrValues,
    });

    const authnUrl = `${config.idaasAuthorizeEndpoint}?${authnParams.toString()}`;

    return res.json({
      adviceHeaders: {
        HTTP_STAPLES_AUTHN_URL: authnUrl,
        HTTP_STAPLES_COOKIE_VALUE: JSON.stringify(sessionCookiePayload),
      },
    });
  } catch (err) {
    logger.error("Error in /advice", {
      correlationId,
      error: err.message,
      stack: err.stack,
    });
    res.status(500).json({ error: "Internal Server Error" });
  }
});



app.listen(config.port, "0.0.0.0", () => {
  logger.info(`Auth service listening on port ${config.port}`);
});
