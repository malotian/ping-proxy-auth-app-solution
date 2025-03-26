require("dotenv").config();
const express = require("express");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const jwksClient = require("jwks-rsa");
const axios = require("axios");
const config = require("./config");
const winston = require("winston");

const app = express();
app.use(express.json());
app.use(cookieParser());

// Enhanced verbose logging
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

// JWKS client setup for JWT signature validation
const jwksUri = config.jwksUri;
const client = jwksClient({ jwksUri });

// Retrieve signing key with detailed logging
function getSigningKey(header, callback) {
  logger.debug("Requesting signing key from JWKS", { kid: header.kid });
  client.getSigningKey(header.kid, (err, key) => {
    if (err) {
      logger.error("Error retrieving signing key", { error: err.message });
      return callback(err);
    }
    const signingKey = key.getPublicKey();
    logger.debug("Obtained signing key successfully", { signingKey });
    callback(null, signingKey);
  });
}

// Middleware: Extract custom headers according to sequence diagram
app.use((req, res, next) => {
  req.correlationId = req.headers["proxy-correlation-id"] || "N/A";
  req.authnUrl = req.headers["http_staples_authn_url"];           // PING Authentication URL (if present)
  req.staplesJwtToken = req.headers["http_staples_jwt"];            // JWT token (if present)
  req.staplesSessionId = req.headers["http_staples_cookie_value"];  // Session cookie value

  logger.debug("Headers extracted", {
    correlationId: req.correlationId,
    method: req.method,
    url: req.originalUrl,
    http_staples_authn_url: req.authnUrl,
    jwtPresent: !!req.staplesJwtToken,
    http_staples_cookie_value: req.staplesSessionId,
  });
  next();
});

// /login Route - Follows the sequence diagram exactly
app.get("/login", (req, res) => {
  const { correlationId, authnUrl, staplesJwtToken, staplesSessionId } = req;
  logger.info("Processing /login request", { correlationId });

  // If HTTP_STAPLES_AUTHN_URL header is present, initiate new authentication flow.
  if (authnUrl) {
    logger.info("Detected HTTP_STAPLES_AUTHN_URL header - initiating new authentication flow", {
      correlationId,
      authnUrl,
      sessionCookieValue: staplesSessionId,
    });
    // Set session cookie with default expiry as per sequence diagram.
    res.cookie("COOKIE_STAPLES_SESSION", staplesSessionId, { httpOnly: true, secure: false });
    logger.debug("Set COOKIE_STAPLES_SESSION cookie with default expiry", { correlationId, cookieValue: staplesSessionId });
    // Redirect to PING Authorization URL
    logger.info("Redirecting browser to PING Authorization URL", { correlationId, redirectUrl: authnUrl });
    return res.redirect(authnUrl);
  }

  // If HTTP_STAPLES_JWT header is present, validate and process existing session.
  if (staplesJwtToken) {
    logger.info("Detected HTTP_STAPLES_JWT header - validating existing session", { correlationId });
    jwt.verify(staplesJwtToken, getSigningKey, { algorithms: ["RS256"] }, (err, decoded) => {
      if (err) {
        logger.warn("JWT verification failed", { correlationId, error: err.message });
        return res.status(401).send("Invalid JWT");
      }

      logger.info("JWT verified successfully", { correlationId, decoded });
      const rememberMe = decoded.RememberMe === true;
      const cookieOptions = {
        httpOnly: true,
        secure: false,
        ...(rememberMe ? { maxAge: 180 * 24 * 60 * 60 * 1000 } : {}), // Persistent cookie if 'RememberMe' is true.
      };

      // Set session cookie according to whether 'RememberMe' is enabled.
      res.cookie("COOKIE_STAPLES_SESSION", staplesSessionId, cookieOptions);
      logger.info("Session cookie set", {
        correlationId,
        sessionId: staplesSessionId,
        rememberMe,
        cookieOptions,
      });

      // Forward the request to downstream TierB via Zuul.
      logger.info("Forwarding validated JWT to downstream TierB via Zuul", { correlationId });
      return res.json(decodeStaplesJwt(staplesJwtToken, correlationId));
    });
    return;
  }

  // Neither HTTP_STAPLES_AUTHN_URL nor HTTP_STAPLES_JWT present: user must initiate authentication.
  logger.info("No authentication headers found; prompting user to login", { correlationId });
  return res.send("<h1>Login Required</h1><p>Please initiate authentication.</p>");
});

// /callback Route - Handles redirection from PING as per sequence diagram
app.get("/callback", async (req, res) => {
  const correlationId = req.correlationId;
  logger.info("Received /callback request", { correlationId, query: req.query });
  try {
    const staplesJwtToken = req.staplesJwtToken;
    const staplesSessionId = req.staplesSessionId;

    if (!staplesJwtToken) {
      logger.warn("No HTTP_STAPLES_JWT token provided in /callback", { correlationId });
      return res.status(401).json({ error: "No HTTP_STAPLES_JWT token provided" });
    }

    jwt.verify(staplesJwtToken, getSigningKey, { algorithms: ["RS256"] }, (err, decoded) => {
      if (err) {
        logger.error("JWT verification failed in /callback", { correlationId, error: err.message });
        return res.status(401).json({ error: "Invalid staplesJwtToken", details: err.message });
      }

      logger.info("JWT verified successfully in /callback", { correlationId, decoded });
      const rememberMe = decoded.RememberMe === true;
      const cookieOptions = {
        httpOnly: true,
        secure: false,
        ...(rememberMe ? { maxAge: 180 * 24 * 60 * 60 * 1000 } : {}), // Persistent cookie if applicable.
      };

      // Set session cookie as per sequence diagram instructions.
      res.cookie("COOKIE_STAPLES_SESSION", staplesSessionId, cookieOptions);
      logger.info("Session cookie set in /callback", {
        correlationId,
        sessionId: staplesSessionId,
        rememberMe,
        cookieOptions,
      });

      return res.json(decodeStaplesJwt(staplesJwtToken, correlationId));

    });
  } catch (error) {
    logger.error("Error processing /callback", { correlationId, error: error.message });
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

function decodeStaplesJwt(jwtToken, correlationId) {
  // Decode the outer JWT token with full details (header, payload, signature)
  const decodedOuter = jwt.decode(jwtToken, { complete: true });
  
  if (!decodedOuter) {
    logger.error("Failed to decode outer JWT", { correlationId });
    return { error: "Invalid outer JWT token" };
  }

  // Decode nested tokens if present
  let decodedAccess = null;
  if (decodedOuter.payload && decodedOuter.payload.AccessToken) {
    decodedAccess = jwt.decode(decodedOuter.payload.AccessToken, { complete: true });
  }
  
  let decodedId = null;
  if (decodedOuter.payload && decodedOuter.payload.IdToken) {
    decodedId = jwt.decode(decodedOuter.payload.IdToken, { complete: true });
  }

  let decodedRefresh = null;
  if (decodedOuter.payload && decodedOuter.payload.RefreshToken) {
    decodedRefresh = jwt.decode(decodedOuter.payload.RefreshToken, { complete: true });
  } 

  logger.info("Decoded JWT token with nested tokens", {
    correlationId,
    outerToken: decodedOuter,
    accessToken: decodedAccess,
    idToken: decodedId,
    refershToken: decodedRefresh
  });

  return {
    message: "Decoded JWT Token",
    StaplesJWT: decodedOuter,
    AccessTokenDecoded: decodedAccess,
    IdTokenDecoded: decodedId,
    RefreshTokenDecoded: decodedRefresh,
  };
}

// Start the TierA service with detailed startup logging
app.listen(config.port, () => {
  logger.info(`app running on port ${config.port}`);
});
