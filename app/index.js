require("dotenv").config();
const express = require("express");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const jwksClient = require("jwks-rsa");
const axios = require("axios");
const config = require("./config");
const winston = require("winston");
const path = require("path");

const app = express();
app.use(express.json());
app.use(cookieParser());

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

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
    logger.info("Redirecting browser to PING Authorization URL", { correlationId, redirectUrl: authnUrl });
    return res.redirect(authnUrl);
  }

  if (!staplesJwtToken) {
    logger.warn("No HTTP_STAPLES_JWT token provided in /login", { correlationId });
    return res.status(401).json({ error: "No HTTP_STAPLES_JWT token provided" });
  }

  jwt.verify(staplesJwtToken, getSigningKey, { algorithms: ["RS256"] }, (err, decoded) => {
    if (err) {
      logger.error("JWT verification failed in /login", { correlationId, error: err.message });
      return res.status(401).json({ error: "Invalid staplesJwtToken", details: err.message });
    }

    logger.info("JWT verified successfully in /login", { correlationId, decoded });
    const keepMeLoggedIn = decoded.KeepMeLoggedIn === true;
    const cookieOptions = {
      httpOnly: true,
      secure: false,
      ...(keepMeLoggedIn ? { maxAge: 180 * 24 * 60 * 60 * 1000 } : {}), // Persistent cookie if applicable.
    };

    // Set session cookie as per sequence diagram instructions.
    res.cookie("COOKIE_STAPLES_SESSION", staplesSessionId, cookieOptions);
    logger.info("Session cookie set in /login", {
      correlationId,
      sessionId: staplesSessionId,
      keepMeLoggedIn,
      cookieOptions,
    });

    return res.render("jsonViewer", { inputData: expandTimestamps(parseJwt(staplesJwtToken, true)) });
  
  });
});

// /callback Route - Handles redirection from PING as per sequence diagram
app.get("/callback", async (req, res) => {
  const correlationId = req.correlationId;
  logger.info("Received /callback request", { correlationId, query: req.query });
  try {

    const { correlationId, staplesJwtToken, staplesSessionId } = req;

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
      const keepMeLoggedIn = decoded.KeepMeLoggedIn === true;
      const cookieOptions = {
        httpOnly: true,
        secure: false,
        ...(keepMeLoggedIn ? { maxAge: 180 * 24 * 60 * 60 * 1000 } : {}), // Persistent cookie if applicable.
      };

      // Set session cookie as per sequence diagram instructions.
      res.cookie("COOKIE_STAPLES_SESSION", staplesSessionId, cookieOptions);
      logger.info("Session cookie set in /callback", {
        correlationId,
        sessionId: staplesSessionId,
        keepMeLoggedIn,
        cookieOptions,
      });

      logger.info("Redirecting from /callback to TargetUrl", { correlationId, TargetUrl: decoded.TargetUrl });
      return res.redirect(decoded.TargetUrl);
    
    });
  } catch (error) {
    logger.error("Error processing /callback", { correlationId, error: error.message });
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

const jwtRegex = /^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+$/;

function parseJwt(input, recursive = true) {
  // Use regex to check if input is a JWT string.
  if (typeof input === "string" && jwtRegex.test(input)) {
    const decoded = jwt.decode(input, { complete: true });
    if (!decoded) {
      throw new Error("Failed to decode token");
    }
    if (recursive && decoded.payload && typeof decoded.payload === "object") {
      Object.keys(decoded.payload).forEach(key => {
        if (typeof decoded.payload[key] === "string" && jwtRegex.test(decoded.payload[key])) {
          decoded.payload[key] = parseJwt(decoded.payload[key], recursive);
        }
      });
    }
    return decoded;
  }
  if (typeof input === "object" && input !== null) {
    Object.keys(input).forEach(key => {
      input[key] = parseJwt(input[key], recursive);
    });
  }
  return input;
}

function expandTimestamps(obj) {
  if (Array.isArray(obj)) {
    return obj.map(expandTimestamps);
  }

  if (obj !== null && typeof obj === 'object') {
    for (const key of Object.keys(obj)) {
      obj[key] = expandTimestamps(obj[key]);
    }
    return obj;
  }

  if (typeof obj === 'number' && obj >= 1e9) {
    const date = new Date(obj * 1000);
    const longDate = date.toLocaleString('en-US', {
      weekday: 'long',
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: 'numeric',
      minute: 'numeric',
      second: 'numeric',
      timeZone: 'UTC',
      timeZoneName: 'short'
    });
    return `${obj}|${longDate}`;
  }

  return obj;
}
// Start the TierA service with detailed startup logging
app.listen(config.port, () => {
  logger.info(`app running on port ${config.port}`);
});
