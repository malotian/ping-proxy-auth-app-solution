require('dotenv').config();
const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const config = require('./config');
const crypto = require('crypto');
const jwksClient = require("jwks-rsa");
const axios = require("axios");
const winston = require('winston');

const app = express();

// Middleware: parse JSON and cookies.
app.use(express.json());
app.use(cookieParser());

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

// Create a Winston logger with timestamps and structured output.
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

// Override session ID from headers if provided.
app.use((req, res, next) => {
  if (req.headers['http_staples_uuid']) {
    req.sessionID = req.headers['http_staples_uuid'];
    logger.info("Overriding sessionID from header", {
      correlationId: req.correlationId,
      sessionID: req.sessionID
    });
  }
  next();
});

// Configure express-session.
app.use(session({
  genid: (req) => req.sessionID || crypto.randomUUID(),
  secret: config.sharedSessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: false,
    maxAge: null // Session cookie expires on browser close.
  }
}));

// Function to safely parse a JWT.
const parseJWT = (token) => {
  try {
    const decoded = jwt.decode(token); // Decode without verifying.
    return decoded || {}; // Ensure an object is returned.
  } catch (error) {
    logger.error("Invalid JWT", { correlationId: 'N/A', error: error.message });
    return null;
  }
};

// /login endpoint: Handles login flow.
app.get('/login', (req, res) => {
  const correlationId = req.correlationId;
  logger.info("Received /login request headers", {
    correlationId,
    rawHeaders: req.rawHeaders
  });

  const authnUrl = req.headers['http_staples_authn_url'];
  const jwtHeader = req.headers['http_staples_jwt'];
  const sessionUUID = req.headers['http_staples_uuid'];

  let jwtData = jwtHeader ? parseJWT(jwtHeader) : null;

  if (sessionUUID) {
    // Store session data.
    req.session.user = {
      sessionUUID,
      jwt: jwtData || null,
      rememberMe: jwtData?.remember_me ?? null,
    };

    let cookieOptions = {
      httpOnly: true,
      secure: false,
    };

    if (req.session.user.rememberMe) {
      cookieOptions.maxAge = 180 * 24 * 60 * 60 * 1000; // 180 days.
    }

    res.cookie('COOKIE_STAPLES_SESSION', sessionUUID, cookieOptions);
    logger.info(`Session established for: ${sessionUUID}`, {
      correlationId,
      sessionUser: req.session.user
    });
  }

  if (authnUrl) {
    logger.info(`Redirecting to authentication URL: ${authnUrl}`, { correlationId });
    return res.redirect(authnUrl);
  }

  return res.send('<h1>Login Page</h1><p>Please login to continue.</p>');
});

// /logout endpoint: Destroys the current session.
app.get('/logout', (req, res) => {
  const correlationId = req.correlationId;
  req.session.destroy((err) => {
    if (err) {
      logger.error("Error destroying session", { correlationId, error: err });
      return res.status(500).send('Failed to logout');
    }
    res.clearCookie('COOKIE_STAPLES_SESSION');
    logger.info("Session destroyed successfully", { correlationId });
    return res.send('<h1>Logged Out</h1><p>Session cleared successfully.</p>');
  });
});

// /session-check endpoint: Verifies if an active session exists.
app.get('/session-check', (req, res) => {
  if (req.session.user) {
    return res.json({
      message: 'Session Active',
      sessionData: req.session.user
    });
  }
  return res.status(401).json({ message: 'No active session' });
});

// Set JWKS URI (replace with actual JWKS URI).
const JWKS_URI = "http://auth.lab.com:3002/.well-known/jwks.json";

// Initialize JWKS Client.
const client = jwksClient({
  jwksUri: JWKS_URI,
});

// Function to retrieve the signing key from JWKS.
function getSigningKey(header, callback) {
  client.getSigningKey(header.kid, (err, key) => {
    if (err) {
      return callback(err);
    }
    const signingKey = key.publicKey || key.rsaPublicKey;
    callback(null, signingKey);
  });
}

/**
 * /callback endpoint: Handles the callback from IDAAS after authentication.
 * It verifies the provided JWT and responds with the token details.
 */
app.get('/callback', async (req, res) => {
  const correlationId = req.correlationId;
  try {
    logger.info("Received /callback request headers", {
      correlationId,
      headers: req.headers
    });

    // Extract the staplesJWT from headers (supporting various header casings).
    const staplesJWT = req.headers['http_staples_jwt'] || req.headers['HTTP_STAPLES_JWT'] || req.headers['http-staples-jwt'];

    if (!staplesJWT) {
      logger.warn("No staplesJWT provided", { correlationId });
      return res.status(401).json({ error: "No staplesJWT provided" });
    }

    // Verify the JWT using the signing key from JWKS.
    jwt.verify(staplesJWT, getSigningKey, { algorithms: ["RS256"] }, (err, decoded) => {
      if (err) {
        logger.error("JWT verification failed", { correlationId, error: err.message });
        return res.status(401).json({ error: "Invalid staplesJWT token", details: err.message });
      }
      logger.info("Token validation successful", { correlationId, decoded });
      // Store the decoded token in the request for further processing if needed.
      req.stapleJWT = decoded;
      return res.json({ message: "Token validation successful", stapleJWT: decoded });
    });

  } catch (error) {
    logger.error("Error processing /callback", {
      correlationId,
      error: error.message
    });
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

// Start the server.
app.listen(config.port, '0.0.0.0', () => {
  logger.info(`App listening on port ${config.port}`);
});
