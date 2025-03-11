require('dotenv').config();
const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');  // Import JWT package
const config = require('./config');
const crypto = require('crypto');
const jwksClient = require("jwks-rsa");
const axios = require("axios");

const app = express();

// Middleware
app.use(express.json());
app.use(cookieParser());

// Override session ID from headers if provided
app.use((req, res, next) => {
  if (req.headers['http_staples_uuid']) {
    req.sessionID = req.headers['http_staples_uuid'];
  }
  next();
});

// Configure express-session
app.use(session({
  genid: (req) => req.sessionID || crypto.randomUUID(),
  secret: config.sharedSessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: false,
    maxAge: null // Default session cookie (expires on browser close)
  }
}));

/// Function to parse JWT safely
const parseJWT = (token) => {
  try {
    const decoded = jwt.decode(token); // Decode JWT without verifying
    return decoded || {}; // Ensure it returns an object (empty if decoding fails)
  } catch (error) {
    console.error('Invalid JWT:', error);
    return null; // Return null if JWT is invalid
  }
};

// Tier-A /login GET endpoint
app.get('/login', (req, res) => {
  console.log('Received headers in app /login:', req.rawHeaders);

  const authnUrl = req.headers['http_staples_authn_url'];
  const jwtHeader = req.headers['http_staples_jwt'];
  const sessionUUID = req.headers['http_staples_uuid'];

  let jwtData = jwtHeader ? parseJWT(jwtHeader) : null; // Parse JWT only if available

  if (sessionUUID) {
    // Store session data
    req.session.user = {
      sessionUUID,
      jwt: jwtData || null, // Store null if JWT is missing or invalid
      rememberMe: jwtData?.remember_me ?? null, // If remember_me is missing, set to null
    };

    let cookieOptions = {
      httpOnly: true,
      secure: false,
    };

    if (req.session.user.rememberMe) {
      cookieOptions.maxAge = 180 * 24 * 60 * 60 * 1000; // 180 days
    }

    res.cookie('COOKIE_STAPLES_SESSION', sessionUUID, cookieOptions);
    console.log(`Session established for: ${sessionUUID}`, req.session.user);
  }

  if (authnUrl) {
    console.log(`Redirecting to authentication URL: ${authnUrl}`);
    return res.redirect(authnUrl);
  }

  return res.send('<h1>Login Page</h1><p>Please login to continue.</p>');
});

// Logout Endpoint (to destroy session)
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Error destroying session:', err);
      return res.status(500).send('Failed to logout');
    }

    res.clearCookie('COOKIE_STAPLES_SESSION');
    return res.send('<h1>Logged Out</h1><p>Session cleared successfully.</p>');
  });
});

// Check Session
app.get('/session-check', (req, res) => {
  if (req.session.user) {
    return res.json({
      message: 'Session Active',
      sessionData: req.session.user
    });
  }
  return res.status(401).json({ message: 'No active session' });
});

// Set your JWKS URI (Replace with actual JWKS URI)
const JWKS_URI = "http://auth.lab.com:3002/.well-known/jwks.json";

// Initialize JWKS Client
const client = jwksClient({
  jwksUri: JWKS_URI,
});

// Function to get the signing key from JWKS
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
 * /callback endpoint: Handles the callback from IDAAS after user authentication.
 * Exchanges the authorization code for tokens and updates the session record.
 */
app.get('/callback', async (req, res) => {
  try {
    console.log('Received headers in /callback:', req.headers);

    // Extract JWT token from headers
    const staplesJWT = req.headers['http_staples_jwt'] || req.headers['HTTP_STAPLES_JWT'] || req.headers['http-staples-jwt'];

    if (!staplesJWT) {
      return res.status(401).json({ error: "No staplesJWT provided" });
    }

    // Retrieve the signing key dynamically
    jwt.verify(staplesJWT, getSigningKey, { algorithms: ["RS256"] }, (err, decoded) => {
      if (err) {
        console.error("JWT verification failed:", err.message);
        return res.status(401).json({ error: "Invalid staplesJWT token", details: err.message });
      }

      console.log("Token validation successful:", decoded);

      // Store user info in request object (for further processing if needed)
      req.stapleJWT = decoded;

      // Send successful response
      return res.json({ message: "Token validation successful", stapleJWT: decoded });
    });

  } catch (error) {
    console.error("Error processing /callback:", error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

// Start server
app.listen(config.port, '0.0.0.0', () => {
  console.log(`app listening on port ${config.port}`);
});
