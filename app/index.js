require('dotenv').config();
const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');  // Import JWT package
const config = require('./config');
const crypto = require('crypto');

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
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
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
  console.log('Received headers in Tier-A /login:', req.rawHeaders);

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
      sameSite: 'Strict'
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

// Start server
app.listen(config.port, () => {
  console.log(`Tier-A (staples) app listening on port ${config.port}`);
});
