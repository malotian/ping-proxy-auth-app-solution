require('dotenv').config();
const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
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
  genid: (req) => req.sessionID || crypto.randomUUID(), // Use custom session ID or generate one
  name: 'COOKIE_STAPLES_SESSION', // Custom session cookie name
  secret: config.sharedSessionSecret, // Used for signing session ID
  resave: false,  
  saveUninitialized: false, // Avoid saving empty sessions
  cookie: {
    httpOnly: true,  
    secure: process.env.NODE_ENV === 'production', // Only secure in production
    sameSite: 'strict',  
    maxAge: null // Default session cookie (expires on browser close)
  }
}));

// Tier-A /login GET endpoint
app.get('/login', (req, res) => {
  console.log('Received headers in Tier-A /login:', req.rawHeaders);

  const authnUrl = req.headers['http_staples_authn_url'];
  const jwtHeader = req.headers['http_staples_jwt'];
  const sessionUUID = req.headers['http_staples_uuid'];

  if (authnUrl) {
    console.log(`Redirecting to authentication URL: ${authnUrl}`);
    return res.redirect(authnUrl);
  }

  if (jwtHeader && sessionUUID) {
    // Store session data
    req.session.user = {
      sessionUUID,
      jwt: jwtHeader,
      rememberMe: jwtHeader.includes('remember_me:true')
    };

    // If remember_me is true, extend session expiration
    if (req.session.user.rememberMe) {
      req.session.cookie.maxAge = 180 * 24 * 60 * 60 * 1000; // 180 days
    }

    console.log(`Session established for: ${sessionUUID}`);
    return res.send(`<h1>Session Established</h1><p>Session cookie set with sessionUUID: ${sessionUUID}</p>`);
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
  console.log(`app listening on port ${config.port}`);
});
