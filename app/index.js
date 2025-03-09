require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const config = require('./config');
const app = express();

app.use(express.json());
app.use(cookieParser());

// Tier-A /login GET endpoint
app.get('/login', (req, res) => {
  // Retrieve custom headers set by the reverse proxy.
  const authnUrl = req.headers['http_staples_authn_url']; // AuthnURL provided if re-authentication is needed
  const jwtHeader = req.headers['http_staples_jwt'];         // JWT token (with possible "remember_me" attribute)
  const sessionUUID = req.headers['http_staples_uuid'];       // Session UUID

  console.log('Received headers in Tier-A /login:', req.headers);

  if (authnUrl) {
    // Redirect the browser to the IDAAS/PING authentication endpoint
    console.log(`Redirecting to authentication URL: ${authnUrl}`);
    return res.redirect(authnUrl);
  } else if (jwtHeader && sessionUUID) {
    // If JWT and UUID are provided, set a cookie for session tracking.
    // Determine cookie options based on the "remember_me" claim.
    let cookieOptions = {
      httpOnly: true,
      secure: true,
      sameSite: 'strict'
    };
    
    if (jwtHeader.includes('remember_me:true')) {
      // Set cookie expiration for 180 days if remember_me is active.
      cookieOptions.maxAge = 180 * 24 * 60 * 60 * 1000;
    }

    res.cookie('COOKIE_STAPLES_SESSION', sessionUUID, cookieOptions);
    console.log(`Setting session cookie: ${sessionUUID}`, cookieOptions);
    return res.send(`<h1>Session Established</h1><p>Session cookie set: ${sessionUUID}</p>`);
  } else {
    // No advice headers found – render a basic login page.
    return res.send('<h1>Login Page</h1><p>Please login to continue.</p>');
  }
});

// Tier-A /login POST endpoint for processing login form submission (if applicable)
app.post('/login', (req, res) => {
  res.json({
    message: 'Login successful (Tier-A)',
    receivedHeaders: req.rawHeaders,
    data: req.body
  });
});

app.listen(config.port, () => {
  console.log(`Tier-A (staples) app listening on port ${config.port}`);
});
