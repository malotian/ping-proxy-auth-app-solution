require('dotenv').config();
const express = require('express');
const axios = require('axios');
const cookieParser = require('cookie-parser');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const config = require('./config');

const app = express();
app.use(express.json());

app.use(cookieParser());

// In-memory persistence store (for demo purposes)
const sessionStore = {};

/**
 * Compute a device fingerprint based on IP and User-Agent.
 * In a real system, you might include additional factors.
 */
function computeDeviceFingerprint(context) {
  // Combine the values into one string
  const fingerprintData = context.ip + context.userAgent + context.accept + context.acceptLanguage;

  // Compute a SHA-256 hash of the combined string to use as the fingerprint
  return crypto.createHash('sha256').update(fingerprintData).digest('hex');
}

/**
 * Dummy check: determines if the access token is expired.
 * Replace with real expiration logic.
 */
function isAccessTokenExpired(session) {
  // For demo: treat token value "expired" as expired.
  return session.AccessToken === 'expired';
}

/**
 * Dummy check: determines if the refresh token is valid.
 */
function isRefreshTokenValid(session) {
  return session.RefreshToken && session.RefreshToken !== 'invalid';
}

/**
 * Dummy function to build a JWT from session details.
 * Replace with actual JWT creation and signing.
 */
function buildStaplesJWT(session) {
  // For demo, return a simple token string.
  return { token: `JWT-${session.AccessToken || 'no-token'}` };
}

/**
 * /advice endpoint: Called by NGINX with full HTTP request context.
 * It inspects the request, computes a device fingerprint,
 * and checks if a valid session exists via COOKIE_STAPLES_SESSION.
 */
app.post('/advice', async (req, res) => {
  try {
    console.log("Received request at /advice");

    // context = {
    //   method: req.method,
    //   url: req.originalUrl,
    //   headers: req.headers,
    //   body: req.body,
    //   query: req.query,
    //   params: req.params,
    //   // Convert cookies to a string format (if needed)
    //   cookies: req.cookies ? Object.entries(req.cookies).map(([key, value]) => `${key}=${value}`).join('; ') : '',
    //   ip: req.headers['x-forwarded-for']?.split(',')[0].trim() || req.connection?.remoteAddress || 'Unknown',
    //   userAgent: req.get('User-Agent') || '',
    //   accept: req.get('Accept') || '',
    //   acceptLanguage: req.get('Accept-Language') || ''
    // };

    const context = req.body;

    console.log('Context:', JSON.stringify(context, null, 2));


    // Step 1: Compute device fingerprint
    const deviceId = computeDeviceFingerprint(context);
    console.log(`Computed Device Fingerprint: ${deviceId}`);

    let sessionUUID = context.cookies['COOKIE_STAPLES_SESSION'];

    if (sessionUUID) {
      console.log(`Found: COOKIE_STAPLES_SESSION: ${sessionUUID}`);
    } else {
      console.log("Not Found: COOKIE_STAPLES_SESSION");
    }

    let session = sessionUUID ? sessionStore[sessionUUID] : null;
    const contextUrl = new URL(context.url);

    if (session) {
      console.log(`Session found for UUID: ${sessionUUID}`);
      // Step 3: Validate session fingerprint
      if (session.FingerPrint !== deviceId) {
        console.warn(`Fingerprint mismatch! Possible session hijacking for UUID: ${sessionUUID}`);
        session = null; // Invalidate session to force re-authentication
      }
      else if (contextUrl.searchParams.has('code') && contextUrl.pathname.endsWith('/callback')) {
        console.log("Code recived");
        const data = qs.stringify({
          grant_type: 'authorization_code',
          code: contextUrl.searchParams.get('code'),
          client_id: config.idaasClientID,
          client_secret: config.idaasClientSecret,
          redirect_uri: config.appCallbackEnpoint,
        });

        const tokenConfig = {
          method: 'post',
          maxBodyLength: Infinity,
          url: config.idaasAccessTokenEndpoint,
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          data,
        };

        try {
          const idaasResponse = await axios.request(tokenConfig);
          session.AccessToken = idaasResponse.data.AccessToken;
          session.IdToken = idaasResponse.data.IdToken;
          session.RefreshToken = idaasResponse.data.RefreshToken;
          session.FingerPrint = deviceId;
          if (idaasResponse.data.rememberMe) session.rememberMe = true;

          const staplesJWT = buildStaplesJWT(session);
          logger.info(`Session ${sessionUUID} updated after token exchange. Sending JWT.`);
          return res.json({ headers: { HTTP_STAPLES_JWT: staplesJWT.token } });
        } catch (error) {
          logger.error(`Error exchanging token for session ${sessionUUID}: ${error.message}`);
          return res.status(500).json({ error: error.message });
        }
      }
      else if (isAccessTokenExpired(session)) {
        console.log(`Access token expired for UUID: ${sessionUUID}`);

        // Step 4: Attempt token renewal if refresh token is valid
        if (isRefreshTokenValid(session)) {
          try {
            console.log(`Refreshing access token for UUID: ${sessionUUID}`);
            const idaasResponse = await axios.post(config.idaasRenewUrl, {
              refreshToken: session.RefreshToken
            });

            session.AccessToken = idaasResponse.data.AccessToken;
            session.RefreshToken = idaasResponse.data.RefreshToken;
            session.FingerPrint = deviceId; // Update fingerprint after successful refresh

            console.log(`Access token refreshed successfully for UUID: ${sessionUUID}`);
          } catch (err) {
            console.error(`Error refreshing token for UUID: ${sessionUUID}`, err.message);
            session = null; // Force re-authentication on failure
          }
        } else {
          console.warn(`Refresh token invalid for UUID: ${sessionUUID}, requiring re-authentication.`);
          session = null; // Force re-authentication
        }
      }
    } else {
      console.log("No valid session found, initiating authentication flow.");
    }

    // Step 5: Generate response headers for NGINX
    let adviceHeaders = {};

    if (session && session.AccessToken) {
      console.log(`Valid session found for UUID: ${sessionUUID}. Generating JWT.`);

      // Build Staples JWT
      let staplesJWT = buildStaplesJWT(session);
      if (session.rememberMe) {
        staplesJWT.remember_me = true;
      }

      adviceHeaders = {
        HTTP_STAPLES_JWT: staplesJWT.token,
        HTTP_STAPLES_UUID: sessionUUID
      };
    } else {
      // No valid session -> Start new authentication flow
      sessionUUID = uuidv4();
      const state = uuidv4();
      const nonce = uuidv4();

      sessionStore[sessionUUID] = {
        AccessToken: null,
        IdToken: null,
        RefreshToken: null,
        FingerPrint: deviceId,
        nonce: nonce // Store nonce for validation later
      };

      console.log(`New authentication flow initiated. Generated UUID: ${sessionUUID}`);

      // Build IDAAS authentication URL
      const authParams = new URLSearchParams({
        client_id: config.idaasClientID,
        redirect_uri: config.appCallbackEnpoint,
        scope: config.scope,
        response_type: config.response_type,
        state: state,
        nonce: nonce,
        acr_values: config.acrValues
      });

      const authnUrl = `${config.idaasAuthorizeEndpoint}?${authParams.toString()}`;
      console.log(`Generated authentication URL: ${authnUrl}`);

      adviceHeaders = {
        HTTP_STAPLES_AUTHN_URL: authnUrl,
        HTTP_STAPLES_UUID: sessionUUID
      };
    }

    // Step 6: Send response to NGINX
    console.log("Sending response headers to NGINX:", adviceHeaders);
    res.json({ adviceHeaders });

  } catch (error) {
    console.error('Error in /advice:', error.message);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


/**
 * /callback endpoint: Handles the callback from IDAAS after user authentication.
 * Exchanges the authorization code for tokens and updates the session record.
 */
app.post('/callback', async (req, res) => {
  try {
    // Extract the authorization code and session UUID from the callback request.
    const { code, sessionUUID } = req.body;
    if (!code || !sessionUUID) {
      return res.status(400).json({ error: 'Missing code or session UUID' });
    }

    // Simulate back-channel call to IDAAS to exchange the code for tokens.
    const idaasResponse = await axios.post(config.idaasAccessTokenEndpoint, { code });

    // Retrieve the session record.
    let session = sessionStore[sessionUUID];
    if (!session) {
      return res.status(404).json({ error: 'Session not found' });
    }

    // Update the session record with tokens from IDAAS.
    session.AccessToken = idaasResponse.data.AccessToken;
    session.IdToken = idaasResponse.data.IdToken;
    session.RefreshToken = idaasResponse.data.RefreshToken;
    session.FingerPrint = computeDeviceFingerprint(req);
    if (idaasResponse.data.rememberMe) {
      session.rememberMe = true;
    }

    // Build an updated StaplesJWT.
    let staplesJWT = buildStaplesJWT(session);
    if (session.rememberMe) {
      staplesJWT.remember_me = true;
    }

    // Advise NGINX to set the HTTP_STAPLES_JWT header.
    res.json({ headers: { HTTP_STAPLES_JWT: staplesJWT.token } });

  } catch (error) {
    console.error('Error in /callback:', error.message);
    res.status(500).json({ error: error.message });
  }
});

app.listen(config.port, () => {
  console.log(`Auth service listening on port ${config.port}`);
});
