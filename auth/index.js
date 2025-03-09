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
function computeDeviceFingerprint(req) {
  // Use X-Forwarded-For header if available (common when behind a proxy)
  const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress || '';
  const userAgent = req.get('User-Agent') || '';
  const accept = req.get('Accept') || '';
  const acceptLanguage = req.get('Accept-Language') || '';

  // Combine the values into one string
  const fingerprintData = ip + userAgent + accept + acceptLanguage;

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
 * /advice endpoint: Called by NGINX with complete HTTP request context.
 * This endpoint inspects the request, computes a device fingerprint,
 * and checks if a valid session exists (by examining COOKIE_STAPLES_SESSION).
 */
app.post('/advice', async (req, res) => {
  try {
    // Compute device fingerprint from request (e.g., IP and User-Agent)
    const deviceId = computeDeviceFingerprint(req);

    // Check for existing session cookie
    let sessionUUID = req.cookies['COOKIE_STAPLES_SESSION'];
    let session = sessionUUID ? sessionStore[sessionUUID] : null;

    // If a session exists, validate it.
    if (session) {
      // Compare the session fingerprint with the current device fingerprint
      if (session.FingerPrint === deviceId) {
        // Check if the access token is expired.
        if (isAccessTokenExpired(session)) {
          // If refresh token is valid, renew the access token via IDAAS.
          if (isRefreshTokenValid(session)) {
            // Simulate a back-channel call to IDAAS for token renewal.
            const idaasResponse = await axios.post(config.idaasRenewUrl, {
              refreshToken: session.RefreshToken
            });
            session.AccessToken = idaasResponse.data.AccessToken;
            session.RefreshToken = idaasResponse.data.RefreshToken;
            session.FingerPrint = deviceId;
          } else {
            // Refresh token is invalid; require re-authentication.
            session = null;
          }
        }
      } else {
        // Fingerprint mismatch: possible cookie theft. Require re-authentication.
        session = null;
      }
    }

    // Prepare advice headers to be sent back to NGINX.
    let adviceHeaders = {};

    if (session && session.AccessToken) {
      // Valid session found. Build the StaplesJWT.
      let staplesJWT = buildStaplesJWT(session);
      if (session.rememberMe) {
        // Add claim if remember_me is active.
        staplesJWT.remember_me = true;
      }
      adviceHeaders = {
        HTTP_STAPLES_JWT: staplesJWT.token,
        HTTP_STAPLES_UUID: sessionUUID
      };
    } else {
      // No valid session exists: trigger new authentication flow.
      // Generate a new UUID and initialize a session record.
      sessionUUID = uuidv4();
      const state = uuidv4();
      const nonce = uuidv4();
      sessionStore[sessionUUID] = {
        AccessToken: null,
        IdToken: null,
        RefreshToken: null,
        FingerPrint: deviceId,
        nonce: nonce // store nonce for later validation
      };

      // Compose the IDAAS authentication URL 
      const params = new URLSearchParams({
        client_id: config.idaasClientID,
        redirect_uri: config.appCallbackEnpoint,
        scope: config.scope,
        response_type: config.response_type,
        state: state,
        nonce: nonce,
        acr_values: config.acrValues,
      });

      // Build the full authentication URL
      const authnUrl = `${config.idaasAuthorizeEndpoint}?${params.toString()}`;

      adviceHeaders = {
        HTTP_STAPLES_AUTHN_URL: authnUrl,
        HTTP_STAPLES_UUID: sessionUUID
      };
    }

    // Send advice back to NGINX.
    res.json({ adviceHeaders });

  } catch (error) {
    console.error('Error in /advice:', error.message);
    res.status(500).json({ error: error.message });
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
