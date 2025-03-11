require('dotenv').config();
const express = require('express');
const axios = require('axios');
const cookieParser = require('cookie-parser');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const config = require('./config');
const qs = require('qs');
const jwt = require("jsonwebtoken");
const { generateKeyPairSync } = require("crypto");
const forge = require("node-forge");

const app = express();
app.use(express.json());

app.use(cookieParser());

// In-memory persistence store (for demo purposes)
const sessionStore = {};

// Generate RSA Key Pair
const { privateKey, publicKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

// Convert Public Key to JWKS Format
const forgeKey = forge.pki.publicKeyFromPem(publicKey);
const n = Buffer.from(forgeKey.n.toByteArray()).toString("base64url");
const e = Buffer.from(forgeKey.e.toByteArray()).toString("base64url");

// Serve JWKS endpoint correctly
app.get("/.well-known/jwks.json", (req, res) => {
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

  return jwt.sign(session, privateKey, {
    algorithm: "RS256",
    expiresIn: "1h",
    keyid: "staples-kid", // Ensure keyid matches JWKS kid
  });
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

          console.log("IDAAS Response:", idaasResponse.data);

          session.AccessToken = idaasResponse.data.access_token;
          session.IdToken = idaasResponse.data.id_token;
          session.RefreshToken = idaasResponse.data.refresh_token;
          session.FingerPrint = deviceId;
          console.log(`Session updated after token exchange:\n`, JSON.stringify(session, null, 2));

          if (idaasResponse.data.rememberMe) session.rememberMe = true;

          const staplesJWT = buildStaplesJWT(session);

          console.log(`Created staplesJWT: ${staplesJWT}`);

          return res.json({ adviceHeaders: { HTTP_STAPLES_JWT: staplesJWT } });
        } catch (error) {
          console.log(`Error exchanging token for session ${sessionUUID}: ${error.message}`);
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

            session.AccessToken = idaasResponse.data.access_token;
            session.IdToken = idaasResponse.data.id_token;
            session.RefreshToken = idaasResponse.data.refresh_token;
            session.FingerPrint = deviceId; // Update fingerprint after successful refresh

            console.log(`Access token refreshed successfully:\n`, JSON.stringify(session, null, 2));
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
        SessionUUID: sessionUUID,
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


app.listen(config.port, '0.0.0.0', () => {
  console.log(`Auth service listening on port ${config.port}`);
});
