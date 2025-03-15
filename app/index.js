require("dotenv").config();
const express = require("express");
const session = require("express-session");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const config = require("./config");
const crypto = require("crypto");
const jwksClient = require("jwks-rsa");
const axios = require("axios");
const winston = require("winston");

const app = express();

// Create a Winston logger with timestamps and structured output.
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    // Custom format: [timestamp] [LEVEL] message {optional meta}
    winston.format.printf(({ level, message, timestamp, ...meta }) => {
      return `${timestamp} [${level.toUpperCase()}] ${message}${
        Object.keys(meta).length ? " " + JSON.stringify(meta) : ""
      }`;
    })
  ),
  transports: [new winston.transports.Console()],
});

// Middleware: parse JSON and cookies.
app.use(express.json());
app.use(cookieParser());

// Middleware to attach a unique correlationId from the proxy header (or default).
// Middleware to extract Staples-specific headers and attach them to req.
app.use((req, res, next) => {

  req.correlationId = req.headers["proxy-correlation-id"] || "N/A";

  // Retrieve header values with Staples-specific naming.
  const staplesSessionId = req.headers["http_staples_uuid"];
  const staplesAuthModuleUrl = req.headers["http_staples_authn_url"];
  const staplesJwtToken = req.headers["http_staples_jwt"];

  // Override sessionID if a Staples session ID is provided.
  if (staplesSessionId) {
    req.staplesSessionId = staplesSessionId;
    logger.info("Overriding sessionID from header", {
      correlationId: req.correlationId,
      staplesSessionId: req.staplesSessionId,
    });
  }

  // Set the Staples Auth Module URL if provided.
  if (staplesAuthModuleUrl) {
    req.staplesAuthModuleUrl = staplesAuthModuleUrl;
    logger.info("Setting Staples Auth Module URL from header", {
      correlationId: req.correlationId,
      staplesAuthModuleUrl: req.staplesAuthModuleUrl,
    });
  }

  // Set the Staples JWT token if provided.
  if (staplesJwtToken) {
    req.staplesJwtToken = staplesJwtToken;
    logger.info("Setting Staples JWT token from header", {
      correlationId: req.correlationId,
      staplesJwtToken: req.staplesJwtToken,
    });
  }

  next();
});

// Note: Removed the previous middleware that directly overrode the sessionID.

// Configure express-session.
app.use(
  session({
    genid: (req) => req.staplesSessionId || crypto.randomUUID(),
    secret: config.sharedSessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: false,
      maxAge: null, // Session cookie expires on browser close.
    },
  })
);

// Function to safely parse a JWT.
const parseJWT = (token) => {
  try {
    const decoded = jwt.decode(token); // Decode without verifying.
    return decoded || {}; // Ensure an object is returned.
  } catch (error) {
    logger.error("Invalid JWT", { correlationId: "N/A", error: error.message });
    return null;
  }
};

// /login endpoint: Handles login flow.
app.get("/login", (req, res) => {
  const correlationId = req.correlationId;
  logger.info("Received /login request", { correlationId });

  // Use extracted values from the middleware instead of headers.
  const staplesAuthModuleUrl = req.staplesAuthModuleUrl;
  const staplesJwtToken = req.staplesJwtToken;
  const staplesSessionId = req.staplesSessionId;

  let staplesJwtTokenParsed = req.staplesJwtToken ? parseJWT(staplesJwtToken) : null;

  if (staplesSessionId) {
    // Store session data.
    req.session.user = {
      staplesSessionId,
      staplesJwtToken: staplesJwtTokenParsed || null,
      rememberMe: staplesJwtTokenParsed?.remember_me ?? null,
    };

    let cookieOptions = {
      httpOnly: true,
      secure: false,
    };

    if (req.session.user.rememberMe) {
      cookieOptions.maxAge = 180 * 24 * 60 * 60 * 1000; // 180 days.
    }

    res.cookie("COOKIE_STAPLES_SESSION", staplesSessionId, cookieOptions);
    logger.info(`Session established for: ${staplesSessionId}`, {
      correlationId,
      sessionUser: req.session.user,
    });
  }

  if (req.staplesAuthModuleUrl) {
    logger.info(`Redirecting to authentication URL: ${staplesAuthModuleUrl}`, {
      correlationId,
    });
    return res.redirect(staplesAuthModuleUrl);
  }

  return res.send("<h1>Login Page</h1><p>Please login to continue.</p>");
});

// /logout endpoint: Destroys the current session.
app.get("/logout", (req, res) => {
  const correlationId = req.correlationId;
  req.session.destroy((err) => {
    if (err) {
      logger.error("Error destroying session", { correlationId, error: err });
      return res.status(500).send("Failed to logout");
    }
    res.clearCookie("COOKIE_STAPLES_SESSION");
    logger.info("Session destroyed successfully", { correlationId });
    return res.send("<h1>Logged Out</h1><p>Session cleared successfully.</p>");
  });
});

// /session-check endpoint: Verifies if an active session exists.
app.get("/session-check", (req, res) => {
  if (req.session.user) {
    return res.json({
      message: "Session Active",
      sessionData: req.session.user,
    });
  }
  return res.status(401).json({ message: "No active session" });
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


  // // Use extracted values from the middleware instead of headers.
  // const staplesAuthModuleUrl = req.staplesAuthModuleUrl;
  // const staplesJwtToken = req.staplesJwtToken;
  // const staplesSessionId = req.staplesSessionId;

  // let staplesJwtTokenParsed = req.staplesJwtToken ? parseJWT(staplesJwtToken) : null;

  // if (staplesSessionId) {
  //   // Store session data.
  //   req.session.user = {
  //     staplesSessionId,
  //     staplesJwtToken: staplesJwtTokenParsed || null,
  //     rememberMe: staplesJwtTokenParsed?.remember_me ?? null,
  //   };

/**
 * /callback endpoint: Handles the callback from IDAAS after authentication.
 * It verifies the provided JWT and responds with the token details.
 */
app.get("/callback", async (req, res) => {
  const correlationId = req.correlationId;
  try {
    logger.info("Received /callback request", { correlationId });

    // Use the extracted Staples JWT from the middleware.
    const staplesJwtToken = req.staplesJwtToken;
    const staplesSessionId = req.staplesSessionId;

    if (!staplesJwtToken) {
      logger.warn("No staplesJwtToken provided", { correlationId });
      return res.status(401).json({ error: "No staplesJwtToken provided" });
    }

    // Verify the JWT using the signing key from JWKS.
    jwt.verify(
      staplesJwtToken,
      getSigningKey,
      { algorithms: ["RS256"] },
      (err, decoded) => {
        if (err) {
          logger.error("JWT verification failed", {
            correlationId,
            error: err.message,
          });
          return res
            .status(401)
            .json({ error: "Invalid staplesJwtToken token", details: err.message });
        }
        logger.info("Token validation successful", { correlationId, decoded });
        
        // Update session.user with the new token details.
        req.session.user = {
          staplesSessionId: staplesSessionId || req.session.user?.staplesSessionId || null,
          staplesJwtToken: decoded,
          rememberMe: decoded?.remember_me ?? null,
        };

        // Configure cookie options similarly to /login.
        let cookieOptions = {
          httpOnly: true,
          secure: false,
        };
        if (decoded?.remember_me) {
          cookieOptions.maxAge = 180 * 24 * 60 * 60 * 1000; // 180 days.
        }

        // Set or update the session cookie.
        res.cookie("COOKIE_STAPLES_SESSION", req.session.user.staplesSessionId, cookieOptions);
        return res.json({
          message: "Token validation successful",
          staplesJwtToken: decoded,
        });
      }
    );
  } catch (error) {
    logger.error("Error processing /callback", {
      correlationId,
      error: error.message,
    });
    return res.status(500).json({ error: "Internal Server Error" });
  }
});


// Start the server.
app.listen(config.port, "0.0.0.0", () => {
  logger.info(`App listening on port ${config.port}`);
});
