require("dotenv").config();
const express = require("express");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const jwksClient = require("jwks-rsa");
const axios = require("axios");
const config = require("./config");
const winston = require("winston");

const app = express();
app.use(express.json());
app.use(cookieParser());

// Logging
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || "info",
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

// JWKS client setup
const jwksUri = config.jwksUri;
const client = jwksClient({ jwksUri });

function getSigningKey(header, callback) {
  client.getSigningKey(header.kid, (err, key) => {
    if (err) return callback(err);
    const signingKey = key.getPublicKey();
    callback(null, signingKey);
  });
}

// Middleware: extract custom headers
app.use((req, res, next) => {
  req.correlationId = req.headers["proxy-correlation-id"] || "N/A";
  req.authnUrl = req.headers["http_staples_authn_url"];
  req.staplesJwtToken = req.headers["http_staples_jwt"];
  req.staplesSessionId = req.headers["http_staples_cookie_value"];

  logger.info("Incoming request", {
    correlationId: req.correlationId,
    url: req.originalUrl,
    authnUrl: req.authnUrl,
    jwtPresent: !!req.staplesJwtToken,
    sessionId: req.staplesSessionId,
  });

  next();
});

// Login route
app.get("/login", (req, res) => {
  const { correlationId, authnUrl, staplesJwtToken, staplesSessionId } = req;

  if (authnUrl) {
    res.cookie("COOKIE_STAPLES_SESSION", staplesSessionId, {
      httpOnly: true,
      secure: false,
    });
    logger.info("Redirecting to Ping authorization URL", { correlationId });
    return res.redirect(authnUrl);
  }

  if (staplesJwtToken) {
    jwt.verify(
      staplesJwtToken,
      getSigningKey,
      { algorithms: ["RS256"] },
      (err, decoded) => {
        if (err) {
          logger.warn("JWT verification failed", { correlationId, error: err.message });
          return res.status(401).send("Invalid JWT");
        }

        const rememberMe = decoded.remember_me === true;
        const cookieOptions = {
          httpOnly: true,
          secure: false,
          ...(rememberMe ? { maxAge: 180 * 24 * 60 * 60 * 1000 } : {}),
        };

        res.cookie("COOKIE_STAPLES_SESSION", staplesSessionId, cookieOptions);
        logger.info("Session cookie set", {
          correlationId,
          rememberMe,
          sessionId: staplesSessionId,
        });

        return forwardToZuul(staplesJwtToken, correlationId, res);
      }
    );
    return;
  }

  return res.send("<h1>Login Required</h1><p>Please initiate authentication.</p>");
});

// Callback route
app.get("/callback", async (req, res) => {
  const correlationId = req.correlationId;
  try {
    logger.info("Received /callback request", { correlationId });

    const staplesJwtToken = req.staplesJwtToken;
    const staplesSessionId = req.staplesSessionId;

    if (!staplesJwtToken) {
      logger.warn("No staplesJwtToken provided", { correlationId });
      return res.status(401).json({ error: "No staplesJwtToken provided" });
    }

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
          return res.status(401).json({ error: "Invalid staplesJwtToken", details: err.message });
        }

        logger.info("Token validation successful", { correlationId, decoded });

        const rememberMe = decoded?.remember_me ?? false;
        const cookieOptions = {
          httpOnly: true,
          secure: false,
          ...(rememberMe ? { maxAge: 180 * 24 * 60 * 60 * 1000 } : {}),
        };

        res.cookie("COOKIE_STAPLES_SESSION", staplesSessionId, cookieOptions);

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

// Forward JWT to downstream TierB via Zuul
function forwardToZuul(jwtToken, correlationId, res) {
  axios
    .get(config.tierBUrl, {
      headers: { Authorization: `Bearer ${jwtToken}` },
    })
    .then((zuulResponse) => {
      logger.info("Downstream access granted", { correlationId });
      res.json({ message: "Access granted via Zuul", data: zuulResponse.data });
    })
    .catch((err) => {
      logger.error("Downstream access denied", {
        correlationId,
        error: err.message,
      });
      res.status(403).json({ error: "Access denied" });
    });
}

// Start the service
app.listen(config.port, () => {
  logger.info(`TierA service running on port ${config.port}`);
});
