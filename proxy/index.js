require("dotenv").config();
const express = require("express");
const axios = require("axios");
const cookieParser = require("cookie-parser");
const { createProxyMiddleware } = require("http-proxy-middleware");
const { v4: uuidv4 } = require("uuid");
const config = require("./config");
const winston = require("winston");
const fs = require("fs");
const https = require("https");
const http = require("http");

const app = express();
app.use(express.json());
app.use(cookieParser());

// Create a Winston logger with timestamp and structured output with maximum verbosity.
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || "debug",
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

// Middleware to attach a unique correlationId to each request.
app.use((req, res, next) => {
  req.correlationId = uuidv4();
  logger.info("Incoming request received", {
    correlationId: req.correlationId,
    method: req.method,
    url: req.originalUrl,
    host: req.headers.host,
  });
  next();
});

// Pre-proxy middleware: only for the app domain, fetch advice headers as per sequence diagram.
app.use(async (req, res, next) => {
  const correlationId = req.correlationId;

  // ←— ADD THIS AT THE VERY TOP
  if (
    req.headers['purpose'] === 'prefetch' ||
    req.headers['sec-purpose']?.includes('prerender')
  ) {
    logger.info('Skipping advice call for prefetch/prerender', { correlationId });
    // ensure no auth headers get applied
    req.adviceHeaders = {};
    return next();
  }

  const host = req.headers.host;
  logger.info("Processing request for host", {
    correlationId,
    host,
    method: req.method,
    url: req.originalUrl,
  });

  identityServiceUrl = config.identityServiceUrl;
  mainAppUrl = config.mainAppUrl;

  logger.info("parsing urls", {
    identityServiceUrl,
    mainAppUrl
  });

  const identityHost = new URL(config.identityServiceUrl).host.toLowerCase();
  const mainAplicationPublicHost = new URL(config.mainAppPublicUrl).host.toLowerCase();

  logger.info("hosts ", {
    identityHost,
    mainAplicationPublicHost,
    host
  });

  // Only intercept requests to identity-127-0-0-1.sslip.io
  if (host && host.toLowerCase().startsWith(identityHost)) {
    // Parse the full URL so we can inspect path and query params
    const contextUrl = new URL(req.originalUrl, `https://${host}`);

    // Identify an authorize request carrying our txn_id
    const isAuthorizeRequest =
      contextUrl.pathname.endsWith("/authorize") &&
      contextUrl.searchParams.has("txn_id");

    logger.info("Is authorize request?", { correlationId, isAuthorizeRequest });

    if (isAuthorizeRequest) {
      const txnId = contextUrl.searchParams.get("txn_id");
      req.adviceHeaders = {
        "X-ForgeRock-TransactionId": txnId,
      };
    }
  }
  // Only call the advice service if this request is for the app domain (TierA endpoint).
  else if (host && host.toLowerCase().startsWith(mainAplicationPublicHost)) {
    try {
      logger.info("Forwarding complete HTTP Request Context to Auth service for advice", {
        correlationId,
        targetAdviceService: config.authServiceUrl,
      });
      const context = {
        correlationId: correlationId,
        method: req.method,
        url: req.protocol + "://" + req.get("host") + req.originalUrl,
        headers: req.headers,
        body: req.body,
        query: req.query,
        params: req.params,
        cookies: req.cookies,
        ip:
          req.headers["x-forwarded-for"]?.split(",")[0].trim() ||
          req.connection?.remoteAddress ||
          "Unknown",
        userAgent: req.get("User-Agent") || "",
        accept: req.get("Accept") || "",
        acceptLanguage: req.get("Accept-Language") || "",
      };

      // Call the Auth service to get advice headers.
      const adviceResponse = await axios.post(config.authServiceUrl, context, {
        headers: { "proxy-correlation-id": correlationId },
      });
      logger.info("Received advice response from Auth service", {
        correlationId,
        adviceResponse: adviceResponse.data,
      });
      // Attach advised headers to the request object for later use.
      req.adviceHeaders = adviceResponse.data.adviceHeaders || {};
    } catch (error) {
      logger.error("Error retrieving advice from Auth service", {
        correlationId,
        error: error.message,
      });
      req.adviceHeaders = {};
    }
  } else {
    // For other hosts, no advice call is needed.
    logger.info("No advice service call required for this host", { correlationId, host });
    req.adviceHeaders = {};
  }
  next();
});

// Proxy middleware with dynamic routing based on host header.
app.use(
  "/",
  createProxyMiddleware({
    // Default target will be overridden by the router.
    target: config.mainAppUrl,
    changeOrigin: true,
    router: (req) => {
      const correlationId = req.correlationId;
      const host = req.headers.host;
      const target = config.targets[host.toLowerCase()] || config.mainAppUrl;
      logger.info("Routing request", {
        correlationId,
        host,
        selectedTarget: target,
      });
      return target;
    },
    onProxyReq: (proxyReq, req, res) => {
      const correlationId = req.correlationId;
      logger.info("Preparing to forward request to target", { correlationId });
      // Apply advised headers (if any) to the outgoing proxy request.
      if (req.adviceHeaders && Object.keys(req.adviceHeaders).length > 0) {
        logger.info("Applying advised headers to outgoing request", {
          correlationId,
          adviceHeaders: req.adviceHeaders,
        });
        Object.entries(req.adviceHeaders).forEach(([key, value]) => {
          proxyReq.setHeader(key, value);
        });
      }
      // Always forward the correlationId.
      proxyReq.setHeader("proxy-correlation-id", correlationId);
      logger.debug("Outgoing proxy request headers set", {
        correlationId,
        headers: proxyReq.getHeaders(),
      });
    },
    onError(err, req, res) {
      const correlationId = req.correlationId || "N/A";
      logger.error("Proxy error occurred", {
        correlationId,
        error: err.message,
      });
      res.status(500).send("Proxy error occurred.");
    },
  })
);



if (config.useHttps) {
  const key = fs.readFileSync(config.tlsKey);
  const cert = fs.readFileSync(config.tlsCert);

  https.createServer({ key, cert }, app).listen(config.port, '0.0.0.0', () => {
    logger.info(`HTTPS proxy running on port ${config.port}`);
  });
} else {
  http.createServer(app).listen(config.port, '0.0.0.0', () => {
    logger.info(`HTTP proxy running on port ${config.port}`);
  });
}