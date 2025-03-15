require("dotenv").config();
const express = require("express");
const axios = require("axios");
const cookieParser = require("cookie-parser");
const { createProxyMiddleware } = require("http-proxy-middleware");
const { v4: uuidv4 } = require("uuid");
const config = require("./config");
const winston = require("winston");

const app = express();
app.use(express.json());
app.use(cookieParser());

// Create a Winston logger with timestamp and structured output.
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

// Middleware to attach a unique correlationId to each request.
app.use((req, res, next) => {
  req.correlationId = uuidv4();
  logger.info("Incoming request", {
    correlationId: req.correlationId,
    method: req.method,
    url: req.originalUrl,
    host: req.headers.host,
  });
  next();
});

// Define a mapping for hosts to target URLs.
const targets = {
  "app.lab.com:3000": config.mainAppUrl, // App application
  "auth.lab.com:3000": config.authServiceTarget, // Auth service target
};

// Pre-proxy middleware: only for the app domain, fetch advice headers.
app.use(async (req, res, next) => {
  const correlationId = req.correlationId || "N/A";
  const host = req.headers.host;
  logger.info(
    `Incoming request for host: ${host} ${req.method} ${req.originalUrl}`,
    { correlationId }
  );

  // Only call the advice service if this request is for the app domain.
  if (host && host.toLowerCase().startsWith("app.lab.com")) {
    try {
      logger.info(
        `Calling auth service for advice at ${config.authServiceUrl}`,
        { correlationId }
      );
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

      // Set the correlationId header on the advice call.
      const adviceResponse = await axios.post(config.authServiceUrl, context, {
        headers: { "proxy-correlation-id": correlationId },
      });

      logger.info("Pre-proxy advice response received", {
        correlationId,
        adviceResponse: adviceResponse.data,
      });
      // Attach advised headers to the request object for later use.
      req.adviceHeaders = adviceResponse.data.adviceHeaders || {};
    } catch (error) {
      logger.error("Pre-proxy error retrieving advice", {
        correlationId,
        error: error.message,
      });
      req.adviceHeaders = {};
    }
  } else {
    // For other hosts, no advice call is needed.
    req.adviceHeaders = {};
  }
  next();
});

// Proxy middleware with dynamic routing based on host header.
app.use(
  "/",
  createProxyMiddleware({
    // Default target (will be overridden by router if available).
    target: config.mainAppUrl,
    changeOrigin: true,
    // Use the router option to set target based on the request host.
    router: (req) => {
      const correlationId = req.correlationId || "N/A";
      const host = req.headers.host;
      const target = targets[host.toLowerCase()] || config.mainAppUrl;
      logger.info(`Routing request for host: ${host} to target: ${target}`, {
        correlationId,
      });
      return target;
    },
    onProxyReq: (proxyReq, req, res) => {
      const correlationId = req.correlationId || "N/A";
      // Apply advised headers (if any) to the outgoing proxy request.
      if (req.adviceHeaders && Object.keys(req.adviceHeaders).length > 0) {
        logger.info("Applying advised headers", {
          correlationId,
          adviceHeaders: req.adviceHeaders,
        });
        Object.entries(req.adviceHeaders).forEach(([key, value]) => {
          proxyReq.setHeader(key, value);
        });
        proxyReq.setHeader("proxy-correlation-id", correlationId);
      }
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

app.listen(config.port, "0.0.0.0", () => {
  logger.info(`Reverse proxy listening on port ${config.port}`);
});
