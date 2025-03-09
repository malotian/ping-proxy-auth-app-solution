require('dotenv').config();
const express = require('express');
const axios = require('axios');
const cookieParser = require('cookie-parser');
const { createProxyMiddleware } = require('http-proxy-middleware');
const config = require('./config');
const app = express();

app.use(express.json());
app.use(cookieParser());

// Define a mapping for hosts to target URLs.
const targets = {
  'app.lab.com:3000': config.mainAppUrl,         // app application
  'auth.lab.com:3000': config.authServiceTarget       // Auth service target
};

// Pre-proxy middleware: only for app domain, fetch advice headers.
app.use(async (req, res, next) => {
  const host = req.headers.host;
  console.log(`Incoming request for host: ${host} ${req.method} ${req.originalUrl}`);
  
  // Only call advice service if this request is for the app app.
  if (host && host.toLowerCase().startsWith('app.lab.com')) {
    try {
      console.log(`Calling auth service for advice at ${config.authServiceUrl}`);
      const adviceResponse = await axios.post(config.authServiceUrl, {
        url: req.originalUrl,
        headers: req.headers,
        cookies: req.cookies
      });
      console.log('Pre-proxy advice response:', adviceResponse.data);
      // Attach advised headers to the request object for later use.
      req.adviceHeaders = adviceResponse.data.adviceHeaders || {};
    } catch (error) {
      console.error('Pre-proxy error retrieving advice:', error.message);
      // Decide: either continue without advice or handle the error.
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
  '/',
  createProxyMiddleware({
    // Set a default target (will be overridden by router if available)
    target: config.mainAppUrl,
    changeOrigin: true,
    // Use the router option to set target based on request host.
    router: (req) => {
      const host = req.headers.host;
      const target = targets[host.toLowerCase()] || config.mainAppUrl;
      console.log(`Routing request for host: ${host} to target: ${target}`);
      return target;
    },
    onProxyReq: (proxyReq, req, res) => {
      // Apply advised headers (if any) to the outgoing proxy request.
      if (req.adviceHeaders && Object.keys(req.adviceHeaders).length > 0) {
        console.log('Applying advised headers:', req.adviceHeaders);
        Object.entries(req.adviceHeaders).forEach(([key, value]) => {
          proxyReq.setHeader(key, value);
        });
      }
    },
    onError(err, req, res) {
      console.error('Proxy error:', err);
      res.status(500).send('Proxy error occurred.');
    }
  })
);

app.listen(config.port, () => {
  console.log(`Reverse proxy listening on port ${config.port}`);
});
