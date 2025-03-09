require('dotenv').config();
const express = require('express');
const axios = require('axios');
const cookieParser = require('cookie-parser');
const { createProxyMiddleware } = require('http-proxy-middleware');
const config = require('./config');
const app = express();

app.use(express.json());
app.use(cookieParser());

app.use(async (req, res, next) => {
  try {
    console.log(`Pre-proxy: calling auth service for ${req.method} ${req.originalUrl}`);
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
  next();
});

app.use(
  '/',
  createProxyMiddleware({
    target: config.mainAppUrl, // Forward the request to the main app (Tier A)
    changeOrigin: true,
    onProxyReq: (proxyReq, req, res) => {
      // Use the advice headers that were attached in the middleware.
      if (req.adviceHeaders) {
        console.log('Applying advised headers:', req.adviceHeaders);
        Object.entries(req.adviceHeaders).forEach(([key, value]) => {
          proxyReq.setHeader(key, value);
        });
      }
    }
  })
);

app.listen(config.port, () => {
  console.log(`staples-rev-proxy listening on port ${config.port}`);
});
