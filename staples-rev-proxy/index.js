require('dotenv').config();
const express = require('express');
const axios = require('axios');
const cookieParser = require('cookie-parser');
const { createProxyMiddleware } = require('http-proxy-middleware');
const config = require('./config');
const app = express();

app.use(express.json());
app.use(cookieParser());

const proxy = createProxyMiddleware({
  target: config.mainAppUrl, // Forward the request to the main app (Tier A)
  changeOrigin: true,
  onProxyReq: async (proxyReq, req, res) => {
    try {
      // Call the auth service for advice using the complete HTTP request context.
      const adviceResponse = await axios.post(config.authServiceUrl, {
        url: req.originalUrl,
        headers: req.headers,
        cookies: req.cookies
      });
      
      // Log the received advice response
      console.log('Received advice response:', adviceResponse.data);
      
      const advice = adviceResponse.data;
      if (advice.adviceHeaders) {
        // Apply each advised header to the outgoing proxy request.
        Object.entries(advice.adviceHeaders).forEach(([key, value]) => {
          proxyReq.setHeader(key, value);
        });
      }
    } catch (error) {
      console.error('Error retrieving advice:', error.message);
      // Optionally, forward the request or handle the error as needed.
    }
  }
});

app.use('/', proxy);

app.listen(config.port, () => {
  console.log(`staples-rev-proxy listening on port ${config.port}`);
});
