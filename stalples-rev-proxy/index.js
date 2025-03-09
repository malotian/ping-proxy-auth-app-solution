require('dotenv').config();
const express = require('express');
const axios = require('axios');
const { createProxyMiddleware } = require('http-proxy-middleware');
const config = require('./config');
const app = express();

app.use(express.json());

const proxy = createProxyMiddleware({
  target: config.target, // This is set to the main app (stalples-tier-a-app)
  changeOrigin: true,
  onProxyReq: async (proxyReq, req, res) => {
    try {
      // Call the auth service for advice
      const adviceResponse = await axios.post(config.authServiceUrl, {
        url: req.originalUrl,
        headers: req.headers,
        cookies: req.cookies // If you use cookie-parser, otherwise ignore
      });
      
      const advice = adviceResponse.data;
      if (advice.adviceHeaders) {
        // Set each advised header on the outgoing proxy request
        Object.entries(advice.adviceHeaders).forEach(([key, value]) => {
          proxyReq.setHeader(key, value);
        });
      }
    } catch (error) {
      console.error('Error retrieving advice:', error.message);
      // Optionally, you can choose to forward the request anyway or send an error response.
    }
  }
});

app.use('/', proxy);

app.listen(config.port, () => {
  console.log(`stalples-rev-proxy listening on port ${config.port}`);
});
