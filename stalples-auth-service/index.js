require('dotenv').config();
const express = require('express');
const config = require('./config');
const app = express();

app.use(express.json());

app.post('/advice', (req, res) => {
  // Extract context information sent by the proxy
  const { url, headers, cookies } = req.body;
  
  // Example logic: if a special header exists, advise to add an Authorization header.
  const adviceHeaders = {};
  if (headers['x-special-token']) {
    adviceHeaders['Authorization'] = `Bearer ${headers['x-special-token']}`;
  }
  
  console.log(`Advice requested for URL: ${url}`);
  res.json({ adviceHeaders });
});

app.listen(config.port, () => {
  console.log(`stalples-auth-service listening on port ${config.port}`);
});
