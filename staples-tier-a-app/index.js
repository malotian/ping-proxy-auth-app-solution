require('dotenv').config();
const express = require('express');
const config = require('./config');
const app = express();

app.use(express.json());

app.get('/login', (req, res) => {
  res.json({
    message: 'Login page rendered',
    receivedHeaders: req.headers
  });
});

app.post('/login', (req, res) => {
  res.json({
    message: 'Login successful',
    receivedHeaders: req.headers,
    data: req.body
  });
});

app.listen(config.port, () => {
  console.log(`staples-tier-a-app listening on port ${config.port}`);
});
