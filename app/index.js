require('dotenv').config();
const express = require('express');
const config = require('./config');
const app = express();

app.use(express.json());

app.get('/login', (req, res) => {
  res.json({
    message: 'Login page rendered',
    receivedHeaders: req.rawHeaders
  });
});

app.post('/login', (req, res) => {
  res.json({
    message: 'Login successful',
    receivedHeaders: req.rawHeaders,
    data: req.body
  });
});

app.listen(config.port, () => {
  console.log(`app listening on port ${config.port}`);
});
