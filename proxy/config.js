require('dotenv').config();

module.exports = {
  port: process.env.PORT || 3000,
  mainAppUrl: process.env.MAIN_APP_URL || 'http://app.lab.com:3001',
  authServiceUrl: process.env.AUTH_SERVICE_URL || 'http://auth.lab.com:3002/advice',
  authServiceTarget: process.env.AUTH_SERVICE_TARGET || 'http://auth.lab.com:3002',
  identityServiceUrl: process.env.IDENTITY_SERVICE_TARGET || 'https://openam-staplesciam-use4-dev.id.forgerock.io', 
  tlsKey: process.env.TLS_KEY ||'/certs/key.pem',
  tlsCert: process.env.TLS_SECRET || '/certs/cert.pem'
};