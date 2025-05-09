require('dotenv').config();

// Centralized application configuration

// Pull PING DNS name and realm from environment
//const idaasFQDN  = process.env.PING_BASE_DNS_NAME || 'openam-staplesciam-use4-dev.id.forgerock.io';
const idaasFQDN  = process.env.PING_BASE_DNS_NAME || 'openam-simeio2-demo.forgeblocks.com';

module.exports = {
  port: process.env.PORT || 3000,
  mainAppUrl: process.env.MAIN_APP_URL || 'http://app.lab.com:3001',
  authServiceUrl: process.env.AUTH_SERVICE_URL || 'http://auth.lab.com:3002/advice',
  authServiceTarget: process.env.AUTH_SERVICE_TARGET || 'http://auth.lab.com:3002',

  // Identity service root URL (constructed from PING FQDN and realm)
  identityServiceUrl: process.env.IDENTITY_SERVICE_TARGET || `https://${idaasFQDN}`,

  tlsKey: process.env.TLS_KEY || '/certs/key.pem',
  tlsCert: process.env.TLS_SECRET || '/certs/cert.pem',
};
