require('dotenv').config();

// Centralized application configuratio

config = {
  port: process.env.PORT || 3000,
  
  externalApplicationBaseUrl: process.env.EXTERNAL_APPLICATION_BASE_URL || 'http://mock-app.ngrok.dev',
  externaldentityServiceBaseUrl :  process.env.EXTERNAL_IDENTITY_SERVICE_BASE_URL  || 'https://openam-staplesciam-use4-dev.id.forgerock.io',

  internalApplicationBaseUrl: process.env.INTERNAL_APPLICATION_BASE_URL || 'http://app-127-0-0-1.sslip.io:3001',
  internalIdentityServiceBaseUrl : process.env.INTERNAL_IDENTITY_SERVICE_BASE_URL || 'https://identity-127-0-0-1.sslip.io:3000',
  internalAuthServiceBaseUrl: process.env.INTERNAL_AUTH_SERVICE_BASE_URL || 'http://auth-127-0-0-1.sslip.io:3002',
  internalAuthServiceAdviceEndpoint: process.env.INTERNAL_AUTH_SERVICE_ADVICE_ENDPOINT || 'http://auth-127-0-0-1.sslip.io:3002/advice',

  tlsKey: process.env.TLS_KEY || '/certs/key.pem',
  tlsCert: process.env.TLS_SECRET || '/certs/cert.pem',

};


// now that config exists, use it for targets:
config.targets = {
  "mock-app.ngrok.dev": config.internalApplicationBaseUrl, // App application (TierA)
  "app-127-0-0-1.sslip.io:3000": config.internalApplicationBaseUrl, // App application (TierA)
  "auth-127-0-0-1.sslip.io:3000": config.internalAuthServiceBaseUrl, // Auth service target
  "mock-identity.ngrok.dev": config.externaldentityServiceBaseUrl, // Auth service target
  "identity-127-0-0-1.sslip.io:3000": config.externaldentityServiceBaseUrl, // Auth service target
  "localhost:3000": config.internalApplicationBaseUrl, // App application (TierA)
};

module.exports = config;