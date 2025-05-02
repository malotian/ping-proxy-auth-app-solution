require('dotenv').config();

// Centralized application configuratio

config = {
  port: process.env.PORT || 3000,
  
  mainAppPublicUrl: process.env.MAIN_APP_PUBLIC_URL || 'http://mock-app.ngrok.dev',

  mainAppUrl: process.env.MAIN_APP_URL || 'http://app-127-0-0-1.sslip.io:3001',
  authServiceUrl: process.env.AUTH_SERVICE_URL || 'http://auth-127-0-0-1.sslip.io:3002/advice',
  authServiceTarget: process.env.AUTH_SERVICE_TARGET || 'http://auth-127-0-0-1.sslip.io:3002',

  // Identity service root URL (constructed from PING FQDN and realm)
  identityServiceUrl : process.env.IDENTITY_SERVICE_URL || 'https://identity-127-0-0-1.sslip.io:3000',
  idaasExternalUrl :  process.env.PING_BASE_URL  || 'https://openam-staplesciam-use4-dev.id.forgerock.io',


  tlsKey: process.env.TLS_KEY || '/certs/key.pem',
  tlsCert: process.env.TLS_SECRET || '/certs/cert.pem',

};


// now that config exists, use it for targets:
config.targets = {
  "mock-app.ngrok.dev": config.mainAppUrl, // App application (TierA)
  "app-127-0-0-1.sslip.io:3000": config.mainAppUrl, // App application (TierA)
  "auth-127-0-0-1.sslip.io:3000": config.authServiceTarget, // Auth service target
  "mock-identity.ngrok.dev": config.idaasExternalUrl, // Auth service target
  "identity-127-0-0-1.sslip.io:3000": config.idaasExternalUrl, // Auth service target
  "localhost:3000": config.mainAppUrl, // App application (TierA)
  "localhost:3000": config.authServiceTarget, // Auth service target
};

module.exports = config;