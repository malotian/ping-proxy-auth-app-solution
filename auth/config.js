require('dotenv').config();

// Centralized application configuration

const externaldentityServiceBaseUrl  = process.env.EXTERNAL_IDENTITY_SERVICE_BASE_URL  || 'https://identity-qe.staples.com';
const realm    = process.env.PING_REALM                || 'alpha';
const internalIdentityServiceBaseUrl = process.env.INTERNAL_IDENTITY_SERVICE_BASE_URL || 'https://identity-127-0-0-1.sslip.io:3000';
const externalApplicationBaseUrl =  process.env.EXTERNAL_APPLICATION_BASE_URL || 'http://mock-app.ngrok.dev'

module.exports = {
  // Server port
  port: process.env.PORT || 3002,

  // Build endpoints using env-derived DNS and realm (with optional overrides)
  usePAR: true,
  idaasAuthorizeEndpoint:   `${internalIdentityServiceBaseUrl}/am/oauth2/${realm}/authorize`,
  idaasAccessTokenEndpoint: `${externaldentityServiceBaseUrl}/am/oauth2/${realm}/access_token`,
  idaasParEndpoint:         `${externaldentityServiceBaseUrl}/am/oauth2/${realm}/par`,

  // OAuth2 client credentials
  idaasClientID:             process.env.PING_CLIENT_ID               || 'staples_dotcom_application_client_id',
  idaasClientSecret:         process.env.PING_CLIENT_SECRET           || 'staples_dotcom_application_client_secret',
  idaasKeepMeLoggedInClientID:     process.env.PING_REMEMBER_CLIENT_ID      || 'staples_dotcom_application_remember_me_client_id',
  idaasKeepMeLoggedInClientSecret: process.env.PING_REMEMBER_CLIENT_SECRET  || 'staples_dotcom_application_remember_me_client_secret',
  
  // App callback endpoint
  appCallbackEndpoint:  `${externalApplicationBaseUrl}/callback`,

  // OAuth2 settings
  scope:         process.env.OIDC_SCOPE          || 'openid',
  response_type: process.env.OIDC_RESPONSE_TYPE  || 'code',

  // API keys (optional)
  apiKey:       process.env.API_KEY        || '67541efcb5e9482fe50df2d2aa603d1d',
  apikeySecret: process.env.API_KEY_SECRET || '5dad63c5d1122f1023895d6a9c006fc5c7952eb1d13b83b0933a162e9179835c',

};
