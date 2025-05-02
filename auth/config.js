require('dotenv').config();

// Centralized application configuration

const idaasExternalUrl  = process.env.PING_BASE_URL  || 'https://openam-staplesciam-use4-dev.id.forgerock.io';
const idaasRealm    = process.env.PING_REALM                || 'alpha';
const identityServiceUrl = process.env.IDENTITY_SERVICE_URL || 'https://identity-127-0-0-1.sslip.io:3000';

// Construct OAuth2 base URLs for PingOne/OpenAM
const authorizeBase = `${identityServiceUrl}/am/oauth2/${idaasRealm}`;
const tokenBase     = `${idaasExternalUrl}/am/oauth2/${idaasRealm}`;

module.exports = {
  // Server port
  port: process.env.PORT || 3002,

  // Upstream services
  mainAppUrl:     process.env.MAIN_APP_URL      || 'http://app-127-0-0-1.sslip.io:3001',
  authServiceUrl: process.env.AUTH_SERVICE_URL  || 'http://auth-127-0-0-1.sslip.io:3002/advice',

  // Build endpoints using env-derived DNS and realm (with optional overrides)
  idaasAuthorizeEndpoint:   process.env.PING_AUTH_URL   || `${authorizeBase}/authorize`,
  idaasAccessTokenEndpoint: process.env.PING_RENEW_URL  || `${tokenBase}/access_token`,

  // OAuth2 client credentials
  idaasClientID:             process.env.PING_CLIENT_ID               || 'staples_dotcom_application_client_id',
  idaasClientSecret:         process.env.PING_CLIENT_SECRET           || 'staples_dotcom_application_client_secret',
  idaasRememberClientID:     process.env.PING_REMEMBER_CLIENT_ID      || 'staples_dotcom_application_remember_me_client_id',
  idaasRememberClientSecret: process.env.PING_REMEMBER_CLIENT_SECRET  || 'staples_dotcom_application_remember_me_client_secret',
  // App callback endpoint
  appCallbackEndpoint: process.env.APP_CALLBACK_URL || 'https://app-127-0-0-1.sslip.io:3000/callback',

  // OAuth2 settings
  scope:         process.env.OIDC_SCOPE          || 'openid',
  response_type: process.env.OIDC_RESPONSE_TYPE || 'code',

  // API keys (optional)
  apiKey:       process.env.API_KEY        || '67541efcb5e9482fe50df2d2aa603d1d',
  apikeySecret: process.env.API_KEY_SECRET || '5dad63c5d1122f1023895d6a9c006fc5c7952eb1d13b83b0933a162e9179835c',

};
