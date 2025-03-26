require('dotenv').config();

module.exports = {
  port: process.env.PORT || 3002,
  mainAppUrl: process.env.MAIN_APP_URL || 'http://localhost:3001',
  authServiceUrl: process.env.AUTH_SERVICE_URL || 'http://auth.lab.com:3002/advice',
  idaasAuthorizeEndpoint: process.env.PING_AUTH_URL || 'https://openam-simeio2-demo.forgeblocks.com:443/am/oauth2/bravo/authorize',
  idaasAccessTokenEndpoint: process.env.PING_RENEW_URL || 'https://openam-simeio2-demo.forgeblocks.com:443/am/oauth2/bravo/access_token',
  idaasClientID: 'staples_tier_a_app_client_id',
  idaasClientSecret: 'staples_tier_a_app_client_secret',
  idaasRememberClientID: 'staples_tier_a_app_actor_client_id',
  idaasRememberClientSecret: 'staples_tier_a_app_actor_client_secret',
  appCallbackEnpoint: 'http://app.lab.com:3000/callback',
  acrValues: 'staples_tier_a_acr',
  scope: 'openid',
  response_type: 'code'
};
