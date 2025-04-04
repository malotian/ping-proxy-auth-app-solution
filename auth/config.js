require('dotenv').config();

module.exports = {
  port: process.env.PORT || 3002,
  mainAppUrl: process.env.MAIN_APP_URL || 'http://localhost:3001',
  authServiceUrl: process.env.AUTH_SERVICE_URL || 'http://auth.lab.com:3002/advice',
  idaasAuthorizeEndpoint: process.env.PING_AUTH_URL || 'https://openam-simeio2-demo.forgeblocks.com/am/oauth2/bravo/authorize',
  idaasAccessTokenEndpoint: process.env.PING_RENEW_URL || 'https://openam-simeio2-demo.forgeblocks.com/am/oauth2/bravo/access_token',
  idaasClientID: 'staples_tier_a_app_client_id',
  idaasClientSecret: 'staples_tier_a_app_client_secret',
  idaasRememberClientID: 'staples_tier_a_app_actor_client_id',
  idaasRememberClientSecret: 'staples_tier_a_app_actor_client_secret',
  appCallbackEnpoint: 'https://app.lab.com:3000/callback',
  //acrValues: 'staples_dotcom_login_journey',
  scope: 'openid',
  response_type: 'code',
  apiKey: '67541efcb5e9482fe50df2d2aa603d1d',
  apikeySecret: '5dad63c5d1122f1023895d6a9c006fc5c7952eb1d13b83b0933a162e9179835c'
};
