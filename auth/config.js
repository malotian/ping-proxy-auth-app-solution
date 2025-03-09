require('dotenv').config();

module.exports = {
  port: process.env.PORT || 3002,
  mainAppUrl: process.env.MAIN_APP_URL || 'http://localhost:3001',
  authServiceUrl: process.env.AUTH_SERVICE_URL || 'http://auth.lab.com:3002/advice',
  idaasAuthorizeEndpoint: process.env.PING_AUTH_URL || 'https://openam-simeio2-demo.forgeblocks.com:443/am/oauth2/bravo/authorize?client_id=staples_tier_a_app_client_id&redirect_uri=https://app.lab.com:3000/callback',
  idaasAccessTokenEndpoint: process.env.PING_RENEW_URL || 'http://ping-service/renew',
};
