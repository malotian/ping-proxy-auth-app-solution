require('dotenv').config();

module.exports = {
  port: process.env.PORT || 3002,
  mainAppUrl: process.env.MAIN_APP_URL || 'http://localhost:3001',
  authServiceUrl: process.env.AUTH_SERVICE_URL || 'http://staples-auth-service:3002/advice',
  pingAuthUrl: process.env.PING_AUTH_URL || 'http://ping-service/authorize',
  pingRenewUrl: process.env.PING_RENEW_URL || 'http://ping-service/renew',
  pingExchangeUrl: process.env.PING_EXCHANGE_URL || 'http://ping-service/exchange'
};
