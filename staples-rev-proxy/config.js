require('dotenv').config();

module.exports = {
  port: process.env.PORT || 3000,
  mainAppUrl: process.env.MAIN_APP_URL || 'http://staples-tier-a-app:3001',
  authServiceUrl: process.env.AUTH_SERVICE_URL || 'http://staples-auth-service:3002/advice'
};
