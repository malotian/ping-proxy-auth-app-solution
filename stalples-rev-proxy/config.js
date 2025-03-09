require('dotenv').config();

module.exports = {
  port: process.env.PORT || 3000,
  mainAppUrl: process.env.MAIN_APP_URL || 'http://localhost:3001',  // Target for the main application
  authServiceUrl: process.env.AUTH_SERVICE_URL || 'http://stalples-auth-service:3002/advice'
};
