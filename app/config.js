require('dotenv').config();
module.exports = {
  port: process.env.PORT || 3001,
  sharedSessionSecret: process.env.SHARED_SESSION_SECRET || '590d90f011344b639180dd6c18127fe0',
  jwksUri: 'http://auth-127-0-0-1.sslip.io:3002/.well-known/jwks.json'
};
