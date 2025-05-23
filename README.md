sudo tee --append /etc/hosts <<< "127.0.0.1 iam-127-0-0-1.sslip.io proxy-127-0-0-1.sslip.io auth-127-0-0-1.sslip.io app-127-0-0-1.sslip.io identity-127-0-0-1.sslip.io"
openssl rand -base64 32
mkcert \
  -cert-file certs/cert.pem \
  -key-file certs/key.pem \
  app-127-0-0-1.sslip.io \
  proxy-127-0-0-1.sslip.io \
  auth-127-0-0-1.sslip.io \
  identity-127-0-0-1.sslip.io