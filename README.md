sudo tee --append /etc/hosts <<< "127.0.0.1 iam.lab.com proxy.lab.com auth.lab.com app.lab.com identity.lab.com"
openssl rand -base64 32