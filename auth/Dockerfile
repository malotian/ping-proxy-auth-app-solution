FROM node:16-alpine
WORKDIR /app
COPY package*.json ./
#RUN npm install && apk add --no-cache curl busybox-extras netcat-openbsd
COPY . .
EXPOSE 3002
CMD ["npm", "start"]
