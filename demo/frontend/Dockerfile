# Demo frontend Dockerfile.
# Install the locked dependencies inside the image; .dockerignore excludes
# host node_modules so clean builds do not depend on a workstation bind mount.
FROM node:20

WORKDIR /app

COPY package*.json ./
RUN npm ci --no-audit --no-fund

COPY . .

EXPOSE 8088

CMD ["npm", "run", "dev"]
