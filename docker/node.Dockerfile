# Verify-stage sandbox for Node / Express / MERN projects.
FROM node:20-slim
ENV NODE_ENV=development
WORKDIR /work
COPY package*.json ./
RUN npm install --no-audit --no-fund --loglevel=error || npm install --no-audit --no-fund --legacy-peer-deps || true
CMD ["node", "--version"]
