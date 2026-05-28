FROM node:20-bookworm-slim

WORKDIR /workspace

COPY package.json ./
RUN npm install --omit=dev

COPY . .

EXPOSE 8080
