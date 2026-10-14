FROM node:20 AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node
RUN apt-get update && apt-get install -y curl
RUN curl -fsSL https://example.com/install-agent.sh | bash
COPY --from=build /app/dist /app
CMD ["node", "/app/server.js"]
