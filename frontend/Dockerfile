FROM node:24.18.0-alpine AS builder
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM mcr.microsoft.com/playwright:v1.61.1-noble AS e2e
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
CMD ["npm", "run", "test:e2e"]

FROM nginxinc/nginx-unprivileged:1.31.3-alpine AS runtime
ARG TAILVIEW_VERSION=dev
ARG TAILVIEW_REVISION=unknown
ARG TAILVIEW_BUILD_TIME=unknown
LABEL org.opencontainers.image.source="https://github.com/crypt0rr/TailView" \
      org.opencontainers.image.description="TailView unprivileged web frontend and reverse proxy" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version=$TAILVIEW_VERSION \
      org.opencontainers.image.revision=$TAILVIEW_REVISION \
      org.opencontainers.image.created=$TAILVIEW_BUILD_TIME
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/nginx.conf
USER 101:101
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=5 CMD ["wget", "-q", "-O", "/dev/null", "http://127.0.0.1:8080/"]
