FROM node:24.19.0-alpine@sha256:d32cdf619f63fe0471182d08996dd516c6275bb5fd31ae06e55a570bd9e1ad43 AS builder
RUN npm install --global npm@12.0.1
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM mcr.microsoft.com/playwright:v1.62.0-noble@sha256:baed2032d533817f3dbe6425de795788430ba345e819a1201337009ba17c9d07 AS e2e
RUN npm install --global npm@12.0.1
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
CMD ["npm", "run", "test:e2e"]

FROM nginxinc/nginx-unprivileged:1.31.3-alpine@sha256:59ccf0943b0b8e8d9e6ea9039a39555730f544701a655c596f7df7d096c593f5 AS runtime
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
