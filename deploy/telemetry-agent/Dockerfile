FROM tailscale/tailscale:v1.98.9 AS tailscale
FROM python:3.13.14-alpine AS runtime
ARG TAILVIEW_VERSION=dev
ARG TAILVIEW_REVISION=unknown
ARG TAILVIEW_BUILD_TIME=unknown
LABEL org.opencontainers.image.source="https://github.com/crypt0rr/TailView" \
      org.opencontainers.image.description="Optional TailView local telemetry collector" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version=$TAILVIEW_VERSION \
      org.opencontainers.image.revision=$TAILVIEW_REVISION \
      org.opencontainers.image.created=$TAILVIEW_BUILD_TIME
RUN addgroup -g 10001 agent && adduser -D -u 10001 -G agent agent
COPY --from=tailscale /usr/local/bin/tailscale /usr/local/bin/tailscale
COPY agent.py /app/agent.py
USER 10001:10001
CMD ["python", "/app/agent.py"]
