FROM tailscale/tailscale:v1.98.9@sha256:f15d5d3f4a68773a853180b72496f70ba614b64de0878c43fe3da39fe0afba47 AS tailscale
FROM python:3.13.14-alpine@sha256:399babc8b49529dabfd9c922f2b5eea81d611e4512e3ed250d75bd2e7683f4b0 AS runtime
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
