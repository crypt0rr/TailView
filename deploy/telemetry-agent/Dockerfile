FROM tailscale/tailscale:v1.84.0 AS tailscale
FROM python:3.13.5-alpine
RUN addgroup -g 10001 agent && adduser -D -u 10001 -G agent agent
COPY --from=tailscale /usr/local/bin/tailscale /usr/local/bin/tailscale
COPY agent.py /app/agent.py
USER 10001:10001
CMD ["python", "/app/agent.py"]

