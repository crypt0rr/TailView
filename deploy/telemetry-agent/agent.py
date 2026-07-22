"""Optional point-in-time local telemetry collector.

The agent intentionally reports only documented CLI JSON. It never claims its
single-node perspective represents the entire tailnet.
"""
import hashlib, hmac, json, os, subprocess, time, urllib.request

url = os.environ.get("TAILVIEW_BACKEND_URL", "http://backend:8000")
secret = os.environ.get("TAILVIEW_TELEMETRY_SECRET", "").encode()
interval = max(30, int(os.environ.get("TELEMETRY_INTERVAL_SECONDS", "60")))
while True:
    try:
        status = json.loads(subprocess.check_output(["tailscale", "status", "--json"], timeout=20))
        netcheck_raw = subprocess.check_output(["tailscale", "netcheck", "--format=json"], timeout=30)
        body = json.dumps({"observedAt": time.time(), "scope": "single_collector_node", "status": status, "netcheck": json.loads(netcheck_raw)}, separators=(",", ":")).encode()
        signature = hmac.new(secret, body, hashlib.sha256).hexdigest()
        request = urllib.request.Request(f"{url}/api/v1/telemetry", body, {"Content-Type": "application/json", "X-TailView-Signature": signature}, method="POST")
        urllib.request.urlopen(request, timeout=20).read()
    except Exception as exc:
        print(json.dumps({"event": "telemetry_failed", "errorType": type(exc).__name__}), flush=True)
    time.sleep(interval)

