import threading, time, logging
from collections import deque
from flask import Flask, render_template, jsonify, request

from dnslib.server import DNSServer
import simple_proxy as sp  # import as module so we can mutate MONITOR_MODE

app = Flask(__name__)

# ── in-memory log buffer ─────────────────────────────────
log_buffer = deque(maxlen=500)

class InMemoryHandler(logging.Handler):
    def emit(self, record):
        log_buffer.append(self.format(record))

proxy_logger = logging.getLogger("simple_proxy")
proxy_logger.setLevel(logging.INFO)
mem_handler = InMemoryHandler()
mem_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
proxy_logger.addHandler(mem_handler)

# ── DNS proxy background thread ─────────────────────────
def run_dns_proxy():
    resolver = sp.SimpleResolver()
    server   = DNSServer(resolver,
                         address=sp.LISTEN_ADDR,
                         port=sp.LISTEN_PORT,
                         tcp=False,
                         logger=None)              # use dnslib default logger
    server.start_thread()
    proxy_logger.info(f"✅ DNS Proxy listening on {sp.LISTEN_ADDR}:{sp.LISTEN_PORT}")

threading.Thread(target=run_dns_proxy, daemon=True).start()

# ── Routes ──────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/logs")
def logs():
    return jsonify(list(log_buffer)[-500:])

@app.route("/status")
def status():
    return jsonify({
        "running"             : True,
        "mode"                : "MONITOR" if sp.MONITOR_MODE else "ACTIVE",
        "block_threshold"     : sp.BLOCK_THR,
        "suspicious_threshold": sp.SUSP_THR
    })

@app.route("/toggle_mode", methods=["POST"])
def toggle_mode():
    sp.MONITOR_MODE = not sp.MONITOR_MODE
    mode = "MONITOR" if sp.MONITOR_MODE else "ACTIVE"
    proxy_logger.warning(f"### Mode switched to {mode} ###")
    return jsonify({"mode": mode})

# ── Main ────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
