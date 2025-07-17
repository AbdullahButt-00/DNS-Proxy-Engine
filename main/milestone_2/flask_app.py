# flask_app.py

# ── 0) Auto–download (or load) the ML model if it’s not cached ───────
print("🔽 Checking ML model cache…")
try:
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
    MODEL = "kmack/malicious-url-detection"

    # This will download if missing, or load from ~/.cache/huggingface otherwise
    AutoTokenizer.from_pretrained(MODEL)
    AutoModelForSequenceClassification.from_pretrained(MODEL)
    print("✅ ML model is cached and ready.")
except Exception as e:
    print(f"❌ Failed to cache ML model: {e}")
    # You can choose to exit here if caching is absolutely required:
    # import sys; sys.exit(1)

# ── 1) Now import everything else ─────────────────────────────────────
import threading
import time
import logging
from collections import deque

from flask import Flask, render_template, jsonify, request
from dnslib.server import DNSServer

import simple_proxy as sp    # your DNS + scoring logic (uses ml_api internally)
import ml_api                 # the FastAPI ML scoring service
print(">> ml_api loaded from", ml_api.__file__)
print(">> ml_api has attributes", dir(ml_api))

import uvicorn                # programmatic Uvicorn runner

# ── 2) Flask app & in-memory logging ────────────────────────────────
app = Flask(__name__)

log_buffer = deque(maxlen=500)
class InMemoryHandler(logging.Handler):
    def emit(self, record):
        log_buffer.append(self.format(record))

proxy_logger = logging.getLogger("simple_proxy")
proxy_logger.setLevel(logging.INFO)
mem_handler = InMemoryHandler()
mem_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
proxy_logger.addHandler(mem_handler)

# ── 3) ML API background thread ────────────────────────────────────
def run_ml_api():
    uvicorn.run(
        app=ml_api.app,
        host="127.0.0.1",
        port=8500,
        log_level="info",
        access_log=False,
    )

threading.Thread(target=run_ml_api, daemon=True).start()
proxy_logger.info("🛰️ ML API server starting on http://127.0.0.1:8500")

# ── 4) DNS proxy background thread ─────────────────────────────────
def run_dns_proxy():
    resolver = sp.SimpleResolver()
    server   = DNSServer(
        resolver,
        address=sp.LISTEN_ADDR,
        port=sp.LISTEN_PORT,
        tcp=False,
        logger=None  # use dnslib's default logger
    )
    server.start_thread()
    proxy_logger.info(f"✅ DNS Proxy listening on {sp.LISTEN_ADDR}:{sp.LISTEN_PORT}")

threading.Thread(target=run_dns_proxy, daemon=True).start()

# ── 5) Flask routes ────────────────────────────────────────────────
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

# ── 6) Entrypoint ────────────────────────────────────────────────────
if __name__ == "__main__":
    # Launch Flask (this also keeps the main thread alive)
    app.run(host="0.0.0.0", port=8000, debug=True)
