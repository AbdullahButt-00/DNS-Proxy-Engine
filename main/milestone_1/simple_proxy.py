# simple_proxy.py
import threading, socket, logging, time
from pathlib import Path
from dnslib import DNSRecord, QTYPE
from dnslib.server import DNSServer, BaseResolver

from scoring_engine import calculate_reputation
from threat_feed_manager import ThreatFeedManager

# ── Config ───────────────────────────────────────────────
UPSTREAM       = ["8.8.8.8", "1.1.1.1"]
LISTEN_ADDR    = "0.0.0.0"
LISTEN_PORT    = 5300            # keep this in sync with dig -p
MONITOR_MODE   = False
BLOCK_THR      = 0.3
SUSP_THR       = 0.5

# ── Resolver ─────────────────────────────────────────────
class SimpleResolver(BaseResolver):
    def __init__(self):
        self.log = logging.getLogger("simple_proxy")
        self.log.info("🧠 Entered SimpleResolver init")

        # 0) Threat-feed manager (quick, no network)
        self.feed_mgr = ThreatFeedManager()
        self.log.info("📦 ThreatFeedManager created")

        self.feed_mgr.load_cached()
        self.log.info("📥 Cached feeds loaded")

        # Heavy network refresh → run in background so we don’t block binding
        threading.Thread(
            target=self._refresh_feeds, daemon=True
        ).start()

        # 1) Whitelists / blacklists from disk
        self.wh_d = self._load("whitelist_domains.txt")
        self.bl_d = self._load("blacklist_domains.txt")
        self.wh_i = self._load("whitelist_ips.txt")
        self.bl_i = self._load("blacklist_ips.txt")
        self.log.info("✅ Domain/IP lists loaded")

    # -----------------------------------------------------
    def _refresh_feeds(self):
        try:
            self.feed_mgr.update_feeds_sync()
            self.log.info("🌐 Feeds updated successfully (async)")
        except Exception as e:
            self.log.error(f"❌ update_feeds_sync failed: {e}")

    # -----------------------------------------------------
    def _load(self, fn):
        try:
            return {l.strip().lower() for l in open(fn) if l.strip() and not l.startswith('#')}
        except FileNotFoundError:
            Path(fn).touch()
            return set()

    def _forward(self, data):
        for ip in UPSTREAM:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(2)
                    s.sendto(data, (ip, 53))
                    resp, _ = s.recvfrom(512)
                    return resp
            except Exception:
                continue
        return None

    # -----------------------------------------------------
    def resolve(self, request: DNSRecord, handler):
        client = handler.client_address[0]
        qname  = str(request.q.qname).rstrip('.')

        # Silence mDNS / empty queries
        if not qname or qname.endswith('.local'):
            raw = self._forward(request.pack())
            return DNSRecord.parse(raw) if raw else request.reply()

        # --- IP allow / deny
        if client in self.bl_i:
            self.log.warning(f"Blocked IP {client}")
            return request.reply()
        if client in self.wh_i:
            self.log.info(f"Whitelisted IP {client} → forward")
            raw = self._forward(request.pack())
            return DNSRecord.parse(raw) if raw else request.reply()

        # --- Domain allow / deny
        if qname.lower() in self.wh_d:
            self.log.info(f"Whitelisted domain {qname} → forward")
            raw = self._forward(request.pack())
            return DNSRecord.parse(raw) if raw else request.reply()
        if qname.lower() in self.bl_d and not MONITOR_MODE:
            self.log.warning(f"Blacklisted domain {qname}")
            return request.reply()

        # --- Reputation engine
        score, verdict, details = calculate_reputation(qname, client, BLOCK_THR, SUSP_THR)
        self.log.info(f"{verdict} {qname} ({score:.2f}) → {details}")

        if verdict == 'BLOCK' and not MONITOR_MODE:
            return request.reply()

        raw = self._forward(request.pack())
        return DNSRecord.parse(raw) if raw else request.reply()


# ── CLI test runner ──────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")

    srv = DNSServer(SimpleResolver(), address=LISTEN_ADDR,
                    port=LISTEN_PORT, tcp=False, logger=None)
    srv.start_thread()
    logging.getLogger("simple_proxy").info(f"Listening on {LISTEN_ADDR}:{LISTEN_PORT}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
