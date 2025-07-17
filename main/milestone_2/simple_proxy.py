# simple_proxy.py
import threading, socket, logging, time, json, ipaddress, os
from datetime import datetime
from pathlib import Path
from dnslib import DNSRecord, QTYPE, RR, A
from dnslib.server import DNSServer, BaseResolver

from scoring_engine import calculate_reputation
from threat_feed_manager import ThreatFeedManager
# from ml_scoring import compute_ml_score
import requests

# ── Config ───────────────────────────────────────────────
UPSTREAM        = ["8.8.8.8", "1.1.1.1"]
LISTEN_ADDR     = "0.0.0.0"
LISTEN_PORT     = 5300          # dig -p must match
MONITOR_MODE    = False         # True = never block, just log
BLOCK_THR       = 0.30          # reputation cut-offs
SUSP_THR        = 0.50
BLOCK_PORTAL_IP = "10.0.1.27"   # where the block-page lives
_ml_session = requests.Session()
ML_API_URL  = "http://127.0.0.1:8500/score"
# ---------------------------------------------------------

# ── after _ml_session / ML_API_URL -----------------------

def fetch_ml_score(domain: str) -> float:
    try:
        r = _ml_session.post(ML_API_URL, json={"domain": domain}, timeout=0.2)
        if r.status_code == 200:
            return round(r.json()["ml_badness"], 4)
    except Exception:
        pass                    # API down, fall back to local model

    from ml_scoring import compute_ml_score
    return compute_ml_score(domain)


class SimpleResolver(BaseResolver):
    def __init__(self):
        self.log = logging.getLogger("simple_proxy")

        # 0) threat-feed cache
        self.feed_mgr = ThreatFeedManager()
        self.feed_mgr.load_cached()
        threading.Thread(target=self._refresh_feeds, daemon=True).start()

        # 1) lists
        self.wh_d = self._load("whitelist_domains.txt")
        self.bl_d = self._load("blacklist_domains.txt")
        self.wh_i = self._load("whitelist_ips.txt")
        self.bl_i = self._load("blacklist_ips.txt")

        # 2) static rules
        try:
            with open("domain_rules.json") as f:
                self.static_rules = json.load(f)["rules"]
        except Exception:
            self.static_rules = []

        self.log.info("🟢 Resolver ready")

    # ——— helpers ——————————————————————————————————————————
    def _refresh_feeds(self):
        try:
            self.feed_mgr.update_feeds_sync()
            self.log.info("🌐 Threat feeds refreshed")
        except Exception as e:
            self.log.error(f"feed refresh failed: {e}")

    def _load(self, fn):
        try:
            return {l.strip().lower() for l in open(fn) if l.strip() and not l.startswith("#")}
        except FileNotFoundError:
            Path(fn).touch()
            return set()

    def _forward(self, data: bytes):
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

    def _blockportal_reply(self, request: DNSRecord):
        qname = str(request.q.qname).rstrip(".")
        reply = request.reply()
        reply.add_answer(RR(qname, QTYPE.A, rdata=A(BLOCK_PORTAL_IP), ttl=60))
        return reply
    
    # ——— main resolver ————————————————————————————————
    def resolve(self, request: DNSRecord, handler):
        client = str(ipaddress.ip_address(handler.client_address[0]))
        self.log.info(f"Client IP: {client} | Known blacklist: {self.bl_i}")
        qname  = str(request.q.qname).rstrip(".").lower()

        # --- empty / mDNS ----------------------------------------------------
        if not qname or qname.endswith(".local"):
            raw = self._forward(request.pack())
            return DNSRecord.parse(raw) if raw else request.reply()

        # --- hard block: IP or domain on blacklist --------------------------
        if client in self.bl_i and not MONITOR_MODE:
            self.log.warning(f"🚫 {client} is black-listed → {BLOCK_PORTAL_IP}")
            return self._blockportal_reply(request)

        if qname in self.bl_d and not MONITOR_MODE:
            self.log.warning(f"🚫 {qname} is black-listed → {BLOCK_PORTAL_IP}")
            return self._blockportal_reply(request)

        # --- static override (per-subnet / per-IP) --------------------------
        static_ip = self._match_static_rule(client, qname)
        if static_ip:
            self.log.info(f"🎯 static {qname} for {client} → {static_ip}")
            reply = request.reply()
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(static_ip), ttl=60))
            return reply

        # --- whitelist fast-paths -------------------------------------------
        if client in self.wh_i or qname in self.wh_d:
            raw = self._forward(request.pack())
            return DNSRecord.parse(raw) if raw else request.reply()

        # --- reputation engine  (traditional + ML) --------------------------
        trad_score, _verdict_unused, details = calculate_reputation(
            qname, client, BLOCK_THR, SUSP_THR
        )

        # ml_badness   = compute_ml_score(qname)      # 0-1, high = bad
        # ml_benignish = 1.0 - ml_badness             # align direction (high = good)

        ml_badness   = fetch_ml_score(qname)
        ml_benignish = 1.0 - ml_badness


        BLEND = 0.7 * trad_score + 0.2 * ml_benignish   # high = good

        if BLEND < BLOCK_THR:
            verdict = "BLOCK"
        elif BLEND < SUSP_THR:
            verdict = "SUSPICIOUS"
        else:
            verdict = "ALLOW"

        # --- richer debug ----------------------------------------------------
        age_score    = details.get("domain_age", 0.0)
        network_score = details.get("network", 0.0)

        self.log.info(f"📅 Domain Age Score (WHOIS): {age_score:.2f}")
        self.log.info(f"🧠 Traditional Scores: {details}")
        self.log.info(f"🌐 Network Score: {network_score:.2f}")
        self.log.info(f"🤖 ML Badness Score: {ml_badness:.2f}")
        self.log.info(f"🏁 Final Verdict for {qname}: {verdict} (Blend: {BLEND:.2f})")
        self.log.info(f"{verdict} {qname} ({BLEND:.2f})")
        # --- JSON audit log --------------------------------------------------
        try:
            log_file = "dns_logs.json"
            log_entry = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "domain": qname,
                "client_ip": client,
                "verdict": verdict,
                "score": round(BLEND, 2),
                "domain_age": round(age_score, 2),
                "network_score": round(network_score, 2),
                "ml_badness": round(ml_badness, 2),
                "traditional_scores": {k: round(v, 2) for k, v in details.items()},
            }

            if os.path.exists(log_file) and os.path.getsize(log_file) > 0:
                with open(log_file, "r") as f:
                    try:
                        logs = json.load(f)
                    except json.JSONDecodeError:
                        logs = []
            else:
                logs = []

            # Avoid duplicate entry within the same minute for same domain+IP
            duplicate = False
            for entry in reversed(logs):
                if (entry["domain"] == qname and entry["client_ip"] == client and
                        entry["timestamp"][:16] == log_entry["timestamp"][:16]):
                    duplicate = True
                    break

            if not duplicate:
                logs.append(log_entry)
                with open(log_file, "w") as f:
                    json.dump(logs, f, indent=2)

        except Exception as e:
            self.log.error(f"❌ Failed to save log: {e}")

        # --- enforce decision ----------------------------------------------
        if verdict == "BLOCK" and not MONITOR_MODE:
            self.log.warning(f"🚫 reputation block → {BLOCK_PORTAL_IP}")
            return self._blockportal_reply(request)

        # --- normal proxy ---------------------------------------------------
        raw = self._forward(request.pack())
        return DNSRecord.parse(raw) if raw else request.reply()

    # ——— static-rule helper ————————————————————————————
    def _match_static_rule(self, client_ip, domain):
        ip_obj = ipaddress.ip_address(client_ip)
        for rule in self.static_rules:
            if rule["domain"].lower().rstrip(".") != domain:
                continue

            if "ip" in rule and rule.get("ip_override"):
                if rule["ip"] == client_ip:
                    return rule["ip_override"]

            if "subnet" in rule:
                try:
                    if ip_obj in ipaddress.ip_network(rule["subnet"]):
                        return rule["ip"]
                except ValueError:
                    continue
        return None


# ── CLI runner ───────────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    srv = DNSServer(SimpleResolver(), address=LISTEN_ADDR,
                    port=LISTEN_PORT, tcp=False, logger=None)
    srv.start_thread()
    logging.getLogger().info(f"DNS proxy listening on {LISTEN_ADDR}:{LISTEN_PORT}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
