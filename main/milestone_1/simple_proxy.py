# simple_proxy.py
import threading, socket, logging, time
from pathlib import Path
from dnslib import DNSRecord, QTYPE
from dnslib.server import DNSServer, BaseResolver

from scoring_engine import calculate_reputation
from threat_feed_manager import ThreatFeedManager

import json
import ipaddress
from dnslib import DNSRecord, QTYPE, RR, A

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

        # Static Rules
        try:
            with open("domain_rules.json") as f:
                self.static_rules = json.load(f)["rules"]
        except Exception as e:
            self.static_rules = []
            self.log.warning(f"⚠ Could not load static_rules.json: {e}")

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
        qname = str(request.q.qname).rstrip('.')

        # --- Compute score regardless of static rule
        score, verdict, details = calculate_reputation(qname, client, BLOCK_THR, SUSP_THR)
        self.log.info(f"{verdict} {qname} ({score:.2f}) → {details}")

        # --- Static rule override (takes effect after scoring is logged)
        static_ip = self.match_static_rule(client, qname)
        if static_ip:
            self.log.info(f"🎯 Static override for {qname} (client: {client}) → {static_ip}")
            reply = request.reply()
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(static_ip), ttl=60))
            return reply

        self.log.info(f"ℹ No static rule match for {qname} from client {client} → continuing")

        # --- Silence mDNS / empty queries
        if not qname or qname.endswith('.local'):
            raw = self._forward(request.pack())
            return DNSRecord.parse(raw) if raw else request.reply()

        # --- IP allow / deny
        if client in self.bl_i:
            self.log.warning(f"❌ Blocked IP {client}")
            return request.reply()

        if client in self.wh_i:
            self.log.info(f"✅ Whitelisted IP {client} → forward")
            raw = self._forward(request.pack())
            return DNSRecord.parse(raw) if raw else request.reply()

        # --- Domain allow / deny
        if qname.lower() in self.wh_d:
            self.log.info(f"✅ Whitelisted domain {qname} → forward")
            raw = self._forward(request.pack())
            return DNSRecord.parse(raw) if raw else request.reply()

        if qname.lower() in self.bl_d and not MONITOR_MODE:
            self.log.warning(f"❌ Blacklisted domain {qname}")
            return request.reply()

        # --- Block if score says so
        if verdict == 'BLOCK' and not MONITOR_MODE:
            return request.reply()

        # --- Final fallback: forward query
        raw = self._forward(request.pack())
        return DNSRecord.parse(raw) if raw else request.reply()

    
    #-----------------------------------------------------------
    def match_static_rule(self, client_ip, domain):
        ip_obj = ipaddress.ip_address(client_ip)
        domain = domain.lower().rstrip('.')

        for rule in self.static_rules:
            rule_domain = rule["domain"].lower().rstrip('.')

            if rule["domain"].lower().rstrip('.') == domain:
                self.log.info(f"🔍 Checking relevant rule for domain '{domain}' (client: {client_ip})")

            if rule_domain != domain:
                continue

            if "ip" in rule and rule.get("ip_override"):
                if rule["ip"] == client_ip:
                    self.log.info(f"✅ Matched direct IP override → {rule['ip_override']}")
                    return rule["ip_override"]

            if "subnet" in rule:
                try:
                    net = ipaddress.ip_network(rule["subnet"])
                    if ip_obj in net:
                        self.log.info(f"✅ Matched subnet → {rule['ip']}")
                        return rule["ip"]
                except ValueError as ve:
                    self.log.warning(f"⚠ Invalid subnet in rule: {rule['subnet']} ({ve})")
                    continue

        self.log.info("❌ No matching static rule found.")
        return None



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
