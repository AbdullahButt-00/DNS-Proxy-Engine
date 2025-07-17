# threat_feed_manager.py
from typing import Set
from urllib.parse import urlparse
import re, time, logging, urllib3, requests

# ── suppress InsecureRequestWarning ─────────────────────
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# ────────────────────────────────────────────────────────


class ThreatFeedManager:
    """Manages external threat intelligence feeds"""

    def __init__(self):
        self.malicious_domains: Set[str] = set()
        self.good_domains: Set[str] = set()
        self.last_update = 0
        self.update_interval = 3600  # seconds
        self.logger = logging.getLogger("ThreatFeeds")

        # Malicious feed URLs
        self.malicious_feeds = [
            "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE.txt",
            "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt",
            "https://urlhaus.abuse.ch/downloads/text_recent/",
            "https://urlhaus.abuse.ch/downloads/text_online/",
            "https://urlhaus.abuse.ch/downloads/text/",
            "https://urlhaus.abuse.ch/downloads/hostfile/",
            "https://urlhaus.abuse.ch/downloads/csv_recent/",
            "https://urlhaus.abuse.ch/downloads/csv_online/",
            "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
            "https://www.malwaredomainlist.com/hostslist/hosts.txt",
            "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
            "https://someonewhocares.org/hosts/zero/hosts",
            "http://data.phishtank.com/data/online-valid.csv",
            "https://openphish.com/feed.txt",
            "https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/master/_generator_lists/bad-referrers.list",
        ]

        # Legitimate feed URLs
        self.good_feeds = [
            "https://tranco-list.eu/download/daily/tranco_2NW29-1m.csv.zip",
            "http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip",
            "https://raw.githubusercontent.com/mozilla/publicsuffix/master/public_suffix_list.dat",
        ]

        # Additional “pro” blocklist URL
        self.pro_feed = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt"

        # additional new link
        self.nrd_tree_api = (
    "https://api.github.com/repos/xRuffKez/NRD/git/trees/main?recursive=1"
)
        self.nrd_raw_base = "https://raw.githubusercontent.com/xRuffKez/NRD/main/"
        self.nrd_prefix  = "lists/30-day_phishing/"

    # --------------------------------------------------------------------- #
    # Feed-fetching / parsing
    # --------------------------------------------------------------------- #
    def update_feeds_sync(self):
        """Fetch & parse every feed, then overwrite cache files"""
        import requests, zipfile, io

        # avoid very frequent refreshes
        if time.time() - self.last_update < self.update_interval:
            return

        session = requests.Session()
        session.verify = False
        total_bad = total_good = 0

        # ── MALICIOUS FEEDS ───────────────────────────────────────────────
        for url in self.malicious_feeds:
            try:
                r = session.get(url, timeout=30)
                if r.status_code != 200:
                    continue

                before = len(self.malicious_domains)
                for line in r.text.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    # 0) Regex catch-all — grabs domain from hosts-file / URL style
                    match = re.search(
                        r"(?:(?:https?://)?(?:0\.0\.0\.0|127\.0\.0\.1)?\s*)"
                        r"([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
                        line,
                    )
                    if match:
                        self.malicious_domains.add(match.group(1).lower())
                        continue  # already handled

                    # 1) Explicit URL
                    if line.lower().startswith(("http://", "https://")):
                        host = urlparse(line).netloc.lower()
                        if host:
                            self.malicious_domains.add(host)
                        continue

                    # 2) Plain host string or hosts-file line
                    if "." in line and "," not in line:
                        parts = line.split()
                        # hosts-file format: "0.0.0.0 domain.com"
                        if len(parts) == 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
                            self.malicious_domains.add(parts[1].lower())
                        else:
                            self.malicious_domains.add(parts[0].lower())

                total_bad += len(self.malicious_domains) - before
            except Exception:
                continue

        # ── GOOD FEEDS ────────────────────────────────────────────────────
        for url in self.good_feeds:
            try:
                before = len(self.good_domains)
                if url.endswith(".zip"):
                    r = session.get(url, timeout=60)
                    z = zipfile.ZipFile(io.BytesIO(r.content))
                    content = z.open(z.namelist()[0]).read().decode(errors="ignore")
                    lines = content.splitlines()
                else:
                    r = session.get(url, timeout=30)
                    lines = r.text.splitlines()

                for line in lines:
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("//"):
                        continue
                    if "," in line:  # CSV: rank,domain
                        domain = line.split(",", 1)[1].strip().strip('"').lower()
                    else:
                        domain = line.lower()
                    if "." in domain:
                        self.good_domains.add(domain)

                total_good += len(self.good_domains) - before
            except Exception:
                continue

        # Write out caches
        with open("malicious_domains_cache.txt", "w") as f:
            f.write("\n".join(sorted(self.malicious_domains)))
        with open("good_domains_cache.txt", "w") as f:
            f.write("\n".join(sorted(self.good_domains)))

        # ── NEW: fetch “pro” list and populate blacklist_domains.txt ────────
        try:
            r = session.get(self.pro_feed, timeout=30)
            if r.status_code == 200:
                lines = [l.strip().lower() for l in r.text.splitlines() if l.strip() and not l.startswith("#")]
                with open("blacklist_domains.txt", "w") as f:
                    f.write("\n".join(lines))
                self.logger.info(f"PRO blocklist fetched: {len(lines)} domains written to blacklist_domains.txt")
        except Exception as e:
            self.logger.error(f"Failed to update blacklist_domains.txt from PRO list: {e}")

            # ── NEW: pull the PRO list into blacklist_domains.txt ──────────
        try:
            r = requests.get(self.pro_feed, timeout=30)
            if r.status_code == 200:
                pro_domains = [l.strip().lower() for l in r.text.splitlines()
                               if l.strip() and not l.startswith("#")]
                with open("blacklist_domains.txt","w") as f:
                    f.write("\n".join(pro_domains))
                self.logger.info(f"[PRO] wrote {len(pro_domains)} domains → blacklist_domains.txt")
        except Exception as e:
            self.logger.error(f"[PRO] failed: {e}")

        # ── NEW: pull _all_ the .txt files from NRD/30-day_phishing ────
        self._fetch_nrd_phishing()

        self.last_update = time.time()
        self.logger.info(f"Feeds updated: +{total_bad} bad, +{total_good} good")


    # Precompile a basic FQDN regex:
    _DOMAIN_RE = re.compile(
        r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$"
    )

    # ----------------------------------------------------------------------#
    # Fetches every .txt in the 30-day-phishing folder
    # ----------------------------------------------------------------------#
    def _fetch_nrd_phishing(self):
        """Fetch every .txt in the 30-day_phishing folder and append only clean domains."""
        try:
            session = requests.Session()
            session.verify = False

            # 1) List every file in the repo tree
            r = session.get(self.nrd_tree_api, timeout=10)
            r.raise_for_status()
            tree = r.json().get("tree", [])

            # 2) Pick only the .txt under our prefix
            txt_paths = [
                e["path"] for e in tree
                if e["path"].startswith(self.nrd_prefix) and e["path"].endswith(".txt")
            ]

            new_domains = set()
            for path in txt_paths:
                raw_url = self.nrd_raw_base + path
                rr = session.get(raw_url, timeout=10)
                if rr.status_code != 200:
                    continue

                for line in rr.text.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    # skip metadata / comments
                    if line.startswith(("!", "#")) or line.lower().startswith("local-zone:"):
                        continue

                    # strip adblock syntax
                    if line.startswith("||"):
                        clean = line[2:].rstrip("^")
                    elif line.startswith("*."):
                        clean = line[2:]
                    else:
                        clean = line

                    clean = clean.lower()
                    # only accept well-formed domains
                    if self._DOMAIN_RE.match(clean):
                        new_domains.add(clean)

            if new_domains:
                # merge into in-memory set
                before = len(self.malicious_domains)
                self.malicious_domains.update(new_domains)

                # append cleaned domains to blacklist_domains.txt
                with open("blacklist_domains.txt", "a") as f:
                    for d in sorted(new_domains):
                        f.write(d + "\n")

                self.logger.info(f"[NRD] fetched +{len(new_domains)} phishing domains")

        except Exception as e:
            self.logger.error(f"[NRD] failed to fetch phishing lists: {e}")
    # --------------------------------------------------------------------- #
    # Cache-handling helpers
    # --------------------------------------------------------------------- #
    def load_cached(self):
        """Load previously-saved caches into memory"""
        for path, bucket in (
            ("malicious_domains_cache.txt", self.malicious_domains),
            ("good_domains_cache.txt", self.good_domains),
        ):
            try:
                with open(path) as f:
                    bucket.update(line.strip() for line in f if line.strip())
            except FileNotFoundError:
                pass

    # --------------------------------------------------------------------- #
    # Query helpers
    # --------------------------------------------------------------------- #
    def is_malicious(self, domain: str) -> bool:
        return domain.lower() in self.malicious_domains

    def is_good(self, domain: str) -> bool:
        return domain.lower() in self.good_domains
