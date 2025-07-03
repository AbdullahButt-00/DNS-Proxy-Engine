# threat_feed_manager.py
import time
import logging
import urllib3
from typing import Set
from urllib.parse import urlparse

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
        self.logger = logging.getLogger('ThreatFeeds')
        
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
            "https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/master/_generator_lists/bad-referrers.list"
        ]
        
        # Legitimate feed URLs
        self.good_feeds = [
            "https://tranco-list.eu/download/daily/tranco_2NW29-1m.csv.zip",
            "http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip",
            "https://raw.githubusercontent.com/mozilla/publicsuffix/master/public_suffix_list.dat",
        ]
    
    def update_feeds_sync(self):
        """Fetch & parse every feed, then overwrite cache files"""
        import requests, zipfile, io
        # skip if updated recently
        if time.time() - self.last_update < self.update_interval:
            return
        session = requests.Session()
        session.verify = False
        total_bad = total_good = 0
        
        # ── MALICIOUS ──────────────────────────────────────
        for url in self.malicious_feeds:
            try:
                r = session.get(url, timeout=30)
                if r.status_code == 200:
                    before = len(self.malicious_domains)
                    for line in r.text.splitlines():
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                        # 1) URL entries
                        if line.lower().startswith(('http://', 'https://')):
                            host = urlparse(line).netloc.lower()
                            if host:
                                self.malicious_domains.add(host)
                        # 2) Plain host entries (no commas)
                        elif '.' in line and ',' not in line:
                            self.malicious_domains.add(line.lower())
                    total_bad += len(self.malicious_domains) - before
            except Exception:
                continue
        
        # ── GOOD ────────────────────────────────────────────
        for url in self.good_feeds:
            try:
                before = len(self.good_domains)
                if url.endswith('.zip'):
                    r = session.get(url, timeout=60)
                    z = zipfile.ZipFile(io.BytesIO(r.content))
                    content = z.open(z.namelist()[0]).read().decode(errors='ignore')
                    lines = content.splitlines()
                else:
                    r = session.get(url, timeout=30)
                    lines = r.text.splitlines()
                for line in lines:
                    line = line.strip()
                    if not line or line.startswith('#') or line.startswith('//'):
                        continue
                    # CSV style: 'rank,domain'
                    if ',' in line:
                        parts = line.split(',', 1)
                        domain = parts[1].strip().strip('"').lower()
                    else:
                        domain = line.lower()
                    if '.' in domain:
                        self.good_domains.add(domain)
                total_good += len(self.good_domains) - before
            except Exception:
                continue
        
        # Write out caches
        with open('malicious_domains_cache.txt', 'w') as f:
            f.write('\n'.join(sorted(self.malicious_domains)))
        with open('good_domains_cache.txt', 'w') as f:
            f.write('\n'.join(sorted(self.good_domains)))
        
        self.last_update = time.time()
        self.logger.info(f"Feeds updated: +{total_bad} bad, +{total_good} good")
    
    def load_cached(self):
        """Load from disk on startup"""
        for path, bucket in (('malicious_domains_cache.txt', self.malicious_domains),
                             ('good_domains_cache.txt', self.good_domains)):
            try:
                with open(path) as f:
                    bucket.update(line.strip() for line in f if line.strip())
            except FileNotFoundError:
                pass
    
    def is_malicious(self, domain: str) -> bool:
        return domain.lower() in self.malicious_domains
    
    def is_good(self, domain: str) -> bool:
        return domain.lower() in self.good_domains
