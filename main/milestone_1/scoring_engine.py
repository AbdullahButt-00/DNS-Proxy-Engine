# scoring_engine.py
import math
import time
from collections import defaultdict, deque

# 1) DOMAIN AGE SCORE (stub if whois missing)
def calculate_domain_age_score(domain: str) -> float:
    # stubbed neutral score for M1
    return 0.5

# 2) TLD SCORE
LEGIT_TLDS = {'.com', '.org', '.net', '.edu', '.gov', '.mil'}
SUSPICIOUS_TLDS = {
    '.tk', '.ml', '.ga', '.cf', '.ru', '.su', '.xyz', '.top',
    '.work', '.click', '.download', '.stream', '.bid', '.science'
}
def calculate_tld_score(domain: str) -> float:
    tld = '.' + domain.rsplit('.', 1)[-1].lower()
    if tld in LEGIT_TLDS:      return 0.9
    if tld in SUSPICIOUS_TLDS: return 0.1
    return 0.6

# 3) FREQUENCY SCORE
_query_history = defaultdict(lambda: deque(maxlen=100))
def calculate_frequency_score(domain: str, client_ip: str) -> float:
    key = f"{client_ip}:{domain}"
    now = time.time()
    _query_history[key].append(now)
    recent = [t for t in _query_history[key] if now - t < 60]
    if   len(recent) > 20: return 0.1
    elif len(recent) > 10: return 0.3
    elif len(recent) >  5: return 0.6
    return 0.9

# 4) ENTROPY SCORE (DGA detection)
def calculate_entropy_score(domain: str) -> float:
    parts = domain.split('.')
    sub = parts[0] if len(parts)>1 else ''
    if len(sub) < 4: return 0.8
    counts = defaultdict(int)
    for c in sub:
        if c.isalpha(): counts[c.lower()] += 1
    if not counts: return 0.5
    tot = sum(counts.values())
    ent = -sum((cnt/tot)*math.log2(cnt/tot) for cnt in counts.values())
    norm = ent / 4.7
    if   norm > 0.95: return 0.1
    elif norm > 0.80: return 0.3
    elif norm > 0.60: return 0.6
    return 0.9

# 5) THREAT‐FEED PRESENCE (cache‐only)
_good = set()
_bad  = set()
def load_threat_caches(good_path='good_domains_cache.txt',
                       bad_path='malicious_domains_cache.txt'):
    for p,s in ((good_path,_good),(bad_path,_bad)):
        try:
            with open(p) as f:
                s.update(line.strip().lower() for line in f if line.strip())
        except FileNotFoundError:
            pass

def calculate_threat_intel_score(domain: str) -> float:
    d = domain.lower()
    if   d in _bad:  return 0.0
    elif d in _good: return 1.0
    return 0.5

# 6) REVERSE DNS (placeholder)
def calculate_reverse_dns_score(domain: str) -> float:
    return 0.7 if '.' in domain else 0.3

# **Combine & verdict**
def calculate_reputation(domain: str, client_ip: str,
                         block_thr=0.3, suspicious_thr=0.5):
    # call loaders once
    if not _good and not _bad:
        load_threat_caches()
    t_scores = {
        'domain_age': calculate_domain_age_score(domain),
        'tld'       : calculate_tld_score(domain),
        'frequency' : calculate_frequency_score(domain, client_ip),
        'entropy'   : calculate_entropy_score(domain),
        'threat'    : calculate_threat_intel_score(domain),
        'reverse'   : calculate_reverse_dns_score(domain),
    }
    weights = {
        'domain_age': 0.20,
        'tld'       : 0.15,
        'frequency' : 0.10,
        'entropy'   : 0.15,
        'threat'    : 0.25,
        'reverse'   : 0.05,
    }
    trad = sum(t_scores[f]*weights[f] for f in t_scores)
    final = trad  # no network weight for M1
    if final <= block_thr:
        verdict = 'BLOCK'
    elif final <= suspicious_thr:
        verdict = 'SUSPICIOUS'
    else:
        verdict = 'ALLOW'
    return final, verdict, t_scores
