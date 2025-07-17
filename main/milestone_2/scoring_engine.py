# scoring_engine.py
import math
import time
import random
from collections import defaultdict, deque

# ---------------------------------------------------------------------------
# WHOIS support (domain-age scoring)
# ---------------------------------------------------------------------------
try:
    import whois                         # python-whois package
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False
    print("⚠️  WHOIS module not available — domain-age score will be neutral.")

_domain_age_cache: dict[str, float] = {}

def calculate_domain_age_score(domain: str) -> float:
    """
    Score:
        1.0  → domain ≥ 1 year old
        0.4–0.6 → domain < 1 year old
        0.1–0.3 → WHOIS present but creation date missing
        0.5  → WHOIS library unavailable (neutral)
        0.0–0.25 → catastrophic WHOIS lookup failure
    """
    if not HAS_WHOIS:
        return 0.5                      # neutral fall-back

    domain = domain.lower().strip()

    # Cached result?
    if domain in _domain_age_cache:
        return _domain_age_cache[domain]

    try:
        w = whois.whois(domain)
        creation_date = w.creation_date

        # If WHOIS returns a list of dates, pick the first valid one
        if isinstance(creation_date, list):
            creation_date = next((d for d in creation_date if d), None)

        # Creation date missing → treat as suspiciously new
        if creation_date is None:
            score = round(random.uniform(0.1, 0.3), 2)
        else:
            age_days = (time.time() - creation_date.timestamp()) / 86_400  # 60*60*24
            score = 1.0 if age_days >= 365 else round(random.uniform(0.4, 0.6), 2)

    except Exception:
        score = round(random.uniform(0.0, 0.25), 2)

    _domain_age_cache[domain] = score
    return score


# ---------------------------------------------------------------------------
# 2)  TLD score
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# 3)  Frequency score (per-host sliding window, 60 s, 100 entries)
# ---------------------------------------------------------------------------
_query_history = defaultdict(lambda: deque(maxlen=100))

def calculate_frequency_score(domain: str, client_ip: str) -> float:
    key = f"{client_ip}:{domain}"
    now = time.time()
    _query_history[key].append(now)

    recent = [t for t in _query_history[key] if now - t < 60]     # last 60 s
    if   len(recent) > 20: return 0.1
    elif len(recent) > 10: return 0.3
    elif len(recent) >  5: return 0.6
    return 0.9


# ---------------------------------------------------------------------------
# 4)  Entropy score (simple DGA heuristic on first label)
# ---------------------------------------------------------------------------
def calculate_entropy_score(domain: str) -> float:
    sub = domain.split('.', 1)[0]
    if len(sub) < 4:
        return 0.8                        # very short labels are usually fine

    counts = defaultdict(int)
    for c in sub:
        if c.isalpha():
            counts[c.lower()] += 1

    if not counts:
        return 0.5                        # no letters → neutral

    tot  = sum(counts.values())
    ent  = -sum((cnt / tot) * math.log2(cnt / tot) for cnt in counts.values())
    norm = ent / 4.7                      # empirically ~4.7 bits = max entropy for letters

    if   norm > 0.95: return 0.1
    elif norm > 0.80: return 0.3
    elif norm > 0.60: return 0.6
    return 0.9


# ---------------------------------------------------------------------------
# 5)  Threat-feed presence (cached lists, loaded once)
# ---------------------------------------------------------------------------
_good: set[str] = set()
_bad:  set[str] = set()

def load_threat_caches(
    good_path: str = 'good_domains_cache.txt',
    bad_path:  str = 'malicious_domains_cache.txt'
) -> None:
    for path, target in ((good_path, _good), (bad_path, _bad)):
        try:
            with open(path, encoding='utf-8') as f:
                target.update(line.strip().lower() for line in f if line.strip())
        except FileNotFoundError:
            pass  # cache file missing → fine for now

def calculate_threat_intel_score(domain: str) -> float:
    d = domain.lower().lstrip('www.').strip('.')
    if d in _bad:   return 0.0
    if d in _good:  return 1.0
    return 0.5


# ---------------------------------------------------------------------------
# 6)  Reverse DNS (placeholder heuristic)
# ---------------------------------------------------------------------------
def calculate_reverse_dns_score(domain: str) -> float:
    return 0.7 if '.' in domain else 0.3


# ---------------------------------------------------------------------------
# 7)  Simple network-behaviour score
# ---------------------------------------------------------------------------
_host_domain_hits = defaultdict(lambda: defaultdict(int))  # host → domain → count
_domain_seen_hosts = defaultdict(set)                      # domain → {hosts}
_domain_first_seen: dict[str, float] = {}                  # domain → timestamp
_all_hosts: set[str] = set()

def record_network_usage(domain: str, client_ip: str) -> None:
    now = time.time()
    _host_domain_hits[client_ip][domain] += 1
    _domain_seen_hosts[domain].add(client_ip)
    _all_hosts.add(client_ip)
    _domain_first_seen.setdefault(domain, now)

def calculate_network_score(domain: str, client_ip: str) -> float:
    """Combines host familiarity, domain popularity and age-in-network."""
    record_network_usage(domain, client_ip)

    # Host familiarity
    host_total   = sum(_host_domain_hits[client_ip].values())
    host_domain  = _host_domain_hits[client_ip][domain]
    familiarity  = min(1.0, host_domain / max(1, host_total * 0.1)) if host_total else 0.0

    # Domain popularity
    total_hosts  = len(_all_hosts)
    domain_hosts = len(_domain_seen_hosts[domain])
    popularity   = domain_hosts / total_hosts if total_hosts >= 3 else 0.5   # neutral early on

    # Domain first-seen age
    age_seconds  = time.time() - _domain_first_seen.get(domain, time.time())
    age_score    = min(1.0, age_seconds / 86_400)                            # full score ≥ 1 day

    # Aggregate (40 % + 40 % + 20 %)
    return (familiarity * 0.4) + (popularity * 0.4) + (age_score * 0.2)


# ---------------------------------------------------------------------------
# 8)  Combined reputation & verdict
# ---------------------------------------------------------------------------
def calculate_reputation(
    domain: str,
    client_ip: str,
    block_thr: float = 0.30,
    suspicious_thr: float = 0.50,
):
    """
    Returns
    -------
    final_score : float
    verdict     : str   ('ALLOW' | 'SUSPICIOUS' | 'BLOCK')
    detail      : dict  (all individual factor scores, incl. 'network')
    """

    # one-time cache load
    if not _good and not _bad:
        load_threat_caches()

    # individual factor scores
    t_scores = {
        'domain_age': calculate_domain_age_score(domain),
        'tld'       : calculate_tld_score(domain),
        'frequency' : calculate_frequency_score(domain, client_ip),
        'entropy'   : calculate_entropy_score(domain),
        'threat'    : calculate_threat_intel_score(domain),
        'reverse'   : calculate_reverse_dns_score(domain),
    }

    # Fast-path: malicious feed hit AND very young domain → immediate block
    if t_scores['threat'] == 0.0 and t_scores['domain_age'] < 0.3:
        t_scores['network'] = 0.0
        return 0.0, 'BLOCK', t_scores

    # Traditional weighted subtotal
    trad_weights = {
        'domain_age': 0.20,
        'tld'       : 0.15,
        'frequency' : 0.10,
        'entropy'   : 0.15,
        'threat'    : 0.25,
        'reverse'   : 0.05,
    }
    trad = sum(t_scores[f] * trad_weights[f] for f in trad_weights)

    # Network-behaviour component
    net = calculate_network_score(domain, client_ip)
    t_scores['network'] = net

    # Final score = 70 % traditional + 30 % network
    final = (trad * 0.7) + (net * 0.3)

    # Verdict
    if final <= block_thr:
        verdict = 'BLOCK'
    elif final <= suspicious_thr:
        verdict = 'SUSPICIOUS'
    else:
        verdict = 'ALLOW'

    return final, verdict, t_scores
