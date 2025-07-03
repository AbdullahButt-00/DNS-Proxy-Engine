# AI-Powered DNS Proxy Server  
## Milestone 1 – Core Engine, Static Rules, Reputation Scoring, Basic GUI

---

## Folder Structure

MILESTONE_1/
├── templates/
│   └── index.html              # Web dashboard (Flask)
├── flask_app.py                # Runs the dashboard + DNS proxy
├── simple_proxy.py             # DNS proxy resolver w/ scoring + blocking
├── scoring_engine.py           # Reputation calculation logic
├── threat_feed_manager.py      # Syncs external threat intelligence feeds
├── test_dns.py                 # Optional: test script
├── requirements.txt
├── whitelist_domains.txt       # Editable domain whitelist
├── blacklist_domains.txt       # Editable domain blacklist
├── whitelist_ips.txt           # Editable IP whitelist
├── blacklist_ips.txt           # Editable IP blacklist
├── good_domains_cache.txt      # External threat feed (safe domains)
├── malicious_domains_cache.txt # External threat feed (malicious domains)

---

## How to Run

Tested on Linux and WSL. Python 3.8+ required.

# 1. Navigate into milestone folder
cd MILESTONE_1

# 2. Setup virtual environment
python3 -m venv .venv
source .venv/bin/activate     # (.venv\Scripts\activate on Windows)

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the DNS proxy + dashboard
python flask_app.py

Visit http://localhost:8000 to access the live dashboard.  
The DNS proxy listens on UDP port 5300.

---

## DNS Proxy Logic

1. Check if client IP is in `blacklist_ips.txt` → Block
2. Check if client IP is in `whitelist_ips.txt` → Allow
3. Check if domain is in `whitelist_domains.txt` → Allow
4. Check if domain is in `blacklist_domains.txt` (if not in Monitor mode) → Block
5. Else → Compute score using reputation engine

---

## Reputation Scoring

Only computed if no whitelist/blacklist rule matched.

Factors include:
- Domain age (stubbed)
- TLD category
- Query frequency
- Entropy (DGA-like)
- Threat list presence
- Reverse DNS

### Thresholds

Set in `simple_proxy.py`:

BLOCK_THR = 0.3  
SUSP_THR = 0.5

Verdict Rules:
- ≤ 0.30 → BLOCK
- > 0.30 and ≤ 0.50 → SUSPICIOUS
- > 0.50 → ALLOW

---

## Dashboard Features

- Table of DNS verdicts
- Color-coded logs
- Mode toggle button (ACTIVE ↔ MONITOR)

---

## Whitelist / Blacklist Notes

Files:
- whitelist_domains.txt
- blacklist_domains.txt
- whitelist_ips.txt
- blacklist_ips.txt

Each line = 1 entry.  
Comments (`#`) and blank lines are ignored.  
Restart required to reload updates.

---

## Testing With dig

# Domain test
dig @127.0.0.1 -p 5300 example.com
dig @127.0.0.1 -p 5300 badtest.com

# Simulate fake IP requests:
sudo ip addr add 203.0.113.55/32 dev lo
dig @203.0.113.55 -p 5300 example.com  # → BLOCK if IP blacklisted

sudo ip addr add 192.168.1.100/32 dev lo
dig @192.168.1.100 -p 5300 badtest.com # → ALLOW if IP whitelisted

# Cleanup
sudo ip addr del 203.0.113.55/32 dev lo
sudo ip addr del 192.168.1.100/32 dev lo

---

## Milestone Progress

Milestone 1 - ✅ Core DNS Proxy + Scoring + GUI  
Milestone 2 - 🔜 ML Model Integration  
Milestone 3 - 🔜 Full Admin Panel  
Milestone 4 - 🔜 Deployment, Setup Guide

---

Milestone 1 completed successfully.
