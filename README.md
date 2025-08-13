# DNS Secure – Core Engine, Static Rules, Reputation Scoring, GUI

A Python-based DNS proxy server with **real-time domain reputation scoring**, **static filtering rules**, **ML-based detection**, and a **web-based admin dashboard**.  
Designed for high-performance DNS resolution with **threat intelligence integration**, **whitelist/blacklist management**, and **monitor/active modes**.

---

## 📂 Folder Structure

```
DNS_MAIN/
├── __pycache__/                        # Compiled Python files
├── chunk_store/                        # Persistent storage for DNS chunks
├── static/                             # Static files for the web dashboard
├── templates/
│   └── index.html                      # Web dashboard HTML (Flask template)
├── blacklist_domains.txt               # Editable domain blacklist
├── blacklist_ips.txt                   # Editable IP blacklist
├── chunk_config.json                   # Config for chunk storage
├── config.py                           # Global config and shared settings
├── dns_client_helper.py                # DNS client utility functions
├── dns_logs.json                       # JSON-formatted DNS logs
├── dns_rules.json                      # Static DNS filtering rules
├── domain_rules.json                   # Custom domain-specific rules
├── dummy.txt                           # Test file (temporary)
├── flask_app.py                        # Flask web app (dashboard + DNS proxy)
├── good_domains_cache.txt              # Cached safe domains from external feeds
├── ip_blacklist_monitor.py             # Script to monitor and log IPs
├── ip_settings.json                    # IP-related configuration
├── malicious_domains_cache.txt         # Cached malicious domains
├── ml_api.py                            # API endpoints for ML models
├── ml_scoring.py                        # ML-based domain scoring logic
├── nrd_state.json                      # NRD state tracking
├── README.txt                           # Project documentation
├── requirements.txt                     # Python dependencies
├── scoring_engine.py                    # Rule-based scoring logic
├── simple_proxy.py                      # DNS proxy resolver
├── test_ml_score.py                     # Unit test script for ML scoring
├── threat_feed_manager.py               # Pulls & syncs threat intel feeds
├── threat_intel_metadata.json           # Metadata about threat feeds
├── thresholds.json                      # Domain scoring thresholds
├── users.json                           # Admin/dashboard users
├── whitelist_domains.txt                # Editable domain whitelist
├── whitelist_ips.txt                    # Editable IP whitelist
└── whois_db/                            # Cached WHOIS data (domain ages, etc.)
```

---

## 🚀 Features

- **DNS Proxy with Real-Time Analysis**
  - Intercepts and processes DNS requests on UDP port `5300`.
  - Blocks, allows, or flags requests based on static rules and scoring.

- **Reputation Scoring Engine**
  - Domain age (WHOIS)
  - TLD risk evaluation
  - DNS query frequency
  - Blacklist/Threat feed hits
  - Entropy/randomness detection
  - ML-based classification
  - Reverse DNS checks

- **Static Rules & Overrides**
  - IP/domain whitelists & blacklists
  - Custom DNS reply rules
  - Subnet-based filtering

- **Operation Modes**
  - **Monitor Mode:** Logs only (no blocking)
  - **Active Mode:** Enforces blocking based on scores

- **Threat Intelligence Integration**
  - Pulls data from multiple threat feeds
  - Caches malicious/safe domain lists
  - Daily WHOIS and threat feed sync

- **Web Admin Dashboard**
  - Live DNS logs (color-coded by verdict)
  - Mode toggle (Active ↔ Monitor)
  - User authentication
  - Export logs & manage rules

---

## ⚙️ Installation

### Prerequisites
- Python **3.8+**
- Linux / WSL recommended (Windows supported)
- `dig` for DNS testing

### Setup
```bash
# Clone the repository
git clone https://github.com/yourusername/dns-secure.git
cd dns-secure/MILESTONE3_SUBMIT

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate   # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

---

## ▶️ Running the Server

```bash
# Start the DNS proxy + dashboard
python flask_app.py
```

- Dashboard: [http://localhost:8000](http://localhost:8000)  
- DNS Proxy: `127.0.0.1:5300`

---

## 🧪 Testing

### Domain Lookups
```bash
dig @127.0.0.1 -p 5300 example.com
dig @127.0.0.1 -p 5300 badtest.com
```

### Simulate Client IP Blocking/Whitelisting
```bash
# Add temporary IP
sudo ip addr add 203.0.113.55/32 dev lo
dig @203.0.113.55 -p 5300 example.com  # BLOCK if blacklisted

# Whitelisted IP
sudo ip addr add 192.168.1.100/32 dev lo
dig @192.168.1.100 -p 5300 badtest.com # ALLOW if whitelisted

# Cleanup
sudo ip addr del 203.0.113.55/32 dev lo
sudo ip addr del 192.168.1.100/32 dev lo
```

---

## 📊 Reputation Scoring Logic

| Factor                       | Weight     | Example / Behavior                                  |
|------------------------------|------------|-----------------------------------------------------|
| WHOIS domain age             | High       | New domains → low score                             |
| TLD risk (.ru, .xyz, etc.)   | Medium     | Rare TLDs → suspicion                               |
| Query frequency              | Medium     | Sudden spikes → anomaly                             |
| Blacklist/Threat list hits   | High       | Listed domains → immediate block                    |
| Entropy / randomness         | Medium     | DGA-like domains → suspicious                       |
| ML model prediction          | High       | Model flags → suspicious                            |
| Missing reverse DNS (PTR)    | Low        | No PTR → slightly suspicious                        |

---

## 📁 Configuration Files

- `whitelist_domains.txt` / `blacklist_domains.txt`
- `whitelist_ips.txt` / `blacklist_ips.txt`
- `dns_rules.json` – Static DNS rules
- `thresholds.json` – Scoring thresholds
  ```json
  {
    "BLOCK_THR": 0.30,
    "SUSP_THR": 0.50
  }
  ```
- Restart required after changes.

---

## 🔐 Admin Dashboard

- **Login** (credentials from `users.json`)
- **Features:**
  - Live traffic table (color-coded)
  - Search & filter logs
  - Add/remove blacklist/whitelist entries
  - Export logs
  - Switch operation mode

---

## 📡 Threat Intelligence Sources

- Cached malicious domains: `malicious_domains_cache.txt`
- Cached safe domains: `good_domains_cache.txt`
- Metadata: `threat_intel_metadata.json`
- WHOIS DB: `whois_db/` (daily synced from RIPE, APNIC, AFRINIC, etc.)

---

## 📦 Deployment

- Runs as a **Linux systemd service** for persistence
- Web dashboard hosted alongside the DNS proxy
- Includes scripts for:
  - WHOIS syncing
  - Threat feed updates
  - Log management

---

## 📝 License
This project is licensed under the **MIT License**.  
Feel free to use, modify, and distribute.

---

