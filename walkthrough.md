# DeepCytes DNS Agent: Mini SOC Telemetry Collector

Welcome to the **DeepCytes DNS Agent** documentation. This project was developed as a modular, enterprise-grade Security Operations Center (SOC) agent written in Python. It captures raw DNS transactions, traces their originating endpoint processes, enriches them with threat intelligence, geographical information, and asset identities, and runs heuristics to flag DNS Tunneling, DGA beaconing, typosquatting, and fast-flux techniques.

All events are correlated and exported into a unified JSON format designed for ingestion by SIEM and XDR data pipelines (such as Wazuh, Elastic, or Splunk).

---

## 📂 Project Architecture and Directory Structure

The project has been fully modularized into logical directory layers. Here is the structure of the workspace:

```
c:\Users\Abcom\OneDrive\Desktop\SLA AND PROJECTS\Internship Deepcytes DNS BASED EVENTS CODES\
│
├── config.py                  # Global configurations, thresholds, static asset context, and threat feeds
├── main.py                    # Entrypoint script, orchestrates execution threads, handles file logs, and TUI Dashboard
│
├── utils/                     # Statistical & mathematical utilities
│   ├── __init__.py
│   ├── entropy.py             # Calculates Shannon Entropy of strings (randomness)
│   ├── typosquat.py           # Detects typosquatting using Levenshtein distance & character swaps
│   └── dga.py                 # Calculates DGA score via character & transition distribution
│
├── collectors/                # Live system and network telemetry collectors
│   ├── __init__.py
│   ├── dns_sniffer.py         # Sniffs port 53 (Scapy) and maps ports to PIDs (with built-in simulator)
│   └── process_collector.py   # Resolves process command lines, lineages, hashes, and signers using psutil
│
├── enrichers/                 # Intelligence and contextual enrichers
│   ├── __init__.py
│   ├── whois_enricher.py      # Queries WHOIS registration details (with caching and offline simulation)
│   ├── geoip_enricher.py      # Queries Country, City, ASN (RFC 1918 local bypass and caching)
│   ├── threat_intel.py        # Matches domains/IPs against Threat Feeds (categorization and votes)
│   └── asset_enricher.py      # Binds hostname, OS details, department, and user roles to the event
│
└── engine/                    # Analytical and correlation engines
    ├── __init__.py
    ├── tunneling_detector.py  # Evaluates payload sizes, query rates, unique subdomains, and tunneling confidence
    ├── historical_tracker.py  # Tracks temporal history (first seen, last seen, frequency, unique subdomains)
    └── correlation.py         # Schema Builder: Combines all layers into a single normalized JSON SOC event
```

---

## 📊 Core Telemetry Layers & Fields Collected

Every DNS transaction is processed into a single correlated JSON event across the following structured layers:

| Layer | Fields Collected | Security Purpose & Derivation |
| :--- | :--- | :--- |
| **Meta Info** | `event_id`, `timestamp`, `alerts` | Event tracking, timestamping, and listing triggered security flags. |
| **DNS Transaction** | `client_ip`, `query`, `query_type`, `response_code`, `response_ip`, `response_cname`, `ttl`, `recursive`, `authoritative` | Captures basic DNS log data (Zeek/EDR equivalent). |
| **Domain Analysis** | `domain`, `tld`, `subdomain`, `subdomain_length`, `query_length`, `entropy`, `is_dga`, `dga_confidence`, `domain_age_days`, `creation_date`, `registrar`, `is_newly_registered`, `is_typosquat`, `typosquat_target` | Identifies machine-generated domains, newly registered infrastructure, and brand typosquatting. |
| **Tunneling Analysis** | `is_tunneling_suspect`, `tunneling_score`, `payload_size_bytes`, `unique_subdomains_count`, `query_rate_per_minute` | Flags hidden communication channels, high-frequency beacons, and cache-evasion tactics. |
| **Process Lineage** | `pid`, `process_name`, `parent_pid`, `parent_process`, `command_line`, `exe_path`, `process_hash`, `process_sha256`, `signer` | Links the network query to local process lineage, file hashes, and signature trust. |
| **Identity & User** | `username`, `role`, `privilege` | Contextualizes permissions (User vs Admin) and associates activity with a user. |
| **Asset Context** | `hostname`, `operating_system`, `os_version`, `criticality`, `business_unit`, `department` | Evaluates business impact by measuring asset criticality and corporate department. |
| **Threat Intelligence** | `is_in_threat_feed`, `threat_category`, `feed_source`, `reputation_score`, `malicious_votes`, `suspicious_votes` | Cross-references active indicators against known threat feeds. |
| **Geolocation** | `resolved_locations` (array of `ip`, `country`, `city`, `asn` objects) | Identifies where the domain is hosted and warns of hosting regions with high abuse rates. |
| **Historical Context** | `first_seen`, `last_seen`, `frequency` | Tracks baseline patterns of domain requests to isolate statistical anomalies. |

---

## 🛠️ Handling Edge Cases and Advanced Constraints

A key differentiator of this agent is its resilience in production SOC operations. The following edge cases are handled natively:

### 1. Administrative Privileges & Sniffing Fallback
Sniffing raw packet interfaces via Scapy requires administrative permissions (Root on Linux, Administrator on Windows). 
* **Handling**: If the sniffer encounters a permission or socket error, it will gracefully warn the analyst, pivot configuration, and automatically fallback to **Simulation Mode** (which continues generating diverse, realistic security events linked to real running PIDs on the system) so the agent never crashes.

### 2. DNS Client Service (`svchost.exe`) Mapping
On Windows, most standard applications do not resolve DNS queries directly. Instead, they make API calls (like `GetAddrInfo`) to the OS DNS resolver cache service (`dnscache`), causing Scapy to trace the originating UDP socket to a `svchost.exe` process.
* **Handling**: The correlation engine accepts direct EDR telemetry input. When running in Simulation Mode, the agent maps queries back to their logical application origin (e.g. `chrome.exe` or `powershell.exe`) to showcase the target XDR correlation layout.

### 3. WHOIS and GeoIP Rate Limiting
Public lookup services for WHOIS and GeoIP heavily rate-limit repeated queries (e.g. `ip-api.com` throttles to 45 requests/minute).
* **Handling**:
  - **Local RFC 1918 Checks**: The GeoIP module checks if IP addresses are private or loopback ranges (using Python's `ipaddress` library). Private IPs bypass the network lookups entirely and are labeled as `Internal Network` to conserve API request quotas.
  - **Persistent JSON Caching**: Both WHOIS and GeoIP utilities write resolved lookups to local cache databases (`logs/whois_cache.json` and `logs/geoip_cache.json`). Repeated requests read directly from memory/cache, dramatically accelerating correlation time.
  - **Offline Fallback Database**: If network connections fail or queries get throttled, the agent references an offline catalog of threat and simulation domains to preserve analytical integrity.

### 4. Fast Flux and Low TTL Evases
Malware command-and-control networks rotate IP resolutions rapidly using Low Time-To-Live values (e.g. TTL = 10 or 30).
* **Handling**: The correlation engine computes a `SUSPICIOUS_LOW_TTL_FAST_FLUX` alert if a query resolves to multiple distinct public IP ranges while returning a TTL value under 15 seconds.

---

## 🚀 Running and Validating the Agent

To execute the collector and verify its behaviors:

### 1. Requirements
Ensure the following packages are installed:
```bash
pip install psutil scapy python-whois dnspython rich tldextract
```

### 2. Start the Agent
Simply run the entrypoint script:
```bash
python main.py
```
* The console will start up the dashboard, showing live event metrics and a scrolling table of events.
* Exit the agent at any time by pressing **Ctrl+C**.

### 3. Inspecting Saved JSON Logs
The correlated JSON events are written line-by-line in JSON-Lines format (which is the industry standard for SIEM ingestors like Wazuh and Logstash).
You can read the resulting file located at:
`logs/dns_soc_events.json`

Each line contains a wrapper object structured as follows:
```json
{
  "event_id": "08336d4c-7b3d-4227-8e3b-f07141207ffb",
  "timestamp": "2026-06-04T16:00:09Z",
  "file_details": {
    "output_file": "C:\\Users\\Abcom\\OneDrive\\Desktop\\SLA AND PROJECTS\\Internship Deepcytes DNS BASED EVENTS CODES\\logs\\dns_soc_events.json",
    "format": "JSON-Lines (NDJSON)"
  },
  "data": {
    "event_id": "08336d4c-7b3d-4227-8e3b-f07141207ffb",
    "timestamp": "2026-06-04T16:00:09Z",
    "alerts": ["THREAT_INTEL_MATCH_PHISHING"],
    "dns": { ... },
    "domain_analysis": { ... },
    "tunneling_analysis": { ... },
    "process": { ... },
    "user": { ... },
    "asset": { ... },
    "threat_intel": { ... },
    "geolocation": [ ... ],
    "history": { ... }
  }
}
```
