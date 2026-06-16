# DeepCytes DNS Agent: Walkthrough of Telemetry & Visualization Updates

This walkthrough details the changes made to the DNS security agent to support the new JSON schema, single Kafka topic ingestion, frontend dashboard charts, and visual report generation.

---

## 📂 Project Architecture and Directory Structure

The project remains structured modularly, with recent additions for report generation and frontend visualizations:

```
c:\Users\Abcom\OneDrive\Desktop\SLA AND PROJECTS\Internship Deepcytes DNS BASED EVENTS CODES\
│
├── config.py                  # Global configurations (Updated to use single Kafka raw events topic)
├── main.py                    # Core execution engine (Updated with get_device_fingerprint and new JSON wrapping)
├── dashboard.py               # SOC Telemetry Frontend (Updated with responsive Chart.js graphs)
├── generate_soc_docx.py       # [NEW] Generates the SOC Analyst Visualization Blueprint document
├── DNS_SOC_Analyst_Visualizations.docx # [NEW] Generated visual blueprint report
│
├── utils/                     # Statistical & mathematical utilities
│   ├── kafka_producer.py      # Kafka integration (Updated to support new schema and single topic routing)
│   ├── ...
```

---

## 🔒 1. Updated JSON Log Format & Device Fingerprinting

The log events written to `logs/dns_soc_events.json` have been restructured to output a standardized XDR format. Each line contains:
1. `device_fingerprint`: Holds host identifier variables collected at runtime (`ip`, `mac_address`, `os`, `username`, `agent_name`).
2. `event_id`: Unique tracking ID.
3. `event_type`: Mapped from alerts (e.g. `THREAT_INTEL_MATCH_PHISHING`) or defaults to `DNS_QUERY`.
4. `severity`: Mapped to `CRITICAL`, `LESS_CRITICAL`, or `INFORMATORY`.
5. `payload`: The full nested telemetry content (original `soc_event`).

### Example Structured Output
```json
{
  "device_fingerprint": {
    "ip": "192.168.0.101",
    "mac_address": "94:e2:3c:1d:cd:2e",
    "os": "Windows 11 Enterprise",
    "username": "rishik_admin",
    "agent_name": "DeepCytes DNS Agent"
  },
  "event_id": "537e61fe-51fa-40c6-9569-a80673f94c3c",
  "event_type": "DNS_QUERY",
  "severity": "INFORMATORY",
  "payload": {
    "event_id": "537e61fe-51fa-40c6-9569-a80673f94c3c",
    "timestamp": "2026-06-16T12:03:35Z",
    "alerts": [],
    "dns": { "client_ip": "192.168.1.52", "query": "github.com", "query_type": "A" },
    "process": { "pid": 4824, "process_name": "chrome.exe" },
    "risk": { "score": 0, "severity": "LOW" }
  }
}
```

---

## 📡 2. Kafka Topic Consolidation

Per the updated instructions, we consolidated Kafka routing by:
- Deleting the `dns-alerts` topic from configurations.
- Routing all telemetry data (benign traffic, DGA, typosquat, and tunneling alerts alike) into a single, high-throughput topic: **`dns-events-raw`** (controlled via `config.KAFKA_TOPIC_RAW`).
- Modifying `utils/kafka_producer.py` to transparently extract internal data from both the old `"data"` schema and the new `"payload"` schema.

---

## 📊 3. Modern SOC Frontend Visualizations

The frontend dashboard (`dashboard.py`) was enhanced with a premium, responsive chart system powered by **Chart.js** via CDN.
We added:
1. **Severity Distribution (Doughnut Chart)**: Shows a breakdown of `Critical`, `Less Critical`, and `Informatory` traffic volume.
2. **New Domains Trend (Frequency Graph)**: A line chart graphing new domain queries over a rolling timeline to flag registration spikes.
3. **Active Threat Vectors (Horizontal Bar Chart)**: Plots alert frequencies for DGA, Tunneling, Typosquatting, and Threat Intel feeds horizontally.
4. **Top Talkers (Horizontal Bar Chart)**: Visualizes the most frequently queried destination domains to help detect anomalous beacons.
5. **Entropy vs. Risk Score (2D Scatter Plot)**: Plots character-based Shannon Entropy values against calculated Risk Scores to expose high-entropy tunneling outliers.

The dashboard remains fully backwards-compatible, parsing historical log files using `log.payload || log.data || {}` safely.

---

## 📄 4. SOC Visual Blueprint Report (`.docx`)

We created a custom Python script [generate_soc_docx.py](file:///C:/Users/Abcom/OneDrive/Desktop/SLA%20AND%20PROJECTS/Internship%20Deepcytes%20DNS%20BASED%20EVENTS%20CODES/generate_soc_docx.py) and generated the document:
**[DNS_SOC_Analyst_Visualizations.docx](file:///C:/Users/Abcom/OneDrive/Desktop/SLA%20AND%20PROJECTS/Internship%20Deepcytes%20DNS%20BASED%20EVENTS%20CODES/DNS_SOC_Analyst_Visualizations.docx)**

The document details:
- **Core Graphs**: Hourly New Domain Trend, Severity Distribution, Threat Vectors, Top Talkers, and Entropy Scatter Plots.
- **Utility**: Why each visualization is critical to a SOC analyst's daily workflow.
- **Connections**: What telemetry metrics (e.g. WHOIS dates, Shannon entropy, risk scores) connect to construct these views.
