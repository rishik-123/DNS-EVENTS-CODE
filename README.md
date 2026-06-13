# DeepCytes DNS Security Agent & SOC Telemetry Pipeline

An advanced, real-time Security Operations Center (SOC) telemetry collection agent designed to capture DNS traffic (live or simulation mode), perform real-time correlation and security heuristic analysis, route threat indicators via Apache Kafka, and visualize telemetry metrics through an interactive Web GUI Dashboard.

---

## 1. Project Architecture Summary

The pipeline is split into three main tiers:
1. **Collection & Analysis (Agent)**: 
   - Uses Scapy to sniff DNS requests on local network interfaces (or generates traffic in simulation mode).
   - Core correlation engine runs heuristic checks (DGA detection, DNS tunneling, low TTL analysis, and typosquatting detection) against local threat feeds.
   - Saves final logs locally in JSON Lines (NDJSON) format under `logs/dns_soc_events.json`.
2. **Streaming Broker (Kafka)**:
   - Routes telemetry events asynchronously based on threat severity.
   - **`dns-events-raw`**: Receives all normal / benign DNS events.
   - **`dns-alerts`**: Dedicated high-priority queue for security detections.
   - Uses the queried `domain` as the partition key to guarantee chronological sequence mapping inside partitions.
3. **Visualization (Web GUI Dashboard)**:
   - A lightweight multithreaded web server that reads `logs/dns_soc_events.json` in real time.
   - Visualizes live KPI stats, provides audio alarms via browser-synthesized beeps, and allows analysts to click rows to expand the full deep JSON payloads.

---

## 2. Prerequisites

- **Python**: Version 3.8 or higher.
- **Dependencies**: Install required Python libraries by running:
  ```bash
  pip install -r requirements.txt
  ```
  *(Requires `kafka-python`, `rich`, `scapy`, etc.)*
- **Apache Kafka**: Pre-installed under `C:\kafka_2.13-4.3.0` (using KRaft mode).
- **Network Privileges**: Administrative command prompt required to sniff raw sockets if simulation mode is disabled (`SIMULATION_MODE = False`).

---

## 3. Step-by-Step Setup and Execution Commands

Always run commands from their respective directories. Follow the stages below:

### Phase A: Setup and Start Apache Kafka (Standalone KRaft)
Open a new Windows command prompt (`cmd`) and navigate to your Kafka root folder:

1. **Format Log Directories** (Run once to prepare KRaft storage):
   ```cmd
   cd C:\kafka_2.13-4.3.0
   .\bin\windows\kafka-storage.bat format -t LSn9dWs_RQmd9SNvmYxqeQ -c .\config\server.properties --standalone
   ```

2. **Start the Kafka Server** (Keep this command prompt window open):
   ```cmd
   .\bin\windows\kafka-server-start.bat .\config\server.properties
   ```

---

### Phase B: Create Integration Topics
Open a **second command prompt** to configure the topics:

1. **Verify Connection & List Topics**:
   ```cmd
   cd C:\kafka_2.13-4.3.0
   .\bin\windows\kafka-topics.bat --bootstrap-server localhost:9092 --list
   ```

2. **Create the Telemetry & Alert Topics** (Configured with 3 partitions for scale and horizontal processing):
   ```cmd
   .\bin\windows\kafka-topics.bat --create --topic dns-events-raw --bootstrap-server localhost:9092 --partitions 3 --replication-factor 1
   ```
   ```cmd
   .\bin\windows\kafka-topics.bat --create --topic dns-alerts --bootstrap-server localhost:9092 --partitions 3 --replication-factor 1
   ```

---

### Phase C: Run the Sniffer Agent & Web GUI Dashboard
Navigate to your Python project directory (`c:\Users\Abcom\OneDrive\Desktop\SLA AND PROJECTS\Internship Deepcytes DNS BASED EVENTS CODES`) to run the applications:

1. **Start the DeepCytes DNS Agent**:
   This runs the telemetry collector, correlation logic, local file logging, and sends messages to Kafka.
   ```cmd
   python main.py
   ```
   *(On Windows, if sniffing live network traffic, run this terminal as Administrator; otherwise, it falls back automatically to Simulation mode).*

2. **Start the Web GUI Dashboard Server**:
   In a new terminal window inside your Python project folder, run:
   ```cmd
   python dashboard.py
   ```
   * The terminal will launch the local multithreaded server on port `8080`.
   * It will automatically open your default browser. If it doesn't, navigate to: **[http://localhost:8080](http://localhost:8080)**.

3. **(Optional) Observe Logs Directly in Kafka CLI Consumers**:
   To observe raw messages streaming into Kafka topics via command line:
   - To watch Raw Events:
     ```cmd
     cd C:\kafka_2.13-4.3.0
     .\bin\windows\kafka-console-consumer.bat --topic dns-events-raw --bootstrap-server localhost:9092 --property print.key=true --property key.separator=" | "
     ```
   - To watch Alerts/Threats:
     ```cmd
     cd C:\kafka_2.13-4.3.0
     .\bin\windows\kafka-console-consumer.bat --topic dns-alerts --bootstrap-server localhost:9092 --property print.key=true --property key.separator=" | "
     ```

---

## 4. Key Dashboard Controls
- **Live Stream Logs Table**: Displays chronological timestamp, requested domain, transaction types, process details, and classification badges.
- **Log Payload Inspector**: Click any row in the log table to expand the dropdown section containing the formatted JSON data payload.
- **Audio Alerts Switch**: Located at the top right header. When active, it uses the browser's Web Audio API to emit a synthesizer beep upon detecting a new alert.
- **Connection Status Badge**: Indicates if the server is dynamically polling the active log database.
