# System Documentation: DeepCytes Kafka Integration & Data Lifecycle

This document provides a technical walkthrough of how the Apache Kafka ingestion pipeline operates within the **DeepCytes DNS Security Agent**. It details the routing logic, the partition hashing schema, the JSON data formats, and the database processing flows.

---

## 1. System-Wide Telemetry Flow

The diagram below details the path a DNS network transaction takes from the moment it is sniffed to its insertion into the databases and archives:

```mermaid
flowchart TD
    %% Telemetry Sniffing & Aggregation
    subgraph Capture [Endpoint Capture & Correlation]
        A[DNS Traffic Sniffer] -->|1. Sniff raw UDP/53| B[Correlation Engine]
        B -->|2. Check Heuristics & Feeds| C{Heuristics Verdict}
        C -->|If security findings trigger| D[Appends Alert Labels]
        C -->|If benign traffic| E[Normal Event Wrapper]
    end

    %% Ingestion Logic & Brokering
    subgraph Ingestion [Kafka Ingestion Tier]
        E -->|3. Route Event| F[DNSKafkaProducer]
        D -->|3. Route Event| F
        F -->|4. Checks alerts array| G{Is Alerts Empty?}
        
        G -->|Yes| H[Topic: dns-events-raw]
        G -->|No| I[Topic: dns-alerts]
        
        %% Partitioning
        H -->|5. Hashing Key: Query Domain| J[Partition Selection]
        I -->|5. Hashing Key: Query Domain| J
        J -->|Hash(domain) % 3 = 0| P0(Partition 0)
        J -->|Hash(domain) % 3 = 1| P1(Partition 1)
        J -->|Hash(domain) % 3 = 2| P2(Partition 2)
    end

    %% Downstream parsing
    subgraph Storage [Database Processing & Archiving]
        P0 -->|6. Batch Ingest| K[Consumer Parser Service]
        P1 -->|6. Batch Ingest| K
        P2 -->|6. Batch Ingest| K
        K -->|7. Normalization & GeoIP Enrichment| L[(Database ClickHouse / TimescaleDB)]
        L -->|8. Database ACK| M[Commit Offset to Broker]
        L -->|9. After 90 days| N[(Cold Storage: Compressed Parquet on S3)]
    end
```

---

## 2. In-Depth Processing & Routing Logic

### A. Topic Routing Logic
The decision to categorize a log as a routine event or an active security alert is evaluated dynamically by checking the event's `alerts` array:

```
┌────────────────────────────────────────────────────────┐
│               Incoming Correlated Event                │
└──────────────────────────┬─────────────────────────────┘
                           │
             Check: len(data.alerts) > 0 ?
                           │
             ┌─────────────┴─────────────┐
             ▼                           ▼
          [ YES ]                     [ NO ]
    (Contains findings:           (Benign query)
     DGA, Tunneling, etc.)               │
             │                           ▼
             ▼                   [ Route to Topic ]
     [ Route to Topic ]           "dns-events-raw"
       "dns-alerts"
```

* **Producer Implementation**:
  ```python
  if alerts:
      topic = "dns-alerts"
  else:
      topic = "dns-events-raw"
  ```

### B. Partition Key Hashing Logic
To allow multiple consumers to process data in parallel without losing temporal sequence order, we use a **Key-Based Partitioning Strategy**:
* **The Message Key**: The queried domain (e.g. `ztvnhmhm4zj95w3.xyz` or `google.com`).
* **The Formula**: 
  $$\text{Target Partition} = \text{MurmurHash2}(\text{Domain Key}) \pmod 3$$
* **Order Guarantee**: Because the mathematical hash of a specific domain string is static, all queries requesting that same domain will map to the exact same partition. Since partitions are read sequentially, the chronological order of requests to that domain is preserved.

---

## 3. Data Schema & Logs Transmitted

The table below describes the logs generated and mapped to each topic:

| Topic | Log Type | Subtypes | Description |
| :--- | :--- | :--- | :--- |
| **`dns-events-raw`** | DNS | `QUERY`, `RESPONSE` | Captures benign activities, typical applications (e.g. office365.com, live.com). Used for asset baselining and threat hunting. |
| **`dns-alerts`** | Alert | `DGA`, `TUNNELING`, `TYPOSQUAT`, `THREAT_INTEL` | Triggers when entropy exceeds limit, brand typos are found, or queried domain matches local blacklists. |

### Message Envelope Schema Layout

Below is the structure of the JSON payload sent by the producer to Kafka:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        KAFKA JSON ENVELOPE                             │
├────────────────────────────────────────────────────────────────────────┤
│ Key: "ztvnhmhm4zj95w3.xyz"                                             │
├────────────────────────────────────────────────────────────────────────┤
│ Value:                                                                 │
│ {                                                                      │
│   "event_id": "a4b1c2d3-e4f5-6789-0123-456789abcdef",                  │
│   "timestamp": "2026-06-13T04:22:04Z",                                 │
│                                                                        │
│   "data": {                                                            │
│     "event_id": "a4b1c2d3-e4f5-6789-0123-456789abcdef",                │
│     "timestamp": "2026-06-13T04:22:04Z",                               │
│     "alerts": ["DGA_DETECTED", "THREAT_INTEL_MATCH"],                  │
│                                                                        │
│     "dns": {                                                           │
│       "query": "ztvnhmhm4zj95w3.xyz",                                  │
│       "query_type": "A",                                               │
│       "response_code": "NXDOMAIN",                                     │
│       "ttl": 10                                                        │
│     },                                                                 │
│                                                                        │
│     "process": {                                                       │
│       "pid": 4096,                                                     │
│       "process_name": "cmd.exe",                                       │
│       "command_line": "ping ztvnhmhm4zj95w3.xyz"                       │
│     },                                                                 │
│                                                                        │
│     "threat_intel": {                                                  │
│       "is_malicious": true,                                            │
│       "threat_category": "c2",                                         │
│       "source": "Google Threat Intel (PLASMAGRID C2)"                  │
│     }                                                                  │
│   }                                                                    │
│ }                                                                      │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Consumer Database Ingestion & Fault-Tolerance Logic

To store formatted data in real time and recover from system failures:

```
                  ┌──────────────────────────────┐
                  │   Consumer Pulls Log Batch   │
                  └──────────────┬───────────────┘
                                 │
                   Parse & Normalize to ECS Schema
                                 │
                                 ▼
                  ┌──────────────────────────────┐
                  │  Insert Batch into Database  │
                  └──────────────┬───────────────┘
                                 │
                       Did Write Succeed (ACK)?
                                 ├──────────────────────┐
                             [ YES ]                  [ NO ]
                                 │                      │
                                 ▼                      ▼
                  ┌──────────────────────────────┐  ┌───────────────────────┐
                  │ Commit Offset back to Kafka  │  │ Rollback Transaction  │
                  │   (Update consumer bookmark) │  │  (Retry Log Batch)    │
                  └──────────────────────────────┘  └───────────────────────┘
```

1. **Format-On-Ingest**: When reading the raw JSON envelope, the Consumer normalizes variables (e.g. mapping process lists or Geolocation coordinates) to fit structured table fields before writing them.
2. **Synchronous Commits**: Auto-commit is set to `False`. The offset is committed to Kafka **only** after receiving a database success return. This prevents data loss if the consumer crashes mid-transaction.
3. **Idempotence**: The `event_id` UUID serves as the database unique constraint key. If a consumer restarts and replays a partition chunk, the database ignores duplicates, ensuring **Exactly-Once logic**.

---

## 5. Detailed Producer Routing Flow Diagram

The diagram below details the program logic inside the Producer (`utils/kafka_producer.py`) when it receives a single telemetry event:

```mermaid
flowchart TD
    %% Event input
    Start([1. Event Received]) --> EventInput[event_wrapper JSON structure]
    
    %% Extraction
    EventInput --> ExtractSocEvent[2. Extract 'data' object]
    ExtractSocEvent --> ExtractAlerts[3. Extract 'alerts' list]
    
    %% Decision Branch
    ExtractAlerts --> DecisionAlerts{4. Are there any alert tags in the list?}
    
    DecisionAlerts -->|Yes| RouteAlerts[5. Assign Topic: 'dns-alerts']
    DecisionAlerts -->|No| RouteEvents[5. Assign Topic: 'dns-events-raw']
    
    %% Key extraction
    RouteAlerts --> ExtractKey[6. Extract Routing Key: soc_event.dns.query]
    RouteEvents --> ExtractKey
    
    %% Hashing & Broker Send
    ExtractKey --> KafkaSend[7. Call: producer.send]
    KafkaSend --> ValueEncoder[8. Value Encoded to JSON Bytes]
    ValueEncoder --> KeyEncoder[9. Key Encoded to UTF-8 Bytes]
    
    %% Sync flush
    KeyEncoder --> PartitionSelect[10. Hash(Key) % 3 Partition Selection]
    PartitionSelect --> BrokerFlush[11. Call: producer.flush]
    BrokerFlush --> End([12. Safe Delivery in Broker Queues])
```

#### Step-by-Step Logic Breakdown:
1. **Input Packet**: The producer receives `event_wrapper` which wraps the raw system data, telemetry indicators, alerts, and process details.
2. **Object Breakdown**: The producer extracts the internal `data` block and inspects `data.alerts`.
3. **Branch Condition**:
   - If `alerts` is populated (e.g. `["DGA_DETECTED"]`), the destination topic is set to `dns-alerts`.
   - If `alerts` is empty, the topic is set to `dns-events-raw`.
4. **Key Assignment**: The queried domain string (e.g. `google.com`) is extracted to act as the partition routing key.
5. **Serialization**: The Kafka client serializes the payload to JSON bytes and the key to UTF-8 bytes.
6. **Delivery**: The client uses the partition selector (Hash(domain) % 3) to write to the designated broker queues and flushes the thread immediately for near-zero latency.
