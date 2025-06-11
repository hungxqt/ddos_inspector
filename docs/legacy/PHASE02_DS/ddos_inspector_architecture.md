
# 🧩 Shared Data Pipeline – Module Architecture for `ddos_inspector`

## 🎯 Objective
Design a lightweight, real-time, and reproducible data pipeline for Snort 3 plugin `ddos_inspector`, which integrates statistical and behavioral analysis using multi-threaded safe queues and exposes operational metrics. This pipeline must work identically across multiple nodes with consistent logic flow and output (Addition 1 compliance).

---

## 🧱 Pipeline Overview

```
                    +-----------------------+
                    | Snort 3 Packet Stream |
                    +-----------------------+
                                |
                                V
                    +------------------------+
                    | Pre-filter Module      |
                    | (drop DNS, ARP, etc.)  |
                    +------------------------+
                                |
                                V
                     +--------------------------+
                     | Boost::SPSC Queue        |
                     | (lock-free, FIFO, meta)  |
                     +--------------------------+
                                |
                 +----------------+   +-----------------------+
                 | Stats Engine   |   | Behavior Profiler     |
                 | (EWMA, Entropy)|   | (TCP/HTTP Monitoring) |
                 +----------------+   +-----------------------+
                                |             |
                                +------v------+
                                       |
                               +---------------+
                               | Decision Core |
                               | (logic fusion)|
                               +---------------+
                                       |
                               +---------------+
                               |   Mitigator   |
                               | (nftables/ip) |
                               +---------------+
```

---

## 🔧 Core Components

### 🧊 Pre-filter Module
- Removes non-TCP/UDP/DDoS-irrelevant packets
- Ensures minimal workload downstream
- Language: C++

---

### 🔄 Boost::SPSC Queue
- Lock-free single producer (packet hook) / single consumer (engine)
- Packet metadata: src IP, dst port, proto, flags, payload len, ts
- Guarantees same order across all nodes

---

### 📊 Stats Engine (`stats_engine.cpp`)
- Computes EWMA per IP and Entropy for IP/URI/Port
- Recalculates thresholds (`μ`, `σ`) every 5 min
- Publishes to Prometheus:
  - `ewma{src}`
  - `entropy_srcip`, `entropy_uri`
  - `alert_level{src, type="ewma"}`

---

### 🧠 Behavior Profiler (`behavior_tracker.cpp`)
- Tracks per-IP:
  - Half-open TCP
  - HTTP session duration
  - Idle connection + low req/s
- Publishes to Prometheus:
  - `tcp_half_open`, `session_duration`, `suspect_flags`

---

### 🧮 Decision Core
- Fuses outputs from both engines
- Rules:
  - High EWMA + Entropy + behavior → ALERT
  - Flags only if combined anomaly level > threshold
- If attack → forward IP to Mitigator

---

### 🔐 Mitigator (`firewall_action.cpp`)
- Uses `nftables` dynamic set:
  - `nft add element inet filter ddos_block { <bad_ip> }`
- Periodic cleanup:
  - Every 60s → remove IPs clean for 10 min
- Logs to Prometheus + `/var/log/ddos_inspector.log`

---

## 📡 Monitoring & Metrics

- All modules expose Prometheus-friendly `/metrics`
- Consistent naming: `ddosinspector_<module>_<metric>`
- Alerts:
  - `ddos_precision_low`
  - `ddos_fallback_triggered`
  - `active_mitigations_total`

---

## ⏱ Timing Targets (Performance Budget)

| Module             | Max Latency |
|--------------------|-------------|
| Pre-filter         | < 0.5 ms    |
| SPSC enqueue       | < 0.1 ms    |
| Stats Engine       | < 2 ms      |
| Behavior Tracker   | < 4 ms      |
| Decision Core      | < 1.5 ms    |
| Mitigator Action   | < 1 ms      |
| **End-to-End**     | **< 10 ms** |

---

## ⚙️ Directory Structure

```
src/
├── ddos_main.cpp         # Entry point for Snort plugin
├── stats_engine.cpp      # EWMA, Entropy logic
├── behavior_tracker.cpp  # TCP session state
├── firewall_action.cpp   # nftables integration
├── spsc_queue.hpp        # Boost SPSC wrapper
├── metrics_exporter.cpp  # Prometheus metrics
└── config.yaml           # Global parameters
```

---

## 🔁 Cross-System Consistency Notes

- Time-aligned window logic
- Shared YAML config = identical thresholds across devices
- Deterministic execution of alert path
- Unit test files to validate EWMA & Entropy matching across machines

---

## 🧩 Next Steps

- Add Prometheus alerting rule templates
- Create `.dot` and `.png` architecture visualization
- Generate Graph-based documentation for integration with GitHub Wiki

---

**This pipeline meets all Snort 3 plugin constraints while ensuring performance (<10ms), cross-host reproducibility, and AI-Security research integrity.**
