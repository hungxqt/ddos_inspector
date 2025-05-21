# ddos_inspector - Smarter DDoS Detection Module for Snort 3

![Status](https://img.shields.io/badge/status-active-brightgreen)
![C++](https://img.shields.io/badge/language-C++-blue)
![Snort 3](https://img.shields.io/badge/snort-3.x-critical)
![License](https://img.shields.io/badge/license-MIT-green)
![Contributions](https://img.shields.io/badge/contributions-welcome-orange)


**ddos_inspector** is a lightweight, real-time DDoS detection and mitigation plugin designed for [Snort 3](https://snort.org/). Unlike traditional static rule-based detection or heavy ML-based systems like SnortML, this plugin combines statistical methods and behavioral profiling to identify and block malicious traffic — all with minimal system overhead.

---

## 🔍 Key Features

- **Statistical Analysis**: Detects anomalies using EWMA (Exponentially Weighted Moving Average) and entropy-based methods.
- **Behavioral Profiling**: Flags suspicious behaviors like half-open TCP connections and prolonged HTTP sessions (e.g., slowloris).
- **Real-Time Mitigation**: Integrates with `iptables`/`nftables` to block malicious IPs dynamically.
- **Lightweight**: 
  - CPU usage < 5%
  - RAM usage < 100MB
  - Detection latency < 10ms
- **No ML Frameworks**: Pure C++ implementation without TensorFlow or external ML dependencies.

---

## 🎯 Detection Capabilities

- **SYN Floods**: Detects incomplete TCP handshake attacks.
- **UDP/ICMP Floods**: Handles volumetric attacks with high packet rates.
- **HTTP Floods**: Detects excessive application-layer traffic.
- **Slowloris Attacks**: Identifies persistent, low-volume connections.

---

## 🧩 Architecture Overview

- `ddos_main.cpp`: Manages packet flow and plugin orchestration.
- `stats_engine.cpp`: Implements EWMA & entropy calculation logic.
- `behavior_tracker.cpp`: Monitors long-lived sessions and TCP anomalies.
- `firewall_action.cpp`: Executes mitigation using `nftables` or `ipset`.

### Data Flow

1. **Pre-Filter**: Removes non-TCP/UDP traffic to reduce processing load.
2. **Statistics Engine**: Computes entropy and packet rates, exports Prometheus metrics.
3. **Behavior Tracker**: Analyzes connection state (e.g., >80 half-open TCP sockets).
4. **Mitigation Engine**: Blocks IPs with high anomaly scores for 10 minutes.
5. **Auto-Recovery**: Periodic re-evaluation unbans clean IPs automatically.

---

## 🧪 Testing & Evaluation

- **Environment**: Tested with Mininet, hping3, Slowloris, and tcpreplay.
- **Metrics**:
  - Detection Precision ≥ 93%
  - False Positive Rate ≤ 3%
  - Detection time < 1s, Block time < 2s

| Attack Type      | Detection Time | Block Time | FPR     |
|------------------|----------------|------------|---------|
| SYN Flood        | <1s            | <2s        | <2%     |
| HTTP Flood       | <1s            | <2s        | <2%     |
| Slowloris        | <5s            | <2s        | <3%     |

---

## 🛠 Installation

```bash
# Prerequisites
sudo apt install snort3 libpcap-dev libboost-all-dev nftables cmake

# Build
mkdir build && cd build
cmake ..
make -j$(nproc)
```

> Place the plugin in Snort's plugin directory and add appropriate `inspector` config in `snort.lua`.

---

## 📜 License

This project is developed as part of the ADHHP research team (2025) and is released under an open-source license to foster community collaboration and improvements.

---

## 👥 Team

- **Duong Quoc An - [@Anduong1200](https://github.com/Anduong1200)** (Leader)
- **Tran Quoc Hung - [@hung-qt](https://github.com/hung-qt)**
- **Mai Hong Phat - [@samael](https://github.com/pzhat)**
- **Le Nguyen Anh Dat**
- **Bui Quang Hieu**
- **Supervisor**: Pham Ho Trong Nguyen

---

## 📌 Future Directions

- Multi-host attack correlation support
- ELK/Prometheus integration dashboards
- Extendable framework for other intrusion detection use cases

---

## 🔗 Contact

Feel free to raise issues, contribute, or reach out for collaboration.
Email: anduong1200@gmail.com
