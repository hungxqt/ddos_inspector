
# 🧠 Algorithmic Specification Output – `ddos_inspector`
**Module: Statistical & Behavioral Detection Logic for DDoS Detection in Snort 3**

---

## 1. 📈 EWMA (Exponentially Weighted Moving Average)

**Goal**: Detect volumetric anomalies (e.g., SYN, UDP floods) in packet rate per IP or per flow.

### 🔸 Formula
```
EWMA_t = α * x_t + (1 - α) * EWMA_{t-1}
```

- `x_t`: Current packet count in window (1s)
- `α = 0.3`: Empirically optimal smoothing factor
- Alert if:
```
EWMA_t > μ + 3σ
```

### 🔸 Implementation
- Sliding window: 1s
- Per-source IP basis
- Deterministic update logic across machines using fixed precision and clock alignment

### 🔸 Output Metrics (Prometheus)
- `packet_rate{src="IP"}`
- `ewma{src="IP"}`
- `alert_level{src="IP", type="ewma"}`

---

## 2. 🧮 Entropy Analysis

**Goal**: Detect randomness in traffic characteristics (HTTP floods, spoofed packets).

### 🔸 Formula (Shannon Entropy)
```
H = -Σ(p_i * log₂(p_i))
```
- `p_i`: frequency of source IPs, URIs, ports

### 🔸 Features Analyzed
- Source IP entropy
- Destination port entropy
- HTTP URI entropy

### 🔸 Detection Logic
- Sliding window: 5s
- Alert if:
```
H > μ + 3σ (feature-specific threshold)
```

- Thresholds adaptively recalculated every 5 minutes using Prometheus metrics

### 🔸 Metrics Exported
- `entropy_srcip`, `entropy_uri`, `entropy_port`
- `alert_level{src="IP", type="entropy"}`

---

## 3. 🧠 Behavioral Detection

**Goal**: Detect stealthy attacks like Slowloris by profiling TCP/HTTP behavior.

### 🔸 Tracked Features
| Feature                         | Threshold            | Relevance                             |
|----------------------------------|----------------------|----------------------------------------|
| Half-open TCP connections       | > 80 / IP            | SYN flood or idle connections          |
| HTTP session duration           | > 120s / IP          | Slowloris-style prolonged sessions     |
| Idle connection w/ <2 req/min   | active > 60s         | Low-and-slow HTTP/HTTPS attack         |

- Detected using time-delta-based state table

### 🔸 Actions
- Suspect IPs added to nftables set
- Logged with timestamp + reason
- Auto-pruned after 10 mins of clean behavior

### 🔸 Prometheus Export
- `tcp_half_open{src="IP"}`
- `session_duration{src="IP"}`
- `alert_level{src="IP", type="behavior"}`

---

## 4. 🔄 Adaptive Fallback & Self-Healing

**Goal**: Maintain precision and system availability during uncertain traffic conditions

### 🔸 Triggers
- Prometheus alert `ddos_precision_low` (precision < 93%)

### 🔸 Response
1. Switch mode from INLINE to TAP (60s passive)
2. Recalculate μ, σ over last 5 minutes
3. If precision < 90% after fallback → disable plugin, activate Snort ruleset, notify SOC

### 🔸 Logging
- `ddos_mode_state{}`: current operation mode
- `ddos_rollback_count`: counter of fallbacks

---

## 5. ⚙️ Summary of Parameters

| Parameter                   | Value             | Notes                            |
|----------------------------|-------------------|----------------------------------|
| EWMA smoothing α           | 0.3               | Empirical, adjustable            |
| Entropy analysis window    | 5 seconds         | Short-term randomness check      |
| HTTP session max duration  | 120s              | Flagged as suspicious if exceeded|
| Half-open TCP threshold    | 80                | Above this → flag IP             |
| Auto-unban timeout         | 10 mins           | Clean IPs removed                |

---

## 6. 📤 Exported Metrics Overview

All exported metrics are accessible via Prometheus:

```
/metrics:
    packet_rate{src_ip}
    ewma{src_ip}
    entropy_srcip
    entropy_uri
    entropy_port
    tcp_half_open{src_ip}
    session_duration{src_ip}
    alert_level{src_ip, type}
    ddos_precision
    ddos_fallback_triggered
    ddos_mode_state
```

---

## 7. 🧪 Attack-Type Mapping Matrix

| Attack Type     | EWMA  | Entropy | Behavior Profiling |
|-----------------|-------|---------|---------------------|
| SYN Flood       | ✅    | ❌      | ✅                  |
| UDP Flood       | ✅    | ✅      | ❌                  |
| HTTP Flood      | ❌    | ✅      | ✅                  |
| Slowloris       | ❌    | ❌      | ✅                  |

---

## 🔬 Notes for Distributed Consistency

- All modules should share:
  - Same entropy/ewma α values
  - Clock-synchronized sliding window handling
  - Git-tracked config files for reproducibility

- All detection logic produces identical output if the same traffic is replayed across 5 independent machines (Addition 1 compliance)

---

**Aligned with:**
- Scientific reproducibility
- AI-Security standards
- Efficient Snort plugin architecture
