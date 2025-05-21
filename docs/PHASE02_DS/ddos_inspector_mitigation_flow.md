
# 🛡 Mitigation Control Flow – `ddos_inspector`

## 🎯 Objective
Formalize a robust, adaptive, and research-consistent logic for real-time mitigation, rollback, and automatic unban. This design meets all criteria for AI-security research: transparency, traceability, low-overhead execution, and deterministic behavior across distributed setups.

---

## 🔁 Flowchart Overview

```
[Anomaly Detected]
        ↓
[Decision Core]
        ↓
[Severity Score > Threshold?] ── No ──> [Ignore / Log only]
        │
       Yes
        ↓
[Block IP using nftables]
        ↓
[Log Event + Reason + Timestamp]
        ↓
[Export Metrics to Prometheus]
        ↓
[Start Decay Timer for Auto-Unban (10 mins)]
```

---

## 🔐 Mitigation Action Logic

### Command Executed
```bash
nft add element inet filter ddos_block { <ip_address> }
```

### Parameters:
- **Reason**: "ewma_high", "entropy_burst", "long_session"
- **Added to Prometheus**:
  - `active_mitigations_total`
  - `ddos_mitigation_reason{src, reason}`

---

## 🧼 Auto-Unban Design

### Decay Timer:
- **Trigger**: Background thread (runs every 60s)
- **Condition**:
  - IP has been clean (no alert) for 10 minutes
  - IP is still in mitigation set

### If clean:
```bash
nft delete element inet filter ddos_block { <ip_address> }
```
- Remove from memory cache
- Log unban event
- Update metric: `unban_success_total`

---

## 🔄 Precision Drop Response: Rollback

### Monitored via Prometheus:
```promql
avg_over_time(ddos_precision[5m]) < 0.93
```

### Rollback Actions:
1. Switch to **TAP mode** (monitor only for 60s)
2. Recalculate μ, σ from 5-minute window
3. If precision still < 90%:
   - Roll back to Snort native ruleset
   - Trigger: `ddos_fallback_triggered++`
   - Export: `ddos_mode_state{mode="TAP"}`

---

## 📈 Observability Metrics

| Metric                       | Type        | Description                                  |
|-----------------------------|-------------|----------------------------------------------|
| `active_mitigations_total`  | Counter     | Number of IPs blocked                        |
| `ddos_mitigation_reason{}`  | Label/Enum  | Reason for block (entropy/ewma/session)      |
| `unban_success_total`       | Counter     | Auto-unban success count                     |
| `ddos_precision`            | Gauge       | Live accuracy of detection module            |
| `ddos_fallback_triggered`   | Counter     | Total rollbacks triggered                    |
| `ddos_mode_state`           | Enum/Gauge  | Current plugin state (INLINE/TAP)            |

---

## ⏱ Performance Guarantees

| Stage               | Target Latency |
|---------------------|----------------|
| Mitigation action   | < 1 ms         |
| Auto-unban check    | < 0.5 ms       |
| Rollback switch     | < 1.5 ms       |
| Metrics push        | < 2 ms         |
| Total roundtrip     | < 5 ms         |

---

## 🔁 Reproducibility & Safety

- **No permanent blocking**: All IPs removed automatically if anomaly does not persist.
- **All blocking decisions timestamped and logged**.
- **Prometheus-exported metrics ensure transparency** across distributed systems.
- **Rollback ensures no persistent FP-induced disruption**.

---

## ✅ Scientific Compliance

This design:
- Meets AI-security reproducibility requirements
- Avoids ML black-boxing: uses explainable rule-based mitigation
- Is compatible with Snort 3 C++ plugin architecture
- Uses deterministic decay, low memory state tracking, and lock-free timers
