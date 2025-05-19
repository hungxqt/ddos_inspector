# Designing Pre-filtering Logic in Snort 3 DDoS Plugin (`ddos_inspector`)

As we developed our `ddos_inspector` plugin for Snort 3, one of the early architectural decisions we made was to **implement a lightweight pre-filtering stage**. This section summarizes our reasoning, technical approach, and future implications of this design choice from a research and development perspective.

---

## 🎯 Research Motivation: Why Pre-filter?

From both theoretical and practical perspectives, pre-filtering offers multiple advantages:

- **Efficiency**: Reduces processing load by skipping packets that are not relevant to DDoS attack vectors.
- **Precision**: Eliminates noise introduced by unrelated protocols (e.g., ARP, ICMPv6), improving statistical signal clarity.
- **Scalability**: Supports real-time performance under high-volume conditions (10k+ pkts/sec).
- **Modular Design**: Establishes a clean boundary between low-cost filtering and higher-cost detection logic.

In traditional IDPS systems, everything is handed to the rule engine, which wastes CPU cycles on irrelevant data. We designed our plugin to avoid that pitfall.

---

## 🧪 Assumptions and Threat Model

We focused on DDoS attack types that primarily exploit:

- **TCP** (SYN floods, Slowloris)
- **UDP** (Amplification attacks)
- **ICMP** (Optional, for ping floods)

Therefore, protocols like ARP, IPv6 ND, GRE, ESP, or multicast are out of scope.

---

## 🔧 Implementation Strategy

We placed the pre-filter inside the `eval()` function — the first method Snort calls per packet.

```cpp
void DdosInspector::eval(snort::Packet* p)
{
    if (!p || p->ip_version != 4)
        return;

    if (p->proto != IPPROTO_TCP && p->proto != IPPROTO_UDP)
        return;

    // Heavy logic (entropy, behavior) goes below
}
```

**Key design choices:**

- We check for **IPv4 only**, since most attack tools default to IPv4.
- We allow **TCP and UDP only**.
- Future enhancement: add `allow_icmp` toggle via plugin config.

This avoids the overhead of processing `p->payload`, stream decoding, or entropy analysis for irrelevant traffic.

---

## 📈 Expected Benefits

| Benefit              | How It Helps                                           |
|----------------------|--------------------------------------------------------|
| CPU Efficiency       | Avoids invoking entropy/stats engine for unwanted data |
| Memory Stability     | Prevents queue growth with garbage protocols           |
| Lower False Positives| Avoids skewed stats caused by control-plane traffic    |
| Adaptive Tuning      | We can later expand to ICMP or restrict UDP if needed  |

---

## 📊 Monitoring the Filter

We also plan to expose Prometheus metrics like:

```cpp
prometheus::counter("packets_dropped_prefilter_ipv6");
prometheus::counter("packets_dropped_prefilter_non_tcpudp");
```

This helps visualize what is being filtered and ensure our assumptions hold in production.

---

## 🔮 Research Outlook

In future iterations, we aim to explore:

- **Dynamic protocol toggles** based on live traffic analysis
- **Flow-aware filters** to drop known safe ports or benign services
- **Machine-assisted tuning** of pre-filter thresholds (e.g., auto-enable ICMP)

Our belief is that intelligent filtering should evolve — not remain hardcoded. By treating this pre-filtering as an adaptive, policy-driven system, we can maintain both performance and flexibility.

---

## ✅ Final Thoughts

The pre-filtering logic is not just an optimization — it's a **defensive design mechanism** that enforces boundaries on what our plugin cares about. It supports our broader research goal of building **accurate, lightweight, and real-time DDoS mitigation inside Snort**, without sacrificing extensibility or analytical depth.