# Designing and Evolving Pre-filtering Logic in Snort 3 DDoS Plugin (`ddos_inspector`)

As we developed our `ddos_inspector` plugin for Snort 3, implementing a **pre-filtering stage** became an essential design feature. This stage allows us to eliminate irrelevant packets early in the pipeline, thus reducing overhead and sharpening our detection focus.

This document reflects our design reasoning, implementation, and a roadmap for upgrading the pre-filter logic — grounded in both current needs and future-proofing considerations.

---

## 🎯 Why Pre-filtering is Necessary

From both theoretical and implementation perspectives, pre-filtering serves four critical goals:

- **Efficiency**: Skip over irrelevant packets early to conserve CPU cycles.
- **Precision**: Avoid contaminating entropy and behavioral stats with unrelated protocol data.
- **Scalability**: Maintain low latency and stable memory usage at high packet rates.
- **Modularity**: Clean separation of traffic eligibility from core detection logic.

This is especially important in high-traffic environments where performance is non-negotiable.

---

## 🧪 Our Threat Model Assumptions

For version 1 of the plugin, we focused on detecting these DDoS vectors:

- **TCP**: SYN floods, Slowloris, HTTP floods
- **UDP**: Amplification and flood attacks
- **ICMP** (optional): Ping floods, smurf-style attacks

Other protocol types like ARP, ESP, GRE, or IPv6 multicast were deemed out of scope.

---

## 🔧 Current Implementation Strategy

Our current implementation pre-filters traffic within the `eval()` hook as follows:

```cpp
void DdosInspector::eval(snort::Packet* p)
{
    if (!p || p->ip_version != 4)
        return;

    if (p->proto != IPPROTO_TCP && p->proto != IPPROTO_UDP)
        return;

    stats_engine.update(p);
    behavior_tracker.analyze(p);

    if (should_block(p->ip_src))
        firewall_action.block(p->ip_src);
}
```

We assume IPv4 as the dominant protocol in most attacks and only allow TCP/UDP by default. This ensures we minimize the processing cost in the early stages.

---

## 📈 Benefits of This Design

| Benefit              | Description |
|----------------------|-------------|
| CPU Efficiency       | Lightweight packet rejection avoids costly analysis |
| Memory Stability     | Reduced queue growth and buffer pressure |
| Lower False Positives| Reduces entropy distortion and behavioral misflags |
| Performance          | Keeps CPU <5%, latency <10ms under high load |

---

## 🧠 Should It Be Upgraded?

Yes — we believe that pre-filtering should evolve. Here’s why:

### ✅ Reasons to Upgrade

1. **Evolving Attack Vectors**:
   - Future attacks might exploit ICMP, IPv6, or application-layer encapsulation.
   - Hardcoded filters risk obsolescence.

2. **Deployment Diversity**:
   - IoT networks may need to inspect more UDP.
   - Enterprises may require IPv6/ICMP handling.

3. **Adaptability**:
   - Filters should respond to traffic conditions, not remain static.
   - Runtime toggles and observability allow security teams to fine-tune detection.

---

## 🛠️ Upgrade Roadmap

| Stage | Feature | Goal |
|-------|---------|------|
| v1    | Hardcoded TCP/UDP filter | Baseline performance and safety |
| v2    | Configurable `allow_icmp` flag (YAML or CLI) | Customizable behavior |
| v3    | Prometheus metrics: `filtered_packets_by_proto` | Observability and analysis |
| v4    | Adaptive filter based on live traffic stats | Smart filtering and future-proofing |

Example configurable logic:

```cpp
if (!allow_icmp && p->proto == IPPROTO_ICMP)
    return;
```

And monitoring insight:

```cpp
prometheus::counter("filtered_non_tcpudp").inc();
```

---

## 🔬 Future Research Directions

- **Flow-aware filtering**: Automatically whitelist known safe flows (e.g., DNS).
- **Auto-tuned filters**: Adjust thresholds based on entropy trends.
- **Protocol fingerprinting**: Exclude malformed or spoofed protocol packets.

---

## ✅ Final Thoughts

The pre-filtering logic is more than a performance tweak — it is a **foundational gatekeeper** for our plugin’s detection accuracy and efficiency. It deserves to be adaptive, configurable, and observable.

Upgrading it will help us scale across different network environments, stay ahead of evolving attack surfaces, and remain scientifically rigorous in how we define "relevant traffic" for DDoS defense.