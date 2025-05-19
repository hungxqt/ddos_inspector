# Understanding Snort 3 Plugin Interface and Hook

As researchers developing a custom DDoS detection module (`ddos_inspector`), we worked deeply with the Snort 3 modular API. To integrate our logic efficiently and cleanly into Snort, we leveraged its **plugin interface** and **plugin hook** system — two fundamental concepts that enable extensibility in Snort 3.

---

## 🔍 What We Mean by Plugin Interface and Hook

| Concept | Explanation |
|---------|-------------|
| **Plugin Interface** | A C++ interface that defines how our plugin interacts with Snort. We implement this interface (e.g., `Inspector`) to inject our logic into the Snort pipeline. |
| **Plugin Hook** | A specific function (like `eval()` or `show_stats()`) that Snort automatically calls at different points during packet processing. We hook into these to run our detection logic. |

---

## 🔧 Why We Use This Architecture

Snort 3’s modular plugin architecture allows us to:
- Isolate our logic without modifying Snort core
- Keep the system lightweight and testable
- Integrate detection and mitigation directly into the processing path

This approach is similar to how plugins work in Nginx, Wireshark, or LLVM — giving us a robust foundation for experimentation and innovation.

---

## 🧱 Plugin Interface Classes We Used

We implemented the `Inspector` interface, since our goal was to analyze live packets and apply mitigation.

Other available interfaces in Snort include:

| Interface Class | Role |
|------------------|------|
| `Inspector`      | Inspects packets (used in `ddos_inspector`) |
| `Logger`         | Logs traffic or alerts |
| `Detector`       | Evaluates rule-based conditions |
| `AppId`, `Analyzer` | Application-layer or protocol detection |

```cpp
#include <snort/inspector.h>

class DdosInspector : public snort::Inspector
{
public:
    void eval(snort::Packet* p) override;
    void show_stats(std::ostream& os) override;
};
```

---

## 🔁 Hooks We Defined

We implemented several key hooks in our plugin:

| Hook Function    | Purpose |
|------------------|---------|
| `eval(Packet*)`  | Runs for every packet — where we applied EWMA, entropy, and behavioral analysis |
| `configure()`    | Used to load detection thresholds, timeouts, and other parameters |
| `show_stats()`   | Exported Prometheus metrics for monitoring |
| `shutdown()`     | Cleaned up allocated resources on exit |

```cpp
void DdosInspector::eval(snort::Packet* p)
{
    if (!is_tcp_or_udp(p))
        return;

    stats_engine.update(p);
    behavior_tracker.analyze(p);

    if (should_block(p->ip_src))
        firewall_action.block(p->ip_src);
}

void DdosInspector::show_stats(std::ostream& os)
{
    os << "Current EWMA: " << stats_engine.get_ewma() << "\n";
    os << "Entropy: " << stats_engine.get_entropy() << "\n";
    os << "Blocked IPs: " << firewall_action.count() << "\n";
}
```

---

## 🔬 How Snort Executes Our Plugin

Here’s the lifecycle that Snort follows with our plugin:

1. Snort starts → calls `SnortPluginLoad()`
2. We register `ddos_inspector` using `register_inspector`
3. For each packet:
   - Snort calls our `eval(Packet*)`
   - We process and analyze the packet
4. Periodically → Snort calls `show_stats()` for our metrics
5. On shutdown → `shutdown()` is triggered for cleanup

```cpp
extern "C" SnortPlugin* SnortPluginLoad()
{
    static SnortPlugin plugin = {
        SNORT_PLUGIN_MAGIC,
        SNORT_VERSION,
        SnortPlugin::INSPECTOR,
        "ddos_inspector",
        "DDoS Detection Plugin",
        nullptr, nullptr, nullptr, nullptr,
        nullptr, nullptr, nullptr, nullptr
    };

    snort::register_inspector<DdosInspector>("ddos_inspector");
    return &plugin;
}
```

---

## 📌 Why This Matters to Us as Researchers

| Benefit	          | Impact |
|---------------------|--------|
| Modularity	          | We developed and tested `ddos_inspector` without altering other Snort components |
| Low Overhead         | Everything ran inline, avoiding the resource cost of ML-based systems |
| Precision Control    | We could implement fallback mechanisms, switching to TAP mode or Snort’s rule-based engine if precision dropped |
| Real-Time Capability | Detection and mitigation completed in under 10 ms — critical for stopping live DDoS attacks |
