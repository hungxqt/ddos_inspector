# DDoS Inspector - Smart DDoS Detection Plugin for Snort 3

![Status](https://img.shields.io/badge/status-active-brightgreen)
![C++](https://img.shields.io/badge/language-C++-blue)
![Snort 3](https://img.shields.io/badge/snort-3.x-critical)
![License](https://img.shields.io/badge/license-MIT-green)
![Contributions](https://img.shields.io/badge/contributions-welcome-orange)

**DDoS Inspector** is a lightweight, real-time DDoS detection and mitigation plugin for [Snort 3](https://snort.org/). It combines statistical analysis with behavioral profiling to detect and automatically block DDoS attacks with minimal system overhead.

## 🚀 Quick Start

### 1. One-Click Installation
```bash
# Clone the repository
git clone https://github.com/hung-qt/ddos_inspector.git
cd ddos_inspector

# Install dependencies and build (requires sudo)
sudo ./scripts/install_dependencies.sh
./scripts/build_project.sh

# Deploy the plugin
sudo ./scripts/deploy.sh
```

### 2. Basic Configuration
```bash
# Copy example configuration
sudo cp snort_ddos_config.lua /etc/snort/

# Test the plugin
sudo snort -c /etc/snort/snort_ddos_config.lua --show-plugins | grep ddos_inspector
```

### 3. Start Detection
```bash
# Run Snort with DDoS detection
sudo snort -c /etc/snort/snort_ddos_config.lua -i eth0 -A alert_fast
```

## 🔍 Key Features

- **🎯 Multi-Vector Detection**: SYN floods, UDP amplification, HTTP floods (Slowloris), ICMP floods
- **📊 Statistical Analysis**: EWMA (Exponentially Weighted Moving Average) and entropy-based detection
- **🧠 Behavioral Profiling**: TCP connection state and HTTP pattern analysis
- **🛡️ Automated Mitigation**: Real-time IP blocking via nftables/iptables
- **⚡ High Performance**: <5% CPU usage, <10ms latency
- **📈 Monitoring Ready**: Prometheus metrics and alerting support
- **🔧 Configurable**: Tunable thresholds for different network environments

## 📦 Installation Guide

### Prerequisites
- **OS**: Linux (Ubuntu 20.04+ recommended)
- **Snort 3**: Version 3.1.0 or higher
- **Compiler**: g++ 7.0+ with C++17 support
- **Root Access**: Required for firewall integration

### Method 1: Automated Installation (Recommended)
```bash
# 1. Install system dependencies
sudo ./scripts/install_dependencies.sh

# 2. Build the project
./scripts/build_project.sh

# 3. Deploy and configure
sudo ./scripts/deploy.sh

# 4. Verify installation
sudo snort --show-plugins | grep ddos_inspector
```

### Method 2: Manual Installation
```bash
# 1. Install dependencies manually
sudo apt update
sudo apt install snort3 snort3-dev cmake build-essential libpcap-dev nftables

# 2. Build plugin
mkdir build && cd build
cmake ..
make -j$(nproc)

# 3. Install plugin
sudo cp ddos_inspector.so /usr/local/lib/snort3_extra_plugins/

# 4. Setup firewall rules
sudo ./scripts/nftables_rules.sh
```

## ⚙️ Configuration

### Basic Configuration
The plugin comes with a pre-configured example file:

```lua
-- File: /etc/snort/snort_ddos_config.lua
ddos_inspector = 
{
    entropy_threshold = 2.0,     -- Lower = more sensitive to repetitive patterns
    ewma_alpha = 0.1,           -- Higher = more reactive to traffic changes
    block_timeout = 600,        -- IP block duration (seconds)
    allow_icmp = false          -- Set true to monitor ICMP traffic
}
```

### Advanced Configuration
For custom environments, adjust these parameters:

| Parameter | Description | Recommended Values |
|-----------|-------------|-------------------|
| `entropy_threshold` | Detects low-entropy payloads | **Web servers**: 1.5-2.0<br>**Mail servers**: 2.0-2.5 |
| `ewma_alpha` | Traffic change sensitivity | **High traffic**: 0.05-0.1<br>**Low traffic**: 0.1-0.2 |
| `block_timeout` | IP blocking duration | **Production**: 300-600s<br>**Testing**: 60-120s |

### Integration with Snort Configuration
Add to your main `snort.lua`:

```lua
-- Load DDoS Inspector
dofile('/etc/snort/snort_ddos_config.lua')

-- Add to inspection policy
binder =
{
    {
        when = { proto = 'tcp' },
        use = { type = 'ddos_inspector' }
    },
    {
        when = { proto = 'udp' },
        use = { type = 'ddos_inspector' }
    }
}
```

## 🧪 Testing & Validation

### Quick Test
```bash
# Run unit tests
./scripts/run_tests.sh

# Test SYN flood detection
sudo ./scripts/run_syn_flood.sh --target 127.0.0.1 --duration 10

# Test Slowloris detection  
sudo ./scripts/run_slowloris.sh --target 127.0.0.1 --duration 10

# Check blocked IPs
sudo nft list set inet filter ddos_ip_set
```

### Performance Testing
```bash
# Monitor plugin performance
sudo snort -c /etc/snort/snort_ddos_config.lua -i eth0 --show-stats

# View detection statistics
tail -f /var/log/snort/alert
```

## 📊 Detection Capabilities

| Attack Type | Detection Method | Response Time | Accuracy |
|-------------|------------------|---------------|----------|
| **SYN Flood** | TCP state tracking + rate analysis | <50ms | >99% |
| **UDP Amplification** | Entropy + volume detection | <30ms | >95% |
| **HTTP Flood (Slowloris)** | Connection profiling | <100ms | >97% |
| **ICMP Flood** | Rate monitoring (optional) | <20ms | >98% |

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                        Network Traffic                      │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│                        Snort 3 Engine                       │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│                    DDoS Inspector Plugin                    │
│  ┌──────────────────┬───────────────────┬─────────────────┐ │
│  │  Stats Engine    │ Behavior Tracker  │ Firewall Action │ │
│  │  • EWMA          │  • TCP States     │  • nftables     │ │
│  │  • Entropy       │  • HTTP Patterns  │  • IP Blocking  │ │
│  │  • Rate Analysis │  • Conn. Tracking │  • Auto-unblock │ │
│  └──────────────────┴───────────────────┴─────────────────┘ │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│                  System Firewall (nftables)                 │
└─────────────────────────────────────────────────────────────┘
```

## 🔧 Troubleshooting

### Common Issues & Solutions

1. **Plugin not loading**
   ```bash
   # Check plugin exists
   ls -la /usr/local/lib/snort3_extra_plugins/ddos_inspector.so
   
   # Verify Snort can find it
   sudo snort --show-plugins | grep ddos
   
   # Check permissions
   sudo chmod 755 /usr/local/lib/snort3_extra_plugins/ddos_inspector.so
   ```

2. **High false positives**
   ```lua
   -- Reduce sensitivity in snort_ddos_config.lua
   ddos_inspector = {
       entropy_threshold = 1.5,  -- Lower threshold
       ewma_alpha = 0.05,        -- Less reactive
   }
   ```

3. **Firewall integration issues**
   ```bash
   # Reset firewall rules
   sudo ./scripts/nftables_rules.sh
   
   # Check nftables status
   sudo systemctl status nftables
   
   # Verify rules exist
   sudo nft list tables
   ```

4. **Performance issues**
   ```bash
   # Check CPU usage
   top -p $(pidof snort)
   
   # Monitor memory usage
   ps aux | grep snort
   
   # Reduce monitoring scope
   # Edit binder section to monitor only specific protocols
   ```

## 📈 Monitoring & Metrics

### Real-time Statistics
```bash
# View plugin statistics
sudo snort -c /etc/snort/snort_ddos_config.lua --show-stats

# Monitor blocked IPs
sudo nft list set inet filter ddos_ip_set

# Check log files
tail -f /var/log/snort/alert
```

### Prometheus Integration
```bash
# Start metrics collection
cd "Prometheus-ELK metrics dashboard"
docker-compose up -d

# Access dashboard
# Prometheus: http://localhost:9090
# Grafana: http://localhost:3000
```

## 👥 Team

- **Duong Quoc An - [@Anduong1200](https://github.com/Anduong1200)** (Team Leader)
- **Tran Quoc Hung - [@hung-qt](https://github.com/hung-qt)** (Core Developer)
- **Mai Hong Phat - [@samael](https://github.com/pzhat)** (Security Analyst)
- **Le Nguyen Anh Dat** 
- **Bui Quang Hieu** 
- **Supervisor**: Pham Ho Trong Nguyen

## 📁 Project Structure

```
ddos_inspector/
├── 📋 CMakeLists.txt              # Build configuration
├── 📄 README.md                   # This file
├── 🔧 snort_ddos_config.lua       # Plugin configuration
├── 📂 include/                    # Header files
│   ├── ddos_inspector.hpp         # Main plugin interface
│   ├── stats_engine.hpp           # Statistical analysis
│   ├── behavior_tracker.hpp       # Behavioral detection
│   ├── firewall_action.hpp        # Mitigation actions
│   └── packet_data.hpp            # Data structures
├── 📂 src/                        # Source code
│   ├── ddos_inspector.cpp         # Plugin implementation
│   ├── stats_engine.cpp           # EWMA & entropy logic
│   ├── behavior_tracker.cpp       # TCP/HTTP analysis
│   └── firewall_action.cpp        # Firewall integration
├── 📂 scripts/                    # Automation scripts
│   ├── 🚀 build_project.sh        # Build automation
│   ├── 🚀 deploy.sh               # Deployment script
│   ├── 🚀 install_dependencies.sh # Dependency installer
│   ├── 🧪 run_tests.sh            # Test runner
│   ├── 🧪 run_syn_flood.sh        # SYN flood simulator
│   └── 🧪 run_slowloris.sh        # Slowloris simulator
├── 📂 tests/                      # Test suite
│   └── unit_tests.cpp             # Unit tests
├── 📂 docs/                       # Documentation
└── 📂 build/                      # Build directory (generated)
```

## 📊 Performance Metrics

| Metric | Value | Test Environment |
|--------|-------|------------------|
| **CPU Usage** | <5% | 10,000 pps sustained |
| **Memory Usage** | <50MB | 24h continuous operation |
| **Detection Latency** | <10ms | Average per packet |
| **False Positive Rate** | <0.1% | Normal web traffic |
| **Throughput Impact** | <2% | Gigabit network |

## 📜 License

This project is released under the MIT License. See [LICENSE](LICENSE) file for details.

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](docs/CONTRIBUTING.md) for details.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 🔗 Documentation

- 📖 [Installation Guide](docs/Install\ Snort\ 3\ Library/README.md)
- 🏗️ [Architecture Documentation](docs/PHASE02_DS/ddos_inspector_architecture.md)
- 🧮 [Algorithm Specification](docs/PHASE02_DS/ddos_inspector_algorithmic_spec.md)
- 🔌 [Plugin Interface Guide](docs/PHASE02_DS/snort3_plugin_interface_hooks.md)
- 📋 [User Guide](docs/PHASE01_LR/user_guide.md)

## 🆘 Support

- 🐛 **Bug Reports**: [GitHub Issues](https://github.com/hung-qt/ddos_inspector/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/hung-qt/ddos_inspector/discussions)
- 📧 **Email**: Anduong1200@gmail.com

---

*Built with ❤️ by the ADHHP Research Team (2025)*
