# Multi-stage build for DDoS Inspector Plugin
FROM ubuntu:22.04 AS builder

# Avoid interactive prompts during build
ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    wget \
    pkg-config \
    libpcap-dev \
    libboost-all-dev \
    libdaq-dev \
    libdnet-dev \
    libhwloc-dev \
    libluajit-5.1-dev \
    libssl-dev \
    libpcre3-dev \
    zlib1g-dev \
    gcc-12 \
    g++-12 \
    && rm -rf /var/lib/apt/lists/*

# Build and install Snort 3
WORKDIR /tmp
RUN wget https://github.com/snort3/snort3/archive/refs/tags/3.1.74.0.tar.gz \
    && tar -xzf 3.1.74.0.tar.gz \
    && cd snort3-3.1.74.0 \
    && ./configure_cmake.sh --prefix=/usr/local/snort3 --enable-tcmalloc \
    && cd build \
    && make -j$(nproc) \
    && make install

# Copy source code
WORKDIR /app
COPY . .

# Build plugin
RUN mkdir -p build \
    && cd build \
    && cmake .. \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_C_COMPILER=gcc-12 \
        -DCMAKE_CXX_COMPILER=g++-12 \
        -DSNORT3_INCLUDE_DIR=/usr/local/snort3/include/snort \
        -DCMAKE_CXX_FLAGS="-O3 -flto" \
    && make -j$(nproc) ddos_inspector

# Runtime stage
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    nftables \
    iptables \
    libpcap0.8 \
    libboost-system1.74.0 \
    libdaq3 \
    libdnet \
    libhwloc15 \
    libluajit-5.1-2 \
    libssl3 \
    libpcre3 \
    zlib1g \
    python3 \
    python3-pip \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Snort 3 runtime
COPY --from=builder /usr/local/snort3 /usr/local/snort3

# Create plugin directory
RUN mkdir -p /usr/local/lib/snort3_extra_plugins

# Copy plugin and configuration
COPY --from=builder /app/build/ddos_inspector.so /usr/local/lib/snort3_extra_plugins/
COPY --from=builder /app/snort_ddos_config.lua /etc/snort/
COPY --from=builder /app/scripts/ /usr/local/bin/

# Configure library paths
RUN echo "/usr/local/snort3/lib" > /etc/ld.so.conf.d/snort3.conf \
    && ldconfig

# Setup firewall rules
RUN chmod +x /usr/local/bin/*.sh \
    && /usr/local/bin/nftables_rules.sh

# Create snort user
RUN useradd -r -s /bin/false snort

# Expose ports for monitoring
EXPOSE 9090 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD /usr/local/snort3/bin/snort --version || exit 1

# Default command
CMD ["/usr/local/snort3/bin/snort", "-c", "/etc/snort/snort_ddos_config.lua", "-i", "eth0", "-A", "alert_fast"]