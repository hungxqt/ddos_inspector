# Multi-stage build for DDoS Inspector Plugin with enhanced production features
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
    libtcmalloc-minimal4 \
    libhyperscan-dev \
    flex \
    bison \
    && rm -rf /var/lib/apt/lists/*

# Build and install Snort 3 with optimizations
WORKDIR /tmp
RUN wget https://github.com/snort3/snort3/archive/refs/tags/3.1.74.0.tar.gz \
    && tar -xzf 3.1.74.0.tar.gz \
    && cd snort3-3.1.74.0 \
    && ./configure_cmake.sh --prefix=/usr/local/snort3 \
        --enable-tcmalloc \
        --enable-jemalloc \
        --enable-hyperscan \
    && cd build \
    && make -j$(nproc) \
    && make install

# Copy source code
WORKDIR /app
COPY . .

# Build plugin with optimizations
RUN mkdir -p build \
    && cd build \
    && cmake .. \
        -DCMAKE_BUILD_TYPE=Release \
        -DSNORT3_INCLUDE_DIR=/usr/local/snort3/include/snort \
        -DCMAKE_CXX_FLAGS="-O3 -march=native -flto" \
    && make -j$(nproc)

# Runtime stage - minimal and secure
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install only runtime dependencies
RUN apt-get update && apt-get install -y \
    nftables \
    iptables \
    iproute2 \
    libpcap0.8 \
    libboost-system1.74.0 \
    libdaq3 \
    libdnet \
    libhwloc15 \
    libluajit-5.1-2 \
    libssl3 \
    libpcre3 \
    zlib1g \
    libtcmalloc-minimal4 \
    libhyperscan5 \
    python3 \
    python3-pip \
    curl \
    jq \
    procps \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies for metrics
RUN pip3 install prometheus-client psutil

# Copy Snort 3 installation
COPY --from=builder /usr/local/snort3 /usr/local/snort3

# Create necessary directories
RUN mkdir -p /usr/local/lib/snort3_extra_plugins \
    && mkdir -p /etc/snort \
    && mkdir -p /var/log/snort \
    && mkdir -p /tmp \
    && mkdir -p /app/scripts

# Copy plugin and configuration files
COPY --from=builder /app/build/ddos_inspector.so /usr/local/lib/snort3_extra_plugins/
COPY --from=builder /app/snort_ddos_config.lua /etc/snort/
COPY --from=builder /app/scripts/ /app/scripts/
COPY --from=builder /app/Prometheus-ELK\ metrics\ dashboard/ddos_inspector_real_metrics.cpp /app/
COPY --from=builder /app/Prometheus-ELK\ metrics\ dashboard/snort_stats_exporter.py /app/

# Configure library paths and permissions
RUN echo "/usr/local/snort3/lib" > /etc/ld.so.conf.d/snort3.conf \
    && ldconfig \
    && chmod +x /app/scripts/*.sh \
    && chmod 755 /usr/local/lib/snort3_extra_plugins/ddos_inspector.so

# Create snort user for security
RUN useradd -r -s /bin/false -d /var/lib/snort snort \
    && chown -R snort:snort /var/log/snort \
    && chown snort:snort /tmp

# Setup firewall capabilities
RUN setcap cap_net_admin+ep /usr/local/snort3/bin/snort

# Add Snort to PATH
ENV PATH="/usr/local/snort3/bin:${PATH}"

# Expose ports
EXPOSE 9091 9092 8080

# Add health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD snort --version && [ -f /tmp/ddos_inspector_stats ] || exit 1

# Add entrypoint script
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Set working directory
WORKDIR /app

# Use non-root user for security (when not requiring network privileges)
# USER snort

# Default command
ENTRYPOINT ["/entrypoint.sh"]
CMD ["snort", "-c", "/etc/snort/snort_ddos_config.lua", "-i", "eth0", "-A", "alert_fast"]