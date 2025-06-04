# Multi-stage build for DDoS Inspector Plugin with enhanced production features
FROM ubuntu:24.04 AS builder

# Avoid interactive prompts during build
ENV DEBIAN_FRONTEND=noninteractive

# Install comprehensive build dependencies for latest Snort 3.8.1.0
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    wget \
    curl \
    pkg-config \
    libpcap-dev \
    libboost-all-dev \
    libdumbnet-dev \
    libhwloc-dev \
    libluajit-5.1-dev \
    libssl-dev \
    libpcre3-dev \
    libpcre2-dev \
    zlib1g-dev \
    libtcmalloc-minimal4 \
    libgoogle-perftools-dev \
    libhyperscan-dev \
    liblzma-dev \
    uuid-dev \
    flex \
    bison \
    autoconf \
    automake \
    libtool \
    ninja-build \
    ccache \
    && rm -rf /var/lib/apt/lists/*

# Setup ccache for faster rebuilds
ENV PATH="/usr/lib/ccache:$PATH"
ENV CCACHE_DIR="/tmp/ccache"
RUN mkdir -p /tmp/ccache

# Create symlinks for TCMalloc to help CMake find it
RUN ln -sf /usr/lib/x86_64-linux-gnu/libtcmalloc_minimal.so.4 /usr/lib/x86_64-linux-gnu/libtcmalloc.so \
    && ln -sf /usr/lib/x86_64-linux-gnu/libtcmalloc_minimal.a /usr/lib/x86_64-linux-gnu/libtcmalloc.a

# Build and install DAQ 3.0.19+ (required for Snort 3.8.1.0)
WORKDIR /tmp
RUN wget https://github.com/snort3/libdaq/archive/refs/tags/v3.0.19.tar.gz \
    && tar -xzf v3.0.19.tar.gz \
    && cd libdaq-3.0.19 \
    && ./bootstrap \
    && ./configure --prefix=/usr/local \
        --enable-static-modules \
    && make -j$(nproc) \
    && make install \
    && ldconfig \
    && cd /usr/local/lib \
    && if [ -f libdaq.so.3.0.19 ] && [ ! -L libdaq.so.3 ]; then \
           rm -f libdaq.so.3 && ln -sf libdaq.so.3.0.19 libdaq.so.3; \
       fi \
    && if [ -f libdaq.so.3.0.19 ] && [ ! -L libdaq.so ]; then \
           rm -f libdaq.so && ln -sf libdaq.so.3.0.19 libdaq.so; \
       fi \
    && ldconfig

# Build and install Snort 3.8.1.0 with optimized configuration
RUN wget https://github.com/snort3/snort3/archive/refs/tags/3.8.1.0.tar.gz \
    && tar -xzf 3.8.1.0.tar.gz \
    && cd snort3-3.8.1.0 \
    && export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH \
    && export CPPFLAGS="-I/usr/local/include" \
    && export LDFLAGS="-L/usr/local/lib -L/usr/lib/x86_64-linux-gnu" \
    && export TCMALLOC_LIBRARIES="/usr/lib/x86_64-linux-gnu/libtcmalloc_minimal.so" \
    && export TCMALLOC_INCLUDE_DIR="/usr/include/google" \
    && ./configure_cmake.sh --prefix=/usr/local/snort3 \
        --enable-tcmalloc \
        --enable-static-daq \
        --enable-large-pcap \
        --enable-debug-msgs \
        --enable-shell \
        --with-daq-includes=/usr/local/include \
        --with-daq-libraries=/usr/local/lib \
    && cd build \
    && make -j$(nproc) \
    && make install \
    || (echo "TCMalloc build failed, retrying without TCMalloc..." \
        && cd /tmp/snort3-3.8.1.0 \
        && rm -rf build \
        && export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH \
        && export CPPFLAGS="-I/usr/local/include" \
        && export LDFLAGS="-L/usr/local/lib" \
        && ./configure_cmake.sh --prefix=/usr/local/snort3 \
            --enable-static-daq \
            --enable-large-pcap \
            --enable-debug-msgs \
            --enable-shell \
            --with-daq-includes=/usr/local/include \
            --with-daq-libraries=/usr/local/lib \
        && cd build \
        && make -j$(nproc) \
        && make install)

# Copy source code
WORKDIR /app
COPY . .

# Clean any existing build directory and cache to prevent path conflicts
RUN rm -rf build/

# Build plugin with enhanced optimizations for Snort 3.8.1.0
RUN mkdir -p build \
    && cd build \
    && cmake .. \
        -DCMAKE_BUILD_TYPE=Release \
        -DSNORT3_INCLUDE_DIR=/usr/local/snort3/include/snort \
        -DCMAKE_CXX_FLAGS="-O3 -march=native -flto -fPIC" \
        -DCMAKE_SHARED_LINKER_FLAGS="-Wl,--as-needed -Wl,--gc-sections" \
        -GNinja \
    && ninja -j$(nproc) \
    && cd .. \
    && ./scripts/build_project.sh

# Runtime stage - minimal and secure
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Install comprehensive runtime dependencies (fixed package versions)
RUN apt-get update && apt-get install -y \
    nftables \
    iptables \
    iproute2 \
    libpcap0.8 \
    libboost-system1.83.0 \
    libboost-filesystem1.83.0 \
    libboost-thread1.83.0 \
    libdumbnet1 \
    libhwloc15 \
    libluajit-5.1-2 \
    libssl3t64 \
    libpcre3 \
    libpcre2-8-0 \
    zlib1g \
    libtcmalloc-minimal4 \
    libhyperscan5 \
    liblzma5 \
    uuid-runtime \
    libunwind8 \
    libnuma1 \
    python3 \
    python3-pip \
    curl \
    jq \
    procps \
    net-tools \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install enhanced Python dependencies for metrics
RUN pip3 install --no-cache-dir --break-system-packages \
    prometheus-client==0.21.0 \
    psutil==6.1.0 \
    pyyaml==6.0.1 \
    requests==2.32.3

# Copy DAQ library and headers from builder
COPY --from=builder /usr/local/lib/libdaq* /usr/local/lib/
COPY --from=builder /usr/local/include/daq* /usr/local/include/
COPY --from=builder /usr/local/lib/pkgconfig/libdaq* /usr/local/lib/pkgconfig/

# Copy Snort 3 installation
COPY --from=builder /usr/local/snort3 /usr/local/snort3

# Create necessary directories with proper permissions - FIX DAQ DIRECTORY ISSUE
RUN mkdir -p /usr/local/lib/snort3_extra_plugins \
    && mkdir -p /usr/local/lib/daq \
    && mkdir -p /etc/snort \
    && mkdir -p /var/log/snort \
    && mkdir -p /tmp \
    && mkdir -p /app/scripts \
    && mkdir -p /app/config \
    && cd /usr/local/lib \
    && if [ -f libdaq.so.3.0.19 ] && [ ! -L libdaq.so.3 ]; then \
           rm -f libdaq.so.3 && ln -sf libdaq.so.3.0.19 libdaq.so.3; \
       fi \
    && if [ -f libdaq.so.3.0.19 ] && [ ! -L libdaq.so ]; then \
           rm -f libdaq.so && ln -sf libdaq.so.3.0.19 libdaq.so; \
       fi

# Copy plugin and configuration files from release folder
COPY --from=builder /app/release/libddos_inspector.so /usr/local/lib/snort3_extra_plugins/
COPY --from=builder /app/release/libddos_core.a /usr/local/lib/
COPY --from=builder /app/release/snort_ddos_config.lua /etc/snort/
COPY --from=builder /app/release/BUILD_INFO.txt /app/
COPY --from=builder /app/scripts/ /app/scripts/
COPY --from=builder /app/prometheus-elk-metrics/ /app/metrics/

# Configure library paths and permissions
RUN echo "/usr/local/snort3/lib" > /etc/ld.so.conf.d/snort3.conf \
    && echo "/usr/local/lib" >> /etc/ld.so.conf.d/snort3.conf \
    && ldconfig \
    && chmod +x /app/scripts/*.sh \
    && chmod 755 /usr/local/lib/snort3_extra_plugins/libddos_inspector.so

# Create snort user for security
RUN useradd -r -s /bin/false -d /var/lib/snort snort \
    && chown -R snort:snort /var/log/snort \
    && chown snort:snort /tmp

# Setup firewall capabilities and security
RUN setcap cap_net_admin+ep /usr/local/snort3/bin/snort \
    && setcap cap_net_raw+ep /usr/local/snort3/bin/snort

# Add Snort to PATH with priority
ENV PATH="/usr/local/snort3/bin:${PATH}"
ENV LD_LIBRARY_PATH="/usr/local/snort3/lib:/usr/local/lib"

# Expose ports for metrics and management
EXPOSE 9091 9092 8080

# Enhanced health check with version verification
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD snort --version 2>&1 | grep -q "Version 3.8.1.0" && \
        [ -f /tmp/ddos_inspector_stats ] && \
        [ -f /usr/local/lib/snort3_extra_plugins/libddos_inspector.so ] || exit 1

# Add entrypoint script
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Set working directory
WORKDIR /app

# Default command with enhanced configuration - made interface configurable
ENTRYPOINT ["/entrypoint.sh"]