#!/bin/bash
# DDoS Inspector - System Dependencies Installation Script
# This script installs all required dependencies for the DDoS Inspector

set -e

# Get script directory and source common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source common functions library
source "$SCRIPT_DIR/common_functions.sh"

# Function to show help
show_help() {
    echo "DDoS Inspector - System Dependencies Installation Script"
    echo "======================================================="
    echo ""
    echo "USAGE:"
    echo "  $0 [OPTIONS]"
    echo ""
    echo "OPTIONS:"
    echo "  -h, --help         Show this help message"
    echo "  --uninstall        Uninstall all dependencies and configurations"
    echo ""
    echo "DESCRIPTION:"
    echo "  This script installs all required system dependencies for the DDoS Inspector,"
    echo "  including build tools, Docker, nftables, and development libraries."
    echo ""
    echo "EXAMPLES:"
    echo "  $0                 # Install all dependencies"
    echo "  $0 --uninstall     # Uninstall all dependencies"
    echo ""
    echo "NOTE:"
    echo "  This script requires root privileges for installation/uninstallation."
    echo "  Help can be displayed without root privileges."
}

# Parse command line arguments for help first
for arg in "$@"; do
    case $arg in
        -h|--help)
            show_help
            exit 0
            ;;
    esac
done

print_info "DDoS Inspector - Installing System Dependencies"
echo "=================================================="

# Parse command line arguments for uninstall
if [ "$1" = "--uninstall" ]; then
    check_root_privileges
    uninstall_dependencies
    exit 0
fi

check_root_privileges

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$NAME
    VER=$VERSION_ID
else
    print_error "Cannot detect OS. This script supports Ubuntu/Debian systems."
    exit 1
fi

print_success "Detected OS: $OS $VER"

# Function to clone only if directory doesn't exist or is empty
safe_git_clone() {
    REPO_URL=$1
    TARGET_DIR=$2
    if [ -d "$TARGET_DIR" ]; then
        if [ -z "$(ls -A "$TARGET_DIR")" ]; then
            print_info "Directory '$TARGET_DIR' exists but is empty. Cloning..."
            git clone "$REPO_URL" "$TARGET_DIR"
        else
            print_status "Skipping clone: '$TARGET_DIR' already exists and is not empty."
        fi
    else
        print_info "Cloning into '$TARGET_DIR'..."
        git clone "$REPO_URL" "$TARGET_DIR"
    fi
}

# Function to uninstall all dependencies and configurations
uninstall_dependencies() {
    print_error "DDoS Inspector - Uninstalling System Dependencies"
    echo "===================================================="
    
    print_warning "This will remove packages that may be used by other applications!"
    echo "   The following will be removed:"
    echo "   • Build tools and development libraries"
    echo "   • Docker and Docker Compose"
    echo "   • nftables (firewall will be disabled)"
    echo "   • Network testing tools"
    echo "   • System user and configurations"
    echo ""
    
    read -p "Are you sure you want to continue? (type 'yes' to confirm): " -r
    if [ "$REPLY" != "yes" ]; then
        print_error "Uninstall cancelled"
        exit 1
    fi
    
    print_info "Stopping and disabling services..."
    
    # Stop and disable DDoS Inspector service
    systemctl stop ddos-inspector 2>/dev/null || true
    systemctl disable ddos-inspector 2>/dev/null || true
    
    # Stop and disable Docker
    systemctl stop docker 2>/dev/null || true
    systemctl disable docker 2>/dev/null || true
    
    # Stop and disable nftables
    systemctl stop nftables 2>/dev/null || true
    systemctl disable nftables 2>/dev/null || true
    
    print_info "Removing Docker and containers..."
    
    # Remove all Docker containers, images, and volumes
    if command -v docker &> /dev/null; then
        docker stop $(docker ps -aq) 2>/dev/null || true
        docker rm $(docker ps -aq) 2>/dev/null || true
        docker rmi $(docker images -q) 2>/dev/null || true
        docker volume rm $(docker volume ls -q) 2>/dev/null || true
        docker network rm $(docker network ls -q) 2>/dev/null || true
    fi
    
    # Remove Docker packages
    apt-get remove --purge -y \
        docker-ce \
        docker-ce-cli \
        containerd.io \
        docker-buildx-plugin \
        docker-compose-plugin 2>/dev/null || true
    
    # Remove Docker Compose standalone
    rm -f /usr/local/bin/docker-compose
    
    print_info "Removing build tools and libraries..."
    
    # Remove development packages (be careful - these might be needed by other software)
    apt-get remove --purge -y \
        build-essential \
        cmake \
        gcc \
        g++ \
        autoconf \
        libtool \
        libpcap-dev \
        libpcre2-dev \
        zlib1g-dev \
        pkg-config \
        bison \
        libssl-dev \
        libhwloc-dev \
        flex \
        libluajit-5.1-dev \
        check \
        libc6-dev \
        liblzma-dev \
        libcurl4-openssl-dev \
        libjson-c-dev \
        libconfig-dev \
        libarchive-dev \
        libsqlite3-dev \
        uuid-dev \
        libffi-dev \
        libreadline-dev 2>/dev/null || true
    
    print_info "Removing network tools..."
    
    # Remove network testing tools
    apt-get remove --purge -y \
        nftables \
        hping3 \
        nmap \
        tcpdump \
        wireshark-common \
        iptraf-ng \
        htop \
        iftop \
        nethogs 2>/dev/null || true
    
    print_info "Removing compiled dependencies..."
    
    # Remove compiled dependencies
    rm -rf /opt/googletest
    rm -rf /opt/libdaq
    rm -rf /opt/libdnet
    rm -rf /opt/luajit-2.0
    
    # Remove custom CMake if installed
    if [ -f /usr/local/bin/cmake ] && [ ! -f /usr/bin/cmake ]; then
        rm -rf /usr/local/bin/cmake
        rm -rf /usr/local/share/cmake*
    fi
    
    # Remove custom OpenSSL if installed
    if [ -f /usr/local/bin/openssl ] && [ ! -f /usr/bin/openssl ]; then
        rm -rf /usr/local/ssl
        rm -rf /usr/local/lib/libssl*
        rm -rf /usr/local/lib/libcrypto*
        rm -rf /usr/local/include/openssl
    fi
    
    print_info "Removing system configurations..."
    
    # Remove system user
    if id "ddos-inspector" &>/dev/null; then
        userdel -r ddos-inspector 2>/dev/null || true
        print_success "Removed ddos-inspector user"
    fi
    
    # Remove log rotation
    rm -f /etc/logrotate.d/ddos-inspector
    
    # Remove systemd service files
    rm -f /etc/systemd/system/ddos-inspector.service
    systemctl daemon-reload
    
    # Remove Docker repository and keys
    rm -f /etc/apt/sources.list.d/docker.list
    rm -f /usr/share/keyrings/docker-archive-keyring.gpg
    
    print_info "Cleaning up packages..."
    
    # Clean up unused packages
    apt-get autoremove --purge -y
    apt-get autoclean
    
    # Update library cache
    ldconfig
    
    echo ""
    print_success "Dependencies uninstall completed!"
    echo ""
    echo -e "${CYAN}[SUMMARY] Removed Components:${NC}"
    echo -e "${GREEN}    [REMOVED] Build Tools (GCC, CMake, Make)${NC}"
    echo -e "${GREEN}    [REMOVED] Snort 3 Dependencies (libdaq, libdnet, LuaJIT)${NC}"
    echo -e "${GREEN}    [REMOVED] Development Libraries (OpenSSL, PCAP, PCRE2)${NC}"
    echo -e "${GREEN}    [REMOVED] Testing Framework (Google Test)${NC}"
    echo -e "${GREEN}    [REMOVED] Docker & Docker Compose${NC}"
    echo -e "${GREEN}    [REMOVED] nftables firewall${NC}"
    echo -e "${GREEN}    [REMOVED] Network testing tools${NC}"
    echo -e "${GREEN}    [REMOVED] System user (ddos-inspector)${NC}"
    echo -e "${GREEN}    [REMOVED] System configurations${NC}"
    echo ""
    print_warning "Some base system packages may have been kept to avoid breaking other software."
    print_info "You may want to reboot the system to ensure all changes take effect."
}

# Update package manager
print_info "Updating package manager..."
apt-get update

# Install essential build tools and Snort 3 dependencies
print_info "Installing essential build tools and Snort 3 dependencies..."
apt-get install -y \
    build-essential \
    git \
    autoconf \
    libtool \
    libpcap-dev \
    libpcre2-dev \
    zlib1g-dev \
    pkg-config \
    bison \
    libssl-dev \
    libhwloc-dev \
    curl \
    flex \
    g++ \
    libluajit-5.1-dev \
    check \
    cmake \
    gcc \
    make \
    libc6-dev \
    liblzma-dev \
    wget \
    apt-transport-https \
    ca-certificates \
    gnupg \
    lsb-release \
    software-properties-common \
    jq \
    net-tools \
    iproute2

# Check and upgrade CMake if older than 3.16.0
print_info "Checking CMake version..."
CMAKE_VERSION=$(cmake --version | grep -oP '\d+\.\d+\.\d+' | head -1)
REQUIRED_CMAKE_VERSION="3.16.0"
if dpkg --compare-versions "$CMAKE_VERSION" lt "$REQUIRED_CMAKE_VERSION"; then
    print_info "CMake too old ($CMAKE_VERSION < $REQUIRED_CMAKE_VERSION), installing newer version..."
    cd /tmp
    curl -LO https://github.com/Kitware/CMake/releases/download/v3.30.5/cmake-3.30.5.tar.gz
    tar -xzvf cmake-3.30.5.tar.gz
    cd cmake-3.30.5
    ./bootstrap && make -j"$(nproc)" && make install
    print_success "CMake upgraded to 3.30.5"
else
    print_success "CMake version $CMAKE_VERSION is sufficient"
fi

# Check g++ version for C++20 support
print_info "Checking g++ version for C++20 support..."
GPP_VERSION=$(g++ -dumpversion)
REQUIRED_GPP_MAJOR=10
if [[ ${GPP_VERSION%%.*} -lt $REQUIRED_GPP_MAJOR ]]; then
    print_info "g++ too old (version $GPP_VERSION), installing g++-12..."
    apt-get install -y g++-12
    update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-12 100
    print_success "g++ upgraded to version 12"
else
    print_success "g++ version $GPP_VERSION supports C++20"
fi

# Check and install OpenSSL from source if needed
print_info "Checking OpenSSL version..."
OPENSSL_VERSION=$(openssl version | awk '{print $2}')
REQUIRED_OPENSSL_VERSION="1.1.1"
if dpkg --compare-versions "$OPENSSL_VERSION" lt "$REQUIRED_OPENSSL_VERSION"; then
    print_info "OpenSSL too old ($OPENSSL_VERSION), installing from source..."
    cd /tmp
    curl -O https://www.openssl.org/source/openssl-1.1.1w.tar.gz
    tar -xzvf openssl-1.1.1w.tar.gz
    cd openssl-1.1.1w
    ./config
    make -j"$(nproc)"
    make install
    ldconfig
    print_success "OpenSSL upgraded to 1.1.1w"
else
    print_success "OpenSSL version $OPENSSL_VERSION is sufficient"
fi

# Build Google Test
print_info "Building Google Test..."
cd /opt
safe_git_clone https://github.com/google/googletest.git googletest
cd googletest
mkdir -p build
cd build
cmake ..
make -j"$(nproc)"
make install
print_success "Google Test installed"

# Build libdaq
print_info "Building libdaq..."
cd /opt
safe_git_clone https://github.com/snort3/libdaq.git libdaq
cd libdaq
./bootstrap
./configure
make -j"$(nproc)"
make install
print_success "libdaq installed"

# Build libdnet
print_info "Building libdnet..."
cd /opt
safe_git_clone https://github.com/dugsong/libdnet.git libdnet
cd libdnet
./configure
make -j"$(nproc)"
make install
print_success "libdnet installed"

# Build LuaJIT
print_info "Building LuaJIT..."
cd /opt
safe_git_clone https://luajit.org/git/luajit.git luajit-2.0
cd luajit-2.0
make -j"$(nproc)"
make install
print_success "LuaJIT installed"

# Install Docker if not present
if ! command -v docker &> /dev/null; then
    print_info "Installing Docker..."
    
    # Add Docker's official GPG key
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
    
    # Add Docker repository
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
    
    # Install Docker
    apt-get update
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    
    # Start and enable Docker
    systemctl start docker
    systemctl enable docker
    
    # Add current user to docker group (if not root)
    if [ "$SUDO_USER" ]; then
        usermod -aG docker "$SUDO_USER"
        print_success "Added $SUDO_USER to docker group"
    fi
    
    print_success "Docker installed successfully"
else
    print_success "Docker is already installed"
fi

# Install Docker Compose (standalone) if not available
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    print_info "Installing Docker Compose..."
    
    # Get latest version
    DOCKER_COMPOSE_VERSION=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | jq -r .tag_name)
    
    # Download and install
    curl -L "https://github.com/docker/compose/releases/download/${DOCKER_COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
    
    print_success "Docker Compose installed successfully"
else
    print_success "Docker Compose is already available"
fi

# Install nftables
if ! command -v nft &> /dev/null; then
    print_info "Installing nftables..."
    apt-get install -y nftables
    
    # Enable nftables service
    systemctl enable nftables
    systemctl start nftables
    
    print_success "nftables installed and enabled"
else
    print_success "nftables is already installed"
fi

# Install network testing tools (optional but useful)
print_info "Installing network testing tools..."
apt-get install -y \
    hping3 \
    nmap \
    tcpdump \
    wireshark-common \
    iptraf-ng \
    htop \
    iftop \
    nethogs || print_warning "Some network tools failed to install (non-critical)"

# Install additional development libraries
print_info "Installing additional development libraries..."
apt-get install -y \
    libcurl4-openssl-dev \
    libjson-c-dev \
    libconfig-dev \
    libarchive-dev \
    libsqlite3-dev \
    uuid-dev \
    libffi-dev \
    libreadline-dev || print_warning "Some development libraries failed to install (non-critical)"

# Create system user for DDoS Inspector (if not exists)
if ! id "ddos-inspector" &>/dev/null; then
    print_info "Creating ddos-inspector system user..."
    useradd -r -s /bin/false -d /opt/ddos-inspector ddos-inspector
    print_success "Created ddos-inspector system user"
else
    print_success "ddos-inspector user already exists"
fi

# Setup log rotation
print_info "Setting up log rotation..."
cat > /etc/logrotate.d/ddos-inspector << 'EOF'
/opt/ddos-inspector/logs/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    copytruncate
    su ddos-inspector ddos-inspector
}
EOF

# Setup systemd service file (template)
print_info "Creating systemd service template..."
cat > /etc/systemd/system/ddos-inspector.service << 'EOF'
[Unit]
Description=DDoS Inspector Protection Service
After=network.target docker.service
Requires=docker.service

[Service]
Type=forking
User=root
WorkingDirectory=/opt/ddos-inspector
ExecStart=/opt/ddos-inspector/scripts/deploy_host.sh --service
ExecStop=/usr/bin/docker-compose down
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Set proper permissions
chmod 644 /etc/systemd/system/ddos-inspector.service
systemctl daemon-reload

# Update library cache
print_info "Updating library cache..."
ldconfig

echo ""
print_success "All dependencies installed successfully!"
echo ""
echo -e "${CYAN}[SUMMARY] Installed Components:${NC}"
echo -e "${GREEN}    [INSTALLED] Build Tools (GCC, CMake, Make)${NC}"
echo -e "${GREEN}    [INSTALLED] Snort 3 Dependencies (libdaq, libdnet, LuaJIT)${NC}"
echo -e "${GREEN}    [INSTALLED] Development Libraries (OpenSSL, PCAP, PCRE2)${NC}"
echo -e "${GREEN}    [INSTALLED] Testing Framework (Google Test)${NC}"
echo -e "${GREEN}    [INSTALLED] Docker & Docker Compose${NC}"
echo -e "${GREEN}    [INSTALLED] nftables firewall${NC}"
echo -e "${GREEN}    [INSTALLED] Network testing tools${NC}"
echo -e "${GREEN}    [INSTALLED] System user (ddos-inspector)${NC}"
echo -e "${GREEN}    [INSTALLED] Log rotation setup${NC}"
echo -e "${GREEN}    [INSTALLED] Systemd service template${NC}"
echo ""
print_info "Next Steps:"
echo "   1. Logout and login again (for Docker group membership)"
echo "   2. Run: ./scripts/deploy_host.sh"
echo ""
print_info "Optional: Enable auto-start with:"
echo "   sudo systemctl enable ddos-inspector"
echo ""

# Verify installations
print_info "Verifying installations..."
echo "   CMake: $(cmake --version 2>/dev/null | head -1 || echo 'NOT FOUND')"
echo "   g++: $(g++ --version 2>/dev/null | head -1 || echo 'NOT FOUND')"
echo "   Docker: $(docker --version 2>/dev/null || echo 'NOT FOUND')"
echo "   Docker Compose: $(docker-compose --version 2>/dev/null || docker compose version 2>/dev/null || echo 'NOT FOUND')"
echo "   nftables: $(nft --version 2>/dev/null || echo 'NOT FOUND')"
echo "   OpenSSL: $(openssl version 2>/dev/null || echo 'NOT FOUND')"
echo "   hping3: $(hping3 --version 2>/dev/null | head -1 || echo 'NOT FOUND')"
echo ""
print_success "Installation completed!"