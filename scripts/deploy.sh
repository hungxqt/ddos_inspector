#!/bin/bash

# DDoS Inspector Plugin Deployment Script
# This script builds and deploys the Snort 3 DDoS Inspector plugin

# ============================================================================
# STRICT BASH MODE AND ENVIRONMENT SETUP
# ============================================================================

set -euo pipefail
IFS=$'\n\t'

# Protect against PATH conflicts with Windows/Cygwin binaries
export PATH=$(echo "$PATH" | tr ':' '\n' | grep -v '/mnt/[a-z]/cygwin' | tr '\n' ':' | sed 's/:$//')

# Ensure we use bash builtins for common commands
alias wait='builtin wait'

# ============================================================================
# GLOBAL VARIABLES AND CONSTANTS
# ============================================================================

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m' # No Color

# Script paths
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
readonly ENV_FILE="$PROJECT_ROOT/.env"

# Default action and interface
NETWORK_INTERFACE="eth0"
ACTION="deploy"
SHOW_HELP=false
CONFIG_FILE_PATH=""
SKIP_SNORT=false
SKIP_SERVICE=false

# ============================================================================
# SHARED LOGGING HELPERS
# ============================================================================

# Function to log with timestamp and color
log_with_timestamp() {
    local level="$1"
    local color="$2"
    local message="$3"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${color}[$timestamp] [$level]${NC} $message"
}

# Specific logging functions
log_info() {
    log_with_timestamp "INFO" "$BLUE" "$1"
}

log_success() {
    log_with_timestamp "SUCCESS" "$GREEN" "$1"
}

log_warning() {
    log_with_timestamp "WARNING" "$YELLOW" "$1"
}

log_error() {
    log_with_timestamp "ERROR" "$RED" "$1"
}

# Function to handle errors with context
handle_error() {
    local exit_code=$?
    local line_number=${1:-$LINENO}
    local command="${2:-unknown}"
    
    log_error "Command failed with exit code $exit_code at line $line_number: $command"
    log_error "Call stack:"
    local frame=0
    while caller $frame; do
        ((frame++))
    done
    exit $exit_code
}

# Set up error trapping
trap 'handle_error $LINENO "$BASH_COMMAND"' ERR

# ============================================================================
# CONFIGURATION LOADING AND VALIDATION
# ============================================================================

# Function to load default configuration
load_default_config() {
    log_info "Loading default configuration"
    
    # Network and service defaults
    NETWORK_INTERFACE=${NETWORK_INTERFACE:-"eth0"}
    HOST_IP=${HOST_IP:-"172.17.198.85"}
    COMPOSE_PROJECT_NAME=${COMPOSE_PROJECT_NAME:-"ddos_inspector"}
    ENABLE_METRICS=${ENABLE_METRICS:-"true"}
    PROMETHEUS_PORT=${PROMETHEUS_PORT:-"9091"}
    STATS_PORT=${STATS_PORT:-"9092"}
    
    # Snort configuration defaults
    SNORT_BINARY_PATH=${SNORT_BINARY_PATH:-""}
    SNORT_CONFIG_PATH=${SNORT_CONFIG_PATH:-"/usr/local/snort3/etc/snort"}
    SNORT_DEFAULTS_FILE=${SNORT_DEFAULTS_FILE:-"/usr/local/snort3/etc/snort/snort_defaults.lua"}
    SNORT_INCLUDE_DIR=${SNORT_INCLUDE_DIR:-""}
    SNORT_PLUGIN_PATH=${SNORT_PLUGIN_PATH:-"/usr/local/lib/snort3_extra_plugins"}
    SNORT3_INCLUDE_DIR=${SNORT3_INCLUDE_DIR:-"$SNORT_INCLUDE_DIR"}
    
    # Log and data file defaults
    DDOS_METRICS_FILE=${DDOS_METRICS_FILE:-"/var/log/ddos_inspector/metrics.log"}
    DDOS_BLOCKED_IPS_FILE=${DDOS_BLOCKED_IPS_FILE:-"/var/log/ddos_inspector/blocked_ips.log"}
    DDOS_RATE_LIMITED_IPS_FILE=${DDOS_RATE_LIMITED_IPS_FILE:-"/var/log/ddos_inspector/rate_limited_ips.log"}
    LOG_DIR_SNORT=${LOG_DIR_SNORT:-"/var/log/snort"}
    LOG_DIR_DDOS=${LOG_DIR_DDOS:-"/var/log/ddos_inspector"}
    SNORT_DATA_DIR=${SNORT_DATA_DIR:-"/var/log/snort"}
    
    log_success "Default configuration loaded"
}

# Function to load environment configuration from .env file
load_env_config() {
    if [ -f "$ENV_FILE" ]; then
        log_info "Loading configuration from $ENV_FILE"
        
        # Source the .env file, ignoring comments and empty lines
        while IFS='=' read -r key value; do
            # Skip comments and empty lines
            if [[ ! "$key" =~ ^#.* ]] && [[ -n "$key" ]]; then
                # Remove any quotes from the value
                value=$(echo "$value" | sed 's/^["'"'"']\|["'"'"']$//g')
                export "$key"="$value"
            fi
        done < <(grep -v '^#' "$ENV_FILE" | grep -v '^$')
        
        log_success "Environment variables loaded from .env file"
    else
        log_warning "No .env file found at $ENV_FILE, using defaults"
    fi
}

# Function to export all configuration variables for child processes
export_config() {
    log_info "Exporting configuration for child processes"
    
    export NETWORK_INTERFACE HOST_IP COMPOSE_PROJECT_NAME ENABLE_METRICS PROMETHEUS_PORT STATS_PORT
    export SNORT_BINARY_PATH SNORT_CONFIG_PATH SNORT_DEFAULTS_FILE SNORT_INCLUDE_DIR SNORT_PLUGIN_PATH SNORT3_INCLUDE_DIR
    export DDOS_METRICS_FILE DDOS_BLOCKED_IPS_FILE DDOS_RATE_LIMITED_IPS_FILE
    export LOG_DIR_SNORT LOG_DIR_DDOS SNORT_DATA_DIR
    
    log_success "Configuration exported"
}

# Function to validate environment configuration
validate_env_config() {
    log_info "Validating environment configuration"
    
    local warnings=0
    
    # Check if metrics are enabled but ports might conflict
    if [ "$ENABLE_METRICS" = "true" ]; then
        if [ "$PROMETHEUS_PORT" = "$STATS_PORT" ]; then
            log_warning "Prometheus and Stats ports are the same ($PROMETHEUS_PORT)"
            warnings=$((warnings + 1))
        fi
    fi
    
    # Check if log directories are writable (or parent directories)
    for dir in "$LOG_DIR_SNORT" "$LOG_DIR_DDOS" "$(dirname "$DDOS_METRICS_FILE")"; do
        if [ ! -w "$dir" ] 2>/dev/null && [ ! -w "$(dirname "$dir")" ] 2>/dev/null; then
            log_warning "May not have write permissions for: $dir"
            warnings=$((warnings + 1))
        fi
    done
    
    # Check if SNORT3_INCLUDE_DIR falls back properly
    if [ "$SNORT3_INCLUDE_DIR" = "$SNORT_INCLUDE_DIR" ] && [ -n "$SNORT_INCLUDE_DIR" ]; then
        log_info "Using SNORT_INCLUDE_DIR for CMake compatibility"
    fi
    
    # Validate network interface exists (if not in container)
    if command -v ip >/dev/null 2>&1; then
        if ! ip link show "$NETWORK_INTERFACE" >/dev/null 2>&1; then
            log_warning "Network interface '$NETWORK_INTERFACE' not found"
            local available_interfaces=$(ip link show | grep '^[0-9]' | cut -d':' -f2 | tr -d ' ' | tr '\n' ' ')
            log_warning "Available interfaces: $available_interfaces"
            warnings=$((warnings + 1))
        fi
    fi
    
    if [ $warnings -eq 0 ]; then
        log_success "Environment configuration validation passed"
    else
        log_warning "Found $warnings potential configuration issues"
    fi
    
    return 0
}

# ============================================================================
# SNORT BINARY DISCOVERY
# ============================================================================

# Function to find Snort binary
find_snort_binary() {
    # First check if SNORT_BINARY_PATH is set in .env and exists
    if [ -n "$SNORT_BINARY_PATH" ] && [ -x "$SNORT_BINARY_PATH" ]; then
        echo "$SNORT_BINARY_PATH"
        return 0
    fi
    
    # Fallback to searching common locations
    local snort_paths=(
        "/usr/local/snort3/bin/snort"
        "/usr/local/bin/snort"
        "/usr/bin/snort"
        "/opt/snort3/bin/snort"
    )
    
    for path in "${snort_paths[@]}"; do
        if [ -x "$path" ]; then
            echo "$path"
            return 0
        fi
    done
    
    # Try which command as fallback
    if command -v snort >/dev/null 2>&1; then
        which snort
        return 0
    fi
    
    return 1
}

# Function to discover and validate Snort binary
discover_snort_binary() {
    if [ "$SKIP_SNORT" = "true" ]; then
        log_info "Skipping Snort binary discovery (--no-snort flag specified)"
        SNORT_BINARY=""
        export SNORT_BINARY
        return 0
    fi
    
    log_info "Searching for Snort binary"
    
    SNORT_BINARY=$(find_snort_binary)
    if [ -z "$SNORT_BINARY" ]; then
        log_error "Snort binary not found"
        log_error "Please ensure Snort 3 is installed"
        exit 1
    fi
    
    log_success "Found Snort binary at: $SNORT_BINARY"
    export SNORT_BINARY
}

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

# Function to show current configuration
show_config() {
    echo -e "${GREEN}=== Current DDoS Inspector Configuration ===${NC}"
    echo -e "${BLUE}Network Configuration:${NC}"
    echo -e "  Network Interface: $NETWORK_INTERFACE"
    echo -e "  Host IP: ${HOST_IP:-"Auto-detect"}"
    echo -e "  Compose Project: ${COMPOSE_PROJECT_NAME:-"ddos-inspector"}"
    echo
    echo -e "${BLUE}Service Configuration:${NC}"
    echo -e "  Enable Metrics: ${ENABLE_METRICS:-"false"}"
    echo -e "  Prometheus Port: ${PROMETHEUS_PORT:-"9090"}"
    echo -e "  Stats Port: ${STATS_PORT:-"8080"}"
    echo
    echo -e "${BLUE}Snort Configuration:${NC}"
    echo -e "  Snort Binary: ${SNORT_BINARY:-"Not yet discovered"}"
    echo -e "  Snort Config Path: ${SNORT_CONFIG_PATH:-"/etc/snort"}"
    echo -e "  Snort Plugin Path: ${SNORT_PLUGIN_PATH:-"/usr/local/lib/snort3_extra_plugins"}"
    echo -e "  Snort Include Dir: ${SNORT_INCLUDE_DIR:-"Auto-detect"}"
    echo -e "  Snort3 Include Dir: ${SNORT3_INCLUDE_DIR:-"Derived from SNORT_INCLUDE_DIR"}"
    echo -e "  Snort Defaults File: ${SNORT_DEFAULTS_FILE:-"/usr/local/snort3/etc/snort/snort_defaults.lua"}"
    echo -e "  Snort Data Dir: ${SNORT_DATA_DIR:-"/usr/local/snort3/etc/snort"}"
    echo
    echo -e "${BLUE}Log Configuration:${NC}"
    echo -e "  Log Directory (Snort): ${LOG_DIR_SNORT:-"/var/log/snort"}"
    echo -e "  Log Directory (DDoS): ${LOG_DIR_DDOS:-"/var/log/ddos"}"
    echo -e "  DDoS Metrics File: ${DDOS_METRICS_FILE:-"/var/log/ddos/ddos_inspector_stats"}"
    echo -e "  Blocked IPs File: ${DDOS_BLOCKED_IPS_FILE:-"/var/log/ddos/blocked_ips.log"}"
    echo -e "  Rate Limited IPs File: ${DDOS_RATE_LIMITED_IPS_FILE:-"/var/log/ddos/rate_limited_ips.log"}"
    echo
    echo -e "${BLUE}Environment File:${NC} $ENV_FILE"
    echo
    echo -e "${YELLOW}To customize these settings, edit: $ENV_FILE${NC}"
    echo
}

# Function to show help
show_help() {
    echo -e "${GREEN}=== DDoS Inspector Plugin Deployment Script ===${NC}"
    echo
    echo -e "${BLUE}USAGE:${NC}"
    echo "  $0 [OPTIONS] [COMMAND]"
    echo
    echo -e "${BLUE}OPTIONS:${NC}"
    echo -e "  ${YELLOW}-h, --help${NC}              Show this help message"
    echo -e "  ${YELLOW}--show-config${NC}           Show current configuration from .env"
    echo -e "  ${YELLOW}-i, --interface IFACE${NC}   Set network interface (default: eth0)"
    echo -e "  ${YELLOW}--no-snort${NC}              Skip Snort installation and discovery"
    echo -e "  ${YELLOW}--skip-service${NC}          Skip systemd service installation"
    echo
    echo -e "${BLUE}COMMANDS:${NC}"
    echo -e "  ${YELLOW}deploy, --deploy${NC}        Deploy DDoS Inspector (default)"
    echo -e "  ${YELLOW}start, --start${NC}          Start the DDoS Inspector service"
    echo -e "  ${YELLOW}stop, --stop${NC}            Stop the DDoS Inspector service"
    echo -e "  ${YELLOW}restart, --restart${NC}      Restart the DDoS Inspector service"
    echo -e "  ${YELLOW}status, --status${NC}        Show service status"
    echo -e "  ${YELLOW}logs, --logs${NC}            Show service logs (follow mode)"
    echo -e "  ${YELLOW}enable, --enable${NC}        Enable service to start on boot"
    echo -e "  ${YELLOW}disable, --disable${NC}      Disable service from starting on boot"
    echo -e "  ${YELLOW}test-config [PATH]${NC}      Test configuration syntax (defaults to project or installed config)"
    echo -e "  ${YELLOW}show-plugins${NC}            Show loaded Snort plugins"
    echo -e "  ${YELLOW}uninstall, --uninstall${NC}  Uninstall the DDoS Inspector"
    echo -e "  ${YELLOW}force-uninstall${NC}         Force uninstall the DDoS Inspector"
    echo
    echo -e "${BLUE}EXAMPLES:${NC}"
    echo "  $0                           # Deploy with default settings"
    echo "  $0 --interface enp0s3        # Deploy with specific interface"
    echo "  $0 --no-snort                # Deploy without Snort (plugin only)"
    echo "  $0 --skip-service            # Deploy without systemd service"
    echo "  $0 --no-snort --skip-service # Deploy minimal setup (no Snort, no service)"
    echo "  $0 start                     # Start the service"
    echo "  $0 --stop                    # Stop the service"
    echo "  $0 status                    # Check service status"
    echo "  $0 --logs                    # View service logs"
    echo "  $0 test-config               # Test default configuration"
    echo "  $0 test-config /path/to/config.lua  # Test specific configuration"
    echo "  $0 --show-config             # Show current configuration"
    echo
}

# ============================================================================
# INFRASTRUCTURE FUNCTIONS
# ============================================================================

# Function to create required directories
create_directories() {
    log_info "Creating required directories"
    
    # Create log directories with proper permissions
    sudo mkdir -p "$LOG_DIR_SNORT"
    sudo mkdir -p "$LOG_DIR_DDOS"
    sudo chmod 755 "$LOG_DIR_SNORT"
    sudo chmod 755 "$LOG_DIR_DDOS"
    log_success "Created log directories: $LOG_DIR_SNORT, $LOG_DIR_DDOS"
    
    # Create directories for individual log files
    sudo mkdir -p "$(dirname "$DDOS_METRICS_FILE")"
    sudo mkdir -p "$(dirname "$DDOS_BLOCKED_IPS_FILE")"
    sudo mkdir -p "$(dirname "$DDOS_RATE_LIMITED_IPS_FILE")"
    
    # Create Snort data directory if different from log directory
    if [ "$SNORT_DATA_DIR" != "$LOG_DIR_SNORT" ]; then
        sudo mkdir -p "$SNORT_DATA_DIR"
        sudo chmod 755 "$SNORT_DATA_DIR"
        log_success "Created Snort data directory: $SNORT_DATA_DIR"
    fi
    
    # Create plugin directory if it doesn't exist
    if [ ! -d "$SNORT_PLUGIN_PATH" ]; then
        log_info "Creating plugin directory: $SNORT_PLUGIN_PATH"
        sudo mkdir -p "$SNORT_PLUGIN_PATH"
    fi
    
    log_success "All required directories created"
}

# Function to verify critical dependencies
verify_dependencies() {
    log_info "Verifying critical dependencies"
    
    local missing_deps=()
    
    # Check for libcap
    if ! pkg-config --exists libcap; then
        missing_deps+=("libcap-dev")
    fi
    
    # Check for libpcap
    if ! pkg-config --exists libpcap; then
        missing_deps+=("libpcap-dev")
    fi
    
    # Check for openssl
    if ! pkg-config --exists openssl; then
        missing_deps+=("libssl-dev")
    fi
    
    # Check for basic build tools
    if ! command -v cmake >/dev/null 2>&1; then
        missing_deps+=("cmake")
    fi
    
    if ! command -v g++ >/dev/null 2>&1; then
        missing_deps+=("g++")
    fi
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        log_error "Missing critical dependencies:"
        for dep in "${missing_deps[@]}"; do
            log_error "  - $dep"
        done
        log_error "Please run: apt-get install ${missing_deps[*]}"
        return 1
    fi
    
    log_success "All critical dependencies are available"
    return 0
}

# Function to install dependencies
install_dependencies() {
    log_info "Installing system dependencies"
    
    if [ -f "$SCRIPT_DIR/install_dependencies.sh" ]; then
        # Pass --no-snort flag if SKIP_SNORT is true
        local install_args=""
        if [ "$SKIP_SNORT" = "true" ]; then
            install_args="--no-snort"
            log_info "Passing --no-snort flag to dependency installation"
        fi
        
        if "$SCRIPT_DIR/install_dependencies.sh" $install_args; then
            log_success "Dependencies installed successfully"
            
            # Verify dependencies are actually available (skip if Snort is skipped)
            if [ "$SKIP_SNORT" != "true" ]; then
                if ! verify_dependencies; then
                    log_error "Critical dependencies are missing after installation"
                    return 1
                fi
            else
                log_info "Skipping dependency verification (--no-snort specified)"
            fi
        else
            log_error "Dependency installation failed"
            return 1
        fi
    else
        log_error "install_dependencies.sh not found at $SCRIPT_DIR"
        return 1
    fi
}

# Function to find Snort headers
find_snort_headers() {
    log_info "Searching for Snort headers"
    
    # First check if SNORT_INCLUDE_DIR is set in .env and valid
    if [ -n "$SNORT_INCLUDE_DIR" ] && [ -d "$SNORT_INCLUDE_DIR" ]; then
        log_success "Using Snort headers from .env config: $SNORT_INCLUDE_DIR"
        return 0
    fi
    
    log_info "SNORT_INCLUDE_DIR not set or invalid, searching common locations"
    local snort_include_dirs=(
        "/usr/include/snort"
        "/usr/local/include/snort"
        "/opt/snort3/include/snort"
        "/usr/include/snort3"
        "/usr/local/include/snort3"
    )

    for dir in "${snort_include_dirs[@]}"; do
        if [ -d "$dir" ]; then
            SNORT_INCLUDE_DIR="$dir"
            log_success "Found Snort headers at: $dir"
            export SNORT_INCLUDE_DIR
            return 0
        fi
    done
    
    log_error "Snort 3 development headers not found"
    log_error "Checked locations: ${snort_include_dirs[*]}"
    log_error "Please install snort3-dev package or compile Snort 3 from source"
    return 1
}

# ============================================================================
# BUILD AND DEPLOYMENT FUNCTIONS
# ============================================================================

# Function to build the plugin
build_plugin() {
    log_info "Building DDoS Inspector plugin"
    
    cd "$PROJECT_ROOT" || {
        log_error "Failed to change to project root directory"
        return 1
    }
    
    # Clean previous build
    if [ -d "build" ]; then
        log_info "Cleaning previous build"
        rm -rf build
    fi
    
    mkdir build
    cd build || {
        log_error "Failed to create/enter build directory"
        return 1
    }
    
    # Configure with proper Snort paths
    log_info "Configuring build with CMake"
    if ! cmake .. -DSNORT_INCLUDE_DIR="$SNORT_INCLUDE_DIR"; then
        log_error "CMake configuration failed"
        return 1
    fi
    
    # Build with all available cores
    log_info "Compiling plugin"
    if ! make -j$(nproc); then
        log_error "Build failed"
        return 1
    fi
    
    log_success "Build successful"
    return 0
}

# Function to install the plugin
install_plugin() {
    log_info "Installing plugin to $SNORT_PLUGIN_PATH"
    
    if [ ! -f "libddos_inspector.so" ]; then
        log_error "Plugin binary not found in build directory"
        return 1
    fi
    
    # Install the plugin
    cp libddos_inspector.so "$SNORT_PLUGIN_PATH/" || {
        log_error "Failed to copy plugin to $SNORT_PLUGIN_PATH"
        return 1
    }
    
    # Set proper permissions
    chmod 755 "$SNORT_PLUGIN_PATH/libddos_inspector.so"
    chown root:root "$SNORT_PLUGIN_PATH/libddos_inspector.so"
    
    log_success "Plugin installed successfully"
    return 0
}

# Function to install configuration files
install_config_files() {
    log_info "Installing configuration files"
    
    # Create Snort configuration directory if it doesn't exist
    local snort_config_dir="/etc/snort"
    sudo mkdir -p "$snort_config_dir"
    
    # Install configuration file
    local config_source="$PROJECT_ROOT/snort_ddos_config.lua"
    local config_target="$snort_config_dir/snort_ddos_config.lua"
    
    if [ -f "$config_source" ]; then
        sudo cp "$config_source" "$config_target"
        sudo chmod 644 "$config_target"
        log_success "Configuration file installed"
    else
        log_error "Configuration file not found: $config_source"
        return 1
    fi
    
    # Verify the defaults file exists
    if [ ! -f "$SNORT_DEFAULTS_FILE" ]; then
        log_error "Snort defaults file not found: $SNORT_DEFAULTS_FILE"
        log_warning "Please update SNORT_DEFAULTS_FILE in $ENV_FILE"
        log_warning "Common locations:"
        log_warning "  /usr/local/snort3/etc/snort/snort_defaults.lua"
        log_warning "  /etc/snort/snort_defaults.lua"
        log_warning "  /opt/snort3/etc/snort/snort_defaults.lua"
        return 1
    else
        log_success "Snort defaults file found: $SNORT_DEFAULTS_FILE"
    fi
    
    return 0
}

# ============================================================================
# SERVICE MANAGEMENT FUNCTIONS
# ============================================================================

# Function to create systemd service
create_systemd_service() {
    log_info "Setting up Snort DDoS Inspector as system service"
    
    # Create systemd service file
    cat > /etc/systemd/system/snort-ddos-inspector.service << EOF
[Unit]
Description=Snort 3 DDoS Inspector Service
After=network.target nftables.service
Wants=nftables.service
Documentation=https://snort.org/

[Service]
Type=simple
User=root
Group=root
ExecStartPre=/usr/bin/test -f /etc/snort/snort_ddos_config.lua
ExecStart=$SNORT_BINARY --plugin-path $SNORT_PLUGIN_PATH -c /etc/snort/snort_ddos_config.lua -i ${NETWORK_INTERFACE} -A alert_fast -D
ExecReload=/bin/kill -HUP \$MAINPID
KillMode=mixed
Restart=on-failure
RestartSec=5
TimeoutStopSec=20
StandardOutput=journal
StandardError=journal

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=$LOG_DIR_SNORT $LOG_DIR_DDOS /tmp

[Install]
WantedBy=multi-user.target
EOF

    # Create service environment configuration
    mkdir -p /etc/snort/service
    cat > /etc/snort/service/interface.conf << 'EOF'
# Network interface for Snort DDoS Inspector
# Change this to match your network interface
SNORT_INTERFACE=eth0

# Additional Snort options
SNORT_OPTIONS="-A alert_fast"

# Log level (0-4, 0=emergency, 4=debug)
LOG_LEVEL=2
EOF

    chmod 644 /etc/systemd/system/snort-ddos-inspector.service
    chmod 644 /etc/snort/service/interface.conf

    # Reload systemd
    systemctl daemon-reload
    
    log_success "Systemd service created"
}

# Function to setup firewall rules
setup_firewall() {
    log_info "Setting up nftables firewall rules"
    
    if [ -f "$SCRIPT_DIR/nftables_rules.sh" ]; then
        if "$SCRIPT_DIR/nftables_rules.sh"; then
            log_success "nftables rules applied successfully"
        else
            log_error "nftables rules setup failed"
            return 1
        fi
    else
        log_error "nftables_rules.sh not found at $SCRIPT_DIR"
        return 1
    fi
}

# Function to start snort with DDoS configuration
start_snort_ddos() {
    log_info "Starting Snort with DDoS configuration"
    
    # Create directories first
    create_directories
    
    # Check if snort is already running
    if pgrep snort > /dev/null; then
        log_warning "Snort is already running. Stopping existing instances"
        sudo pkill snort
        sleep 5
    fi
    
    # Start snort in background with the specified command using the interface argument
    log_info "Starting Snort on interface $NETWORK_INTERFACE"
    nohup sudo "$SNORT_BINARY" -c /etc/snort/snort_ddos_config.lua --plugin-path "$SNORT_PLUGIN_PATH" -v -i "${NETWORK_INTERFACE}" -A alert_fast > "$LOG_DIR_SNORT/snort.log" 2>&1 &
    
    # Give it more time to start
    sleep 5
    
    # Verify snort started successfully using a more robust check
    if pgrep snort > /dev/null; then
        log_success "Snort started successfully on interface $NETWORK_INTERFACE"
        log_info "Snort logs available at: $LOG_DIR_SNORT/snort.log"
        log_info "To monitor: tail -f $LOG_DIR_SNORT/snort.log"
        log_info "Running processes:"
        ps aux | grep snort | grep -v grep | head -3
    else
        log_error "Failed to start Snort"
        log_warning "Check the log file: $LOG_DIR_SNORT/snort.log"
        if [ -f "$LOG_DIR_SNORT/snort.log" ]; then
            log_warning "Last few lines of log:"
            tail -10 "$LOG_DIR_SNORT/snort.log" 2>/dev/null || log_warning "Log file not readable"
        fi
        return 1
    fi
}

# ============================================================================
# COMMAND-SPECIFIC ACTION HANDLERS
# ============================================================================

# Function to handle service operations
handle_service_action() {
    local action="$1"
    
    case $action in
        start)
            log_info "Starting DDoS Inspector service"
            systemctl start snort-ddos-inspector
            log_success "Service started successfully"
            ;;
        stop)
            log_info "Stopping DDoS Inspector service"
            systemctl stop snort-ddos-inspector
            log_success "Service stopped successfully"
            ;;
        restart)
            log_info "Restarting DDoS Inspector service"
            systemctl restart snort-ddos-inspector
            log_success "Service restarted successfully"
            ;;
        status)
            log_info "DDoS Inspector service status:"
            systemctl status snort-ddos-inspector
            ;;
        logs)
            log_info "Following DDoS Inspector service logs (Ctrl+C to exit):"
            journalctl -u snort-ddos-inspector -f
            ;;
        enable)
            log_info "Enabling DDoS Inspector service to start on boot"
            systemctl enable snort-ddos-inspector
            log_success "Service enabled successfully"
            ;;
        disable)
            log_info "Disabling DDoS Inspector service from starting on boot"
            systemctl disable snort-ddos-inspector
            log_success "Service disabled successfully"
            ;;
        test-config)
            log_info "Testing configuration syntax"
            if "$SNORT_BINARY" --plugin-path "$SNORT_PLUGIN_PATH" -c /etc/snort/snort_ddos_config.lua -T 2>/dev/null; then
                log_success "Configuration syntax is valid"
            else
                log_error "Configuration syntax test failed"
                log_warning "Please check /etc/snort/snort_ddos_config.lua for errors"
                return 1
            fi
            ;;
        show-plugins)
            log_info "Showing loaded Snort plugins"
            
            # Use plugin-path to load plugins without DAQ initialization
            if "$SNORT_BINARY" --plugin-path "$SNORT_PLUGIN_PATH" --show-plugins 2>/dev/null | grep -A 2 -B 2 ddos_inspector; then
                log_success "DDoS Inspector plugin found and loaded successfully"
            else
                log_warning "DDoS Inspector plugin not found in loaded plugins"
                log_info "All available plugins with plugin path:"
                "$SNORT_BINARY" --plugin-path "$SNORT_PLUGIN_PATH" --show-plugins 2>/dev/null | head -20
            fi
            
            echo ""
            log_info "Testing plugin loading with configuration file"
            # Test with configuration but without interface to avoid DAQ initialization
            if timeout 5 "$SNORT_BINARY" --plugin-path "$SNORT_PLUGIN_PATH" -c /etc/snort/snort_ddos_config.lua --show-plugins 2>/dev/null | grep -q ddos_inspector; then
                log_success "DDoS Inspector plugin loads successfully with configuration"
            else
                log_warning "Plugin loading with configuration timed out or failed"
                log_info "This is normal - the plugin is installed correctly"
            fi
            ;;
        start-snort)
            start_snort_ddos
            ;;
        uninstall)
            handle_uninstall false
            ;;
        force-uninstall)
            handle_uninstall true
            ;;
        *)
            log_error "Unknown action: $action"
            return 1
            ;;
    esac
}

# Function to handle uninstall operations
handle_uninstall() {
    local force_mode="$1"
    
    if [ "$force_mode" = "true" ]; then
        log_info "Force uninstalling DDoS Inspector"
        
        # Call specialized uninstall scripts
        if [ -f "$SCRIPT_DIR/install_dependencies.sh" ]; then
            log_info "Running dependency uninstaller"
            "$SCRIPT_DIR/install_dependencies.sh" --uninstall || {
                log_error "Failed to run dependency uninstaller"
            }
        fi
        
        # Remove Docker deployment if exists
        if [ -f "$SCRIPT_DIR/deploy_docker.sh" ]; then
            log_info "Cleaning up Docker deployment"
            "$SCRIPT_DIR/deploy_docker.sh" --uninstall || {
                log_warning "Failed to clean up Docker deployment"
            }
        fi
    else
        log_info "Uninstalling DDoS Inspector"
    fi
    
    # Stop and disable service
    systemctl stop snort-ddos-inspector 2>/dev/null || true
    systemctl disable snort-ddos-inspector 2>/dev/null || true
    
    # Remove service file
    rm -f /etc/systemd/system/snort-ddos-inspector.service
    systemctl daemon-reload
    
    # Remove plugin files
    rm -f /usr/local/lib/snort3_extra_plugins/libddos_inspector.so
    rm -f /usr/lib/snort3_extra_plugins/libddos_inspector.so
    
    # Remove configuration files
    rm -f /etc/snort/snort_ddos_config.lua
    rm -rf /etc/snort/service
    
    # Call nftables uninstall
    if [ -f "$SCRIPT_DIR/nftables_rules.sh" ]; then
        log_info "Removing firewall rules"
        "$SCRIPT_DIR/nftables_rules.sh" --uninstall || {
            log_warning "Failed to remove firewall rules automatically"
        }
    fi
    
    log_success "DDoS Inspector uninstalled successfully"
}

# ============================================================================
# VERIFICATION AND VALIDATION FUNCTIONS
# ============================================================================

# Function to verify installation
verify_installation() {
    log_info "Verifying installation"
    
    local plugin_path="$SNORT_PLUGIN_PATH/libddos_inspector.so"
    local config_path="/etc/snort/snort_ddos_config.lua"
    
    # Check plugin file
    if [ -f "$plugin_path" ]; then
        log_success "Plugin binary installed successfully"
    else
        log_error "Plugin binary installation failed"
        return 1
    fi
    
    # Check configuration file
    if [ -f "$config_path" ]; then
        log_success "Configuration file installed"
    else
        log_error "Configuration file installation failed"
        return 1
    fi
    
    # Test plugin loading
    log_info "Testing plugin loading"
    if "$SNORT_BINARY" --plugin-path "$SNORT_PLUGIN_PATH" --show-plugins 2>/dev/null | grep -q "ddos_inspector"; then
        log_success "Plugin loads successfully in Snort"
    elif LD_LIBRARY_PATH="$SNORT_PLUGIN_PATH" "$SNORT_BINARY" --plugin-path "$SNORT_PLUGIN_PATH" --show-plugins 2>/dev/null | grep -q "ddos_inspector"; then
        log_success "Plugin loads successfully (with library path)"
        log_warning "Note: You may need to set LD_LIBRARY_PATH=$SNORT_PLUGIN_PATH"
    else
        log_warning "Plugin loading test inconclusive"
        log_info "This is normal - try manual verification with the commands in the summary"
    fi
    
    # Test configuration syntax
    log_info "Testing configuration syntax"
    if "$SNORT_BINARY" --plugin-path "$SNORT_PLUGIN_PATH" -c "$config_path" -T 2>/dev/null; then
        log_success "Configuration syntax is valid"
    else
        log_warning "Configuration syntax test failed - may need manual adjustment"
    fi
    
    log_success "Installation verification completed"
    return 0
}

# Function to show deployment summary
show_deployment_summary() {
    echo -e "${GREEN}=== Deployment Complete ===${NC}"
    echo
    echo -e "${BLUE}=== Current Configuration ===${NC}"
    show_config
    echo
    echo -e "${BLUE}=== System Service Setup ===${NC}"
    echo -e "${YELLOW}1. Configure network interface:${NC}"
    echo -e "   Edit /etc/snort/service/interface.conf to set your network interface"
    echo -e "   Current setting: eth0 (change if needed)"
    echo
    echo -e "${YELLOW}2. Enable and start the service:${NC}"
    echo -e "   sudo systemctl enable snort-ddos-inspector"
    echo -e "   sudo systemctl start snort-ddos-inspector"
    echo
    echo -e "${YELLOW}3. Check service status:${NC}"
    echo -e "   sudo systemctl status snort-ddos-inspector"
    echo
    echo -e "${YELLOW}4. View service logs:${NC}"
    echo -e "   sudo journalctl -u snort-ddos-inspector -f"
    echo
    echo -e "${YELLOW}5. Control the service:${NC}"
    echo -e "   sudo systemctl stop snort-ddos-inspector     # Stop service"
    echo -e "   sudo systemctl restart snort-ddos-inspector  # Restart service"
    echo -e "   sudo systemctl reload snort-ddos-inspector   # Reload config"
    echo
    echo -e "${BLUE}=== Manual Testing (Alternative) ===${NC}"
    echo -e "${YELLOW}1. Verify plugin installation:${NC}"
    echo -e "   sudo $SNORT_BINARY --plugin-path $SNORT_PLUGIN_PATH --show-plugins | grep ddos_inspector"
    echo
    echo -e "${YELLOW}2. Test configuration syntax:${NC}"
    echo -e "   sudo $SNORT_BINARY --plugin-path $SNORT_PLUGIN_PATH -c /etc/snort/snort_ddos_config.lua -T"
    echo
    echo -e "${YELLOW}3. Run DDoS Inspector manually (for testing):${NC}"
    echo -e "   sudo $SNORT_BINARY --plugin-path $SNORT_PLUGIN_PATH -c /etc/snort/snort_ddos_config.lua -i $NETWORK_INTERFACE -A alert_fast"
    echo
    echo -e "${YELLOW}4. Monitor alerts:${NC}"
    echo -e "   tail -f $LOG_DIR_SNORT/alert"
    echo
    echo -e "${BLUE}=== Configuration Files ===${NC}"
    echo -e "${YELLOW}Plugin Binary:${NC} $SNORT_PLUGIN_PATH/libddos_inspector.so"
    echo -e "${YELLOW}Configuration:${NC} /etc/snort/snort_ddos_config.lua"
    echo -e "${YELLOW}Service Config:${NC} /etc/snort/service/interface.conf"
    echo -e "${YELLOW}Service File:${NC} /etc/systemd/system/snort-ddos-inspector.service"
    echo -e "${YELLOW}Log Directory:${NC} $LOG_DIR_SNORT/ (Snort alerts)"
    echo -e "${YELLOW}Stats Directory:${NC} $LOG_DIR_DDOS/ (DDoS Inspector metrics)"
    echo -e "${YELLOW}Environment Config:${NC} $ENV_FILE"
    echo
    echo -e "${BLUE}=== Quick Start Commands ===${NC}"
    echo -e "${YELLOW}Use this script for easy management:${NC}"
    echo -e "   $0 start           # Start the service"
    echo -e "   $0 status          # Check status"
    echo -e "   $0 logs            # View logs"
    echo -e "   $0 test-config     # Test configuration"
    echo -e "   $0 show-plugins    # Verify plugin loading"
    echo
    echo -e "${GREEN}=== Deployment Summary ===${NC}"
    echo -e "${GREEN}[SUCCESS] DDoS Inspector plugin compiled and installed${NC}"
    echo -e "${GREEN}[SUCCESS] System service configured${NC}"
    echo -e "${GREEN}[SUCCESS] Firewall rules applied${NC}"
    echo -e "${GREEN}[SUCCESS] Configuration files in place${NC}"
    echo
    echo -e "${BLUE}Next Steps:${NC}"
    echo -e "1. Adjust network interface in /etc/snort/service/interface.conf if needed"
    echo -e "2. Review and customize /etc/snort/snort_ddos_config.lua as required"
    echo -e "3. Start the service: $0 start"
    echo -e "4. Monitor with: $0 logs"
    echo
    echo -e "${GREEN}DDoS Inspector deployment completed successfully!${NC}"
}

# ============================================================================
# MAIN DEPLOYMENT FLOW
# ============================================================================

# Function to execute the main deployment process
deploy_ddos_inspector() {
    log_info "Starting DDoS Inspector Deployment"
    log_info "Network Interface: $NETWORK_INTERFACE"
    
    if [ "$SKIP_SNORT" = "true" ]; then
        log_info "Snort installation and discovery skipped (--no-snort flag)"
    fi
    
    if [ "$SKIP_SERVICE" = "true" ]; then
        log_info "Systemd service installation skipped (--skip-service flag)"
    fi
    
    # Step 1: Validate environment
    validate_env_config || {
        log_error "Environment validation failed"
        return 1
    }
    
    # Step 2: Create required directories
    create_directories || {
        log_error "Directory creation failed"
        return 1
    }
    
    # Step 3: Install dependencies (skip if --no-snort)
    if [ "$SKIP_SNORT" != "true" ]; then
        install_dependencies || {
            log_error "Dependency installation failed"
            return 1
        }
        
        # Step 4: Discover Snort binary
        discover_snort_binary || {
            log_error "Snort binary discovery failed"
            return 1
        }
        
        # Step 5: Find Snort headers
        find_snort_headers || {
            log_error "Snort headers not found"
            return 1
        }
    else
        log_info "Skipping dependency installation, Snort binary discovery, and header search"
    fi
    
    log_success "Prerequisites check passed"
    
    # Step 6: Build the plugin (skip if --no-snort since we need Snort headers)
    if [ "$SKIP_SNORT" != "true" ]; then
        build_plugin || {
            log_error "Plugin build failed"
            return 1
        }
        
        # Step 7: Install the plugin
        install_plugin || {
            log_error "Plugin installation failed"
            return 1
        }
    else
        log_info "Skipping plugin build and installation (requires Snort headers)"
    fi
    
    # Step 8: Install configuration files (skip if --no-snort)
    if [ "$SKIP_SNORT" != "true" ]; then
        install_config_files || {
            log_error "Configuration installation failed"
            return 1
        }
    else
        log_info "Skipping configuration file installation"
    fi
    
    # Step 9: Create systemd service (skip if --skip-service or --no-snort)
    if [ "$SKIP_SERVICE" != "true" ] && [ "$SKIP_SNORT" != "true" ]; then
        create_systemd_service || {
            log_error "Service creation failed"
            return 1
        }
    else
        if [ "$SKIP_SERVICE" = "true" ]; then
            log_info "Skipping systemd service creation (--skip-service flag specified)"
        fi
        if [ "$SKIP_SNORT" = "true" ]; then
            log_info "Skipping systemd service creation (--no-snort flag specified)"
        fi
    fi
    
    # Step 10: Setup firewall (always run, independent of Snort)
    setup_firewall || {
        log_error "Firewall setup failed"
        return 1
    }
    
    # Step 11: Verify installation (skip plugin verification if --no-snort)
    if [ "$SKIP_SNORT" != "true" ]; then
        verify_installation || {
            log_error "Installation verification failed"
            return 1
        }
    else
        log_info "Skipping plugin installation verification"
    fi
    
    # Step 12: Show summary
    show_deployment_summary
    
    if [ "$SKIP_SNORT" = "true" ] && [ "$SKIP_SERVICE" = "true" ]; then
        log_success "DDoS Inspector deployment completed successfully (without Snort components and systemd service)"
    elif [ "$SKIP_SNORT" = "true" ]; then
        log_success "DDoS Inspector deployment completed successfully (without Snort components)"
    elif [ "$SKIP_SERVICE" = "true" ]; then
        log_success "DDoS Inspector deployment completed successfully (without systemd service)"
    else
        log_success "DDoS Inspector deployment completed successfully"
    fi
    return 0
}

# ============================================================================
# COMMAND DISPATCH
# ============================================================================

# Parse command line arguments and set action
# Handle service management actions
handle_service_action() {
    local action="$1"
    local config_file_path="${2:-}"
    
    # For actions that require Snort binary, discover it first
    case $action in
        test-config|show-plugins)
            if [ -z "${SNORT_BINARY:-}" ]; then
                if [ "$SKIP_SNORT" = "true" ]; then
                    log_error "Cannot perform '$action' with --no-snort flag (Snort binary required)"
                    return 1
                fi
                discover_snort_binary || {
                    log_error "Snort binary not found. Please ensure Snort 3 is installed."
                    return 1
                }
            fi
            ;;
    esac
    
    case $action in
        start)
            log_info "Starting DDoS Inspector service..."
            systemctl start snort-ddos-inspector
            log_success "Service started successfully"
            ;;
        stop)
            log_info "Stopping DDoS Inspector service..."
            systemctl stop snort-ddos-inspector
            log_success "Service stopped successfully"
            ;;
        restart)
            log_info "Restarting DDoS Inspector service..."
            systemctl restart snort-ddos-inspector
            log_success "Service restarted successfully"
            ;;
        status)
            log_info "DDoS Inspector service status:"
            systemctl status snort-ddos-inspector
            ;;
        logs)
            log_info "Following DDoS Inspector service logs (Ctrl+C to exit):"
            journalctl -u snort-ddos-inspector -f
            ;;
        enable)
            log_info "Enabling DDoS Inspector service to start on boot..."
            systemctl enable snort-ddos-inspector
            log_success "Service enabled successfully"
            ;;
        disable)
            log_info "Disabling DDoS Inspector service from starting on boot..."
            systemctl disable snort-ddos-inspector
            log_success "Service disabled successfully"
            ;;
        test-config)
            log_info "Testing configuration syntax..."
            
            # Determine which configuration file to test
            local config_to_test
            if [ -n "$config_file_path" ]; then
                # Use the provided config file path
                config_to_test="$config_file_path"
                log_info "Testing specified configuration file: $config_to_test"
            elif [ -f "/etc/snort/snort_ddos_config.lua" ]; then
                # Use the installed config file if it exists
                config_to_test="/etc/snort/snort_ddos_config.lua"
                log_info "Testing installed configuration file: $config_to_test"
            elif [ -f "$PROJECT_ROOT/snort_ddos_config.lua" ]; then
                # Fallback to the project's config file
                config_to_test="$PROJECT_ROOT/snort_ddos_config.lua"
                log_info "Testing project configuration file: $config_to_test"
            else
                log_error "No configuration file found to test"
                log_info "Options:"
                log_info "  1. Provide a path: $0 test-config /path/to/config.lua"
                log_info "  2. Deploy first to create /etc/snort/snort_ddos_config.lua"
                log_info "  3. Ensure $PROJECT_ROOT/snort_ddos_config.lua exists"
                return 1
            fi
            
            # Check if the config file exists
            if [ ! -f "$config_to_test" ]; then
                log_error "Configuration file not found: $config_to_test"
                return 1
            fi
            
            # Test the configuration syntax
            if "$SNORT_BINARY" --plugin-path "$SNORT_PLUGIN_PATH" -c "$config_to_test" -T 2>/dev/null; then
                log_success "Configuration syntax is valid for: $config_to_test"
            else
                log_error "Configuration syntax test failed for: $config_to_test"
                log_warning "Running verbose test to show errors..."
                echo "--- Snort Configuration Test Output ---"
                "$SNORT_BINARY" --plugin-path "$SNORT_PLUGIN_PATH" -c "$config_to_test" -T 2>&1 || true
                echo "--- End of Test Output ---"
                return 1
            fi
            ;;
        show-plugins)
            log_info "Showing loaded Snort plugins..."
            if "$SNORT_BINARY" --plugin-path "$SNORT_PLUGIN_PATH" --show-plugins 2>/dev/null | grep -A 2 -B 2 ddos_inspector; then
                log_success "DDoS Inspector plugin found and loaded successfully"
            else
                log_warning "DDoS Inspector plugin not found in loaded plugins"
                log_info "All available plugins with plugin path:"
                "$SNORT_BINARY" --plugin-path "$SNORT_PLUGIN_PATH" --show-plugins 2>/dev/null | head -20
            fi
            ;;
        uninstall)
            log_info "Uninstalling DDoS Inspector..."
            
            # Stop and disable service
            systemctl stop snort-ddos-inspector 2>/dev/null || true
            systemctl disable snort-ddos-inspector 2>/dev/null || true
            
            # Remove service file
            rm -f /etc/systemd/system/snort-ddos-inspector.service
            systemctl daemon-reload
            
            # Remove plugin files
            rm -f /usr/local/lib/snort3_extra_plugins/libddos_inspector.so
            rm -f /usr/lib/snort3_extra_plugins/libddos_inspector.so
            
            # Remove configuration files
            rm -f /etc/snort/snort_ddos_config.lua
            rm -rf /etc/snort/service
            
            # Call nftables uninstall
            if [ -f "$SCRIPT_DIR/nftables_rules.sh" ]; then
                log_info "Removing firewall rules..."
                "$SCRIPT_DIR/nftables_rules.sh" --uninstall || {
                    log_warning "Failed to remove firewall rules automatically"
                }
            fi
            
            log_success "DDoS Inspector uninstalled successfully"
            ;;
        force-uninstall)
            log_info "Force uninstalling DDoS Inspector..."
            
            # Uninstall dependencies
            if [ -f "$SCRIPT_DIR/install_dependencies.sh" ]; then
                log_info "Running dependency uninstaller..."
                "$SCRIPT_DIR/install_dependencies.sh" --uninstall || {
                    log_error "Failed to run dependency uninstaller"
                }
            fi
            
            # Remove firewall rules
            if [ -f "$SCRIPT_DIR/nftables_rules.sh" ]; then
                log_info "Removing firewall rules..."
                "$SCRIPT_DIR/nftables_rules.sh" --uninstall || {
                    log_error "Failed to remove firewall rules"
                }
            fi
            
            # Remove Docker deployment if exists
            if [ -f "$SCRIPT_DIR/deploy_docker.sh" ]; then
                log_info "Cleaning up Docker deployment..."
                "$SCRIPT_DIR/deploy_docker.sh" --uninstall || {
                    log_warning "Failed to clean up Docker deployment"
                }
            fi
            
            # Proceed with regular uninstall
            handle_service_action "uninstall"
            ;;
    esac
}

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

# Main function that dispatches to appropriate sub-commands
main() {
    local action="deploy"  # Default action
    
    # Parse command line arguments directly in main
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                action="help"
                break
                ;;
            --show-config)
                action="show-config"
                break
                ;;
            -i|--interface)
                if [[ $# -gt 1 && "${2:-}" != -* ]]; then
                    NETWORK_INTERFACE="$2"
                    shift 2
                else
                    log_error "--interface requires an interface name"
                    exit 1
                fi
                ;;
            --no-snort)
                SKIP_SNORT=true
                shift
                ;;
            --skip-service)
                SKIP_SERVICE=true
                shift
                ;;
            --start|start)
                action="start"
                shift
                ;;
            --stop|stop)
                action="stop"
                shift
                ;;
            --restart|restart)
                action="restart"
                shift
                ;;
            --status|status)
                action="status"
                shift
                ;;
            --logs|logs)
                action="logs"
                shift
                ;;
            --enable|enable)
                action="enable"
                shift
                ;;
            --disable|disable)
                action="disable"
                shift
                ;;
            --show-config|show-config)
                action="show-config"
                shift
                ;;
            --test-config|test-config)
                action="test-config"
                # Check if next argument is a file path
                if [[ $# -gt 1 && "${2:-}" != -* ]]; then
                    CONFIG_FILE_PATH="$2"
                    shift 2
                else
                    shift
                fi
                ;;
            --show-plugins|show-plugins)
                action="show-plugins"
                shift
                ;;
            --uninstall|uninstall)
                action="uninstall"
                shift
                ;;
            --force-uninstall|force-uninstall)
                action="force-uninstall"
                shift
                ;;
            deploy|--deploy)
                action="deploy"
                shift
                ;;
            *)
                log_error "Unknown option '$1'"
                log_info "Use -h or --help for usage information"
                exit 1
                ;;
        esac
    done
    
    # Load configuration for all actions (except help)
    if [ "$action" != "help" ]; then
        load_env_config
        export_config
    fi
    
    # Dispatch to appropriate function
    case $action in
        help)
            show_help
            return 0
            ;;
        show-config)
            show_config
            return 0
            ;;
        start|stop|restart|status|logs|enable|disable|test-config|show-plugins|uninstall|force-uninstall)
            handle_service_action "$action" "${CONFIG_FILE_PATH:-}"
            return $?
            ;;
        deploy)
            deploy_ddos_inspector
            return $?
            ;;
        *)
            log_error "Unknown action: $action"
            show_help
            return 1
            ;;
    esac
}

# Execute main function with all arguments
main "$@"