#!/bin/bash

# Enhanced Docker Compose Deployment Script for DDoS Inspector
set -e

# Protect against PATH conflicts with Windows/Cygwin binaries
# Remove problematic Windows paths that might interfere with bash builtins
export PATH=$(echo "$PATH" | tr ':' '\n' | grep -v '/mnt/[a-z]/cygwin' | tr '\n' ':' | sed 's/:$//')

# Ensure we use bash builtins for common commands
alias wait='builtin wait'

# Get script directory and source common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Source common functions library
source "$SCRIPT_DIR/common_functions.sh"

print_success "DDoS Inspector Docker Compose Deployment"

# Configuration
COMPOSE_PROJECT_NAME="ddos_inspector"
COMPOSE_FILE="docker-compose.yml"

# Parse command line arguments
DEPLOYMENT_MODE="full"
INTERFACE="eth0"
ENABLE_MONITORING="true"
DETACHED="true"
BUILD_IMAGES="true"
FORCE_RECREATE="false"
INTERACTIVE_MODE="false"
SERVICE_MODE="false"
SKIP_DEPS="false"

# Docker-specific dependency installation
install_docker_dependencies() {
    print_info "Missing Docker dependencies detected. Installing..."
    echo ""
    
    if [ ! -f "$SCRIPT_DIR/install_dependencies.sh" ]; then
        print_error "install_dependencies.sh not found in $SCRIPT_DIR"
        exit 1
    fi
    
    # Check if running as root or with sudo
    if [ "$EUID" -ne 0 ]; then
        print_info "Administrator privileges required for dependency installation."
        print_info "Re-running with sudo..."
        sudo "$SCRIPT_DIR/install_dependencies.sh"
        
        echo ""
        print_success "Dependencies installed. Please logout and login again for Docker group membership."
        print_info "Then re-run this script: $0"
        exit 0
    else
        "$SCRIPT_DIR/install_dependencies.sh"
    fi
}

show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -m, --mode MODE          Deployment mode: full|core|monitoring|test"
    echo "  -i, --interface IFACE    Network interface (default: auto-detect)"
    echo "  --interactive            Interactive interface selection mode"
    echo "  -f, --foreground         Run in foreground (not detached)"
    echo "  -n, --no-monitoring      Skip monitoring stack (Grafana, Prometheus, etc.)"
    echo "  -b, --no-build           Skip building images (use existing)"
    echo "  -r, --recreate           Force recreate all containers"
    echo "  -s, --stop               Stop all services"
    echo "  -d, --down               Stop and remove all services"
    echo "  --uninstall              Uninstall all services and dependencies"
    echo "  -l, --logs               Show logs for all services"
    echo "  -t, --test               Test mode - validate configuration only"
    echo "  --service                Run in service mode (for systemd)"
    echo "  --skip-deps              Skip dependency check and installation"
    echo "  -h, --help               Show this help"
    echo ""
    echo "Deployment Modes:"
    echo "  full        - Deploy complete stack (DDoS Inspector + monitoring)"
    echo "  core        - Deploy only DDoS Inspector service"
    echo "  monitoring  - Deploy only monitoring stack"
    echo "  test        - Validate docker-compose configuration"
    echo ""
    echo "Interface Selection:"
    echo "  -i eth0               - Use specific interface"
    echo "  --interactive         - Interactive interface selection"
    echo "  (no -i option)        - Auto-detect interface"
    echo ""
    echo "Examples:"
    echo "  $0 --mode full --interface eth0"
    echo "  $0 --mode core --no-build"
    echo "  $0 --interactive"
    echo "  $0 --stop"
    echo "  $0 --logs"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -m|--mode)
            DEPLOYMENT_MODE="$2"
            shift 2
            ;;
        -i|--interface)
            INTERFACE="$2"
            shift 2
            ;;
        --interactive)
            INTERACTIVE_MODE="true"
            shift
            ;;
        -f|--foreground)
            DETACHED="false"
            shift
            ;;
        -n|--no-monitoring)
            ENABLE_MONITORING="false"
            shift
            ;;
        -b|--no-build)
            BUILD_IMAGES="false"
            shift
            ;;
        -r|--recreate)
            FORCE_RECREATE="true"
            shift
            ;;
        -s|--stop)
            DEPLOYMENT_MODE="stop"
            shift
            ;;
        -d|--down)
            DEPLOYMENT_MODE="down"
            shift
            ;;
        --uninstall)
            DEPLOYMENT_MODE="uninstall"
            shift
            ;;
        -l|--logs)
            DEPLOYMENT_MODE="logs"
            shift
            ;;
        -t|--test)
            DEPLOYMENT_MODE="test"
            shift
            ;;
        --service)
            SERVICE_MODE="true"
            shift
            ;;
        --skip-deps)
            SKIP_DEPS="true"
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Change to project root
cd "$PROJECT_ROOT"

# Check if docker-compose.yml exists
if [ ! -f "$COMPOSE_FILE" ]; then
    print_error "docker-compose.yml not found in project root"
    exit 1
fi

# Enhanced Docker and dependency checking
check_docker_comprehensive() {
    if ! check_docker_availability; then
        return 1
    fi
    
    # Check Docker Compose command
    if docker compose version &> /dev/null; then
        COMPOSE_CMD="docker compose"
    elif command -v docker-compose &> /dev/null; then
        COMPOSE_CMD="docker-compose"
    else
        print_error "Docker Compose is not installed"
        return 1
    fi
    
    return 0
}

# Enhanced dependency checking for Docker environment
check_docker_dependencies() {
    local missing_deps=()
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        missing_deps+=("Docker")
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null 2>&1; then
        missing_deps+=("Docker Compose")
    fi
    
    # Check nftables
    if ! command -v nft &> /dev/null; then
        missing_deps+=("nftables")
    fi
    
    # Check if Docker daemon is running
    if command -v docker &> /dev/null && ! docker info &> /dev/null; then
        missing_deps+=("Docker daemon (not running)")
    fi
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        print_warning "Missing dependencies: ${missing_deps[*]}"
        return 1
    fi
    return 0
}

# Function to remove existing containers by name to prevent conflicts
remove_existing_containers() {
    print_info "Checking for existing containers..."
    
    # List of container names that might conflict
    local container_names=(
        "ddos_inspector"
        "ddos_prometheus"
        "ddos_grafana"
        "ddos_elasticsearch"
        "ddos_kibana"
        "ddos_logstash"
        "ddos_alertmanager"
        "ddos_metrics_exporter"
        "snort_stats_exporter"
        "ddos_node_exporter"
    )
    
    local containers_removed=0
    
    for container_name in "${container_names[@]}"; do
        if docker ps -a --format "table {{.Names}}" | grep -q "^${container_name}$"; then
            print_warning " Found existing container: $container_name"
            
            # Stop the container if it's running
            if docker ps --format "table {{.Names}}" | grep -q "^${container_name}$"; then
                print_info " Stopping running container: $container_name"
                docker stop "$container_name" >/dev/null 2>&1 || true
            fi
            
            # Remove the container
            print_info "Removing container: $container_name"
            docker rm "$container_name" >/dev/null 2>&1 || true
            containers_removed=$((containers_removed + 1))
        fi
    done
    
    if [ $containers_removed -eq 0 ]; then
        print_success "No conflicting containers found"
    else
        print_success "Removed $containers_removed existing containers"
    fi
    
    # Also clean up any orphaned containers from this project
    print_info "Cleaning up orphaned containers..."
    docker container prune -f --filter label=com.docker.compose.project="$COMPOSE_PROJECT_NAME" >/dev/null 2>&1 || true
}

# Create environment file
create_env_file() {
    print_info "Creating environment configuration..."
    
    # Determine interface to use
    local selected_interface="$INTERFACE"
    
    if [ "$INTERACTIVE_MODE" = "true" ]; then
        selected_interface=$(interactive_interface_selection)
    elif [ "$selected_interface" = "eth0" ] && [ "$SERVICE_MODE" != "true" ]; then
        # Auto-detect if using default and not in service mode
        print_info "Auto-detecting network interface..."
        selected_interface=$(detect_host_interface)
        print_success "Auto-detected interface: $selected_interface"
    fi
    
    # Validate the selected interface
    if ! validate_interface "$selected_interface" >/dev/null 2>&1; then
        if [ "$SERVICE_MODE" = "true" ]; then
            print_warning "Interface validation failed in service mode, using default"
            selected_interface="eth0"
        else
            print_error "Interface validation failed"
            exit 1
        fi
    fi
    
    # Update the interface variable
    INTERFACE="$selected_interface"
    
    # Detect host IP for the interface
    if ip addr show "$INTERFACE" &>/dev/null; then
        HOST_IP=$(ip addr show "$INTERFACE" | grep 'inet ' | awk '{print $2}' | cut -d/ -f1 | head -1)
        print_success "Detected IP for $INTERFACE: $HOST_IP"
    else
        print_warning "Interface $INTERFACE not found, using default"
        HOST_IP="127.0.0.1"
    fi
    
    # Create .env file
    cat > .env << EOF
# DDoS Inspector Docker Compose Configuration
NETWORK_INTERFACE=$INTERFACE
HOST_IP=$HOST_IP
COMPOSE_PROJECT_NAME=$COMPOSE_PROJECT_NAME

# Service Configuration
ENABLE_METRICS=true
PROMETHEUS_PORT=9091
STATS_PORT=9092
EOF
    
    print_success "Environment file created"
}

# Handle different deployment modes
case $DEPLOYMENT_MODE in
    "stop")
        print_warning "Stopping all services..."
        if check_docker_comprehensive; then
            $COMPOSE_CMD stop
            print_success "All services stopped"
        fi
        exit 0
        ;;
        
    "down")
        print_warning "Stopping and removing all services..."
        if check_docker_comprehensive; then
            $COMPOSE_CMD down -v
            print_success "All services stopped and removed"
        fi
        exit 0
        ;;
        
    "uninstall")
        print_error "Uninstalling all services and dependencies..."
        if check_docker_comprehensive; then
            $COMPOSE_CMD down -v
            print_success "All services stopped and removed"
        fi
        print_error "Removing Docker and dependencies..."
        sudo apt-get remove --purge -y docker docker-compose
        print_success "Uninstallation complete"
        exit 0
        ;;
        
    "logs")
        print_info "Showing logs for all services..."
        if check_docker_comprehensive; then
            $COMPOSE_CMD logs -f
        fi
        exit 0
        ;;
        
    "test")
        print_info "Validating docker-compose configuration..."
        if check_docker_comprehensive; then
            create_env_file
            $COMPOSE_CMD config
            print_success "Configuration is valid"
        fi
        exit 0
        ;;
esac

# Main deployment logic
print_info "Starting deployment in ${DEPLOYMENT_MODE} mode"

# Check dependencies unless skipped
if [ "${SKIP_DEPS:-false}" = "false" ]; then
    print_info "Checking system dependencies..."
    
    if ! check_docker_dependencies; then
        print_warning "Some dependencies are missing or not properly configured."
        
        if [ "$SERVICE_MODE" = "true" ]; then
            print_error "Cannot install dependencies in service mode. Please run manually first."
            exit 1
        fi
        
        if [ "$INTERACTIVE_MODE" = "true" ] || [ "$DETACHED" = "false" ]; then
            read -p "Would you like to install missing dependencies automatically? (y/N): " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                install_docker_dependencies
            else
                print_error "Cannot proceed without required dependencies."
                print_info "Run: sudo $SCRIPT_DIR/install_dependencies.sh"
                exit 1
            fi
        else
            print_error "Cannot proceed without required dependencies in non-interactive mode."
            print_info "Run: sudo $SCRIPT_DIR/install_dependencies.sh"
            exit 1
        fi
    else
        print_success "All dependencies are satisfied"
    fi
fi

# Check Docker availability
if ! check_docker_comprehensive; then
    exit 1
fi

# Remove existing containers to prevent conflicts
remove_existing_containers

# Create environment file
create_env_file

# Show current configuration
echo ""
print_info "Deployment Configuration:"
echo -e "   Interface: ${YELLOW}$INTERFACE${NC}"
echo -e "   Host IP: ${YELLOW}$HOST_IP${NC}"
echo -e "   Mode: ${YELLOW}$DEPLOYMENT_MODE${NC}"
echo -e "   Firewall: ${YELLOW}nftables (container + host)${NC}"
echo -e "   Project Root: ${YELLOW}$PROJECT_ROOT${NC}"
echo ""

# Ask for confirmation unless in service mode or non-interactive
if [ "$SERVICE_MODE" = "false" ] && [ "$INTERACTIVE_MODE" = "true" ]; then
    read -p "Proceed with deployment? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_error "Deployment cancelled"
        exit 1
    fi
fi

# Prepare Docker Compose options
COMPOSE_OPTS=""
if [ "$DETACHED" = "true" ]; then
    COMPOSE_OPTS="$COMPOSE_OPTS -d"
fi

if [ "$BUILD_IMAGES" = "true" ]; then
    COMPOSE_OPTS="$COMPOSE_OPTS --build"
fi

if [ "$FORCE_RECREATE" = "true" ]; then
    COMPOSE_OPTS="$COMPOSE_OPTS --force-recreate"
fi

# Stop existing services
print_warning "Stopping existing services..."
$COMPOSE_CMD down 2>/dev/null || true

# Deploy based on mode
case $DEPLOYMENT_MODE in
    "full")
        print_info "Deploying full stack (DDoS Inspector + Monitoring)"
        $COMPOSE_CMD up $COMPOSE_OPTS
        ;;
        
    "core")
        print_info "Deploying core DDoS Inspector service only"
        $COMPOSE_CMD up $COMPOSE_OPTS ddos-inspector
        ;;
        
    "monitoring")
        print_info "Deploying monitoring stack only"
        $COMPOSE_CMD up $COMPOSE_OPTS prometheus grafana elasticsearch kibana logstash alertmanager ddos-metrics-exporter snort-stats-exporter node-exporter
        ;;
        
    *)
        print_error "Unknown deployment mode: ${DEPLOYMENT_MODE}"
        show_help
        exit 1
        ;;
esac

# Wait for services to start
if [ "$DETACHED" = "true" ] && [ "$DEPLOYMENT_MODE" != "test" ]; then
    print_info "Waiting for services to start..."
    sleep 10
    
    # Check service status
    print_info "Service Status:"
    $COMPOSE_CMD ps
    
    # Show service health
    echo ""
    print_info "Health Check:"
    RUNNING_SERVICES=$($COMPOSE_CMD ps --services --filter "status=running" | wc -l)
    TOTAL_SERVICES=$($COMPOSE_CMD ps --services | wc -l)
    
    if [ "$RUNNING_SERVICES" -eq "$TOTAL_SERVICES" ]; then
        print_success "All $TOTAL_SERVICES services are running"
    else
        print_warning "$RUNNING_SERVICES/$TOTAL_SERVICES services are running"
        print_info "Check logs with: ${YELLOW}$0 --logs${NC}"
    fi
fi

# Show access information
if [ "$DEPLOYMENT_MODE" = "full" ] || [ "$DEPLOYMENT_MODE" = "monitoring" ]; then
    echo ""
    print_success "Deployment complete!"
    echo ""
    print_info "Access Points:"
    echo -e "  [DASHBOARD] Grafana Dashboard: ${YELLOW}http://localhost:3000${NC}"
    echo -e "       Username: admin | Password: ddos_inspector_2025"
    echo -e "  [METRICS] Prometheus Metrics: ${YELLOW}http://localhost:9090${NC}"
    echo -e "  [LOGS] Kibana Logs: ${YELLOW}http://localhost:5601${NC}"
    echo -e "  [ALERTS] AlertManager: ${YELLOW}http://localhost:9093${NC}"
    echo -e "  [STATS] DDoS Metrics: ${YELLOW}http://localhost:9091/metrics${NC}"
    echo -e "  [STATS] Snort Stats: ${YELLOW}http://localhost:9092/metrics${NC}"
fi

if [ "$DEPLOYMENT_MODE" = "full" ] || [ "$DEPLOYMENT_MODE" = "core" ]; then
    echo ""
    print_info "Monitoring Commands:"
    echo -e "  View real-time stats: ${YELLOW}cat /var/log/ddos_inspector/ddos_inspector_stats${NC}"
    echo -e "  Check container logs: ${YELLOW}$0 --logs${NC}"
    echo -e "  List blocked IPs: ${YELLOW}sudo $SCRIPT_DIR/nftables_rules.sh --list${NC}"
    echo -e "  Service status: ${YELLOW}$COMPOSE_CMD ps${NC}"
fi

echo ""
print_info "Management Commands:"
echo -e "  Stop services: ${YELLOW}$0 --stop${NC}"
echo -e "  Remove all: ${YELLOW}$0 --down${NC}"
echo -e "  Uninstall: ${YELLOW}$0 --uninstall${NC}"
echo -e "  View logs: ${YELLOW}$0 --logs${NC}"
echo -e "  Restart services: ${YELLOW}$COMPOSE_CMD restart${NC}"

echo ""
print_success "Your host's $INTERFACE interface is now protected!"
