#!/bin/bash

# DDoS Inspector Docker Compose Wrapper with Metrics Reset
# This script wraps docker-compose commands and automatically resets metrics on 'down'

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[DDoS Inspector]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[DDoS Inspector]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[DDoS Inspector]${NC} $1"
}

print_error() {
    echo -e "${RED}[DDoS Inspector]${NC} $1"
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo ""
    echo "Enhanced docker-compose wrapper for DDoS Inspector with automatic metrics reset"
    echo ""
    echo "Commands:"
    echo "  up [OPTIONS]       Start all services"
    echo "  down [OPTIONS]     Stop all services (preserves user configs)"
    echo "  down-full          Stop all services and remove all data including configs"
    echo "  restart            Restart all services with metrics reset only"
    echo "  restart-full       Restart all services with complete reset"
    echo "  logs [SERVICE]     Show logs for service(s)"
    echo "  status             Show status of all services"
    echo "  reset-metrics      Reset metrics only (preserve user configs)"
    echo "  reset-full         Reset everything including user configurations"
    echo "  clean              Full cleanup (down + remove volumes + reset everything)"
    echo ""
    echo "Examples:"
    echo "  $0 up -d                    # Start in detached mode"
    echo "  $0 down                     # Stop and reset metrics only"
    echo "  $0 down-full                # Stop and reset everything including configs"
    echo "  $0 restart                  # Restart with clean metrics (keep configs)"
    echo "  $0 reset-metrics            # Reset metrics without stopping services"
    echo "  $0 logs ddos-inspector      # Show DDoS Inspector logs"
}

# Function to reset metrics
reset_metrics() {
    print_status "Resetting all metrics and data..."
    cd "$PROJECT_DIR"
    
    if [ -f "./scripts/reset_metrics.sh" ]; then
        ./scripts/reset_metrics.sh
    else
        print_error "Reset script not found at ./scripts/reset_metrics.sh"
        return 1
    fi
}

# Function to reset everything including configurations
reset_everything() {
    print_status "Resetting all data including user configurations..."
    cd "$PROJECT_DIR"
    
    print_warning "This will remove ALL user configurations in Grafana and Kibana!"
    read -p "Are you sure? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        # Full reset with volume removal
        $DOCKER_COMPOSE down --volumes
        reset_metrics
        print_success "Complete reset finished - all data and configurations removed!"
    else
        print_status "Full reset cancelled."
    fi
}

# Function to check if docker-compose is available
check_docker_compose() {
    if command -v docker-compose >/dev/null 2>&1; then
        DOCKER_COMPOSE="docker-compose"
    elif command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
        DOCKER_COMPOSE="docker compose"
    else
        print_error "Neither 'docker-compose' nor 'docker compose' found. Please install Docker Compose."
        exit 1
    fi
}

# Main command handling
main() {
    check_docker_compose
    
    if [ $# -eq 0 ]; then
        show_usage
        exit 1
    fi
    
    cd "$PROJECT_DIR"
    
    case "$1" in
        up)
            shift
            print_status "Starting DDoS Inspector monitoring stack..."
            $DOCKER_COMPOSE up "$@"
            ;;
            
        down)
            shift
            print_status "Stopping DDoS Inspector monitoring stack (preserving configs)..."
            $DOCKER_COMPOSE down "$@"
            print_success "Services stopped"
            
            # Reset metrics only (preserve configurations)
            reset_metrics
            print_success "Metrics reset complete. User configurations preserved!"
            ;;
            
        down-full)
            shift
            print_status "Stopping DDoS Inspector monitoring stack (removing all data)..."
            $DOCKER_COMPOSE down --volumes "$@"
            print_success "Services stopped and volumes removed"
            
            # Reset metrics after successful shutdown
            reset_metrics
            print_success "Complete reset finished - all data removed!"
            ;;
            
        restart)
            print_status "Restarting DDoS Inspector with clean metrics (preserving configs)..."
            $DOCKER_COMPOSE down
            reset_metrics
            print_status "Starting services with fresh metrics..."
            $DOCKER_COMPOSE up -d
            print_success "Restart completed with clean metrics and preserved configs!"
            ;;
            
        restart-full)
            print_status "Restarting DDoS Inspector with complete reset..."
            $DOCKER_COMPOSE down --volumes
            reset_metrics
            print_status "Starting services with fresh everything..."
            $DOCKER_COMPOSE up -d
            print_success "Full restart completed with everything reset!"
            ;;
            
        logs)
            shift
            $DOCKER_COMPOSE logs "$@"
            ;;
            
        status)
            print_status "Service Status:"
            $DOCKER_COMPOSE ps
            echo ""
            print_status "Volume Status:"
            docker volume ls | grep -E "(ddos|prometheus|grafana|elasticsearch)" || echo "No DDoS Inspector volumes found"
            ;;
            
        reset-metrics)
            reset_metrics
            ;;
            
        reset-full)
            reset_everything
            ;;
            
        clean)
            print_warning "This will completely remove all data and containers!"
            read -p "Are you sure? (y/N): " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                print_status "Performing nuclear cleanup..."
                $DOCKER_COMPOSE down --volumes --remove-orphans
                docker system prune -f --volumes
                reset_metrics
                print_success "Complete cleanup finished!"
            else
                print_status "Cleanup cancelled."
            fi
            ;;
            
        help|--help|-h)
            show_usage
            ;;
            
        *)
            print_status "Passing command to docker-compose: $*"
            $DOCKER_COMPOSE "$@"
            ;;
    esac
}

# Run main function with all arguments
main "$@"