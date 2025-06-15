#!/bin/bash

# DDoS Inspector Project Alias Script
# Source this file to add convenient aliases for project management

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Main project directory
export DDOS_PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Enhanced docker-compose with metrics reset
alias ddos-compose='$DDOS_PROJECT_DIR/scripts/docker-compose-wrapper.sh'

# Quick commands
alias ddos-up='ddos-compose up -d'
alias ddos-down='ddos-compose down'              # Metrics-only reset (preserves configs)
alias ddos-down-full='ddos-compose down-full'    # Full reset including configs
alias ddos-restart='ddos-compose restart'        # Restart with metrics reset only
alias ddos-restart-full='ddos-compose restart-full'  # Restart with full reset
alias ddos-logs='ddos-compose logs'
alias ddos-status='ddos-compose status'
alias ddos-reset='ddos-compose reset-metrics'    # Reset metrics only
alias ddos-reset-full='ddos-compose reset-full'  # Reset everything including configs
alias ddos-clean='ddos-compose clean'

# Development helpers
alias ddos-build='cd $DDOS_PROJECT_DIR && make -C build'
alias ddos-test='cd $DDOS_PROJECT_DIR && ./build/unit_tests'
alias ddos-metrics='cat $DDOS_PROJECT_DIR/data/ddos_inspector/ddos_inspector_stats'

echo -e "${GREEN}[INFO] DDoS Inspector aliases loaded!${NC}"
echo ""
echo "Available commands:"
echo "    ddos-up           - Start all services in background"
echo "    ddos-down         - Stop services and reset metrics only (keep configs)"
echo "    ddos-down-full    - Stop services and reset everything including configs"
echo "    ddos-restart      - Full restart with clean metrics (preserve configs)"
echo "    ddos-restart-full - Full restart with complete reset"
echo "    ddos-logs         - Show service logs"
echo "    ddos-status       - Show service and volume status"
echo "    ddos-reset        - Reset metrics only (keep services running)"
echo "    ddos-reset-full   - Reset everything including user configurations"
echo "    ddos-clean        - Nuclear cleanup (remove everything)"
echo ""
echo "Development commands:"
echo "    ddos-build        - Build the project"
echo "    ddos-test         - Run unit tests"
echo "    ddos-metrics      - Show current metrics"
echo ""
echo -e "${YELLOW}[NOTE] Key difference:${NC}"
echo -e "    ${GREEN}ddos-down      = Preserves your Grafana/Kibana configs${NC}"
echo -e "    ${RED}ddos-down-full = Removes all configs (back to defaults)${NC}"