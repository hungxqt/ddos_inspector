#!/bin/bash
# Automated release script for DDoS Inspector Plugin

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
REPO_NAME="ddos-inspector"
PLUGIN_NAME="ddos_inspector"
BUILD_DIR="build"
DIST_DIR="dist"

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check if we're in a git repository
    if ! git rev-parse --git-dir > /dev/null 2>&1; then
        log_error "Not in a git repository"
        exit 1
    fi
    
    # Check if we're on main branch
    current_branch=$(git branch --show-current)
    if [[ "$current_branch" != "main" ]]; then
        log_warning "You're on branch '$current_branch', not 'main'"
        read -p "Continue? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    # Check for uncommitted changes
    if ! git diff-index --quiet HEAD --; then
        log_error "You have uncommitted changes. Please commit or stash them first."
        exit 1
    fi
    
    # Check if gh CLI is installed
    if ! command -v gh &> /dev/null; then
        log_error "GitHub CLI (gh) is not installed. Please install it first."
        log_info "Visit: https://cli.github.com/"
        exit 1
    fi
    
    # Check if authenticated with GitHub
    if ! gh auth status &> /dev/null; then
        log_error "Not authenticated with GitHub. Please run 'gh auth login' first."
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

get_version() {
    if [[ -n "$1" ]]; then
        version="$1"
    else
        # Get current version from git tags
        current_version=$(git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0")
        log_info "Current version: $current_version"
        
        echo "Select release type:"
        echo "1) Patch (v1.0.1)"
        echo "2) Minor (v1.1.0)"
        echo "3) Major (v2.0.0)"
        echo "4) Custom version"
        read -p "Choice (1-4): " choice
        
        case $choice in
            1) version=$(echo $current_version | awk -F. '{$NF = $NF + 1;} 1' | sed 's/ /./g') ;;
            2) version=$(echo $current_version | awk -F. '{$(NF-1) = $(NF-1) + 1; $NF = 0} 1' | sed 's/ /./g') ;;
            3) version=$(echo $current_version | awk -F. '{$1 = substr($1,1,1) (substr($1,2) + 1); $(NF-1) = 0; $NF = 0} 1' | sed 's/ /./g') ;;
            4) read -p "Enter custom version (e.g., v1.2.3): " version ;;
            *) log_error "Invalid choice"; exit 1 ;;
        esac
    fi
    
    # Ensure version starts with 'v'
    if [[ ! "$version" =~ ^v ]]; then
        version="v$version"
    fi
    
    log_info "Target version: $version"
}

run_tests() {
    log_info "Running tests..."
    
    if [[ -d "$BUILD_DIR" ]]; then
        rm -rf "$BUILD_DIR"
    fi
    
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"
    
    cmake .. -DCMAKE_BUILD_TYPE=Release
    make -j$(nproc)
    
    if ! ctest --output-on-failure; then
        log_error "Tests failed. Aborting release."
        exit 1
    fi
    
    cd ..
    log_success "All tests passed"
}

build_plugin() {
    log_info "Building optimized plugin..."
    
    cd "$BUILD_DIR"
    make -j$(nproc) "$PLUGIN_NAME"
    
    # Verify plugin was built
    if [[ ! -f "${PLUGIN_NAME}.so" ]]; then
        log_error "Plugin build failed - ${PLUGIN_NAME}.so not found"
        exit 1
    fi
    
    # Check plugin symbols
    if ! nm -D "${PLUGIN_NAME}.so" | grep -q snort_plugins; then
        log_warning "Plugin may not have correct Snort symbols"
    fi
    
    cd ..
    log_success "Plugin built successfully"
}

create_distribution() {
    log_info "Creating distribution package..."
    
    if [[ -d "$DIST_DIR" ]]; then
        rm -rf "$DIST_DIR"
    fi
    
    mkdir -p "$DIST_DIR"
    
    # Copy files
    cp "$BUILD_DIR/${PLUGIN_NAME}.so" "$DIST_DIR/"
    cp snort_ddos_config.lua "$DIST_DIR/"
    cp README.md "$DIST_DIR/"
    cp LICENSE "$DIST_DIR/"
    cp -r docs/ "$DIST_DIR/"
    
    mkdir -p "$DIST_DIR/scripts"
    cp scripts/nftables_rules.sh "$DIST_DIR/scripts/"
    cp scripts/setup_env.sh "$DIST_DIR/scripts/"
    
    # Create version info
    cat > "$DIST_DIR/VERSION" << EOF
DDoS Inspector Plugin $version
Built on: $(date)
Commit: $(git rev-parse HEAD)
Branch: $(git branch --show-current)
EOF
    
    # Create installation script
    cat > "$DIST_DIR/install.sh" << 'EOF'
#!/bin/bash
# Installation script for DDoS Inspector Plugin

set -e

PLUGIN_DIR="/usr/local/lib/snort3_extra_plugins"
CONFIG_DIR="/etc/snort"

echo "Installing DDoS Inspector Plugin..."

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (use sudo)" 
   exit 1
fi

# Create directories
mkdir -p "$PLUGIN_DIR"
mkdir -p "$CONFIG_DIR"

# Copy plugin
cp ddos_inspector.so "$PLUGIN_DIR/"
chmod 644 "$PLUGIN_DIR/ddos_inspector.so"

# Copy configuration
cp snort_ddos_config.lua "$CONFIG_DIR/"

# Setup firewall rules
if [[ -f "scripts/nftables_rules.sh" ]]; then
    chmod +x scripts/nftables_rules.sh
    ./scripts/nftables_rules.sh
fi

# Update library cache
ldconfig

echo "Installation completed!"
echo "Plugin installed to: $PLUGIN_DIR/ddos_inspector.so"
echo "Configuration available at: $CONFIG_DIR/snort_ddos_config.lua"
echo ""
echo "Next steps:"
echo "1. Configure your snort.lua to include the ddos_inspector plugin"
echo "2. Start Snort with: snort -c /etc/snort/snort.lua -i <interface>"
EOF
    
    chmod +x "$DIST_DIR/install.sh"
    
    # Create tarball
    cd "$DIST_DIR"
    tar -czf "../${PLUGIN_NAME}-${version}-linux-x86_64.tar.gz" *
    cd ..
    
    log_success "Distribution package created"
}

create_release() {
    log_info "Creating GitHub release..."
    
    # Create and push tag
    git tag -a "$version" -m "Release $version"
    git push origin "$version"
    
    # Create release notes
    cat > release_notes.md << EOF
# DDoS Inspector Plugin $version

## What's New
- Real-time DDoS detection and mitigation for Snort 3
- Statistical analysis using EWMA and entropy detection  
- Behavioral profiling for TCP/HTTP traffic
- Automated firewall integration with nftables

## Installation
1. Download the plugin file: \`ddos_inspector.so\`
2. Copy to Snort 3 plugins directory: \`/usr/local/lib/snort3_extra_plugins/\`
3. Configure in your \`snort.lua\` file
4. Run setup scripts for firewall rules

Alternatively, use the provided installation script:
\`\`\`bash
tar -xzf ${PLUGIN_NAME}-${version}-linux-x86_64.tar.gz
cd ${PLUGIN_NAME}-${version}
sudo ./install.sh
\`\`\`

## Files Included
- \`ddos_inspector.so\` - Main plugin library
- \`snort_ddos_config.lua\` - Example configuration
- \`scripts/\` - Installation and setup scripts
- \`docs/\` - Documentation and guides
- \`install.sh\` - Automated installation script

## System Requirements
- Snort 3.1.74.0 or later
- Ubuntu 20.04/22.04 or compatible Linux distribution
- nftables or iptables for mitigation

## Performance
- <10ms latency under high load
- <5% CPU overhead at 10k pps  
- Memory usage <50MB for 24h operation

## Changelog
$(git log --oneline $(git describe --tags --abbrev=0 HEAD^)..HEAD | sed 's/^/- /')
EOF
    
    # Create GitHub release
    gh release create "$version" \
        "${PLUGIN_NAME}-${version}-linux-x86_64.tar.gz" \
        "$DIST_DIR/${PLUGIN_NAME}.so" \
        --title "DDoS Inspector Plugin $version" \
        --notes-file release_notes.md
    
    # Cleanup
    rm release_notes.md
    
    log_success "GitHub release created: $version"
}

# Main execution
main() {
    log_info "Starting release process for DDoS Inspector Plugin"
    
    check_prerequisites
    get_version "$1"
    run_tests
    build_plugin
    create_distribution
    create_release
    
    log_success "Release $version completed successfully!"
    log_info "Release URL: https://github.com/$(gh repo view --json owner,name -q '.owner.login + \"/\" + .name')/releases/tag/$version"
}

# Handle command line arguments
if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    echo "Usage: $0 [version]"
    echo ""
    echo "Creates a new release of the DDoS Inspector Plugin"
    echo ""
    echo "Arguments:"
    echo "  version    Optional. Version to release (e.g., v1.2.3)"
    echo "             If not provided, will prompt for release type"
    echo ""
    echo "Examples:"
    echo "  $0              # Interactive mode"
    echo "  $0 v1.2.3       # Release specific version"
    exit 0
fi

# Run main function
main "$1"