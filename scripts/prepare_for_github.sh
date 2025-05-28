#!/bin/bash

# DDoS Inspector GitHub Publication Preparation Script
# This script cleans up the project before publishing to GitHub

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${GREEN}🧹 Preparing DDoS Inspector for GitHub Publication${NC}"

# Change to project root
cd "$(dirname "$0")/.."

# 1. Remove build artifacts and compiled files
echo -e "${BLUE}Removing build artifacts...${NC}"
if [ -d "build" ]; then
    echo -e "${YELLOW}Removing build/ directory${NC}"
    rm -rf build/
fi

if [ -d "bin" ]; then
    echo -e "${YELLOW}Removing bin/ directory${NC}"
    rm -rf bin/
fi

if [ -d "lib" ]; then
    echo -e "${YELLOW}Removing lib/ directory${NC}"
    rm -rf lib/
fi

# Remove compiled binaries but keep the release directory structure
if [ -f "release/ddos_inspector.so" ]; then
    echo -e "${YELLOW}Removing compiled plugin binary from release/${NC}"
    rm -f release/ddos_inspector.so
fi

# 2. Remove temporary and cache files
echo -e "${BLUE}Cleaning temporary files...${NC}"
find . -name "*.tmp" -delete 2>/dev/null || true
find . -name "*.temp" -delete 2>/dev/null || true
find . -name "*~" -delete 2>/dev/null || true
find . -name ".DS_Store" -delete 2>/dev/null || true
find . -name "Thumbs.db" -delete 2>/dev/null || true

# Remove Python cache
find . -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find . -name "*.pyc" -delete 2>/dev/null || true

# 3. Clean log files (but keep directory structure)
echo -e "${BLUE}Cleaning log files...${NC}"
if [ -d "Prometheus-ELK metrics dashboard/logs" ]; then
    find "Prometheus-ELK metrics dashboard/logs" -name "*.log" -delete 2>/dev/null || true
    find "Prometheus-ELK metrics dashboard/logs" -name "*.txt" -delete 2>/dev/null || true
    # Keep directory with a README
    if [ ! -f "Prometheus-ELK metrics dashboard/logs/README.md" ]; then
        echo "# Log Directory" > "Prometheus-ELK metrics dashboard/logs/README.md"
        echo "This directory will contain log files when the monitoring system is running." >> "Prometheus-ELK metrics dashboard/logs/README.md"
    fi
fi

# 4. Remove any .env files (if they exist)
echo -e "${BLUE}Checking for environment files...${NC}"
find . -name ".env*" -not -name ".env.example" -delete 2>/dev/null || true

# 5. Create example environment file
echo -e "${BLUE}Creating example environment file...${NC}"
cat > .env.example << 'EOF'
# Example Environment Configuration for DDoS Inspector
# Copy this file to .env and customize for your environment

# Network Configuration
SNORT_INTERFACE=eth0
NETWORK_MODE=host

# Security Settings
PRIVILEGED_MODE=true
CONTAINER_USER=root

# Monitoring Configuration
ENABLE_METRICS=true
PROMETHEUS_RETENTION=7d

# Dashboard Credentials (CHANGE THESE!)
GRAFANA_ADMIN_USER=admin
GRAFANA_ADMIN_PASSWORD=change_me_please

# Resource Limits
ELASTICSEARCH_MEMORY=2g
GRAFANA_MEMORY=512m
PROMETHEUS_MEMORY=1g

# Optional: External integrations
# SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK
# EMAIL_SMTP_SERVER=smtp.example.com
# EMAIL_FROM=alerts@yourcompany.com
EOF

# 6. Update documentation with security notice
echo -e "${BLUE}Adding security notices to documentation...${NC}"

# Add security notice to main README if not present
if ! grep -q "SECURITY NOTICE" README.md; then
    # Create backup
    cp README.md README.md.backup
    
    # Add security section after table of contents
    sed -i '/## Table of Contents/a\\n## 🔒 **Security Notice**\n\n⚠️ **Before deploying in production:**\n- Change all default passwords (especially Grafana: admin/admin)\n- Use HTTPS for web interfaces\n- Configure proper firewall rules\n- Review and customize configuration files\n- Use strong authentication mechanisms\n\n**Default credentials are for development/testing only!**\n' README.md
fi

# 7. Validate project structure
echo -e "${BLUE}Validating project structure...${NC}"

# Check for required files
REQUIRED_FILES=("README.md" "LICENSE" "CMakeLists.txt" ".gitignore")
for file in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "$file" ]; then
        echo -e "${RED}❌ Missing required file: $file${NC}"
    else
        echo -e "${GREEN}✅ Found: $file${NC}"
    fi
done

# Check for sensitive patterns in code files
echo -e "${BLUE}Scanning for potential sensitive information...${NC}"
SENSITIVE_PATTERNS=("password.*=" "secret.*=" "key.*=" "token.*=")
FOUND_SENSITIVE=false

for pattern in "${SENSITIVE_PATTERNS[@]}"; do
    if grep -r -i "$pattern" src/ include/ scripts/ --include="*.cpp" --include="*.hpp" --include="*.sh" >/dev/null 2>&1; then
        echo -e "${YELLOW}⚠️  Found potential sensitive pattern: $pattern${NC}"
        FOUND_SENSITIVE=true
    fi
done

if [ "$FOUND_SENSITIVE" = false ]; then
    echo -e "${GREEN}✅ No sensitive patterns found in source code${NC}"
fi

# 8. File size check
echo -e "${BLUE}Checking for large files...${NC}"
find . -type f -size +10M -not -path "./.git/*" -not -path "./build/*" | while read -r file; do
    echo -e "${YELLOW}⚠️  Large file found: $file ($(du -h "$file" | cut -f1))${NC}"
done

# 9. Create publication checklist
echo -e "${BLUE}Creating publication checklist...${NC}"
cat > GITHUB_PUBLICATION_CHECKLIST.md << 'EOF'
# 📋 GitHub Publication Checklist

## Pre-Publication Cleanup ✅
- [ ] Run `./scripts/prepare_for_github.sh`
- [ ] Remove all build artifacts and compiled binaries
- [ ] Clean temporary and cache files
- [ ] Remove any `.env` files with sensitive data
- [ ] Create `.env.example` with safe defaults

## Security Review 🔒
- [ ] Change all default passwords in documentation
- [ ] Remove any hardcoded secrets or API keys
- [ ] Review configuration files for sensitive information
- [ ] Add security notices to documentation
- [ ] Ensure firewall rules don't expose internal networks

## Documentation Review 📚
- [ ] README.md is complete and accurate
- [ ] Installation instructions are clear
- [ ] Usage examples work correctly
- [ ] All dashboard URLs use localhost (appropriate for examples)
- [ ] License file is present and correct
- [ ] Contributing guidelines are included

## Code Quality 🧹
- [ ] Code is properly commented
- [ ] No debug print statements left in code
- [ ] Error handling is appropriate
- [ ] No TODO comments with sensitive information

## Testing 🧪
- [ ] All tests pass: `./scripts/run_tests.sh`
- [ ] Build process works from clean state
- [ ] Docker deployment works: `./scripts/deploy_docker.sh --test`
- [ ] Documentation examples are validated

## Repository Settings ⚙️
- [ ] Choose appropriate visibility (public/private)
- [ ] Add repository description and tags
- [ ] Configure branch protection rules
- [ ] Set up issue templates
- [ ] Add repository topics/tags for discoverability

## Final Steps 🚀
- [ ] Create initial release/tag
- [ ] Write release notes
- [ ] Consider creating a demo video or screenshots
- [ ] Add badges to README (build status, license, etc.)
- [ ] Share with community if appropriate

---
**Note**: This checklist was generated automatically. Review each item carefully before publication.
EOF

# 10. Final validation
echo -e "${BLUE}Running final validation...${NC}"

# Check git status if in a git repository
if [ -d ".git" ]; then
    echo -e "${BLUE}Git repository status:${NC}"
    git status --porcelain | head -10
    
    # Count untracked files
    UNTRACKED_COUNT=$(git status --porcelain | grep "^??" | wc -l)
    if [ "$UNTRACKED_COUNT" -gt 0 ]; then
        echo -e "${YELLOW}⚠️  $UNTRACKED_COUNT untracked files found${NC}"
        echo -e "${BLUE}Consider adding them to .gitignore if they shouldn't be committed${NC}"
    fi
fi

echo ""
echo -e "${GREEN}🎉 GitHub preparation complete!${NC}"
echo ""
echo -e "${BLUE}📋 Next steps:${NC}"
echo -e "1. Review ${YELLOW}GITHUB_PUBLICATION_CHECKLIST.md${NC}"
echo -e "2. Update any documentation as needed"
echo -e "3. Test the build process: ${YELLOW}./scripts/build_project.sh${NC}"
echo -e "4. Run tests: ${YELLOW}./scripts/run_tests.sh${NC}"
echo -e "5. Commit your changes"
echo -e "6. Create your GitHub repository"
echo ""
echo -e "${GREEN}✅ Your project is ready for GitHub publication!${NC}"