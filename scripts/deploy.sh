#!/bin/bash
#
# DNS Admin Deployment Script
#
# Usage: ./deploy.sh [dns-1|dns-2|all]
#
# Prerequisites:
# - SSH access as 'dns' user to target servers
# - Server IPs defined in environment or below
#

set -e

# Server configuration - set these or use environment variables
DNS1_IP="${DNS1_IP:-23.148.184.39}"
DNS2_IP="${DNS2_IP:-23.148.184.40}"
SSH_USER="${SSH_USER:-dns}"

# Paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
BINARY_NAME="dns-linux-amd64"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

build_backend() {
    log "Building backend for Linux AMD64..."
    cd "$REPO_DIR"
    GOOS=linux GOARCH=amd64 go build -o "$BINARY_NAME" .
    log "Backend built successfully: $BINARY_NAME"
}

build_frontend() {
    log "Building frontend..."
    cd "$REPO_DIR/web"
    npm run build
    log "Frontend built successfully"
}

deploy_to_server() {
    local server_ip=$1
    local server_name=$2
    local server="$SSH_USER@$server_ip"
    
    log "Deploying to $server_name ($server_ip)..."
    
    # Stop service
    log "  Stopping dns-server..."
    ssh "$server" "sudo systemctl stop dns-server" || true
    
    # Deploy backend
    log "  Uploading backend binary..."
    scp "$REPO_DIR/$BINARY_NAME" "$server:/home/dns/$BINARY_NAME.new"
    
    log "  Installing backend binary..."
    ssh "$server" "mv /home/dns/$BINARY_NAME.new /home/dns/dns/$BINARY_NAME && chmod +x /home/dns/dns/$BINARY_NAME"
    
    # Set capabilities
    log "  Setting capabilities for privileged ports..."
    ssh "$server" "sudo setcap 'cap_net_bind_service=+ep' /home/dns/dns/$BINARY_NAME"
    
    # Deploy frontend
    log "  Deploying frontend..."
    ssh "$server" "rm -rf /home/dns/dns/web/dist/dns-admin/browser/*"
    ssh "$server" "mkdir -p /home/dns/dns/web/dist/dns-admin/browser"
    scp -r "$REPO_DIR/web/dist/dns-admin/browser/"* "$server:/home/dns/dns/web/dist/dns-admin/browser/"
    
    # Start service
    log "  Starting dns-server..."
    ssh "$server" "sudo systemctl start dns-server"
    
    # Verify
    log "  Verifying deployment..."
    sleep 2
    if ssh "$server" "sudo systemctl is-active --quiet dns-server"; then
        log "  ✓ Service is running"
    else
        error "  ✗ Service failed to start! Check: ssh $server 'sudo journalctl -u dns-server -n 50'"
    fi
    
    # Check ports
    local ports
    ports=$(ssh "$server" "sudo ss -tlpn | grep -E '443|53|853' | wc -l")
    if [ "$ports" -ge 3 ]; then
        log "  ✓ All ports listening (53, 443, 853)"
    else
        warn "  ⚠ Some ports may not be listening. Check: ssh $server 'sudo ss -tlpn | grep -E \"443|53|853\"'"
    fi
    
    log "  ✓ $server_name deployment complete"
}

show_usage() {
    echo "Usage: $0 [dns-1|dns-2|all] [--skip-build]"
    echo ""
    echo "Options:"
    echo "  dns-1        Deploy to DNS server 1 only ($DNS1_IP)"
    echo "  dns-2        Deploy to DNS server 2 only ($DNS2_IP)"
    echo "  all          Deploy to all servers (default)"
    echo "  --skip-build Skip building and deploy existing artifacts"
    echo ""
    echo "Environment variables:"
    echo "  DNS1_IP      IP address of DNS server 1 (default: $DNS1_IP)"
    echo "  DNS2_IP      IP address of DNS server 2 (default: $DNS2_IP)"
    echo "  SSH_USER     SSH user for deployment (default: $SSH_USER)"
}

# Parse arguments
TARGET="${1:-all}"
SKIP_BUILD=false

for arg in "$@"; do
    case $arg in
        --skip-build) SKIP_BUILD=true ;;
        --help|-h) show_usage; exit 0 ;;
    esac
done

# Validate target
case $TARGET in
    dns-1|dns-2|all) ;;
    --skip-build) TARGET="all" ;;
    *) error "Unknown target: $TARGET. Use dns-1, dns-2, or all" ;;
esac

# Build
if [ "$SKIP_BUILD" = false ]; then
    build_backend
    build_frontend
else
    log "Skipping build (--skip-build specified)"
    if [ ! -f "$REPO_DIR/$BINARY_NAME" ]; then
        error "Backend binary not found: $REPO_DIR/$BINARY_NAME"
    fi
    if [ ! -d "$REPO_DIR/web/dist/dns-admin/browser" ]; then
        error "Frontend build not found: $REPO_DIR/web/dist/dns-admin/browser"
    fi
fi

# Deploy
case $TARGET in
    dns-1)
        deploy_to_server "$DNS1_IP" "dns-1"
        ;;
    dns-2)
        deploy_to_server "$DNS2_IP" "dns-2"
        ;;
    all)
        deploy_to_server "$DNS1_IP" "dns-1"
        deploy_to_server "$DNS2_IP" "dns-2"
        ;;
esac

log "=========================================="
log "Deployment complete!"
log "=========================================="
