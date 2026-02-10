#!/bin/bash
#
# DNS Admin Deployment Script
#
# Usage: ./deploy.sh [dns-1|dns-2|dns-3|dns-4|dns-5|all|lxc|chr]
#
# Prerequisites:
# - SSH access as 'dns' user to target servers (dns-1, dns-2)
# - SSH access as 'root' to Proxmox hosts (dns-3, dns-4 in LXC containers)
# - SSH access as 'admin' to Paradox CHR (dns-5 in container)
# - skopeo installed (brew install skopeo) for CHR deployment
# - Server IPs defined in environment or below
#

set -e

# Server configuration - set these or use environment variables
# VM-based DNS servers (QTRN subnet)
DNS1_IP="${DNS1_IP:-23.148.184.39}"
DNS2_IP="${DNS2_IP:-23.148.184.40}"
SSH_USER="${SSH_USER:-dns}"

# LXC-based DNS servers (Proxmox hosts)
DNS3_PVE_IP="${DNS3_PVE_IP:-209.182.235.45}"
DNS4_PVE_IP="${DNS4_PVE_IP:-172.93.55.21}"
DNS3_LXC_VMID="${DNS3_LXC_VMID:-107}"
DNS4_LXC_VMID="${DNS4_LXC_VMID:-108}"
PVE_USER="${PVE_USER:-root}"

# CHR-based DNS server (Paradox)
DNS5_CHR_IP="${DNS5_CHR_IP:-23.154.8.32}"
CHR_USER="${CHR_USER:-admin}"
CHR_CONTAINER_DIR="${CHR_CONTAINER_DIR:-disk1/containers}"
CHR_CONTAINER_NAME="${CHR_CONTAINER_NAME:-dns-server}"
CHR_VETH="${CHR_VETH:-veth-dns}"
CHR_MOUNTLIST="${CHR_MOUNTLIST:-dns-data}"

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

# Deploy to LXC container on Proxmox host
deploy_to_lxc() {
    local pve_ip=$1
    local vmid=$2
    local server_name=$3
    local pve_server="$PVE_USER@$pve_ip"
    
    log "Deploying to $server_name (LXC $vmid on $pve_ip)..."
    
    # Check if container is running
    log "  Checking container status..."
    if ! ssh "$pve_server" "pct status $vmid" | grep -q "running"; then
        error "  ✗ Container $vmid is not running! Start it first: pct start $vmid"
    fi
    
    # Stop service inside container
    log "  Stopping dns-server..."
    ssh "$pve_server" "pct exec $vmid -- systemctl stop dns-server" || true
    
    # Copy binary to Proxmox host first, then into container
    log "  Uploading backend binary..."
    scp "$REPO_DIR/$BINARY_NAME" "$pve_server:/tmp/$BINARY_NAME"
    
    log "  Installing backend binary into container..."
    ssh "$pve_server" "pct push $vmid /tmp/$BINARY_NAME /opt/dns-server/dns-server"
    ssh "$pve_server" "pct exec $vmid -- chmod +x /opt/dns-server/dns-server"
    ssh "$pve_server" "rm /tmp/$BINARY_NAME"
    
    # Deploy frontend - create tarball first for easier transfer (exclude macOS metadata)
    log "  Packaging frontend..."
    cd "$REPO_DIR"
    COPYFILE_DISABLE=1 tar -czf /tmp/dns-frontend.tar.gz -C web/dist/dns-admin/browser .
    
    log "  Uploading frontend..."
    scp /tmp/dns-frontend.tar.gz "$pve_server:/tmp/dns-frontend.tar.gz"
    
    log "  Installing frontend into container..."
    ssh "$pve_server" "pct exec $vmid -- mkdir -p /opt/dns-server/web/dist/dns-admin/browser"
    ssh "$pve_server" "pct exec $vmid -- rm -rf /opt/dns-server/web/dist/dns-admin/browser/*"
    ssh "$pve_server" "pct push $vmid /tmp/dns-frontend.tar.gz /tmp/dns-frontend.tar.gz"
    ssh "$pve_server" "pct exec $vmid -- tar -xzf /tmp/dns-frontend.tar.gz -C /opt/dns-server/web/dist/dns-admin/browser"
    ssh "$pve_server" "pct exec $vmid -- rm /tmp/dns-frontend.tar.gz"
    ssh "$pve_server" "rm /tmp/dns-frontend.tar.gz"
    rm /tmp/dns-frontend.tar.gz
    
    # Remove any macOS metadata files that might have been created
    ssh "$pve_server" "pct exec $vmid -- find /opt/dns-server/web -name '._*' -delete 2>/dev/null" || true
    
    # Start service
    log "  Starting dns-server..."
    ssh "$pve_server" "pct exec $vmid -- systemctl start dns-server"
    
    # Verify
    log "  Verifying deployment..."
    sleep 2
    if ssh "$pve_server" "pct exec $vmid -- systemctl is-active --quiet dns-server"; then
        log "  ✓ Service is running"
    else
        error "  ✗ Service failed to start! Check: ssh $pve_server 'pct exec $vmid -- journalctl -u dns-server -n 50'"
    fi
    
    # Check ports (inside container)
    local ports
    ports=$(ssh "$pve_server" "pct exec $vmid -- ss -tlpn | grep -E '443|53|853' | wc -l")
    if [ "$ports" -ge 3 ]; then
        log "  ✓ All ports listening inside container (53, 443, 853)"
    else
        warn "  ⚠ Some ports may not be listening. Check: ssh $pve_server 'pct exec $vmid -- ss -tlpn'"
    fi
    
    log "  ✓ $server_name deployment complete"
}

# Build Docker image for CHR (MikroTik container)
# Sets DOCKER_IMAGE_TAR to the path of the built tar file
build_docker_image() {
    log "Building Docker image for CHR deployment..."
    cd "$REPO_DIR"
    
    # Check if skopeo is available
    if ! command -v skopeo &> /dev/null; then
        error "skopeo is not installed. Install with: brew install skopeo"
    fi
    
    # Build with buildkit disabled (helps with compatibility)
    log "  Building Docker image..."
    DOCKER_BUILDKIT=0 docker build --platform linux/amd64 -t dns-server:chr .
    
    # MikroTik requires Docker v1 format (layer.tar), not OCI format (blobs/sha256/)
    # Use skopeo to convert from Docker daemon to docker-archive (v1) format
    log "  Converting to Docker v1 format (required for MikroTik)..."
    DOCKER_IMAGE_TAR="/tmp/dns-server-chr.tar"
    rm -f "$DOCKER_IMAGE_TAR"  # Remove old file - skopeo can't overwrite
    skopeo copy docker-daemon:dns-server:chr "docker-archive:$DOCKER_IMAGE_TAR"
    
    log "  Docker image built: $DOCKER_IMAGE_TAR"
}

# Deploy to MikroTik CHR container
deploy_to_chr() {
    local chr_ip=$1
    local server_name=$2
    local chr_server="$CHR_USER@$chr_ip"
    local container_tar="${CHR_CONTAINER_DIR}/${CHR_CONTAINER_NAME}.tar"
    local container_root="${CHR_CONTAINER_DIR}/dns"
    
    log "Deploying to $server_name (CHR container on $chr_ip)..."
    
    # Build Docker image (unless skip-build)
    local tar_path="/tmp/dns-server-chr.tar"
    if [ "$SKIP_BUILD" = false ]; then
        build_docker_image
        tar_path="$DOCKER_IMAGE_TAR"
    else
        if [ ! -f "$tar_path" ]; then
            error "Docker image not found: $tar_path. Run without --skip-build first."
        fi
        log "  Using existing Docker image: $tar_path"
    fi
    
    # Get current container number - check by name OR by root-dir (in case name differs)
    log "  Checking for existing container..."
    local container_num
    container_num=$(ssh "$chr_server" "/container/print where name=\"$CHR_CONTAINER_NAME\"" 2>/dev/null | grep -oE "^[0-9]+" | head -1 || echo "")
    
    # If not found by name, check by root-dir
    if [ -z "$container_num" ]; then
        container_num=$(ssh "$chr_server" "/container/print where root-dir=\"/$container_root\"" 2>/dev/null | grep -oE "^[0-9]+" | head -1 || echo "")
    fi
    
    # Stop existing container
    if [ -n "$container_num" ]; then
        log "  Stopping existing container $container_num..."
        ssh "$chr_server" "/container/stop $container_num" 2>/dev/null || true
        sleep 3
        
        # Wait for container to stop
        local max_wait=30
        local waited=0
        while [ $waited -lt $max_wait ]; do
            local status
            status=$(ssh "$chr_server" "/container/print proplist=status where .id=$container_num" 2>/dev/null | grep -oE "(stopped|running|extracting)" | head -1 || echo "stopped")
            if [ "$status" = "stopped" ] || [ -z "$status" ]; then
                break
            fi
            log "  Waiting for container to stop... ($status)"
            sleep 2
            waited=$((waited + 2))
        done
        
        log "  Removing old container..."
        ssh "$chr_server" "/container/remove $container_num" 2>/dev/null || true
        sleep 2
    fi
    
    # Remove old container files (but keep data!)
    log "  Cleaning old container files (preserving data)..."
    ssh "$chr_server" "/file/remove \"$container_tar\"" 2>/dev/null || true
    # Note: We do NOT remove $container_root - it may contain the database!
    
    # Upload new image
    log "  Uploading Docker image..."
    scp "$tar_path" "$chr_server:/$container_tar"
    
    # Wait for file to be ready
    sleep 2
    
    # Create new container
    log "  Creating container..."
    ssh "$chr_server" "/container/add file=$container_tar interface=$CHR_VETH root-dir=$container_root name=$CHR_CONTAINER_NAME"
    
    # Wait for container extraction
    log "  Waiting for container extraction..."
    local max_wait=60
    local waited=0
    while [ $waited -lt $max_wait ]; do
        local status
        status=$(ssh "$chr_server" "/container/print proplist=status where name=\"$CHR_CONTAINER_NAME\"" 2>/dev/null | grep -oE "(stopped|running|extracting|error)" | head -1 || echo "")
        if [ "$status" = "stopped" ]; then
            log "  Container extracted (status: stopped)"
            break
        elif [ "$status" = "extracting" ]; then
            log "  Container extracting..."
        elif [ "$status" = "error" ]; then
            error "  Container extraction failed! Check: ssh $chr_server '/container/print detail'"
        fi
        sleep 3
        waited=$((waited + 3))
    done
    
    # Get new container number
    container_num=$(ssh "$chr_server" "/container/print where name=\"$CHR_CONTAINER_NAME\"" 2>/dev/null | grep -oE "^[0-9]+" | head -1)
    if [ -z "$container_num" ]; then
        error "Could not find container after creation. Check: ssh $chr_server '/container/print'"
    fi
    
    # Configure container
    log "  Configuring container $container_num..."
    ssh "$chr_server" "/container/set $container_num mountlists=$CHR_MOUNTLIST start-on-boot=yes logging=yes"
    
    # Start container
    log "  Starting container..."
    ssh "$chr_server" "/container/start $container_num"
    
    # Brief pause for container to initialize
    sleep 1
    
    # Verify container is running
    log "  Verifying deployment..."
    local status_line
    # MikroTik uses single letter flags: S=stopped, N=starting, R=running, T=stopping, E=extracting, F=failed
    status_line=$(ssh "$chr_server" "/container/print brief where name=\"$CHR_CONTAINER_NAME\"" 2>/dev/null | grep -E "^\s*[0-9]" | head -1 || echo "")
    if echo "$status_line" | grep -q "^[0-9 ]*R"; then
        log "  ✓ Container is running"
    else
        error "  ✗ Container failed to start. Status: $status_line. Check: ssh $chr_server '/container/print detail'"
    fi
    
    # Check health endpoint
    log "  Checking health endpoint..."
    if curl -s -k --connect-timeout 5 "https://$chr_ip/api/health" | grep -q "dns"; then
        log "  ✓ API responding"
    else
        warn "  ⚠ API not responding yet. It may take a moment to start."
    fi
    
    # Clean up local temp file
    rm -f "$tar_path"
    
    log "  ✓ $server_name deployment complete"
}

show_usage() {
    echo "Usage: $0 [dns-1|dns-2|dns-3|dns-4|dns-5|all|vms|lxc|chr] [--skip-build]"
    echo ""
    echo "Targets:"
    echo "  dns-1        Deploy to DNS server 1 only (VM - $DNS1_IP)"
    echo "  dns-2        Deploy to DNS server 2 only (VM - $DNS2_IP)"
    echo "  dns-3        Deploy to DNS server 3 only (LXC $DNS3_LXC_VMID on $DNS3_PVE_IP)"
    echo "  dns-4        Deploy to DNS server 4 only (LXC $DNS4_LXC_VMID on $DNS4_PVE_IP)"
    echo "  dns-5        Deploy to DNS server 5 only (CHR container on $DNS5_CHR_IP)"
    echo "  vms          Deploy to VM-based servers only (dns-1, dns-2)"
    echo "  lxc          Deploy to LXC-based servers only (dns-3, dns-4)"
    echo "  chr          Deploy to CHR container only (dns-5)"
    echo "  all          Deploy to all servers (default)"
    echo ""
    echo "Options:"
    echo "  --skip-build Skip building and deploy existing artifacts"
    echo ""
    echo "Environment variables:"
    echo "  DNS1_IP      IP address of DNS server 1 (default: $DNS1_IP)"
    echo "  DNS2_IP      IP address of DNS server 2 (default: $DNS2_IP)"
    echo "  DNS3_PVE_IP  Proxmox host IP for DNS server 3 (default: $DNS3_PVE_IP)"
    echo "  DNS4_PVE_IP  Proxmox host IP for DNS server 4 (default: $DNS4_PVE_IP)"
    echo "  DNS3_LXC_VMID LXC VMID for DNS server 3 (default: $DNS3_LXC_VMID)"
    echo "  DNS4_LXC_VMID LXC VMID for DNS server 4 (default: $DNS4_LXC_VMID)"
    echo "  DNS5_CHR_IP  Paradox CHR IP for DNS server 5 (default: $DNS5_CHR_IP)"
    echo "  SSH_USER     SSH user for VM deployment (default: $SSH_USER)"
    echo "  PVE_USER     SSH user for Proxmox hosts (default: $PVE_USER)"
    echo "  CHR_USER     SSH user for CHR deployment (default: $CHR_USER)"
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
    dns-1|dns-2|dns-3|dns-4|dns-5|all|vms|lxc|chr) ;;
    --skip-build) TARGET="all" ;;
    *) error "Unknown target: $TARGET. Use dns-1, dns-2, dns-3, dns-4, dns-5, vms, lxc, chr, or all" ;;
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
    dns-3)
        deploy_to_lxc "$DNS3_PVE_IP" "$DNS3_LXC_VMID" "dns-3"
        ;;
    dns-4)
        deploy_to_lxc "$DNS4_PVE_IP" "$DNS4_LXC_VMID" "dns-4"
        ;;
    dns-5)
        deploy_to_chr "$DNS5_CHR_IP" "dns-5"
        ;;
    vms)
        deploy_to_server "$DNS1_IP" "dns-1"
        deploy_to_server "$DNS2_IP" "dns-2"
        ;;
    lxc)
        deploy_to_lxc "$DNS3_PVE_IP" "$DNS3_LXC_VMID" "dns-3"
        deploy_to_lxc "$DNS4_PVE_IP" "$DNS4_LXC_VMID" "dns-4"
        ;;
    chr)
        deploy_to_chr "$DNS5_CHR_IP" "dns-5"
        ;;
    all)
        deploy_to_server "$DNS1_IP" "dns-1"
        deploy_to_server "$DNS2_IP" "dns-2"
        deploy_to_lxc "$DNS3_PVE_IP" "$DNS3_LXC_VMID" "dns-3"
        deploy_to_lxc "$DNS4_PVE_IP" "$DNS4_LXC_VMID" "dns-4"
        deploy_to_chr "$DNS5_CHR_IP" "dns-5"
        ;;
esac

log "=========================================="
log "Deployment complete!"
log "=========================================="
