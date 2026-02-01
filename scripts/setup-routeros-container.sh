#!/bin/bash
set -e

# RouterOS Container Setup Script
# This script sets up the container environment on RouterOS 7

ROUTER_HOST="${ROUTER_HOST:-45.32.76.204}"
ROUTER_USER="${ROUTER_USER:-admin}"
CONTAINER_NAME="dns-server"

echo "=========================================="
echo "Setting up Container Environment on RouterOS 7"
echo "Router: ${ROUTER_USER}@${ROUTER_HOST}"
echo "=========================================="

ssh ${ROUTER_USER}@${ROUTER_HOST} << 'ENDSSH'
# Enable container mode if not already enabled
/system/device-mode/update container=yes

# Create a bridge for containers if it doesn't exist
:if ([:len [/interface bridge find name="docker"]] = 0) do={
    /interface bridge add name=docker
    /ip address add address=172.17.0.1/24 interface=docker
}

# Create veth interface for the DNS container
:if ([:len [/interface veth find name="veth-dns"]] = 0) do={
    /interface veth add name=veth-dns address=172.17.0.2/24 gateway=172.17.0.1
    /interface bridge port add bridge=docker interface=veth-dns
}

# Add firewall rules to allow DNS traffic to container
/ip firewall nat
:if ([:len [find comment="dns-container-udp"]] = 0) do={
    add chain=dstnat dst-port=53 protocol=udp action=dst-nat to-addresses=172.17.0.2 to-ports=53 comment="dns-container-udp"
}
:if ([:len [find comment="dns-container-tcp"]] = 0) do={
    add chain=dstnat dst-port=53 protocol=tcp action=dst-nat to-addresses=172.17.0.2 to-ports=53 comment="dns-container-tcp"
}

# Allow container to access internet (for recursion)
:if ([:len [find comment="dns-container-masq"]] = 0) do={
    add chain=srcnat src-address=172.17.0.0/24 action=masquerade comment="dns-container-masq"
}

# Create container directories
/container config set registry-url=https://registry-1.docker.io tmpdir=container/tmp

:put ""
:put "Container environment setup complete!"
:put ""
:put "Network configuration:"
:put "  Container IP: 172.17.0.2"
:put "  Gateway: 172.17.0.1"
:put "  Bridge: docker"
:put ""
:put "NOTE: If this is the first time enabling container mode,"
:put "      the router will need to be rebooted."
ENDSSH

echo ""
echo "Setup complete!"
echo ""
echo "If container mode was just enabled, reboot the router with:"
echo "  ssh ${ROUTER_USER}@${ROUTER_HOST} '/system reboot'"
