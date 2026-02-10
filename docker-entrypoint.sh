#!/bin/sh
# Docker entrypoint script that configures IPv6 via SLAAC or static assignment

# Enable IPv6 if available
if [ -d /proc/sys/net/ipv6 ]; then
    # Enable IPv6 forwarding and accept RA
    echo 1 > /proc/sys/net/ipv6/conf/all/accept_ra 2>/dev/null || true
    echo 2 > /proc/sys/net/ipv6/conf/eth0/accept_ra 2>/dev/null || true
    
    # If IPV6_ADDRESS is set, configure it statically
    if [ -n "$IPV6_ADDRESS" ]; then
        echo "Configuring static IPv6 address: $IPV6_ADDRESS"
        ip -6 addr add "$IPV6_ADDRESS" dev eth0 2>/dev/null || true
    fi
    
    # If IPV6_GATEWAY is set, add default route
    if [ -n "$IPV6_GATEWAY" ]; then
        echo "Configuring IPv6 gateway: $IPV6_GATEWAY"
        ip -6 route add default via "$IPV6_GATEWAY" dev eth0 2>/dev/null || true
    fi
    
    # Wait a moment for SLAAC if no static address was configured
    if [ -z "$IPV6_ADDRESS" ]; then
        echo "Waiting for SLAAC..."
        sleep 3
    fi
    
    # Show IPv6 configuration
    echo "IPv6 addresses:"
    ip -6 addr show dev eth0 2>/dev/null || true
fi

# Execute the DNS server
exec /app/dns-server "$@"
