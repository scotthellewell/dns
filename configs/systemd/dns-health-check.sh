#!/bin/bash
# DNS health check - restarts dns-server if DNS queries fail
# Deployed by deploy.sh, triggered by dns-health-check.timer every 5 minutes

check_dns() {
    # Use 'host' (universally available) instead of 'dig' (not on VMs)
    host -W 3 localhost 127.0.0.1 > /dev/null 2>&1
}

if ! check_dns; then
    echo "$(date): DNS check failed, retrying in 10s..."
    sleep 10
    if ! check_dns; then
        echo "$(date): DNS check failed again, restarting dns-server..."
        systemctl restart dns-server
    fi
fi
