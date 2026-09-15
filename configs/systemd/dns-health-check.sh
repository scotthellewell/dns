#!/bin/bash
# DNS health check - restarts dns-server if DNS queries fail
# Deployed by deploy.sh, triggered by dns-health-check.timer every 5 minutes
#
# The probe must use a name this server actually answers for. A previous
# version probed "localhost", which the resolver has no record for, so it
# returned NXDOMAIN (exit 1) on a perfectly healthy server and restarted
# dns-server every 5 minutes, flushing the cache each time.
#
# We probe the SOA of a zone we are authoritative for: that confirms the
# process is alive and answering without depending on upstream recursion,
# so an upstream outage cannot trigger a spurious restart.

PROBE_ZONE="${PROBE_ZONE:-quicktechresults.com}"

check_dns() {
    # Authoritative SOA - no recursion required.
    host -W 3 -t SOA "$PROBE_ZONE" 127.0.0.1 > /dev/null 2>&1 && return 0
    # Secondary probe in case the zone was renamed/removed: NS of root.
    host -W 3 -t NS . 127.0.0.1 > /dev/null 2>&1 && return 0
    return 1
}

if ! check_dns; then
    echo "$(date): DNS check failed, retrying in 10s..."
    sleep 10
    if ! check_dns; then
        echo "$(date): DNS check failed again, restarting dns-server..."
        systemctl restart dns-server
    fi
fi
