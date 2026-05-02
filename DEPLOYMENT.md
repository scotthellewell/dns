# Deployment Guide

This document describes how to deploy the DNS Admin system to production servers.

## Prerequisites

- SSH access to target servers (as non-root user with sudo privileges)
- Go 1.21+ installed locally for building
- Node.js 18+ and npm for building the frontend
- The `dns` user on target servers with appropriate directory structure

## Server Directory Structure

Each server should have the following structure:

```
/home/dns/dns/
├── dns-linux-amd64        # The server binary
├── data/
│   └── data.db           # SQLite database (auto-created)
└── web/
    └── dist/
        └── dns-admin/
            └── browser/  # Frontend files go here
                ├── index.html
                ├── main-*.js
                ├── chunk-*.js
                ├── styles-*.css
                └── favicon.svg
```

## Systemd Service Configuration

The service is configured in `/etc/systemd/system/dns-server.service`:

```ini
[Unit]
Description=DNS Server
After=network.target

[Service]
Type=simple
User=dns
WorkingDirectory=/home/dns/dns
ExecStart=/home/dns/dns/dns-linux-amd64 -data /home/dns/dns/data
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

## Building

### Backend

Cross-compile for Linux AMD64:

```bash
cd /path/to/dns
GOOS=linux GOARCH=amd64 go build -o dns-linux-amd64 .
```

### Frontend

Build the Angular application:

```bash
cd /path/to/dns/web
npm run build
```

The build output is in `web/dist/dns-admin/browser/`.

## Deployment Steps

### 1. Stop the Service (to allow binary replacement)

```bash
ssh dns@<SERVER_IP> "sudo systemctl stop dns-server"
```

### 2. Deploy Backend Binary

```bash
# Upload to home directory
scp dns-linux-amd64 dns@<SERVER_IP>:/home/dns/dns-linux-amd64.new

# Move to correct location
ssh dns@<SERVER_IP> "mv /home/dns/dns-linux-amd64.new /home/dns/dns/dns-linux-amd64"

# Ensure executable
ssh dns@<SERVER_IP> "chmod +x /home/dns/dns/dns-linux-amd64"
```

### 3. Set Required Capabilities (after each binary replacement)

The binary needs capability to bind to privileged ports (53, 443, 853):

```bash
ssh dns@<SERVER_IP> "sudo setcap 'cap_net_bind_service=+ep' /home/dns/dns/dns-linux-amd64"
```

**⚠️ IMPORTANT:** This step must be repeated every time the binary is replaced!

### 4. Deploy Frontend

```bash
# Clear old files
ssh dns@<SERVER_IP> "rm -rf /home/dns/dns/web/dist/dns-admin/browser/*"

# Upload new files (note: must be in the browser/ subdirectory!)
scp -r web/dist/dns-admin/browser/* dns@<SERVER_IP>:/home/dns/dns/web/dist/dns-admin/browser/
```

### 5. Start the Service

```bash
ssh dns@<SERVER_IP> "sudo systemctl start dns-server"
```

### 6. Verify Deployment

Check service status:

```bash
ssh dns@<SERVER_IP> "sudo systemctl status dns-server"
```

Verify ports are listening:

```bash
ssh dns@<SERVER_IP> "sudo ss -tlpn | grep -E '443|53|853'"
```

Expected output:
```
LISTEN 0 4096 *:53  *:* users:(("dns-linux-amd64",...))
LISTEN 0 4096 *:853 *:* users:(("dns-linux-amd64",...))
LISTEN 0 4096 *:443 *:* users:(("dns-linux-amd64",...))
```

Check logs for errors:

```bash
ssh dns@<SERVER_IP> "sudo journalctl -u dns-server -n 20"
```

## Full Deployment Script (Single Server)

Here's a complete deployment script for one server:

```bash
#!/bin/bash
set -e

SERVER="dns@<SERVER_IP>"
REPO_DIR="/path/to/dns"

cd "$REPO_DIR"

# Build
echo "Building backend..."
GOOS=linux GOARCH=amd64 go build -o dns-linux-amd64 .

echo "Building frontend..."
cd web && npm run build && cd ..

# Deploy
echo "Stopping service..."
ssh $SERVER "sudo systemctl stop dns-server"

echo "Deploying backend..."
scp dns-linux-amd64 $SERVER:/home/dns/dns-linux-amd64.new
ssh $SERVER "mv /home/dns/dns-linux-amd64.new /home/dns/dns/dns-linux-amd64 && chmod +x /home/dns/dns/dns-linux-amd64"

echo "Setting capabilities..."
ssh $SERVER "sudo setcap 'cap_net_bind_service=+ep' /home/dns/dns/dns-linux-amd64"

echo "Deploying frontend..."
ssh $SERVER "rm -rf /home/dns/dns/web/dist/dns-admin/browser/*"
scp -r web/dist/dns-admin/browser/* $SERVER:/home/dns/dns/web/dist/dns-admin/browser/

echo "Starting service..."
ssh $SERVER "sudo systemctl start dns-server"

echo "Checking status..."
ssh $SERVER "sudo systemctl status dns-server --no-pager"
ssh $SERVER "sudo ss -tlpn | grep -E '443|53|853'"

echo "Deployment complete!"
```

## Troubleshooting

### "permission denied" when binding to ports

The binary needs the `cap_net_bind_service` capability. Run:
```bash
sudo setcap 'cap_net_bind_service=+ep' /home/dns/dns/dns-linux-amd64
```

### 404 for web UI

Check that files are in the correct directory:
```bash
ls -la /home/dns/dns/web/dist/dns-admin/browser/
```

The server expects files in `web/dist/dns-admin/browser/` relative to the working directory.

### Service won't start

Check the journal for errors:
```bash
sudo journalctl -u dns-server -n 50
```

### Sync between servers failing

Check that both servers can reach each other on port 443 (HTTPS/WSS). The sync uses websockets over HTTPS.

## Multi-Server Deployment

Use the automated deploy script for all servers:

```bash
# Deploy to all 5 servers (parallel where possible)
./scripts/deploy.sh all

# Deploy to individual servers
./scripts/deploy.sh dns-1
./scripts/deploy.sh dns-3
```

The script handles building, deploying, capabilities, health checks, and service management automatically. It deploys dns-1/dns-2 in parallel, then dns-3/dns-4 in parallel, then dns-5.

### Current Production Servers

| Server | Type | IP | Host | Binary Path |
|--------|------|----|------|------------|
| dns-1 | VM 105 | 23.148.184.39 | ssdnode-1 | /home/dns/dns/dns-linux-amd64 |
| dns-2 | VM 106 | 23.148.184.40 | ssdnode-2 | /home/dns/dns/dns-linux-amd64 |
| dns-3 | LXC 107 | 209.182.235.45 | ssdnode-1 | /opt/dns-server/dns-server |
| dns-4 | LXC 108 | 172.93.55.21 | ssdnode-2 | /opt/dns-server/dns-server |
| dns-5 | Container | 23.154.8.32 | Paradox CHR | /app/dns-server (Docker) |

### Protection Layers

All servers have multi-layer DDoS protection:
1. **IP Block** — Static block lists at host firewall (iptables/RouterOS)
2. **Rate Limit** — Per-IP hashlimit (3-5 qps) at host firewall
3. **Auto-Ban** — RouterOS auto-bans IPs exceeding thresholds (24h)
4. **RRL** — Application-level Response Rate Limiting (5 resp/sec/client)

See `network/docs/firewall.md` for full firewall documentation.

### Health Checks

All servers run `dns-health-check.timer` (systemd timer, every 5 minutes) that auto-restarts the DNS server if queries fail.

### RRL Configuration

Response Rate Limiting is managed via API:
```bash
# Get current config
curl -sk -H "X-API-Key: <key>" https://<server>/api/rrl

# Update config
curl -sk -X PUT -H "X-API-Key: <key>" -H "Content-Type: application/json" \
  -d '{"enabled":true,"responses_per_sec":5,"slip_ratio":2,"window_seconds":1}' \
  https://<server>/api/rrl
```
