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

For HA deployments with multiple servers, repeat the deployment steps for each server. The servers will automatically sync data via their peer connections once running.

### Current Production Servers

Servers are configured in the application's config and use hostnames like:
- `dns-1.<domain>/sync`
- `dns-2.<domain>/sync`

The sync endpoint is WebSocket over HTTPS (wss://).
