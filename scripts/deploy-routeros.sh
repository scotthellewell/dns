#!/bin/bash
set -e

# Configuration
IMAGE_NAME="dns-server"
IMAGE_TAG="${1:-latest}"
ARCH="${2:-arm64}"  # Default to arm64 for RouterOS on ARM
ROUTER_HOST="${ROUTER_HOST:-45.32.76.204}"
ROUTER_USER="${ROUTER_USER:-admin}"
CONTAINER_NAME="dns-server"

# Paths on RouterOS
CONTAINER_ROOT="/container"
CONTAINER_STORE="${CONTAINER_ROOT}/store"
CONTAINER_DATA="${CONTAINER_ROOT}/${CONTAINER_NAME}"

echo "=========================================="
echo "Deploying DNS Server to RouterOS 7"
echo "Router: ${ROUTER_USER}@${ROUTER_HOST}"
echo "Architecture: ${ARCH}"
echo "=========================================="

# Build for the specific architecture and save as tar
echo ""
echo "Building image for ${ARCH}..."
docker buildx build \
    --platform linux/${ARCH} \
    --load \
    -t ${IMAGE_NAME}:${IMAGE_TAG} \
    -f Dockerfile \
    .

# Save the image to a tar file
TAR_FILE="${IMAGE_NAME}-${ARCH}.tar"
echo ""
echo "Exporting image to ${TAR_FILE}..."
docker save ${IMAGE_NAME}:${IMAGE_TAG} -o ${TAR_FILE}

# Compress the tar file
echo "Compressing image..."
gzip -f ${TAR_FILE}
TAR_FILE="${TAR_FILE}.gz"

echo ""
echo "Image size: $(du -h ${TAR_FILE} | cut -f1)"

# Create directory structure on router
echo ""
echo "Creating directory structure on router..."
ssh ${ROUTER_USER}@${ROUTER_HOST} << 'ENDSSH'
# Create container directories if they don't exist
/file print
:if ([:len [/file find name="container"]] = 0) do={
    /tool fetch url="https://127.0.0.1/" dst-path="container/.create" 
    /file remove "container/.create"
}
ENDSSH

# Copy the image to the router
echo ""
echo "Copying image to router (this may take a while)..."
scp ${TAR_FILE} ${ROUTER_USER}@${ROUTER_HOST}:/${TAR_FILE}

# Deploy on RouterOS
echo ""
echo "Deploying container on RouterOS..."
ssh ${ROUTER_USER}@${ROUTER_HOST} << ENDSSH
# Stop and remove existing container if it exists
:do {
    /container stop [find name="${CONTAINER_NAME}"]
    :delay 3s
    /container remove [find name="${CONTAINER_NAME}"]
} on-error={}

# Create mount points for persistent data
/container mounts
:do { add name="${CONTAINER_NAME}-data" src="${CONTAINER_DATA}/data" dst="/app/data" } on-error={}
:do { add name="${CONTAINER_NAME}-cache" src="${CONTAINER_DATA}/cache" dst="/app/cache" } on-error={}
:do { add name="${CONTAINER_NAME}-keys" src="${CONTAINER_DATA}/keys" dst="/app/keys" } on-error={}

# Add the container from the uploaded tar
/container
add file="${TAR_FILE}" interface=veth-dns root-dir="${CONTAINER_STORE}/${CONTAINER_NAME}" \
    mounts="${CONTAINER_NAME}-data,${CONTAINER_NAME}-cache,${CONTAINER_NAME}-keys" \
    start-on-boot=yes logging=yes

# Wait for extraction
:delay 10s

# Start the container
start [find name="${CONTAINER_NAME}"]

:put "Container deployed successfully!"
ENDSSH

# Clean up local tar file
rm -f ${TAR_FILE}

echo ""
echo "=========================================="
echo "Deployment complete!"
echo ""
echo "Container Status:"
ssh ${ROUTER_USER}@${ROUTER_HOST} "/container print where name=\"${CONTAINER_NAME}\""
echo ""
echo "To view logs: ssh ${ROUTER_USER}@${ROUTER_HOST} '/container log ${CONTAINER_NAME}'"
echo "To stop: ssh ${ROUTER_USER}@${ROUTER_HOST} '/container stop [find name=${CONTAINER_NAME}]'"
echo "To start: ssh ${ROUTER_USER}@${ROUTER_HOST} '/container start [find name=${CONTAINER_NAME}]'"
echo "=========================================="
