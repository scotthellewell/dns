#!/bin/bash
set -e

# Configuration
IMAGE_NAME="dns-server"
IMAGE_TAG="${1:-latest}"
REGISTRY="${DOCKER_REGISTRY:-}"  # Optional registry prefix
ROUTER_HOST="45.32.76.204"
ROUTER_USER="admin"
ROUTER_CONTAINER_PATH="/container"

# Full image name
if [ -n "$REGISTRY" ]; then
    FULL_IMAGE="${REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG}"
else
    FULL_IMAGE="${IMAGE_NAME}:${IMAGE_TAG}"
fi

echo "=========================================="
echo "Building DNS Server Docker Image"
echo "Image: ${FULL_IMAGE}"
echo "Architectures: linux/amd64, linux/arm64"
echo "=========================================="

# Ensure buildx is available and create a builder if needed
if ! docker buildx inspect multiarch-builder &>/dev/null; then
    echo "Creating multi-architecture builder..."
    docker buildx create --name multiarch-builder --driver docker-container --use
fi

docker buildx use multiarch-builder

# Build for both architectures
echo ""
echo "Building multi-architecture image..."
docker buildx build \
    --platform linux/amd64,linux/arm64 \
    --tag "${FULL_IMAGE}" \
    --file Dockerfile \
    .

echo ""
echo "Build complete!"
echo ""
echo "To load a specific architecture locally:"
echo "  docker buildx build --platform linux/amd64 --load -t ${IMAGE_NAME}:${IMAGE_TAG} ."
echo "  docker buildx build --platform linux/arm64 --load -t ${IMAGE_NAME}:${IMAGE_TAG}-arm64 ."
echo ""
echo "To push to a registry:"
echo "  docker buildx build --platform linux/amd64,linux/arm64 --push -t ${FULL_IMAGE} ."
