#!/bin/bash
# Script to clean up old containers and images

# Check if using podman or docker
if command -v podman &> /dev/null; then
    COMPOSE_CMD="podman-compose"
    CONTAINER_CMD="podman"
elif command -v docker &> /dev/null; then
    COMPOSE_CMD="docker-compose"
    CONTAINER_CMD="docker"
else
    echo "Error: Neither podman nor docker found"
    exit 1
fi

echo "Cleaning up DDoS Detection containers..."

# Stop and remove containers
$COMPOSE_CMD down 2>/dev/null || true

# Remove containers by name (in case compose didn't catch them)
$CONTAINER_CMD rm -f ddos-server ddos-detection ddos-simulator 2>/dev/null || true

echo "Cleanup complete!"
echo ""
echo "To remove images as well, run:"
echo "  $CONTAINER_CMD rmi ddos-detection-simulator_server ddos-detection-simulator_detection ddos-detection-simulator_simulator"

