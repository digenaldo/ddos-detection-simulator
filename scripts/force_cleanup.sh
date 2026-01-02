#!/bin/bash
# Force cleanup script - removes all containers even if they're running

# Check if using podman or docker
if command -v podman &> /dev/null; then
    CONTAINER_CMD="podman"
    COMPOSE_CMD="podman-compose"
elif command -v docker &> /dev/null; then
    CONTAINER_CMD="docker"
    COMPOSE_CMD="docker-compose"
else
    echo "Error: Neither podman nor docker found"
    exit 1
fi

echo "Force cleaning up DDoS Detection containers..."
echo ""

# Stop all containers first
echo "1. Stopping containers..."
$CONTAINER_CMD stop ddos-server ddos-detection ddos-simulator 2>/dev/null || true

# Remove using compose
echo "2. Removing with compose..."
$COMPOSE_CMD down 2>/dev/null || true

# Force remove by name
echo "3. Force removing containers by name..."
$CONTAINER_CMD rm -f ddos-server ddos-detection ddos-simulator 2>/dev/null || true

# Remove any containers with project prefix
echo "4. Removing containers with project prefix..."
$CONTAINER_CMD ps -a --filter "name=ddos-detection-simulator" --format "{{.Names}}" 2>/dev/null | while read name; do
    if [ -n "$name" ]; then
        echo "   Removing: $name"
        $CONTAINER_CMD rm -f "$name" 2>/dev/null || true
    fi
done

# Remove any containers with ddos in the name
echo "5. Removing any remaining ddos containers..."
$CONTAINER_CMD ps -a --filter "name=ddos" --format "{{.Names}}" 2>/dev/null | while read name; do
    if [ -n "$name" ]; then
        echo "   Removing: $name"
        $CONTAINER_CMD rm -f "$name" 2>/dev/null || true
    fi
done

echo ""
echo "✅ Force cleanup complete!"
echo ""
echo "To verify, run: $CONTAINER_CMD ps -a | grep ddos"

