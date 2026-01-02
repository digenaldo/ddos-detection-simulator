#!/bin/bash
# Script to test DDoS detection system

set -e

echo "=========================================="
echo "DDoS Detection System Test"
echo "=========================================="
echo ""

# Check if using podman or docker
if command -v podman &> /dev/null; then
    COMPOSE_CMD="podman-compose"
    echo "Using Podman Compose"
elif command -v docker &> /dev/null; then
    COMPOSE_CMD="docker-compose"
    echo "Using Docker Compose"
else
    echo "Error: Neither podman-compose nor docker-compose found"
    exit 1
fi

echo ""
echo "Step 1: Starting services..."
$COMPOSE_CMD up -d server detection

echo ""
echo "Waiting for server to be ready..."
sleep 5

echo ""
echo "Step 2: Checking server health..."
curl -f http://localhost:5050/health || {
    echo "Error: Server is not healthy"
    exit 1
}

echo ""
echo "Step 3: Running DDoS simulation..."
echo "This will generate normal traffic, Slowloris, and Hulk attacks"
echo ""

$COMPOSE_CMD run --rm simulator

echo ""
echo "=========================================="
echo "Test completed!"
echo "=========================================="
echo ""
echo "Check the logs with:"
echo "  $COMPOSE_CMD logs detection"
echo ""
echo "Or view real-time logs:"
echo "  $COMPOSE_CMD logs -f detection"
echo ""
echo "To stop all services:"
echo "  $COMPOSE_CMD down"
echo ""

