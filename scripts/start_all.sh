#!/bin/bash
# Script to start all services

set -e

# Check if using podman or docker
if command -v podman &> /dev/null; then
    COMPOSE_CMD="podman-compose"
    REPLACE_FLAG="--replace"
    echo "Using Podman Compose"
elif command -v docker &> /dev/null; then
    COMPOSE_CMD="docker-compose"
    REPLACE_FLAG=""
    echo "Using Docker Compose"
else
    echo "Error: Neither podman-compose nor docker-compose found"
    exit 1
fi

echo "Starting DDoS Detection System..."
echo ""

# Clean up old containers first
echo "Cleaning up old containers (if any)..."
$COMPOSE_CMD down 2>/dev/null || true

echo ""
# Start server and detection
if [ -n "$REPLACE_FLAG" ]; then
    $COMPOSE_CMD up -d $REPLACE_FLAG server detection
else
    $COMPOSE_CMD up -d server detection
fi

echo ""
echo "Services started!"
echo ""
echo "Server: http://localhost:5050"
echo "Health check: http://localhost:5050/health"
echo ""
echo "View logs:"
echo "  $COMPOSE_CMD logs -f"
echo ""
echo "View detection logs:"
echo "  $COMPOSE_CMD logs -f detection"
echo ""
echo "To run simulation:"
echo "  $COMPOSE_CMD run --rm simulator"
echo ""
echo "To stop all services:"
echo "  $COMPOSE_CMD down"
echo ""

