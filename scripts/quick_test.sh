#!/bin/bash
# Quick test script for DDoS detection

set -e

echo "=========================================="
echo "Quick DDoS Detection Test"
echo "=========================================="
echo ""

# Check if using podman or docker
if command -v podman &> /dev/null; then
    COMPOSE_CMD="podman-compose"
    echo "✓ Using Podman Compose"
elif command -v docker &> /dev/null; then
    COMPOSE_CMD="docker-compose"
    echo "✓ Using Docker Compose"
else
    echo "✗ Error: Neither podman-compose nor docker-compose found"
    echo "  Please install podman-compose or docker-compose"
    exit 1
fi

echo ""
echo "Step 1: Cleaning up old containers (if any)..."
$COMPOSE_CMD down 2>/dev/null || true

echo ""
echo "Step 2: Building images..."
$COMPOSE_CMD build

echo ""
echo "Step 3: Starting server and detection system..."
$COMPOSE_CMD up -d server detection

echo ""
echo "Waiting for services to be ready..."
sleep 8

echo ""
echo "Step 4: Checking server health..."
if curl -f -s http://localhost:5050/health > /dev/null; then
    echo "✓ Server is healthy"
else
    echo "✗ Server health check failed"
    echo "  Check logs: $COMPOSE_CMD logs server"
    exit 1
fi

echo ""
echo "Step 5: Running DDoS attack simulation..."
echo "  This will generate:"
echo "    - Normal traffic (10 threads)"
echo "    - Slowloris attack (5 threads)"
echo "    - Hulk attack (5 threads)"
echo ""

# Ensure server is running before running simulator (idempotent)
echo "Ensuring server is running..."
$COMPOSE_CMD up -d --no-recreate server 2>/dev/null || $COMPOSE_CMD up -d server 2>/dev/null || true

# Wait a moment for server to be ready
sleep 2

# Run simulator
echo "Starting simulation..."
$COMPOSE_CMD run --rm simulator

echo ""
echo "=========================================="
echo "Test completed!"
echo "=========================================="
echo ""
echo "📊 View detection results:"
echo "   $COMPOSE_CMD logs detection | grep -i 'attack\|traffic'"
echo ""
echo "📋 View all logs:"
echo "   $COMPOSE_CMD logs -f detection"
echo ""
echo "🛑 Stop all services:"
echo "   $COMPOSE_CMD down"
echo ""
echo "💡 Tip: Keep the detection service running and run the simulator again:"
echo "   $COMPOSE_CMD run --rm simulator"
echo ""

