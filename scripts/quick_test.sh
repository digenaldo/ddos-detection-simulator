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
echo "Step 1: Checking existing containers..."

# Function to check and handle existing containers
check_container() {
    local name=$1
    if command -v podman &> /dev/null; then
        if podman ps -a --format "{{.Names}}" | grep -q "^${name}$"; then
            if podman ps --format "{{.Names}}" | grep -q "^${name}$"; then
                echo "  ✓ Container ${name} is already running"
                return 0
            else
                echo "  → Container ${name} exists but is stopped, starting it..."
                podman start ${name} 2>/dev/null && return 0 || return 1
            fi
        fi
    elif command -v docker &> /dev/null; then
        if docker ps -a --format "{{.Names}}" | grep -q "^${name}$"; then
            if docker ps --format "{{.Names}}" | grep -q "^${name}$"; then
                echo "  ✓ Container ${name} is already running"
                return 0
            else
                echo "  → Container ${name} exists but is stopped, starting it..."
                docker start ${name} 2>/dev/null && return 0 || return 1
            fi
        fi
    fi
    return 1
}

# Check if containers already exist and are running
SERVER_EXISTS=0
DETECTION_EXISTS=0

if check_container "ddos-server"; then
    SERVER_EXISTS=1
fi

if check_container "ddos-detection"; then
    DETECTION_EXISTS=1
fi

# Only clean up if we need to recreate containers
if [ $SERVER_EXISTS -eq 0 ] || [ $DETECTION_EXISTS -eq 0 ]; then
    echo "Some containers need to be created, cleaning up old ones..."
    $COMPOSE_CMD down 2>/dev/null || true
    
    # Only remove containers that don't exist or are stopped
    if [ $SERVER_EXISTS -eq 0 ]; then
        if command -v podman &> /dev/null; then
            podman rm -f ddos-server 2>/dev/null || true
        elif command -v docker &> /dev/null; then
            docker rm -f ddos-server 2>/dev/null || true
        fi
    fi
    
    if [ $DETECTION_EXISTS -eq 0 ]; then
        if command -v podman &> /dev/null; then
            podman rm -f ddos-detection 2>/dev/null || true
        elif command -v docker &> /dev/null; then
            docker rm -f ddos-detection 2>/dev/null || true
        fi
    fi
fi

echo ""
echo "Step 2: Building images..."
$COMPOSE_CMD build

echo ""
echo "Step 3: Starting server and detection system..."
# Only start containers that don't already exist and are running
if [ $SERVER_EXISTS -eq 0 ] || [ $DETECTION_EXISTS -eq 0 ]; then
    $COMPOSE_CMD up -d server detection
else
    echo "  All containers are already running, skipping creation"
fi

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

# Ensure server is running before running simulator
echo "Ensuring server is running..."
if command -v podman &> /dev/null; then
    if podman ps --format "{{.Names}}" | grep -q "^ddos-server$"; then
        echo "  ✓ Server container is running"
    else
        echo "  → Starting server container..."
        podman start ddos-server 2>/dev/null || $COMPOSE_CMD up -d server 2>/dev/null || true
    fi
elif command -v docker &> /dev/null; then
    if docker ps --format "{{.Names}}" | grep -q "^ddos-server$"; then
        echo "  ✓ Server container is running"
    else
        echo "  → Starting server container..."
        docker start ddos-server 2>/dev/null || $COMPOSE_CMD up -d server 2>/dev/null || true
    fi
fi

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

# Wait a moment for logs to be written
sleep 2

# Generate report
echo "📊 Generating detection report..."
echo ""
if python3 -m app.report_generator 2>/dev/null; then
    echo ""
else
    echo "⚠️  Could not generate report. View logs manually:"
    echo "   $COMPOSE_CMD logs detection | grep -i 'attack\|traffic'"
fi

echo ""
echo "📋 Other useful commands:"
echo "   View all logs:        $COMPOSE_CMD logs -f detection"
echo "   Generate report:      ./scripts/generate_report.sh"
echo "   Stop all services:    $COMPOSE_CMD down"
echo ""
echo "💡 Tip: Keep the detection service running and run the simulator again:"
echo "   $COMPOSE_CMD run --rm simulator"
echo ""

