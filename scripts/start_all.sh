#!/bin/bash
# Script to start all services

set -e

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

echo "Starting DDoS Detection System..."
echo ""

# Function to check if container exists and is running
check_and_start_container() {
    local name=$1
    if command -v podman &> /dev/null; then
        if podman ps -a --format "{{.Names}}" | grep -q "^${name}$"; then
            if podman ps --format "{{.Names}}" | grep -q "^${name}$"; then
                echo "  ✓ Container ${name} is already running"
                return 0
            else
                echo "  → Starting existing container ${name}..."
                podman start ${name} 2>/dev/null && return 0
            fi
        fi
    elif command -v docker &> /dev/null; then
        if docker ps -a --format "{{.Names}}" | grep -q "^${name}$"; then
            if docker ps --format "{{.Names}}" | grep -q "^${name}$"; then
                echo "  ✓ Container ${name} is already running"
                return 0
            else
                echo "  → Starting existing container ${name}..."
                docker start ${name} 2>/dev/null && return 0
            fi
        fi
    fi
    return 1
}

echo "Checking existing containers..."
SERVER_RUNNING=0
DETECTION_RUNNING=0

if check_and_start_container "ddos-server"; then
    SERVER_RUNNING=1
fi

if check_and_start_container "ddos-detection"; then
    DETECTION_RUNNING=1
fi

# Only use compose if containers don't exist
if [ $SERVER_RUNNING -eq 0 ] || [ $DETECTION_RUNNING -eq 0 ]; then
    echo ""
    echo "Starting missing containers with compose..."
    $COMPOSE_CMD up -d server detection
else
    echo ""
    echo "All containers are already running!"
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

