#!/bin/bash
# Script to stop all services

# Check if using podman or docker
if command -v podman &> /dev/null; then
    COMPOSE_CMD="podman-compose"
elif command -v docker &> /dev/null; then
    COMPOSE_CMD="docker-compose"
else
    echo "Error: Neither podman-compose nor docker-compose found"
    exit 1
fi

echo "Stopping DDoS Detection System..."
$COMPOSE_CMD down

echo ""
echo "All services stopped!"

