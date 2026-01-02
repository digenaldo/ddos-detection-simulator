#!/bin/bash
# Helper script to check if container exists and start it if needed

CONTAINER_NAME=$1

if [ -z "$CONTAINER_NAME" ]; then
    echo "Usage: $0 <container_name>"
    exit 1
fi

# Check if using podman or docker
if command -v podman &> /dev/null; then
    CONTAINER_CMD="podman"
elif command -v docker &> /dev/null; then
    CONTAINER_CMD="docker"
else
    echo "Error: Neither podman nor docker found"
    exit 1
fi

# Check if container exists
if $CONTAINER_CMD ps -a --format "{{.Names}}" | grep -q "^${CONTAINER_NAME}$"; then
    # Container exists, check if it's running
    if $CONTAINER_CMD ps --format "{{.Names}}" | grep -q "^${CONTAINER_NAME}$"; then
        echo "Container ${CONTAINER_NAME} is already running"
        return 0
    else
        echo "Container ${CONTAINER_NAME} exists but is stopped, starting it..."
        $CONTAINER_CMD start ${CONTAINER_NAME}
        return $?
    fi
else
    echo "Container ${CONTAINER_NAME} does not exist"
    return 1
fi

