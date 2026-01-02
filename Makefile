.PHONY: help build up down logs test clean

help:
	@echo "DDoS Detection System - Makefile Commands"
	@echo ""
	@echo "Available commands:"
	@echo "  make build      - Build Docker images"
	@echo "  make up         - Start server and detection services"
	@echo "  make down       - Stop all services"
	@echo "  make logs       - View logs (follow mode)"
	@echo "  make test       - Run complete test (build, start, simulate)"
	@echo "  make clean      - Remove containers and images"
	@echo "  make simulator  - Run attack simulation"
	@echo ""

# Detect if using podman or docker
COMPOSE_CMD := $(shell if command -v podman-compose > /dev/null 2>&1; then echo podman-compose; elif command -v docker-compose > /dev/null 2>&1; then echo docker-compose; else echo "ERROR: No compose command found"; fi)

build:
	@echo "Building Docker images..."
	$(COMPOSE_CMD) build

up:
	@echo "Cleaning up old containers..."
	@$(COMPOSE_CMD) down 2>/dev/null || true
	@echo "Starting services..."
	@$(COMPOSE_CMD) up -d server detection
	@echo "Services started! Server: http://localhost:5050"

down:
	@echo "Stopping services..."
	$(COMPOSE_CMD) down

logs:
	$(COMPOSE_CMD) logs -f

test: clean build up
	@echo "Waiting for services to be ready..."
	@sleep 8
	@echo "Running attack simulation..."
	@$(COMPOSE_CMD) run --rm simulator
	@echo ""
	@echo "Test completed! View logs with: make logs"

simulator:
	$(COMPOSE_CMD) run --rm simulator

clean:
	@echo "Cleaning up..."
	$(COMPOSE_CMD) down -v
	$(COMPOSE_CMD) rm -f
	@echo "Cleanup complete"

