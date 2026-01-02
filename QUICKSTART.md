# Quick Start Guide

Get the DDoS detection system running in 3 steps!

## Prerequisites

- Podman or Docker installed
- podman-compose or docker-compose installed

## Step 1: Install Podman Compose (if needed)

```bash
# Fedora/RHEL
sudo dnf install podman-compose

# Ubuntu/Debian
pip install podman-compose

# Or use Docker
sudo apt-get install docker-compose
```

## Step 2: Run the Test

```bash
./scripts/quick_test.sh
```

That's it! The script will:
- ✅ Build the images
- ✅ Start the server and detection system
- ✅ Run a DDoS attack simulation
- ✅ Show you the results

## Step 3: View Results

```bash
# See what attacks were detected
podman-compose logs detection | grep -i attack

# Or watch live
podman-compose logs -f detection
```

## Common Commands

```bash
# Start everything
./scripts/start_all.sh

# Run attack simulation
podman-compose run --rm simulator

# Stop everything
./scripts/stop_all.sh

# Or use Make
make test        # Full test
make up          # Start services
make simulator   # Run attack
make down        # Stop services
```

## Troubleshooting

**Container name already in use?**
```bash
# Try standard cleanup first
./scripts/cleanup.sh

# If that doesn't work, use force cleanup
./scripts/force_cleanup.sh

# Or manually:
podman-compose down
podman stop ddos-server ddos-detection ddos-simulator
podman rm -f ddos-server ddos-detection ddos-simulator
```

**Permission errors?**
```bash
sudo podman-compose up -d
```

**Can't find tshark?**
```bash
podman-compose build --no-cache
```

**Services not starting?**
```bash
podman-compose logs
```

For more details, see [README_DOCKER.md](README_DOCKER.md)

