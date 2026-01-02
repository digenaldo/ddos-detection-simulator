# DDoS Detection Project

This repository is part of a Master's degree research project focused on developing and evaluating a detection scheme for application layer DDoS attacks using machine learning and big data analytics techniques. The project aims to contribute to the field of cybersecurity by exploring innovative approaches to enhance threat detection and mitigation strategies.

The research conducted in this project involves the investigation of various classification algorithms, performance evaluation methodologies, and data preprocessing techniques to develop an effective and efficient detection system. The findings and insights gained from this research are intended to advance the understanding of DDoS attack detection and contribute to the development of more robust cybersecurity solutions.

For more information about the research objectives, methodologies, and outcomes, please refer to the project documentation or contact the project supervisor.

- [Paper](https://sol.sbc.org.br/index.php/wgrs/article/view/35631/35418)

## Project Structure

The project is organized as follows:

```
ddos-detection-project/
│
├── bin/
│   └── start.sh                # Script to start the application
│
├── scripts/
│   ├── quick_test.sh           # Quick test script for Docker/Podman
│   ├── start_all.sh            # Start all services
│   ├── stop_all.sh             # Stop all services
│   └── test_detection.sh       # Full test script
│
├── app/
│   ├── __init__.py             # Module initialization
│   ├── server.py               # Flask server code
│   ├── ddos_simulator.py       # DDoS attack simulation code
│   ├── detection.py            # Real-time attack detection code
│   ├── feature_extraction.py   # Feature extraction code
│   └── model_prediction.py     # Model loading and prediction code
│
├── config/
│   ├── __init__.py             # Module initialization
│   └── settings.py             # Environment configuration and settings
│
├── logs/
│   └── app.log                 # Application log file
│
├── models/
│   ├── random_forest_model.pkl  # Trained model file
│   └── minmax_scaler.pkl        # Scaler file for feature normalization
│
├── tests/
│   └── test_detection.py       # Unit tests for detection
│
├── requirements.txt            # Project dependencies
├── Dockerfile                  # Docker image definition
├── docker-compose.yml          # Docker Compose configuration
├── .dockerignore               # Docker ignore patterns
├── README.md                   # Project documentation
└── setup.py                    # Installation script
```

## Quick Start with Docker/Podman (Recommended)

The easiest way to run and test the DDoS detection system is using Docker Compose or Podman Compose.

> **📖 For a quick 3-step guide, see [QUICKSTART.md](QUICKSTART.md)**

### Prerequisites

- **Podman** (recommended) or **Docker** installed
- **podman-compose** or **docker-compose** installed

#### Install Podman Compose (if using Podman):

```bash
# On Fedora/RHEL
sudo dnf install podman-compose

# On Ubuntu/Debian
pip install podman-compose

# Or using pip
pip install podman-compose
```

### Quick Test

Run the complete test with a single command:

```bash
./scripts/quick_test.sh
```

This script will:
1. Build the Docker images
2. Start the Flask server and detection system
3. Run a DDoS attack simulation
4. Show you the detection results

### Manual Control

**Start all services:**
```bash
./scripts/start_all.sh
# Or manually:
podman-compose up -d server detection
```

**Run attack simulation:**
```bash
podman-compose run --rm simulator
```

**View detection logs:**
```bash
podman-compose logs -f detection
```

**Stop all services:**
```bash
./scripts/stop_all.sh
# Or manually:
podman-compose down
```

**Clean up old containers (if you get name conflicts):**
```bash
# Standard cleanup
./scripts/cleanup.sh

# Force cleanup (if standard doesn't work)
./scripts/force_cleanup.sh

# Or manually:
podman-compose down
podman stop ddos-server ddos-detection ddos-simulator
podman rm -f ddos-server ddos-detection ddos-simulator
```

### Services

- **server**: Flask server running on port 5050 (target for attacks)
- **detection**: Real-time DDoS detection system monitoring network traffic
- **simulator**: DDoS attack simulator (runs on demand)

### Network Configuration

The detection service uses `network_mode: "service:server"` to share the network namespace with the server, allowing it to capture traffic on the loopback interface (`lo`).

For Podman, you may need to run with rootless mode or configure capabilities:
```bash
# If you encounter permission issues, you might need:
sudo podman-compose up -d
```

## How to Run the Project (Manual Installation)

To run this project manually, follow the steps below:

### 1. Install Dependencies

Make sure you have Python 3 installed. Then create a virtual environment and install dependencies:

```bash
python3 -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt
```

### 2. Prepare the Environment

The project uses environment variables for configuration. Copy the example file and customize it:

```bash
cp .env.example .env
```

Edit `.env` to configure:
- Network interface for packet capture
- Flask server host and port
- Log levels
- Model paths
- Other settings

The directories `logs/` and `models/` will be created automatically if they don't exist.

### 3. Install and Configure TShark

This project uses `pyshark`, which depends on `tshark` for packet capture. Install `tshark`:

#### macOS (via Homebrew):

```bash
brew install wireshark
sudo chgrp admin /dev/bpf*
sudo chmod g+rw /dev/bpf*
```

Ensure `tshark` is available in your PATH:

```bash
which tshark
```

If necessary, restart your terminal or add the path to your shell config.

### 4. Start the Flask Server

The Flask server will act as the target for the DDoS simulation:

```bash
chmod +x start.sh

./bin/start.sh
```

### 5. Run the DDoS Detection System

To start real-time detection using packet capture:

```bash
sudo python3 -m app.detection
```

**Note:** `sudo` is required to access packet capture interfaces on most systems.

**Note:** The network interface can be configured via the `NETWORK_INTERFACE` environment variable in `.env` (default: `lo0`).

### 6. Simulate DDoS Attacks

Generate attack traffic to test detection:

```bash
python3 -m app.ddos_simulator.py
```

This script simulates Slowloris, Hulk, and normal traffic patterns against the Flask server.

### 7. Monitor Logs

Application logs and detection results are saved to `logs/detection.log`. Monitor them with:

```bash
tail -f logs/detection.log
```

### 8. Notes About Model Compatibility

If you encounter warnings about scikit-learn version mismatch (e.g., when loading `.pkl` files), either:

- Re-train and re-save the models using the current version
- Or downgrade scikit-learn to the version used to create the models (e.g., 1.4.2):

```bash
pip install scikit-learn==1.4.2
```

## Running Tests

To run the unit tests:

```bash
python3 -m pytest tests/
```

Or using unittest:

```bash
python3 -m unittest discover tests
```

## Project Improvements

Recent improvements to the project include:

- ✅ **Docker/Podman support**: Easy deployment with Docker Compose or Podman Compose
- ✅ **Refactored code structure**: Removed global variables, implemented classes for better organization
- ✅ **Centralized configuration**: All settings managed through `config/settings.py` and environment variables
- ✅ **Improved error handling**: Better exception handling and validation throughout the codebase
- ✅ **Type hints and documentation**: Added type hints and docstrings to all modules
- ✅ **Centralized logging**: Unified logging configuration with proper log rotation
- ✅ **Unit tests**: Basic test suite for core functionality
- ✅ **Better code organization**: Separated concerns using classes and proper data structures
- ✅ **Test scripts**: Easy-to-use scripts for testing the detection system

## Configuration

The project supports configuration via environment variables. See `.env.example` for all available options:

- `NETWORK_INTERFACE`: Network interface for packet capture
- `FLASK_HOST` / `FLASK_PORT`: Flask server configuration
- `LOG_LEVEL`: Logging level (DEBUG, INFO, WARNING, ERROR)
- `MODEL_PATH` / `SCALER_PATH`: Paths to ML model files
- `FLOW_TIMEOUT`: Timeout for flow tracking in seconds

## Conclusion

This project setup allows experimentation with real-time DDoS attack detection using machine learning techniques. By running the Flask server, detection system, and traffic simulator together, you can observe detection results in real time and evaluate model performance in a practical scenario.
