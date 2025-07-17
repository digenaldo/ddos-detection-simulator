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
├── README.md                   # Project documentation
└── setup.py                    # Installation script
```

## How to Run the Project

To run this project, follow the steps below:

### 1. Install Dependencies

Make sure you have Python 3 installed. Then create a virtual environment and install dependencies:

```bash
python3 -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt
```

### 2. Prepare the Environment

Set up the environment variables by configuring the `.env` file. This file should include any sensitive or specific configuration needed by the application, such as model paths or API keys.

Also, make sure the `logs/` folder exists. If not, create it manually:

```bash
mkdir -p logs
```

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

If using a different network interface (e.g., `en0` instead of `lo0`), edit the interface name in `app/detection.py`.

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

## Conclusion

This project setup allows experimentation with real-time DDoS attack detection using machine learning techniques. By running the Flask server, detection system, and traffic simulator together, you can observe detection results in real time and evaluate model performance in a practical scenario.
