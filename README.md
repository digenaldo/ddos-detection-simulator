
# DDoS Detection Project

This repository is part of a Master's degree research project focused on developing and evaluating a detection scheme for application layer DDoS attacks using machine learning and big data analytics techniques. The project aims to contribute to the field of cybersecurity by exploring innovative approaches to enhance threat detection and mitigation strategies.

The research conducted in this project involves the investigation of various classification algorithms, performance evaluation methodologies, and data preprocessing techniques to develop an effective and efficient detection system. The findings and insights gained from this research are intended to advance the understanding of DDoS attack detection and contribute to the development of more robust cybersecurity solutions.

For more information about the research objectives, methodologies, and outcomes, please refer to the project documentation or contact the project supervisor.

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
├── tests/
│   └── test_detection.py       # Unit tests for detection
│
├── models/
│   ├── random_forest_model.pkl  # Trained model file
│   └── minmax_scaler.pkl        # Scaler file for feature normalization
│
├── .env                        # Sensitive environment variables
├── requirements.txt            # Project dependencies
├── README.md                   # Project documentation
└── setup.py                    # Installation script
```

## How to Run the Project

To run this project, follow the steps below:

### 1. Install Dependencies

Make sure you have Python installed. You can install the project dependencies using `pip`:

```bash
pip install -r requirements.txt
```

### 2. Prepare the Environment

Set up the environment variables by configuring the `.env` file. This file should include any sensitive or specific configuration needed by the application, such as database credentials or API keys.

### 3. Start the Flask Server

The Flask server will act as the target for the DDoS simulation:

```bash
./bin/start.sh
```

Alternatively, if you want to start the server manually:

```bash
python3 app/server.py
```

### 4. Run the DDoS Detection System

To start capturing packets and detecting DDoS attacks in real-time, run:

```bash
python3 app/detection.py
```

This script will capture network traffic, extract relevant features, and use a pre-trained machine learning model to predict if the traffic is part of a DDoS attack.

### 5. Simulate DDoS Attacks

To generate DDoS attack traffic against the Flask server, use the `ddos_simulator.py` script:

```bash
python3 app/ddos_simulator.py
```

This script will simulate a high volume of requests targeting the server, which will be detected by the real-time detection system.

### 6. Monitor Logs

You can monitor the application logs to see real-time detection results and any issues that arise during execution:

```bash
tail -f logs/app.log
```

## Conclusion

This project setup allows you to experiment with DDoS attack detection using machine learning techniques. By running the Flask server, detection system, and DDoS simulator together, you can observe how the system detects and responds to simulated attacks in real-time.