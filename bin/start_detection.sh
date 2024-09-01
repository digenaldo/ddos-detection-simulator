#!/bin/bash

# Activate the virtual environment if necessary
# source /path/to/your/venv/bin/activate

# Ensure the logs directory exists
# mkdir -p logs

# Start the detection script and log the output
PYTHONPATH=$(pwd) python3 app/detection.py > logs/detection_output.log 2>&1

# Optionally, monitor the logs (comment out if not needed)
# tail -f logs/detection.log