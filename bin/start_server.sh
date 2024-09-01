#!/bin/bash

# Ativa o ambiente virtual, se aplicável
source ddos_detection/bin/activate

export FLASK_APP=app/server.py
flask run --host=0.0.0.0 --port=5000