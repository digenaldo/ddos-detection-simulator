#!/bin/bash
# Script to generate detection report

cd "$(dirname "$0")/.." || exit 1

echo "Generating DDoS Detection Report..."
echo ""

python3 -m app.report_generator

