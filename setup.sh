#!/bin/bash

echo "================================"
echo "NetPal Setup"
echo "================================"
echo ""

# Create virtual environment
echo "[INFO] Creating python virtual environment..."
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Upgrade pip
echo "[INFO] Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo "[INFO] Installing dependencies..."
pip install -r requirements.txt

# Install tools
echo "[INFO] Installing Security tools..."
bash install_tools.sh

echo "\n[SUCCESS] Setup Complete!"
echo "To start NetPal:"
echo "  bash run.sh"
echo "To start manually:"
echo "  source venv/bin/activate && streamlit run app.py"