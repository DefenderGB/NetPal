#!/bin/bash

# NetPal Quick Run Script
# Automatically activates venv and starts the app

# Check if venv exists
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment not found!"
    echo "Run 'bash setup.sh' first to set up the project."
    exit 1
fi

# Activate venv and run app
source venv/bin/activate
streamlit run app.py