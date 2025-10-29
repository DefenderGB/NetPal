#!/bin/bash

# NetPal Quick Run Script
# Runs the app using pipx streamlit

# Check if streamlit is available
if ! command -v streamlit &> /dev/null; then
    echo "❌ Streamlit not found!"
    echo "Run 'bash setup.sh' first to set up the project."
    exit 1
fi

# Check if pipx streamlit is installed
if ! pipx list 2>/dev/null | grep -q "streamlit"; then
    echo "⚠️  Streamlit not installed via pipx!"
    echo "Run 'bash setup.sh' to install streamlit and dependencies."
    exit 1
fi
 
# Run app with pipx streamlit
streamlit run app.py
