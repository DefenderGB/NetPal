#!/bin/bash

echo "================================"
echo "NetPal Setup"
echo "================================"
echo ""

# Check if pipx is installed
if ! command -v pipx &> /dev/null; then
    echo "❌ pipx is not installed!"
    echo ""
    echo "Please install pipx first:"
    echo "  macOS: brew install pipx"
    echo "  Linux: python3 -m pip install --user pipx"
    echo ""
    echo "After installing pipx, run: pipx ensurepath"
    exit 1
fi

# Check if streamlit is installed via pipx
if ! pipx list 2>/dev/null | grep -q "streamlit"; then
    echo "[INFO] Installing streamlit via pipx..."
    pipx install streamlit --pip-args='--prefer-binary'
    if [ $? -ne 0 ]; then
        echo "❌ Failed to install streamlit via pipx"
        exit 1
    fi
    echo "✅ Streamlit installed successfully"
else
    echo "✅ Streamlit already installed via pipx"
fi
 
echo "[INFO] Installing dependencies via pipx inject..."

# Read dependencies from requirements.txt and inject them
# Skip version specifiers and comments
while IFS= read -r line || [ -n "$line" ]; do
    # Skip empty lines and comments
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    
    # Extract package name (before any version specifier)
    package=$(echo "$line" | sed 's/[>=<~!].*//' | xargs)
    
    # Skip streamlit itself since it's the main package
    if [ "$package" = "streamlit" ]; then
        continue
    fi
    
    if [ -n "$package" ]; then
        echo "  → Injecting $package..."
        pipx inject streamlit "$package" --pip-args='--prefer-binary' --quiet 2>/dev/null || echo "    ⚠️  $package may already be installed"
    fi
done < requirements.txt
 
echo "✅ Dependencies injected into pipx streamlit environment"

# Install tools
echo "[INFO] Installing Security tools..."
bash install_tools.sh

echo "\n[SUCCESS] Setup Complete!"
echo "To start NetPal:"
echo "  bash run.sh"
echo "To start manually:"
echo "  streamlit run app.py"
