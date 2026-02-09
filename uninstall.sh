#!/bin/bash
# NetPal Uninstallation Script

echo "================================================"
echo "  NetPal Uninstaller"
echo "================================================"
echo ""
echo "This will remove NetPal and optionally remove"
echo "the tools that were installed with it."
echo ""

# Detect OS
OS="unknown"
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
fi

# Function to ask yes/no question
ask_yes_no() {
    local question="$1"
    read -p "$question (Y/N): " -n 1 -r
    echo
    [[ $REPLY =~ ^[Yy]$ ]]
}

# 1. Uninstall NetPal Python package
echo "[1/6] Uninstalling NetPal Python package..."

# Uninstall from user Python
if pip show netpal &> /dev/null; then
    pip uninstall -y netpal
    echo "✓ Uninstalled from user Python"
else
    echo "○ Not found in user Python"
fi

# Uninstall from root Python
if sudo pip show netpal &> /dev/null; then
    sudo pip uninstall -y netpal
    echo "✓ Uninstalled from root Python"
else
    echo "○ Not found in root Python"
fi

# 2. Remove NetPal system-wide files
echo ""
echo "[2/6] Removing NetPal system files..."

# Remove /usr/local/bin/netpal (could be a symlink or regular file)
if [ -e /usr/local/bin/netpal ]; then
    sudo rm -f /usr/local/bin/netpal
    echo "✓ Removed /usr/local/bin/netpal"
else
    echo "○ /usr/local/bin/netpal not found"
fi

# Remove pipx venv installation if it exists
if [ -f "$HOME/.local/pipx/venvs/pip/bin/netpal" ]; then
    echo "✓ Found pipx installation at $HOME/.local/pipx/venvs/pip/bin/netpal"
    echo "  (Will be removed when uninstalling from user Python)"
fi

# 3. Remove scan results and project data (optional)
echo ""
echo "[3/6] Clean up project data?"
if ask_yes_no "Remove scan_results/ directory (all projects, findings, evidence)?"; then
    if [ -d "scan_results" ]; then
        rm -rf scan_results
        echo "✓ Removed scan_results/ directory"
    else
        echo "○ scan_results/ not found"
    fi
else
    echo "○ Keeping scan_results/ directory"
fi

# 4. Remove Go tools (optional)
echo ""
echo "[4/6] Remove Go tools?"

# Check if httpx exists
HTTPX_EXISTS=false
if command -v httpx &> /dev/null || [ -f "$HOME/go/bin/httpx" ]; then
    HTTPX_EXISTS=true
fi

# Check if nuclei exists
NUCLEI_EXISTS=false
if command -v nuclei &> /dev/null || [ -f "$HOME/go/bin/nuclei" ]; then
    NUCLEI_EXISTS=true
fi

if [ "$HTTPX_EXISTS" = true ] || [ "$NUCLEI_EXISTS" = true ]; then
    echo "Found Go tools installed. These may be used by other programs."
    
    if [ "$HTTPX_EXISTS" = true ]; then
        if ask_yes_no "Remove httpx?"; then
            # Remove from ~/go/bin
            if [ -f "$HOME/go/bin/httpx" ]; then
                rm -f "$HOME/go/bin/httpx"
                echo "✓ Removed ~/go/bin/httpx"
            fi
            # Remove symlink
            if [ -L /usr/local/bin/httpx ]; then
                sudo rm -f /usr/local/bin/httpx
                echo "✓ Removed /usr/local/bin/httpx symlink"
            fi
        else
            echo "○ Keeping httpx"
        fi
    fi
    
    if [ "$NUCLEI_EXISTS" = true ]; then
        if ask_yes_no "Remove nuclei?"; then
            # Remove from ~/go/bin
            if [ -f "$HOME/go/bin/nuclei" ]; then
                rm -f "$HOME/go/bin/nuclei"
                echo "✓ Removed ~/go/bin/nuclei"
            fi
            # Remove symlink
            if [ -L /usr/local/bin/nuclei ]; then
                sudo rm -f /usr/local/bin/nuclei
                echo "✓ Removed /usr/local/bin/nuclei symlink"
            fi
        else
            echo "○ Keeping nuclei"
        fi
    fi
else
    echo "○ No Go tools found"
fi

# 5. Remove nmap (optional)
echo ""
echo "[5/6] Remove nmap?"

if command -v nmap &> /dev/null; then
    echo "nmap is installed. It may be used by other programs."
    if ask_yes_no "Uninstall nmap?"; then
    if [[ "$OS" == "linux" ]]; then
        if command -v apt-get &> /dev/null; then
            sudo apt-get remove -y nmap
            sudo apt-get autoremove -y
        elif command -v yum &> /dev/null; then
            sudo yum remove -y nmap
        elif command -v dnf &> /dev/null; then
            sudo dnf remove -y nmap
        fi
        echo "✓ Removed nmap"
    elif [[ "$OS" == "macos" ]]; then
        if command -v brew &> /dev/null; then
            brew uninstall nmap
            echo "✓ Removed nmap"
        fi
    fi
    else
        echo "○ Keeping nmap"
    fi
else
    echo "○ nmap not installed"
fi

# 6. Remove Go (optional)
echo ""
echo "[6/6] Remove Go?"

if command -v go &> /dev/null; then
    echo "Go is installed. It may be used by other programs."
    if ask_yes_no "Uninstall Go?"; then
    if [[ "$OS" == "linux" ]]; then
        if command -v apt-get &> /dev/null; then
            sudo apt-get remove -y golang-go
            sudo apt-get autoremove -y
        elif command -v yum &> /dev/null; then
            sudo yum remove -y golang
        elif command -v dnf &> /dev/null; then
            sudo dnf remove -y golang
        fi
        echo "✓ Removed Go"
    elif [[ "$OS" == "macos" ]]; then
        if command -v brew &> /dev/null; then
            brew uninstall golang
            echo "✓ Removed Go"
        fi
    fi
    
        # Remove Go workspace
        if [ -d "$HOME/go" ]; then
            if ask_yes_no "Remove ~/go directory (Go workspace)?"; then
                rm -rf "$HOME/go"
                echo "✓ Removed ~/go directory"
            fi
        fi
    else
        echo "○ Keeping Go"
    fi
else
    echo "○ Go not installed"
fi

# Summary
echo ""
echo "================================================"
echo "  Uninstallation Complete"
echo "================================================"
echo ""
echo "NetPal has been uninstalled."
echo ""
echo "Note: Configuration files in netpal/config/ were kept."
echo "Delete manually if needed."
echo ""