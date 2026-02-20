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
    read -p "$question (y/N): " -n 1 -r
    echo
    [[ $REPLY =~ ^[Yy]$ ]]
}

# 1. Remove uv virtual environment and NetPal package
echo "[1/6] Removing NetPal Python environment..."

if [ -d ".venv" ]; then
    rm -rf .venv
    echo "✓ Removed .venv/ virtual environment"
else
    echo "○ .venv/ not found"
fi

# Clean up any legacy system-wide pip installs (no sudo needed for user pip)
if command -v pip &> /dev/null && pip show netpal &> /dev/null 2>&1; then
    pip uninstall -y netpal 2>/dev/null
    echo "✓ Removed legacy pip install of netpal"
fi

# 2. Remove sudoers rule created by install.sh
echo ""
echo "[2/6] Removing sudoers configuration..."

SUDOERS_FILE="/etc/sudoers.d/netpal-$USER"
SUDOERS_LEGACY="/etc/sudoers.d/nmap-$USER"

if [ -f "$SUDOERS_FILE" ] || [ -f "$SUDOERS_LEGACY" ]; then
    echo "Found NetPal sudoers rule(s). Removing requires sudo."
    if ask_yes_no "Remove sudoers rules for nmap/chown?"; then
        if [ -f "$SUDOERS_FILE" ]; then
            sudo rm -f "$SUDOERS_FILE"
            echo "✓ Removed $SUDOERS_FILE"
        fi
        if [ -f "$SUDOERS_LEGACY" ]; then
            sudo rm -f "$SUDOERS_LEGACY"
            echo "✓ Removed $SUDOERS_LEGACY"
        fi
    else
        echo "○ Keeping sudoers rules"
    fi
else
    echo "○ No NetPal sudoers rules found"
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

# 4. Remove Go tools (optional — nuclei only)
echo ""
echo "[4/6] Remove Go tools?"

NUCLEI_EXISTS=false
if command -v nuclei &> /dev/null || [ -f "$HOME/go/bin/nuclei" ]; then
    NUCLEI_EXISTS=true
fi

if [ "$NUCLEI_EXISTS" = true ]; then
    echo "Found Go tools installed. These may be used by other programs."

    if [ "$NUCLEI_EXISTS" = true ]; then
        if ask_yes_no "Remove nuclei?"; then
            if [ -f "$HOME/go/bin/nuclei" ]; then
                rm -f "$HOME/go/bin/nuclei"
                echo "✓ Removed ~/go/bin/nuclei"
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

# 6. Remove uv (optional)
echo ""
echo "[6/6] Remove uv?"

if command -v uv &> /dev/null; then
    echo "uv is installed. It may be used by other Python projects."
    if ask_yes_no "Uninstall uv?"; then
        if [ -f "$HOME/.local/bin/uv" ]; then
            rm -f "$HOME/.local/bin/uv" "$HOME/.local/bin/uvx"
            echo "✓ Removed uv and uvx from ~/.local/bin/"
        elif command -v brew &> /dev/null && brew list uv &> /dev/null; then
            brew uninstall uv
            echo "✓ Removed uv via Homebrew"
        else
            echo "⚠ Could not determine uv install method. Remove manually."
        fi

        # Offer to clean uv cache
        if [ -d "$HOME/.cache/uv" ] || [ -d "$HOME/Library/Caches/uv" ]; then
            if ask_yes_no "Remove uv cache?"; then
                rm -rf "$HOME/.cache/uv" "$HOME/Library/Caches/uv"
                echo "✓ Removed uv cache"
            fi
        fi
    else
        echo "○ Keeping uv"
    fi
else
    echo "○ uv not installed"
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
