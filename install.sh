#!/bin/bash
# NetPal Installation Script
# Usage: bash install.sh [no_nuclei]
#   no_nuclei  — skip nuclei installation (useful when nuclei is installed separately)

set -e

# ── Parse arguments ────────────────────────────────────────────────────────
SKIP_NUCLEI=false
if [[ "$1" == "no_nuclei" ]]; then
    SKIP_NUCLEI=true
fi

# ── Detect OS ──────────────────────────────────────────────────────────────

echo "[INFO] Detecting operating system..."
OS="unknown"
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
    echo "Detected: Linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
    echo "Detected: macOS"
else
    echo "Error: Unsupported operating system: $OSTYPE"
    exit 1
fi

# ── Ensure uv is available ────────────────────────────────────────────────

echo ""
echo "[INFO] Checking for uv..."
if command -v uv &> /dev/null; then
    echo "✓ uv is installed: $(uv --version)"
else
    echo "✗ uv is NOT installed"
    echo "[INFO] Installing uv..."
    curl -LsSf https://astral.sh/uv/install.sh | sh

    # Source the env so uv is available in this session
    if [ -f "$HOME/.local/bin/env" ]; then
        source "$HOME/.local/bin/env"
    fi
    export PATH="$HOME/.local/bin:$PATH"

    if command -v uv &> /dev/null; then
        echo "✓ uv installed: $(uv --version)"
    else
        echo "✗ Failed to install uv."
        echo "  Install uv manually: curl -LsSf https://astral.sh/uv/install.sh | sh"
        exit 1
    fi
fi

echo ""
echo "================================================"
echo "  Installing Required External Tools"
echo "================================================"

# Track installation status
NMAP_INSTALLED=false
PLAYWRIGHT_INSTALLED=false
AWS_INSTALLED=false
NUCLEI_INSTALLED=false
GO_INSTALLED=false

# ── Go ─────────────────────────────────────────────────────────────────────

install_go() {
    echo "[INFO] Installing Go..."
    if [[ "$OS" == "linux" ]]; then
        if command -v apt-get &> /dev/null; then
            sudo apt-get update && sudo apt-get install -y golang-go
        elif command -v yum &> /dev/null; then
            sudo yum install -y golang
        elif command -v dnf &> /dev/null; then
            sudo dnf install -y golang
        fi
    elif [[ "$OS" == "macos" ]]; then
        if command -v brew &> /dev/null; then
            brew install golang
        else
            echo "✗ Homebrew not found. Please install Homebrew first: https://brew.sh"
            return 1
        fi
    fi

    export PATH=$PATH:$HOME/go/bin

    if [[ "$OS" == "linux" ]] && ! grep -q '$HOME/go/bin' ~/.bashrc 2>/dev/null; then
        echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
    elif [[ "$OS" == "macos" ]] && ! grep -q '$HOME/go/bin' ~/.zshrc 2>/dev/null; then
        echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.zshrc
    fi

    if command -v go &> /dev/null; then
        echo "✓ Go installed: $(go version)"
        return 0
    else
        echo "✗ Failed to install Go"
        return 1
    fi
}

echo ""
echo "[INFO] Checking for Go..."
if command -v go &> /dev/null; then
    echo "✓ Go is installed: $(go version)"
    GO_INSTALLED=true
    export PATH=$PATH:$HOME/go/bin
else
    echo "✗ Go is NOT installed"
    read -p "Install Go? (Y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if install_go; then
            GO_INSTALLED=true
        fi
    fi
fi

# ── nmap ───────────────────────────────────────────────────────────────────

echo ""
echo "[INFO] Checking for nmap..."
if command -v nmap &> /dev/null; then
    echo "✓ nmap is installed: $(nmap --version | head -1)"
    NMAP_INSTALLED=true
else
    echo "✗ nmap is NOT installed"
    read -p "Install nmap? (Y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if [[ "$OS" == "linux" ]]; then
            if command -v apt-get &> /dev/null; then
                sudo apt-get update && sudo apt-get install -y nmap
            elif command -v yum &> /dev/null; then
                sudo yum install -y nmap
            elif command -v dnf &> /dev/null; then
                sudo dnf install -y nmap
            fi
        elif [[ "$OS" == "macos" ]]; then
            if command -v brew &> /dev/null; then
                brew install nmap
            else
                echo "✗ Homebrew not found. Please install Homebrew first: https://brew.sh"
            fi
        fi

        if command -v nmap &> /dev/null; then
            echo "✓ nmap installed: $(nmap --version | head -1)"
            NMAP_INSTALLED=true
        fi
    fi
fi

# ── Playwright is installed as a Python dependency via pyproject.toml ─────
# The browser binaries are installed after the venv is set up (see below).

PLAYWRIGHT_INSTALLED=true

# ── AWS CLI (optional) ────────────────────────────────────────────────────

echo ""
echo "[INFO] Checking for AWS CLI (optional for S3 sync)..."
if command -v aws &> /dev/null; then
    echo "✓ AWS CLI is installed: $(aws --version)"
    AWS_INSTALLED=true
else
    echo "○ AWS CLI is not installed (optional for S3 sync)"
    read -p "Install AWS CLI? (Y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if [[ "$OS" == "linux" ]]; then
            if command -v apt-get &> /dev/null; then
                sudo apt-get update && sudo apt-get install -y awscli
            elif command -v yum &> /dev/null; then
                sudo yum install -y awscli
            elif command -v dnf &> /dev/null; then
                sudo dnf install -y awscli
            fi
        elif [[ "$OS" == "macos" ]]; then
            if command -v brew &> /dev/null; then
                brew install awscli
            fi
        fi
        if command -v aws &> /dev/null; then
            echo "✓ AWS CLI installed: $(aws --version)"
            AWS_INSTALLED=true
        fi
    fi
fi

# ── nuclei (optional) ─────────────────────────────────────────────────────

echo ""
if [[ "$SKIP_NUCLEI" == true ]]; then
    echo "[INFO] Skipping nuclei installation (no_nuclei flag set)"
else
    echo "[INFO] Checking for nuclei (optional but recommended)..."
    if command -v nuclei &> /dev/null; then
        echo "✓ nuclei is installed: $(nuclei -version 2>&1 | head -1)"
        NUCLEI_INSTALLED=true
    else
        echo "○ nuclei is not installed (optional but recommended)"
        if [[ "$GO_INSTALLED" == true ]]; then
            read -p "Install nuclei? (Y/N): " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
                export PATH=$PATH:$HOME/go/bin

                if command -v nuclei &> /dev/null; then
                    echo "✓ nuclei installed: $(nuclei -version 2>&1 | head -1)"
                    NUCLEI_INSTALLED=true
                fi
            fi
        else
            echo "✗ Go is required to install nuclei"
        fi
    fi
fi

# ── Python environment & NetPal package ───────────────────────────────────

echo ""
echo "================================================"
echo "  Installing NetPal (Python package via uv)"
echo "================================================"
echo ""

# Check if NetPal is already installed
if [ -d ".venv" ] && .venv/bin/python -c "import netpal" 2>/dev/null; then
    INSTALLED_VERSION=$(.venv/bin/python -c "import netpal; print(netpal.__version__)" 2>/dev/null || echo "unknown")
    echo "✓ NetPal is already installed (version: ${INSTALLED_VERSION})"
    echo ""
    echo "  To reinstall, remove the virtual environment first:"
    echo "    rm -rf .venv && bash install.sh"
    echo ""
    echo "  To update in-place:"
    echo "    source .venv/bin/activate && uv sync --python 3.12 && uv pip install -e ."
    echo ""
    exit 0
fi

if [ "$NMAP_INSTALLED" = true ]; then
    echo "✓ All required external tools are installed!"
    echo ""

    # Create virtual environment with uv (pinned to Python 3.12)
    echo "[INFO] Creating Python 3.12 virtual environment with uv..."
    uv venv --python 3.12
    echo "✓ Virtual environment created at .venv/ (Python 3.12)"

    # Activate the virtual environment
    echo "[INFO] Activating virtual environment..."
    source .venv/bin/activate

    # Sync dependencies (reads pyproject.toml, pinned to Python 3.12)
    echo "[INFO] Syncing dependencies..."
    uv sync --python 3.12
    echo "✓ Dependencies synced"

    # Install the package in editable mode
    echo "[INFO] Installing NetPal in editable mode..."
    uv pip install -e .
    echo "✓ NetPal installed"

    # Install Playwright browser binaries (Chromium)
    echo ""
    echo "[INFO] Installing Playwright Chromium browser..."
    uv run playwright install --with-deps chromium
    echo "✓ Playwright Chromium browser installed"

    # ── Passwordless sudo for nmap and chown ──────────────────────────────────

    if [ "$(id -u)" -eq 0 ]; then
        echo ""
        echo "[INFO] Running as root — passwordless sudo configuration not needed."
    else
        echo ""
        echo "================================================"
        echo "  Passwordless sudo for nmap and chown"
        echo "================================================"
        echo ""
        NMAP_PATH=$(which nmap)
        CHOWN_PATH=$(which chown)
        echo "NetPal requires passwordless sudo access to:"
        echo "  • nmap   ($NMAP_PATH) — SYN scans require root privileges"
        echo "  • chown  ($CHOWN_PATH) — restore file ownership after sudo nmap"
        echo ""
        echo "This will add a sudoers rule:"
        echo "  $USER ALL=(ALL) NOPASSWD: $NMAP_PATH, $CHOWN_PATH"
        echo ""
        read -p "Configure passwordless sudo for nmap and chown? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            sudo sh -c "echo '$USER ALL=(ALL) NOPASSWD: $NMAP_PATH, $CHOWN_PATH' > /etc/sudoers.d/netpal-$USER"
            sudo chmod 0440 /etc/sudoers.d/netpal-$USER
            echo "✓ Sudoers rule created at /etc/sudoers.d/netpal-$USER"

            # Clean up old nmap-only sudoers file if present
            if [ -f "/etc/sudoers.d/nmap-$USER" ]; then
                sudo rm -f /etc/sudoers.d/nmap-$USER
                echo "✓ Removed old /etc/sudoers.d/nmap-$USER (superseded)"
            fi
        else
            echo "○ Skipped. You can configure this later by running:"
            echo "    sudo sh -c \"echo '\$USER ALL=(ALL) NOPASSWD: $NMAP_PATH, $CHOWN_PATH' > /etc/sudoers.d/netpal-\$USER\""
            echo "    sudo chmod 0440 /etc/sudoers.d/netpal-\$USER"
        fi
    fi

    # ── Summary ────────────────────────────────────────────────────────────

    echo ""
    echo "================================================"
    echo "  Installation Complete"
    echo "================================================"
    echo ""
    echo "Required tools:"
    echo "  ✓ nmap installed"
    echo "  ✓ playwright installed (Chromium browser)"
    echo ""
    echo "Optional tools:"
    if [ "$AWS_INSTALLED" = true ]; then
        echo "  ✓ AWS CLI installed (configure for S3 sync)"
    else
        echo "  ○ AWS CLI not installed (optional for S3 sync)"
    fi
    if [ "$NUCLEI_INSTALLED" = true ]; then
        echo "  ✓ nuclei installed"
    else
        echo "  ○ nuclei not installed (optional but recommended)"
    fi
    echo ""
    echo "First activate the environment:"
    echo "  source .venv/bin/activate"
    echo ""
    echo "If not setup, then run and then scan:"
    echo "  1. netpal setup"
    echo "  2. netpal auto --project 'My Network' --range '10.0.0.0/24' --interface en0"
    echo ""
    echo "If AWS S3 is not setup, configure AWS profile for S3 sync:"
    echo "  aws configure set aws_access_key_id \"YOUR_KEY\" --profile netpal-user"
    echo "  aws configure set aws_secret_access_key \"YOUR_SECRET\" --profile netpal-user"
    echo "  aws configure set region us-west-2 --profile netpal-user"
    echo ""
    echo "For detailed instructions, see README.md"
    echo ""
else
    echo "⚠️  REQUIRED TOOLS MISSING — Cannot install Python package!"
    echo ""
    echo "Required tools status:"
    if [ "$NMAP_INSTALLED" = true ]; then
        echo "  ✓ nmap installed"
    else
        echo "  ✗ nmap NOT installed (REQUIRED)"
    fi
    echo ""
    echo "Optional tools status:"
    if [ "$AWS_INSTALLED" = true ]; then
        echo "  ✓ AWS CLI installed"
    else
        echo "  ○ AWS CLI not installed (optional)"
    fi
    if [ "$NUCLEI_INSTALLED" = true ]; then
        echo "  ✓ nuclei installed"
    else
        echo "  ○ nuclei not installed (optional)"
    fi
    echo ""
    echo "⚠️  Please install the missing REQUIRED tools, then run this script again."
    echo ""
    echo "Installation steps:"
    echo "  1. Install required tools (see instructions above)"
    echo "  2. Run: bash install.sh"
    echo ""
    echo "For detailed instructions, see README.md"
    exit 1
fi
