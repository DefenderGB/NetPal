#!/bin/bash
# NetPal Installation Script

set -e

# Detect OS
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

# Check Python version
echo ""
echo "[INFO] Checking Python version..."
python_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "Found Python $python_version"

if ! python3 -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)"; then
    echo "Error: Python 3.8 or higher required"
    exit 1
fi

echo ""
echo "================================================"
echo "  Installing Required Tools"
echo "================================================"

# Track installation status
NMAP_INSTALLED=false
HTTPX_INSTALLED=false
AWS_INSTALLED=false
NUCLEI_INSTALLED=false
GO_INSTALLED=false

# Function to install Go
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
    
    # Add Go bin to PATH
    export PATH=$PATH:$HOME/go/bin
    
    # Add to shell profile if not already there
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

# Check and install Go
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

# Check and install nmap
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

# Check and install httpx
echo ""
echo "[INFO] Checking for httpx..."
if command -v httpx &> /dev/null; then
    echo "✓ httpx is installed: $(httpx -version 2>&1 | head -1)"
    HTTPX_INSTALLED=true
else
    echo "✗ httpx is NOT installed"
    if [[ "$GO_INSTALLED" == true ]]; then
        read -p "Install httpx? (Y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
            export PATH=$PATH:$HOME/go/bin
            
            if command -v httpx &> /dev/null; then
                echo "✓ httpx installed: $(httpx -version 2>&1 | head -1)"
                HTTPX_INSTALLED=true
            fi
        fi
    else
        echo "✗ Go is required to install httpx"
    fi
fi

# Check and install AWS CLI (optional)
echo ""
echo "[INFO] Checking for AWS CLI (optional for S3 sync)..."
if command -v aws &> /dev/null; then
    echo "✓ AWS CLI is installed: $(aws --version)"
    AWS_INSTALLED=true
    echo ""
    echo "To configure AWS profile for S3 sync:"
    echo "  aws configure set aws_access_key_id \"YOUR_KEY\" --profile netpal-user"
    echo "  aws configure set aws_secret_access_key \"YOUR_SECRET\" --profile netpal-user"
    echo "  aws configure set region us-west-2 --profile netpal-user"
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
            else
                echo "✗ Homebrew not found. Install manually: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"
            fi
        fi
        
        if command -v aws &> /dev/null; then
            echo "✓ AWS CLI installed: $(aws --version)"
            AWS_INSTALLED=true
        fi
    fi
fi

# Check and install nuclei (optional)
echo ""
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

# Summary
echo ""
echo "================================================"
echo "  Installation Summary"
echo "================================================"
echo ""

# Check if required tools are installed
if [ "$NMAP_INSTALLED" = true ] && [ "$HTTPX_INSTALLED" = true ]; then
    echo "✓ All required tools are installed!"
    echo ""
    
    # Now install Python package
    echo "[INFO] Installing NetPal package with dependencies..."
    pip install -e . --break-system-packages --ignore-installed
    export PATH=$PATH:~/.local/bin
    
    if [ $? -eq 0 ]; then
        echo ""
        echo "✓ Python dependencies installed"
        echo "✓ NetPal package installed"
        
        # Check if netpal was installed in pipx venv and create symlink
        if [ -f "$HOME/.local/pipx/venvs/pip/bin/netpal" ]; then
            echo ""
            echo "[INFO] Detected pipx installation, creating system-wide symlink..."
            if sudo ln -sf "$HOME/.local/pipx/venvs/pip/bin/netpal" /usr/local/bin/netpal 2>/dev/null; then
                echo "✓ Created symlink: /usr/local/bin/netpal -> $HOME/.local/pipx/venvs/pip/bin/netpal"
            else
                echo "✗ Could not create netpal symlink (may need sudo privileges)"
            fi
        fi
        
        # Install package for root as well (so sudo can access it)
        echo ""
        echo "[INFO] Installing package for sudo/root access..."
        
        # Install with sudo so root Python can access
        sudo pip install -e . --break-system-packages --ignore-installed
        
        if sudo python3 -c "import netpal" 2>/dev/null; then
            echo "✓ Package accessible to sudo/root"
            echo "  You can now run: sudo netpal"
        else
            echo "✗ Package installation for sudo failed"
            echo "  Try: sudo pip install -e ."
        fi
        
        # Create symlinks for Go tools (httpx, nuclei)
        if [ "$HTTPX_INSTALLED" = true ]; then
            HTTPX_PATH=$(which httpx 2>/dev/null)
            if [ -n "$HTTPX_PATH" ]; then
                if sudo ln -sf "$HTTPX_PATH" /usr/local/bin/httpx 2>/dev/null; then
                    echo "✓ Created symlink: /usr/local/bin/httpx -> $HTTPX_PATH"
                else
                    echo "○ Could not create httpx symlink"
                fi
            fi
        fi
        
        if [ "$NUCLEI_INSTALLED" = true ]; then
            NUCLEI_PATH=$(which nuclei 2>/dev/null)
            if [ -n "$NUCLEI_PATH" ]; then
                if sudo ln -sf "$NUCLEI_PATH" /usr/local/bin/nuclei 2>/dev/null; then
                    echo "✓ Created symlink: /usr/local/bin/nuclei -> $NUCLEI_PATH"
                else
                    echo "○ Could not create nuclei symlink"
                fi
            fi
        fi
        
        echo ""
        echo "✓ Sudo access configured - you can now run: sudo netpal"
        
        echo ""
        echo "Optional tools status:"
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
        echo "Next steps:"
        echo "  1. Configure: nano netpal/config/config.json OR run netpal --mode setup"
        echo "  2. Set project_name in config.json"
        echo "  3. Start tool in a sudo tmux session: sudo tmux new -s netpal netpal"
        echo ""
        echo "For detailed instructions, see README.md"
        echo ""
        echo "Installation complete!"
    else
        echo ""
        echo "✗ Failed to install Python package"
        echo "Please check the error messages above"
        exit 1
    fi
else
    echo "⚠️  REQUIRED TOOLS MISSING - Cannot install Python package!"
    echo ""
    echo "Required tools status:"
    if [ "$NMAP_INSTALLED" = true ]; then
        echo "  ✓ nmap installed"
    else
        echo "  ✗ nmap NOT installed (REQUIRED)"
    fi
    if [ "$HTTPX_INSTALLED" = true ]; then
        echo "  ✓ httpx installed"
    else
        echo "  ✗ httpx NOT installed (REQUIRED)"
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
    echo "⚠️  Please review the installation instructions above"
    echo "    and install the missing REQUIRED tools, then run this script again."
    echo ""
    echo "Installation steps:"
    echo "  1. Install required tools (see instructions above)"
    echo "  2. Run: bash install.sh"
    echo ""
    echo "For detailed instructions, see README.md"
    exit 1
fi
echo ""