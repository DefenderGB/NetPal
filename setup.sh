#!/bin/bash

# Detect OS and package manager
detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        PKG_MANAGER="brew"
    elif [[ -f /etc/debian_version ]]; then
        OS="linux"
        PKG_MANAGER="apt"
    elif [[ -f /etc/redhat-release ]]; then
        OS="linux"
        PKG_MANAGER="yum"
    elif command -v dnf &> /dev/null; then
        OS="linux"
        PKG_MANAGER="dnf"
    else
        OS="linux"
        PKG_MANAGER="unknown"
    fi
}

detect_os

# Parse command line arguments
INTERACTIVE=true  # Interactive mode is ON by default
while [[ $# -gt 0 ]]; do
    case $1 in
        -y|--yes)
            INTERACTIVE=false
            shift
            ;;
        -i|--interactive)
            INTERACTIVE=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [-y|--yes] [-i|--interactive]"
            echo "  -y, --yes          Skip all prompts and install everything (non-interactive)"
            echo "  -i, --interactive  Prompt before each installation (default)"
            exit 1
            ;;
    esac
done

# Confirmation helper function
confirm() {
    if [ "$INTERACTIVE" = false ]; then
        return 0  # Auto-accept in non-interactive mode
    fi
    
    local prompt="$1"
    local response
    
    while true; do
        read -p "$prompt [Y/n]: " -r response
        response=${response:-Y}  # Default to Y if empty
        case $response in
            [Yy]|[Yy][Ee][Ss])
                return 0
                ;;
            [Nn]|[Nn][Oo])
                return 1
                ;;
            *)
                echo "Please answer Y or N."
                ;;
        esac
    done
}

echo "================================"
echo "NetPal Setup"
echo "================================"
echo ""

if [ "$INTERACTIVE" = true ]; then
    echo "🔔 Running in INTERACTIVE mode - you will be prompted before each installation"
    echo "   (Use -y or --yes flag to skip all prompts)"
    echo ""
else
    echo "⚡ Running in AUTO-INSTALL mode - installing everything without prompts"
    echo ""
fi

# Check if pipx is installed
if ! command -v pipx &> /dev/null; then
    echo "[+] pipx is not installed (required for managing Python tools)"
    echo ""
    
    if confirm "Install pipx?"; then
        echo "[INFO] Installing pipx..."
        
        if [ "$OS" = "macos" ]; then
            if command -v brew &> /dev/null; then
                brew install pipx
                if [ $? -ne 0 ]; then
                    echo "[-] Failed to install pipx via Homebrew"
                    echo "Please install it manually: brew install pipx"
                    exit 1
                fi
            else
                echo "[-] Homebrew not found. Installing pipx via pip..."
                python3 -m pip install --user pipx
                if [ $? -ne 0 ]; then
                    echo "[-] Failed to install pipx"
                    exit 1
                fi
            fi
        else  # Linux
            if [ "$PKG_MANAGER" = "apt" ]; then
                # Try package manager first, fall back to pip
                if sudo apt-get update && sudo apt-get install -y pipx 2>/dev/null; then
                    echo "[+] pipx installed via apt"
                else
                    echo "[INFO] Installing pipx via pip (apt package not available)..."
                    python3 -m pip install --user pipx
                    if [ $? -ne 0 ]; then
                        echo "[-] Failed to install pipx"
                        exit 1
                    fi
                fi
            elif [ "$PKG_MANAGER" = "dnf" ] || [ "$PKG_MANAGER" = "yum" ]; then
                # Try package manager first, fall back to pip
                if sudo $PKG_MANAGER install -y pipx 2>/dev/null; then
                    echo "[+] pipx installed via $PKG_MANAGER"
                else
                    echo "[INFO] Installing pipx via pip ($PKG_MANAGER package not available)..."
                    python3 -m pip install --user pipx
                    if [ $? -ne 0 ]; then
                        echo "[-] Failed to install pipx"
                        exit 1
                    fi
                fi
            else
                # Unknown package manager, use pip
                echo "[INFO] Installing pipx via pip..."
                python3 -m pip install --user pipx
                if [ $? -ne 0 ]; then
                    echo "[-] Failed to install pipx"
                    exit 1
                fi
            fi
        fi
        
        # Ensure pipx is in PATH
        pipx ensurepath
        echo "[+] pipx installed successfully"
        echo "⚠️  You may need to restart your shell or run: source ~/.bashrc (or ~/.zshrc)"
        echo ""
    else
        echo "[-] pipx is required to continue"
        exit 1
    fi
else
    echo "[+] pipx is installed"
fi

# Check if cmake is installed
if ! command -v cmake &> /dev/null; then
    echo "[+] cmake is not installed (required for building Python packages)"
    echo ""
    
    if confirm "Install cmake?"; then
        echo "[INFO] Installing cmake..."
        
        if [ "$OS" = "macos" ]; then
            if command -v brew &> /dev/null; then
                brew install cmake
                if [ $? -ne 0 ]; then
                    echo "[-] Failed to install cmake"
                    echo "Please install it manually: brew install cmake"
                    exit 1
                fi
            else
                echo "[-] Homebrew not found. Please install Homebrew first:"
                echo "    /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
                exit 1
            fi
        else  # Linux
            if [ "$PKG_MANAGER" = "apt" ]; then
                sudo apt-get update && sudo apt-get install -y cmake
                if [ $? -ne 0 ]; then
                    echo "[-] Failed to install cmake"
                    exit 1
                fi
            elif [ "$PKG_MANAGER" = "dnf" ]; then
                sudo dnf install -y cmake
                if [ $? -ne 0 ]; then
                    echo "[-] Failed to install cmake"
                    exit 1
                fi
            elif [ "$PKG_MANAGER" = "yum" ]; then
                sudo yum install -y cmake
                if [ $? -ne 0 ]; then
                    echo "[-] Failed to install cmake"
                    exit 1
                fi
            else
                echo "[-] Unknown package manager. Please install cmake manually:"
                echo "    Debian/Ubuntu: sudo apt-get install cmake"
                echo "    RHEL/CentOS: sudo yum install cmake"
                echo "    Fedora: sudo dnf install cmake"
                exit 1
            fi
        fi
        echo "[+] cmake installed successfully"
    else
        echo "[+] Skipping cmake installation"
        echo "   Note: Streamlit installation may fail without cmake"
        echo ""
        if ! confirm "Continue anyway?"; then
            echo "Setup cancelled. Install cmake and re-run this script."
            exit 1
        fi
    fi
else
    echo "[+] cmake is installed"
fi

# Check apache arrow (required for pyarrow)
check_apache_arrow() {
    if [ "$OS" = "macos" ]; then
        brew list apache-arrow &> /dev/null
        return $?
    else  # Linux
        # Check if libarrow is installed (various package names)
        ldconfig -p 2>/dev/null | grep -q libarrow || \
        dpkg -l 2>/dev/null | grep -q libarrow || \
        rpm -qa 2>/dev/null | grep -q arrow
        return $?
    fi
}

if ! check_apache_arrow; then
    echo "[+] apache-arrow is not installed (required for pyarrow)"
    echo ""
    
    if confirm "Install apache-arrow?"; then
        echo "[INFO] Installing apache-arrow..."
        
        if [ "$OS" = "macos" ]; then
            if command -v brew &> /dev/null; then
                brew install apache-arrow
                if [ $? -ne 0 ]; then
                    echo "[-] Failed to install apache-arrow"
                    echo "Please install it manually: brew install apache-arrow"
                    exit 1
                fi
            else
                echo "[-] Homebrew not found. Please install Homebrew first."
                exit 1
            fi
        else  # Linux
            if [ "$PKG_MANAGER" = "apt" ]; then
                # Install Arrow C++ library and development headers
                sudo apt-get update && sudo apt-get install -y libarrow-dev
                if [ $? -ne 0 ]; then
                    echo "[-] Failed to install apache-arrow via apt"
                    echo "    Trying to add Apache Arrow repository..."
                    # Try adding Apache Arrow repository
                    sudo apt-get install -y lsb-release wget
                    wget https://apache.jfrog.io/artifactory/arrow/$(lsb_release --id --short | tr 'A-Z' 'a-z')/apache-arrow-apt-source-latest-$(lsb_release --codename --short).deb
                    sudo apt-get install -y ./apache-arrow-apt-source-latest-$(lsb_release --codename --short).deb
                    sudo apt-get update
                    sudo apt-get install -y libarrow-dev
                    if [ $? -ne 0 ]; then
                        echo "⚠️  Could not install apache-arrow. pyarrow will use pre-built wheels instead."
                    fi
                fi
            elif [ "$PKG_MANAGER" = "dnf" ]; then
                sudo dnf install -y arrow-devel
                if [ $? -ne 0 ]; then
                    echo "⚠️  Could not install apache-arrow. pyarrow will use pre-built wheels instead."
                fi
            elif [ "$PKG_MANAGER" = "yum" ]; then
                sudo yum install -y arrow-devel
                if [ $? -ne 0 ]; then
                    echo "⚠️  Could not install apache-arrow. pyarrow will use pre-built wheels instead."
                fi
            else
                echo "⚠️  Unknown package manager. Skipping apache-arrow."
                echo "    pyarrow will attempt to use pre-built wheels."
            fi
        fi
        echo "[+] apache-arrow installation completed"
    else
        echo "[+] Skipping apache-arrow installation"
        echo "   Note: pyarrow will attempt to use pre-built wheels"
        echo ""
        if ! confirm "Continue anyway?"; then
            echo "Setup cancelled. Install apache-arrow and re-run this script."
            exit 1
        fi
    fi
else
    echo "[+] apache-arrow is installed"
fi

# Check if streamlit is installed via pipx
if ! pipx list 2>/dev/null | grep -q "streamlit"; then
    if confirm "Install streamlit via pipx?"; then
        echo "[INFO] Installing streamlit via pipx..."
        pipx install streamlit --pip-args='--prefer-binary'
        if [ $? -ne 0 ]; then
            echo "❌ Failed to install streamlit via pipx"
            exit 1
        fi
        echo "✅ Streamlit installed successfully"
    else
        echo "⏭️  Skipping streamlit installation"
        echo "⚠️  Note: Application requires streamlit to run"
    fi
else
    echo "✅ Streamlit already installed via pipx"
fi

# Only inject dependencies if streamlit is installed
if pipx list 2>/dev/null | grep -q "streamlit"; then
    if confirm "Install application dependencies (from requirements.txt)?"; then
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
    else
        echo "⏭️  Skipping dependency installation"
        echo "⚠️  Note: Application may not function correctly without dependencies"
    fi
else
    echo "⏭️  Skipping dependencies (streamlit not installed)"
fi

if confirm "Install security tools (nmap, nuclei, httpx, netexec)?"; then
    echo "[INFO] Installing Security tools..."
    if [ "$INTERACTIVE" = false ]; then
        bash install_tools.sh -y
    else
        bash install_tools.sh
    fi
else
    echo "⏭️  Skipping security tools installation"
    echo "   Note: Scanning features will be limited without these tools"
fi

echo ""
echo "[SUCCESS] Setup Complete!"
echo ""
echo "To start NetPal:"
echo "  bash run.sh"
echo "To start manually:"
echo "  streamlit run app.py"