#!/bin/bash

echo "================================"
echo "NetPal Security Tools Installer"
echo "================================"
echo ""

# Detect OS
if [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
else
    echo "Unsupported OS: $OSTYPE"
    exit 1
fi

# Check and setup Go PATH
setup_go_path() {
    if command -v go &> /dev/null; then
        echo "✓ Go is installed"
        
        # Check if $HOME/go/bin is in PATH
        if [[ ":$PATH:" != *":$HOME/go/bin:"* ]]; then
            echo "⚠️  Adding $HOME/go/bin to PATH for this session..."
            export PATH="$PATH:$HOME/go/bin"
            
            # Detect shell and suggest adding to rc file
            if [[ -n "$ZSH_VERSION" ]] || [[ "$SHELL" == *"zsh"* ]]; then
                echo ""
                echo "💡 To make this permanent, add this line to ~/.zshrc:"
                echo "   export PATH=\"\$PATH:\$HOME/go/bin\""
            else
                echo ""
                echo "💡 To make this permanent, add this line to ~/.bashrc:"
                echo "   export PATH=\"\$PATH:\$HOME/go/bin\""
            fi
            echo ""
        fi
    else
        echo "⚠️  Go is not installed. Some tools require Go."
        echo "   Install Go: https://golang.org/doc/install"
        return 1
    fi
    return 0
}

# Check if a tool is installed
check_tool() {
    if command -v "$1" &> /dev/null; then
        echo "✓ $1"
        return 0
    else
        echo "✗ $1"
        return 1
    fi
}

# Install nmap
install_nmap() {
    echo ""
    echo "Installing nmap..."
    if [[ "$OS" == "macos" ]]; then
        if command -v brew &> /dev/null; then
            brew install nmap
        else
            echo "❌ Homebrew not found. Install from: https://brew.sh"
            return 1
        fi
    else
        sudo apt-get update && sudo apt-get install -y nmap
    fi
}

# Install nuclei
install_nuclei() {
    echo ""
    
    # Check if running on dev-dsk host
    HOSTNAME=$(hostname)
    if [[ "$HOSTNAME" == *"dev-dsk-"* ]]; then
        echo "⚠️  Skipping nuclei installation"
        echo "   Nuclei should not be installed on dev-dsk hosts"
        echo "   Use your local machine for security scanning"
        return 1
    fi
    
    echo "Installing nuclei..."
    if command -v go &> /dev/null; then
        go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
        echo "✓ Nuclei installed to $HOME/go/bin/nuclei"
    else
        echo "❌ Go required. Install from: https://golang.org/doc/install"
        return 1
    fi
}

# Install httpx
install_httpx() {
    echo ""
    echo "Installing httpx..."
    if command -v go &> /dev/null; then
        go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
        echo "✓ httpx installed to $HOME/go/bin/httpx"
    else
        echo "❌ Go required. Install from: https://golang.org/doc/install"
        return 1
    fi
}

# Install netexec
install_netexec() {
    echo ""
    echo "Installing netexec..."
    if command -v pipx &> /dev/null; then
        pipx install git+https://github.com/Pennyw0rth/NetExec
    elif command -v pip3 &> /dev/null; then
        pip3 install git+https://github.com/Pennyw0rth/NetExec
    else
        echo "❌ pip3 or pipx required"
        return 1
    fi
}

# Setup Go PATH first
setup_go_path

echo ""
echo "Checking installed tools:"
NEED_NMAP=false
NEED_NUCLEI=false
NEED_HTTPX=false
NEED_NETEXEC=false

check_tool nmap || NEED_NMAP=true
check_tool nuclei || NEED_NUCLEI=true
check_tool httpx || NEED_HTTPX=true
check_tool netexec || check_tool nxc || NEED_NETEXEC=true

echo ""

# If all tools are installed, exit
if [[ "$NEED_NMAP" == false && "$NEED_NUCLEI" == false && "$NEED_HTTPX" == false && "$NEED_NETEXEC" == false ]]; then
    echo "✓ All security tools are already installed!"
    exit 0
fi

# Show what needs to be installed
echo "Missing tools detected. Installing..."
echo ""

# Install missing tools
[[ "$NEED_NMAP" == true ]] && install_nmap
[[ "$NEED_NUCLEI" == true ]] && install_nuclei
[[ "$NEED_HTTPX" == true ]] && install_httpx
[[ "$NEED_NETEXEC" == true ]] && install_netexec

echo ""
echo "================================"
echo "Installation Complete!"
echo "================================"
echo ""
echo "Verify tools are accessible:"
echo "  nmap --version"
echo "  nuclei -version"
echo "  httpx -version"
echo "  netexec --version"
echo ""