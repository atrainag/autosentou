#!/bin/bash

# Automated Penetration Testing Tool Installation Script
# This script installs all required dependencies and tools

set -e  # Exit on any error

echo "🔒 Installing Automated Penetration Testing Tool..."
echo "=================================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   print_warning "This script is running as root. Consider running as a regular user."
fi

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
else
    print_error "Unsupported operating system: $OSTYPE"
    exit 1
fi

print_status "Detected OS: $OS"

# Update package lists
print_status "Updating package lists..."
if [[ "$OS" == "linux" ]]; then
    if command -v apt-get &> /dev/null; then
        sudo apt-get update
        PACKAGE_MANAGER="apt"
    elif command -v yum &> /dev/null; then
        sudo yum update
        PACKAGE_MANAGER="yum"
    elif command -v dnf &> /dev/null; then
        sudo dnf update
        PACKAGE_MANAGER="dnf"
    else
        print_error "No supported package manager found"
        exit 1
    fi
elif [[ "$OS" == "macos" ]]; then
    if command -v brew &> /dev/null; then
        brew update
        PACKAGE_MANAGER="brew"
    else
        print_error "Homebrew not found. Please install Homebrew first."
        exit 1
    fi
fi

# Install Python dependencies
print_status "Installing Python dependencies..."
if command -v python3 &> /dev/null; then
    python3 -m pip install --upgrade pip
    python3 -m pip install -r requirements.txt
    print_success "Python dependencies installed"
else
    print_error "Python3 not found. Please install Python 3.8+ first."
    exit 1
fi

# Install system tools
print_status "Installing system tools..."

if [[ "$OS" == "linux" ]]; then
    case $PACKAGE_MANAGER in
        "apt")
            sudo apt-get install -y \
                nmap \
                hydra \
                medusa \
                sqlmap \
                pandoc \
                dnsutils \
                whois \
                python3-pip \
                python3-venv \
                git \
                curl \
                wget \ 
                exploitdb \
                feroxbuster
            ;;
        "yum")
            sudo yum install -y \
                nmap \
                hydra \
                medusa \
                sqlmap \
                pandoc \
                bind-utils \
                whois \
                python3-pip \
                git \
                curl \
                wget \ 
                exploitdb \
                feroxbuster
            ;;
        "dnf")
            sudo dnf install -y \
                nmap \
                hydra \
                medusa \
                sqlmap \
                pandoc \
                bind-utils \
                whois \
                python3-pip \
                git \
                curl \
                wget \ 
                exploitdb \
                feroxbuster
            ;;
    esac
elif [[ "$OS" == "macos" ]]; then
    brew install \
        nmap \
        hydra \
        medusa \
        sqlmap \
        pandoc \
        bind \
        whois \
        python3 \
        git \
        curl \
        wget \ 
        feroxbuster
fi

print_success "System tools installed"

# Install dirsearch
print_status "Installing dirsearch..."
if [[ ! -d "/opt/dirsearch" ]]; then
    sudo mkdir -p /opt
    sudo git clone https://github.com/maurosoria/dirsearch.git /opt/dirsearch
    sudo chmod +x /opt/dirsearch/dirsearch.py
    sudo ln -sf /opt/dirsearch/dirsearch.py /usr/local/bin/dirsearch
    print_success "dirsearch installed"
else
    print_warning "dirsearch already installed"
fi

# Install dnsenum
print_status "Installing dnsenum..."
if [[ ! -d "/opt/dnsenum" ]]; then
    sudo mkdir -p /opt
    sudo git clone https://github.com/fwaeytens/dnsenum.git /opt/dnsenum
    sudo chmod +x /opt/dnsenum/dnsenum.pl
    sudo ln -sf /opt/dnsenum/dnsenum.pl /usr/local/bin/dnsenum
    print_success "dnsenum installed"
else
    print_warning "dnsenum already installed"
fi

# Create wordlists directory
print_status "Creating wordlists directory..."
sudo mkdir -p /usr/share/wordlists
if [[ ! -f "/usr/share/wordlists/rockyou.txt" ]]; then
    print_status "Downloading rockyou.txt wordlist..."
    sudo wget -O /usr/share/wordlists/rockyou.txt https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
    sudo chmod 644 /usr/share/wordlists/rockyou.txt
    print_success "rockyou.txt wordlist installed"
else
    print_warning "rockyou.txt wordlist already exists"
fi

# Install dirb wordlist
if [[ ! -f "/usr/share/wordlists/dirb/common.txt" ]]; then
    print_status "Installing dirb wordlists..."
    if [[ "$OS" == "linux" ]]; then
        case $PACKAGE_MANAGER in
            "apt")
                sudo apt-get install -y dirb
                ;;
            "yum"|"dnf")
                sudo $PACKAGE_MANAGER install -y dirb
                ;;
        esac
    elif [[ "$OS" == "macos" ]]; then
        brew install dirb
    fi
    print_success "dirb wordlists installed"
else
    print_warning "dirb wordlists already exist"
fi

# Create reports directory
print_status "Creating reports directory..."
mkdir -p reports
chmod 755 reports

# Set up environment variables
print_status "Setting up environment variables..."
cat > .env << EOF
# Tool paths
NMAP_PATH=/usr/bin/nmap
DIRSEARCH_PATH=/usr/local/bin/dirsearch
HYDRA_PATH=/usr/bin/hydra
MEDUSA_PATH=/usr/bin/medusa
SQLMAP_PATH=/usr/bin/sqlmap
PANDOC_PATH=/usr/bin/pandoc

# Wordlists
DIRSEARCH_WORDLIST=/usr/share/wordlists/dirb/common.txt
HYDRA_USERNAME_LIST=/usr/share/wordlists/rockyou.txt
HYDRA_PASSWORD_LIST=/usr/share/wordlists/rockyou.txt
MEDUSA_USERNAME_LIST=/usr/share/wordlists/rockyou.txt
MEDUSA_PASSWORD_LIST=/usr/share/wordlists/rockyou.txt
EOF

print_success "Environment variables configured"

# Test tool availability
print_status "Testing tool availability..."
python3 -c "
from  services.config import config_manager
tools = config_manager.validate_tools()
print('Tool Status:')
for tool, available in tools.items():
    status = '✓' if available else '✗'
    print(f'  {tool}: {status}')
"

# Create systemd service (Linux only)
if [[ "$OS" == "linux" ]]; then
    print_status "Creating systemd service..."
    sudo tee /etc/systemd/system/ service > /dev/null << EOF
[Unit]
Description=Automated Penetration Testing Tool
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$(pwd)
ExecStart=/usr/bin/python3 -m uvicorn main:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    print_success "Systemd service created"
fi

# Final setup
print_status "Setting up database..."
python3 -c "
from  database import engine
import models
models.Base.metadata.create_all(bind=engine)
print('Database initialized')
"

print_success "Installation completed successfully!"
echo ""
echo "🚀 Quick Start:"
echo "1. Start the server: python3 -m uvicorn main:app --reload --host 0.0.0.0 --port 8000"
echo "2. Open your browser: http://localhost:8000"
echo "3. View API docs: http://localhost:8000/docs"
echo "4. Use the frontend: Open frontend_example.html in your browser"
echo ""
echo "📚 Documentation:"
echo "- README.md: Complete documentation"
echo "- API docs: http://localhost:8000/docs"
echo "- Frontend example: frontend_example.html"
echo ""
echo "🔧 Configuration:"
echo "- Edit .env file to customize tool paths"
echo "- Modify services/config.py for advanced settings"
echo ""
print_success "Happy pentesting! 🔒"
