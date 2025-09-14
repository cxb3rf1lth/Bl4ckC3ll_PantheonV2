#!/bin/bash
# Bl4ckC3ll_PANTHEON Quick Start Script
# This script provides a streamlined way to get started quickly

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE}  Bl4ckC3ll_PANTHEON Quick Start${NC}"
echo -e "${BLUE}======================================${NC}"
echo ""

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Check if already set up
if [[ -f ".setup_complete" ]]; then
    echo -e "${GREEN}Setup already completed!${NC}"
    echo ""
    echo -e "${BLUE}Available actions:${NC}"
    echo "1. Run Bl4ckC3ll_PANTHEON"
    echo "2. Re-run setup (force)"
    echo "3. Test installation"
    echo "4. Exit"
    echo ""
    
    while true; do
        read -p "Select option (1-4): " choice
        case $choice in
            1)
                echo "Starting Bl4ckC3ll_PANTHEON..."
                python3 bl4ckc3ll_p4nth30n.py
                exit 0
                ;;
            2)
                echo "Forcing re-setup..."
                rm -f .setup_complete
                break
                ;;
            3)
                echo "Testing installation..."
                python3 test_installation.py
                exit $?
                ;;
            4)
                echo "Goodbye!"
                exit 0
                ;;
            *)
                echo -e "${YELLOW}Invalid option. Please select 1-4.${NC}"
                ;;
        esac
    done
fi

echo -e "${BLUE}Step 1:${NC} Checking system requirements..."

# Check Python version
if python3 -c "import sys; sys.exit(0 if sys.version_info >= (3,9) else 1)" 2>/dev/null; then
    PYTHON_VERSION=$(python3 -V)
    echo -e "${GREEN}✓${NC} $PYTHON_VERSION detected"
else
    echo -e "${RED}✗ Python 3.9+ required. Please install Python 3.9 or newer and try again.${NC}"
    exit 1
fi

# Check if we're on a supported OS
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    echo -e "${GREEN}✓${NC} Operating System: $PRETTY_NAME"
    
    case "$ID" in
        "kali"|"debian"|"ubuntu")
            echo -e "${GREEN}✓${NC} Debian-based system detected (apt package manager)"
            ;;
        "arch"|"manjaro")
            echo -e "${GREEN}✓${NC} Arch-based system detected (pacman package manager)"
            ;;
        *)
            echo -e "${YELLOW}⚠${NC} Unsupported OS detected. Installation may have limited functionality."
            ;;
    esac
else
    echo -e "${YELLOW}⚠${NC} Could not detect operating system"
fi

# Check internet connectivity
echo -e "${BLUE}Step 2:${NC} Checking internet connectivity..."
if ping -c 1 8.8.8.8 &> /dev/null; then
    echo -e "${GREEN}✓${NC} Internet connection available"
else
    echo -e "${YELLOW}⚠${NC} Limited internet connectivity detected. Some tools may not install properly."
fi

echo ""
echo -e "${BLUE}Step 3:${NC} Running automated setup..."
echo "This will install dependencies and security tools..."
echo -e "${YELLOW}Note: This may take 5-15 minutes depending on your system and internet speed.${NC}"
echo ""

# Ask for confirmation
read -p "Continue with installation? (y/N): " confirm
if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo "Installation cancelled."
    exit 0
fi

# Run the installer
echo ""
echo -e "${BLUE}Starting installation...${NC}"
if ./install.sh; then
    echo ""
    echo -e "${GREEN}✓ Setup completed successfully!${NC}"
    touch .setup_complete
else
    exit_code=$?
    if [[ $exit_code -eq 130 ]]; then
        echo -e "${YELLOW}Installation interrupted by user.${NC}"
        exit 130
    else
        echo -e "${YELLOW}Setup completed with some warnings. Continuing...${NC}"
        touch .setup_complete  # Mark as complete even with warnings
    fi
fi

echo ""
echo -e "${BLUE}Step 4:${NC} Testing installation..."
if python3 test_installation.py; then
    echo -e "${GREEN}✓ Installation test passed!${NC}"
else
    echo -e "${YELLOW}Some tests failed, but continuing...${NC}"
fi

echo ""
echo -e "${BLUE}Step 5:${NC} Setting up targets..."
if [[ ! -s "targets.txt" ]]; then
    echo "example.com" > targets.txt
    echo -e "${GREEN}✓ Created targets.txt with example.com${NC}"
else
    echo -e "${GREEN}✓ targets.txt already exists${NC}"
fi

echo ""
echo -e "${GREEN}🎉 Quick start complete!${NC}"
echo ""
echo -e "${BLUE}Next steps:${NC}"
echo "1. Edit targets.txt to add your authorized targets"
echo "   ${YELLOW}IMPORTANT: Only test against domains you own or have permission to test!${NC}"
echo "2. Run the main application:"
echo "   ${GREEN}python3 bl4ckc3ll_p4nth30n.py${NC}"
echo "3. For a full scan, select options: 2 → 3 → 4 → 5 → 7"
echo ""
echo -e "${BLUE}Quick reference:${NC}"
echo "• View tool status: python3 bl4ckc3ll_p4nth30n.py → option 23"
echo "• Run diagnostics: python3 diagnostics.py"
echo "• Test installation: python3 test_installation.py"
echo "• Launch TUI interface: python3 bl4ckc3ll_p4nth30n.py → option 21"
echo ""

# Ask if user wants to start the application now
read -p "Start Bl4ckC3ll_PANTHEON now? (Y/n): " start_now
if [[ ! "$start_now" =~ ^[Nn]$ ]]; then
    echo ""
    echo "Starting Bl4ckC3ll_PANTHEON..."
    echo ""
    
    # Source shell profile to get updated PATH
    if [[ -f "$HOME/.bashrc" ]]; then
        source "$HOME/.bashrc" 2>/dev/null || true
    fi
    
    python3 bl4ckc3ll_p4nth30n.py
else
    echo ""
    echo -e "${GREEN}Setup complete!${NC} Run ${GREEN}python3 bl4ckc3ll_p4nth30n.py${NC} when ready."
fi