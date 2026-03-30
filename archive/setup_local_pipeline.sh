#!/bin/bash
# Setup script for Local Mutation Pipeline
# Linux/Mac Bash Script

echo "========================================"
echo "LLMalMorph Local Pipeline Setup"
echo "========================================"
echo ""

# Check Python
echo "[1/5] Checking Python installation..."
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python3 not found! Please install Python 3.8+"
    exit 1
fi
python3 --version
echo ""

# Check if in correct directory
echo "[2/5] Checking directory..."
if [ ! -d "src" ]; then
    echo "ERROR: Please run this script from the project root directory"
    exit 1
fi
echo "Current directory: $(pwd)"
echo ""

# Install dependencies
echo "[3/5] Installing dependencies..."
echo "This may take a few minutes..."
pip3 install -q mistralai requests tree-sitter tree-sitter-c tree-sitter-cpp rarfile
if [ $? -ne 0 ]; then
    echo "WARNING: Some packages failed to install"
    echo "Try: pip3 install -r requirements.txt"
else
    echo "✓ Dependencies installed successfully"
fi
echo ""

# Check config file
echo "[4/5] Checking configuration..."
if [ ! -f "local_config.json" ]; then
    echo "WARNING: local_config.json not found!"
    echo "Please ensure the config file exists"
else
    echo "✓ Config file found: local_config.json"
fi
echo ""

# Check API key
echo "[5/5] Checking API key..."
if [ -z "$MISTRAL_API_KEY" ]; then
    echo "⚠️  WARNING: MISTRAL_API_KEY environment variable not set!"
    echo ""
    echo "Please set your API key:"
    echo "  export MISTRAL_API_KEY=\"your-key\""
    echo ""
    echo "Add to ~/.bashrc or ~/.zshrc to make it permanent:"
    echo "  echo 'export MISTRAL_API_KEY=\"your-key\"' >> ~/.bashrc"
    echo ""
    read -p "Would you like to set it now for this session? (y/n): " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        read -p "Enter your Mistral API key: " API_KEY
        export MISTRAL_API_KEY="$API_KEY"
        echo "✓ API key set for this session"
    fi
else
    echo "✓ API key is set"
fi
echo ""

echo "========================================"
echo "Setup Complete!"
echo "========================================"
echo ""
echo "Next steps:"
echo "  1. Ensure your API key is set (see above)"
echo "  2. Review local_config.json settings"
echo "  3. Run pipeline:"
echo "     python3 test_local.py --stage all"
echo ""
echo "Or open notebook:"
echo "  jupyter notebook test_local.ipynb"
echo ""
echo "For help, see LOCAL_PIPELINE_README.md"
echo ""





