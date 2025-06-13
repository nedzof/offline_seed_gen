#!/bin/bash

# Exit on error
set -e

echo "Starting dependency installation..."

# Create lib directory if it doesn't exist
mkdir -p lib

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check for required tools
if ! command_exists pip; then
    echo "Error: pip is not installed. Please install pip first."
    exit 1
fi

# Install dependencies locally with specific versions
echo "Installing dependencies..."
pip install --target=lib \
    pycryptodomex==3.19.0 \
    qrcode==7.4.2 \
    reportlab==4.0.8 \
    bitcoinx==0.9.0 \
    electrumsv-secp256k1==18.0.0 \
    pillow==11.2.1 \
    typing-extensions==4.14.0 \
    pypng==0.20220715.0 \
    attrs==25.3.0 \
    cffi==1.17.1 \
    pycparser==2.22

# Verify critical dependencies
echo "Verifying installations..."
python3 -c "
import sys
sys.path.insert(0, 'lib')
try:
    from Cryptodome.Cipher import AES
    from Cryptodome.Protocol.KDF import scrypt
    import qrcode
    from reportlab.pdfgen import canvas
    from bitcoinx import BIP32PrivateKey, Bitcoin
    from electrumsv_secp256k1 import create_context
    print('All critical dependencies verified successfully.')
except ImportError as e:
    print(f'Error: Failed to import {str(e)}')
    sys.exit(1)
"

echo "Dependencies installed and verified successfully in lib directory"
echo "You can now run the script offline using: python3 main.py" 