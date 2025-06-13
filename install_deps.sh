#!/bin/bash

# Create lib directory if it doesn't exist
mkdir -p lib

# Install dependencies locally
pip install --target=lib \
    pycryptodomex==3.19.0 \
    qrcode==7.4.2 \
    reportlab==4.0.8

echo "Dependencies installed successfully in lib directory" 