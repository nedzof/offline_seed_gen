#!/bin/bash

# Create lib directory if it doesn't exist
mkdir -p lib

# Download dependencies
pip download --only-binary=:all: --platform manylinux2014_x86_64 --python-version 3.10 --implementation cp --abi cp310 --dest lib \
    pycryptodomex==3.23.0 \
    qrcode==7.4.2 \
    Pillow==10.0.0 \
    bitcoinx==0.9

# Extract wheel files
cd lib
for wheel in *.whl; do
    if [ -f "$wheel" ]; then
        unzip -o "$wheel" -d .
    fi
done

# Clean up wheel files
rm -f *.whl

echo "Dependencies installed locally in lib folder" 