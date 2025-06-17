#!/bin/bash

# Exit on any error, on unset variables, and on pipeline failures
set -euo pipefail

# --- Configuration ---
# Allow overriding the Python executable via an environment variable.
# Default to 'python3' if PYTHON_EXEC is not set.
PYTHON_EXEC=${PYTHON_EXEC:-python3}
PIP_COMMAND="$PYTHON_EXEC -m pip"
LIB_DIR="lib"
REQUIREMENTS_FILE="requirements.txt"

# --- Main Script ---
echo "--- Starting Dependency Installation ---"
echo "Using Python: $($PYTHON_EXEC --version)"
echo "Installing to: $LIB_DIR/"

# Check for required tools
if ! command -v "$PYTHON_EXEC" >/dev/null 2>&1; then
    echo "Error: '$PYTHON_EXEC' not found in PATH. Please install it or set the PYTHON_EXEC environment variable."
    exit 1
fi

# Check for requirements.txt
if [ ! -f "$REQUIREMENTS_FILE" ]; then
    echo "Error: '$REQUIREMENTS_FILE' not found. Please create it with the necessary dependencies."
    exit 1
fi

# Create lib directory
mkdir -p "$LIB_DIR"

# Install/upgrade pip and install dependencies from requirements.txt
echo "Upgrading pip..."
$PIP_COMMAND install --upgrade pip

echo "Installing dependencies from $REQUIREMENTS_FILE..."
$PIP_COMMAND install --target="$LIB_DIR" -r "$REQUIREMENTS_FILE"

# --- Verification ---
echo "Verifying critical dependencies..."
# This verification script now checks for the *actual* direct dependencies
$PYTHON_EXEC -c '
import sys
# Add the local lib directory to the path for this check
sys.path.insert(0, "lib")
try:
    from Cryptodome.Cipher import AES
    from Cryptodome.Protocol.KDF import PBKDF2
    import qrcode
    from mnemonic import Mnemonic
    import bitcoinx
    import psutil
    import zxcvbn
    print("✅ All critical dependencies verified successfully.")
except ImportError as e:
    print(f"❌ Error: Dependency verification failed. Could not import: {e}")
    sys.exit(1)
'

echo "---"
echo "✅ Dependency installation complete."
echo "You can now run the main script in an offline environment." 