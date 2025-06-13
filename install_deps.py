#!/usr/bin/env python3
import os
import sys
import subprocess
from pathlib import Path

def install_dependencies():
    """Install required dependencies in the local Python environment"""
    # Get the path to the local Python executable
    python_path = Path(__file__).parent / 'bin' / 'python3.10'
    if not python_path.exists():
        print(f"Error: Python executable not found at {python_path}")
        sys.exit(1)

    # Get the path to the lib directory
    lib_path = Path(__file__).parent / 'lib'
    if not lib_path.exists():
        print(f"Error: lib directory not found at {lib_path}")
        sys.exit(1)

    # Install pycryptodomex
    pycryptodomex_path = lib_path / 'pycryptodomex-3.23.0-cp37-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl'
    if not pycryptodomex_path.exists():
        print(f"Error: pycryptodomex wheel not found at {pycryptodomex_path}")
        sys.exit(1)

    try:
        # Install pycryptodomex
        subprocess.run([
            str(python_path),
            '-m', 'pip', 'install',
            '--no-index',
            '--find-links', str(lib_path),
            'pycryptodomex'
        ], check=True)
        print("Successfully installed pycryptodomex")

        # Install qrcode
        subprocess.run([
            str(python_path),
            '-m', 'pip', 'install',
            'qrcode'
        ], check=True)
        print("Successfully installed qrcode")

    except subprocess.CalledProcessError as e:
        print(f"Error installing dependencies: {e}")
        sys.exit(1)

if __name__ == '__main__':
    install_dependencies() 