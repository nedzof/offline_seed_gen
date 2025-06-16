#!/usr/bin/env python3

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'lib'))
import time
import json
import base64
import hashlib
import secrets
import getpass
import argparse
import subprocess
import ctypes
import re
import shutil
import random
import hmac
import tempfile
from typing import Tuple, Optional, List, Dict
from pathlib import Path
import traceback
from tqdm import tqdm
import psutil  # Add psutil import
from Cryptodome.Util.Padding import pad, unpad

# Add lib directory to Python path
lib_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'lib')
if lib_path not in sys.path:
    sys.path.insert(0, lib_path)

# Import local dependencies
from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Random import get_random_bytes
from Cryptodome.Hash import SHA256
import qrcode
from qrcode.constants import ERROR_CORRECT_L
from bitcoinx import BIP32PrivateKey, BIP32PublicKey, Network, Bitcoin
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm

# Constants
VERSION = "1.0"
QR_DIR = "qr_bundle"
WORDLIST_FILE = "wordlist.txt"

# Required dependencies
REQUIRED_DEPS = {
    'qrcode': 'included in lib/',
    'qrencode': 'apt-get install qrencode',
    'bitcoinx': 'included in lib/'
}

# Try to lock memory pages (requires root on most systems)
try:
    libc = ctypes.CDLL("libc.so.6")
    MCL_CURRENT = 1
    MCL_FUTURE = 2
    libc.mlockall(MCL_CURRENT | MCL_FUTURE)
except:
    pass  # Not critical if it fails

# Add color and bold formatting for terminal output
BOLD = '\033[1m'
CYAN = '\033[36m'
GREEN = '\033[32m'
YELLOW = '\033[33m'
RED = '\033[31m'
RESET = '\033[0m'

# Add section header helper after color constants
def section_header(title):
    print(f"\n{BOLD}{CYAN}{'='*28}\n  {title}\n{'='*28}{RESET}")

# Helper functions for colored output

def bold_cyan(text):
    return f"{BOLD}{CYAN}{text}{RESET}"

def green(text):
    return f"{GREEN}{text}{RESET}"

def yellow(text):
    return f"{YELLOW}{text}{RESET}"

def red(text):
    return f"{RED}{text}{RESET}"

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a key from the password using PBKDF2."""
    # Use SHA256 for key derivation
    key = PBKDF2(
        password.encode(),
        salt,
        dklen=32,
        count=100000,
        hmac_hash_module=SHA256
    )
    return key

def encrypt_wallet_data(mnemonic: str, passphrase: str, derivation_path: str, password: str) -> str:
    """Encrypt wallet data with password."""
    try:
        # Generate a random salt
        salt = os.urandom(16)
        
        # Generate key from password and salt
        key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode(),
            salt,
            100000,  # Number of iterations
            32  # Key length
        )
        
        # Generate a random IV
        iv = os.urandom(16)
        
        # Create cipher
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Prepare data to encrypt
        data = json.dumps({
            'mnemonic': mnemonic,
            'passphrase': passphrase,
            'derivation_path': derivation_path,
            'version': '1.0'
        })
        
        # Pad data
        padded_data = pad(data.encode(), 16)
        
        # Encrypt
        encrypted_data = cipher.encrypt(padded_data)
        
        # Combine salt, IV, and encrypted data
        result = {
            'salt': base64.b64encode(salt).decode(),
            'iv': base64.b64encode(iv).decode(),
            'ciphertext': base64.b64encode(encrypted_data).decode()
        }
        
        return json.dumps(result)
    except Exception as e:
        raise Exception(f"Encryption failed: {str(e)}")

def decrypt_wallet_info(encrypted_json: str, password: str) -> str:
    """Decrypt wallet info using the provided password."""
    try:
        # Parse the encrypted data
        data = json.loads(encrypted_json)
        salt = base64.b64decode(data['salt'])
        iv = base64.b64decode(data['iv'])
        encrypted_data = base64.b64decode(data['ciphertext'])
        
        # Generate key from password and salt
        key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode(),
            salt,
            100000,  # Number of iterations
            32  # Key length
        )
        
        # Create cipher
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Decrypt
        decrypted_padded = cipher.decrypt(encrypted_data)
        
        # Unpad
        decrypted_data = unpad(decrypted_padded, 16)
        
        return decrypted_data.decode()
    except Exception as e:
        raise Exception(f"Decryption failed: {str(e)}")

def generate_mnemonic() -> str:
    """Generate a new mnemonic phrase."""
    entropy = generate_entropy()
    mnemonic = entropy_to_mnemonic(entropy.hex())
    return ' '.join(mnemonic.split()[:12])

def run_self_test() -> bool:
    """Run self-test to verify all components are working (less verbose)."""
    tests_passed = True
    results = []

    # Test 1: Entropy Generation
    try:
        entropy = generate_entropy()
        if len(entropy) == 32:
            results.append(green("✓ Entropy generation"))
        else:
            results.append(red("✗ Entropy generation"))
            tests_passed = False
    except Exception:
        results.append(red("✗ Entropy generation"))
        tests_passed = False

    # Test 2: Mnemonic Generation
    try:
        mnemonic = generate_mnemonic()
        if len(mnemonic.split()) == 12:
            results.append(green("✓ Mnemonic generation"))
        else:
            results.append(red("✗ Mnemonic generation"))
            tests_passed = False
    except Exception:
        results.append(red("✗ Mnemonic generation"))
        tests_passed = False

    # Test 3: Encryption/Decryption
    try:
        test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        test_passphrase = "testpassphrase"
        test_derivation_path = "m/44'/236'/0'"
        test_password = "test_password123!"
        encrypted = encrypt_wallet_data(
            test_mnemonic,
            test_passphrase,
            test_derivation_path,
            test_password
        )
        decrypted = decrypt_wallet_info(encrypted, test_password)
        decrypted_data = json.loads(decrypted)
        if (decrypted_data['mnemonic'] == test_mnemonic and
            decrypted_data['passphrase'] == test_passphrase and
            decrypted_data['derivation_path'] == test_derivation_path):
            results.append(green("✓ Encryption/Decryption"))
        else:
            results.append(red("✗ Encryption/Decryption"))
            tests_passed = False
    except Exception:
        results.append(red("✗ Encryption/Decryption"))
        tests_passed = False

    # Test 4: QR Code Generation
    try:
        test_data = "test data"
        generate_qr(test_data, "test_qr.png", print_only=True)
        generate_qr_pdf(test_data, "test_qr.pdf", paranoid=False, print_only=True)
        results.append(green("✓ QR code generation"))
    except Exception:
        results.append(red("✗ QR code generation"))
        tests_passed = False

    # Test 5: Password Strength
    try:
        weak_password = "weak"
        strong_password = "StrongP@ssw0rd123!"
        weak_result, _ = check_password_strength(weak_password)
        strong_result, _ = check_password_strength(strong_password)
        if not weak_result and strong_result:
            results.append(green("✓ Password strength check"))
        else:
            results.append(red("✗ Password strength check"))
            tests_passed = False
    except Exception:
        results.append(red("✗ Password strength check"))
        tests_passed = False

    section_header("Self-Test")
    for line in results:
        print(line)
    if tests_passed:
        print(green("✓ All tests passed!"))
    else:
        print(red("✗ Some tests failed."))
    return tests_passed

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Generate and encrypt wallet data')
    parser.add_argument('--paranoid', action='store_true', help='Paranoid mode: ASCII QR only')
    parser.add_argument('--print-only', action='store_true', help='Print-only mode: No file output')
    parser.add_argument('--selftest', action='store_true', help='Run self-test mode')
    parser.add_argument('--decrypt', action='store_true', help='Decrypt wallet info from QR code')
    return parser.parse_args()

def check_security() -> None:
    """Run security checks before proceeding"""
    section_header("Security Checks")
    
    # Check for network connectivity
    try:
        import socket
        socket.create_connection(("8.8.8.8", 53), timeout=1)
        print(yellow("⚠️  Warning: Network connection detected. For maximum security, run this script on an air-gapped system."))
    except:
        print(green("✓ No network connection detected"))
    
    # Check for memory locking
    try:
        if ctypes.CDLL('libc.so.6').mlockall(2) == 0:
            print(green("✓ Memory locking enabled"))
        else:
            print(yellow("⚠️  Warning: Could not lock memory"))
    except:
        print(yellow("⚠️  Warning: Could not enable memory locking"))
    
    # Check for secure environment
    if os.environ.get('DISPLAY'):
        print(yellow("⚠️  Warning: Running in GUI environment. Consider using a terminal-only session."))
    else:
        print(green("✓ Running in terminal environment"))
    
    # Check for root privileges
    if os.geteuid() == 0:
        print(yellow("⚠️  Warning: Running as root. Consider running as a normal user."))
    else:
        print(green("✓ Running as normal user"))
    
    print(bold_cyan("\nSecurity checks completed."))

def generate_entropy(length: int = 32) -> bytes:
    """Generate cryptographically secure random data."""
    return secrets.token_bytes(length)

def entropy_to_mnemonic(entropy):
    """Convert entropy to mnemonic words using BIP39 word list"""
    with open(WORDLIST_FILE, 'r') as f:
        wordlist = [word.strip() for word in f.readlines()]
    
    # Calculate checksum
    entropy_bytes = bytes.fromhex(entropy)
    checksum = hashlib.sha256(entropy_bytes).digest()[0]
    checksum_bits = bin(checksum)[2:].zfill(8)[:len(entropy_bytes) * 8 // 32]
    
    # Combine entropy and checksum
    binary = bin(int(entropy, 16))[2:].zfill(len(entropy) * 4) + checksum_bits
    
    # Split into 11-bit chunks and map to words
    words = []
    for i in range(0, len(binary), 11):
        index = int(binary[i:i+11], 2)
        words.append(wordlist[index])
    
    return ' '.join(words)

def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    """Convert mnemonic to seed using PBKDF2."""
    mnemonic_bytes = mnemonic.encode('utf-8')
    passphrase_bytes = passphrase.encode('utf-8')
    return hashlib.pbkdf2_hmac(
        'sha512',
        mnemonic_bytes,
        b'mnemonic' + passphrase_bytes,
        2048
    )

def seed_to_master_key(seed: bytes) -> BIP32PrivateKey:
    """Convert seed to master key using BIP32."""
    return BIP32PrivateKey.from_seed(seed, Bitcoin)

def derive_addresses(master_key: BIP32PrivateKey, derivation_path: str, count: int = 10) -> List[str]:
    """Derive addresses using the specified derivation path."""
    # Parse the derivation path
    path_parts = derivation_path.split('/')
    if len(path_parts) < 4:
        raise ValueError("Invalid derivation path format")
    
    # Derive the account key
    account_key = master_key
    for part in path_parts[1:]:  # Skip 'm'
        if part.endswith("'"):
            hardened = True
            index = int(part[:-1]) | 0x80000000
        else:
            hardened = False
            index = int(part)
        account_key = account_key.child(index)
    
    addresses = []
    for i in range(count):
        # Derive external chain addresses
        address_key = account_key.child(0).child(i)
        addresses.append(address_key.public_key.to_address().to_string())
    return addresses

def generate_wallet(entropy_length: int = 16, passphrase: str = "", derivation_path: str = "m/44'/236'/0'") -> Dict:
    """Generate a new wallet with the specified parameters."""
    # Generate entropy
    entropy = generate_entropy(entropy_length)
    
    # Convert entropy to mnemonic
    mnemonic = entropy_to_mnemonic(entropy.hex())
    
    # Generate seed from mnemonic and passphrase
    seed = mnemonic_to_seed(mnemonic, passphrase)
    
    # Generate master key
    master_key = seed_to_master_key(seed)
    
    # Create wallet info dictionary
    wallet_info = {
        'mnemonic': mnemonic,
        'passphrase': passphrase,
        'derivation_path': derivation_path,
        'version': VERSION
    }
    
    # Derive master key and xpub/xprv
    xprv = master_key.to_extended_key_string()
    xpub = master_key.public_key.to_extended_key_string()
    # Write cleartext info
    with open("wallet_info_clear.txt", "w") as f:
        f.write("*** WARNING: This file contains all sensitive wallet information. ***\n")
        f.write("Write down and store securely.\n\n")
        f.write(f"Mnemonic (seed phrase):\n{wallet_info['mnemonic']}\n\n")
        f.write(f"Passphrase: {wallet_info['passphrase']}\n\n")
        f.write(f"Derivation path: {wallet_info['derivation_path']}\n\n")
        f.write(f"Master Private Key (xprv):\n{xprv}\n\n")
        f.write(f"Master Public Key (xpub):\n{xpub}\n\n")
    print(green(f"✓ Wallet info saved (plaintext: wallet_info_clear.txt)"))
    
    return wallet_info

def secure_erase_histories():
    """Securely erase shell and Python history files."""
    home = os.path.expanduser('~')
    history_files = [
        os.path.join(home, '.bash_history'),
        os.path.join(home, '.zsh_history'),
        os.path.join(home, '.python_history'),
    ]
    for hist_file in history_files:
        try:
            if os.path.exists(hist_file):
                with open(hist_file, 'w') as f:
                    f.write('')
                os.remove(hist_file)
                print(f"✓ Erased {hist_file}")
        except Exception as e:
            print(f"✗ Could not erase {hist_file}: {e}")
    print("If you want to be absolutely sure, reboot your system to clear RAM traces.")

def secure_exit():
    """Securely exit the program, clearing sensitive data."""
    # Securely delete any temporary files
    temp_files = [
        'wallet_info.txt',
        'wallet_info.txt.decrypted'
    ]
    for file in temp_files:
        secure_delete(file)
    section_header("Exit")
    print(green("✓ Done! Keep your seed phrase and derivation path safe."))
    sys.exit(0)
    
def check_password_strength(password: str) -> Tuple[bool, str]:
    """Check password strength and return (is_valid, error_message)."""
    if len(password) < 15:
        return False, "Password must be at least 15 characters long"
    return True, ""

def secure_delete(filename: str) -> None:
    """Securely delete a file using shred if available, otherwise overwrite."""
    try:
        if os.path.exists(filename):
            if shutil.which('shred'):
                subprocess.run(['shred', '-vfz', '-n', '3', filename], check=True)
            else:
                # Fallback to overwriting
                with open(filename, 'ba+', buffering=0) as f:
                    length = f.tell()
                    f.seek(0)
                    f.write(os.urandom(length))
                    f.flush()
                    os.fsync(f.fileno())
            os.remove(filename)
    except Exception as e:
        print(f"Warning: Could not securely delete {filename}: {e}")

def verify_wordlist_integrity() -> bool:
    WORDLIST_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
    try:
        with open(WORDLIST_FILE, 'rb') as f:
            if hashlib.sha256(f.read()).hexdigest() != WORDLIST_SHA256:
                return False
        return True
    except Exception as e:
        print(f"Error verifying wordlist: {e}")
        return False

def display_ascii_qr(data: str) -> None:
    """Display QR code in terminal using ASCII art."""
    try:
        import qrcode
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_Q,
            box_size=2,
            border=2
        )
        qr.add_data(data)
        qr.make(fit=True)
        qr.print_ascii(invert=True)
    except ImportError:
        print("qrcode module not found. Install with: pip install qrcode[pil]")
        print("Encrypted data (copy/paste into another QR tool):")
        print(data)

def generate_qr(data: str, filename: str, print_only: bool = False) -> None:
    """Generate QR code from data and save to file."""
    try:
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(data)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        
        if not print_only:
            img.save(filename)
            print(green(f"QR code saved to {filename}"))
        else:
            print(yellow("Print-only mode: QR code not saved to file"))
    except Exception as e:
        print(red(f"Error generating QR code: {e}"))
        raise

def generate_qr_pdf(data: str, filename: str, paranoid: bool = False, print_only: bool = False) -> None:
    """Generate PDF with multiple QR codes, splitting address data into chunks of 50 addresses per QR code."""
    try:
        # Try to parse as JSON list of addresses
        try:
            addresses = json.loads(data)
            if isinstance(addresses, list):
                # Split into chunks of 50 addresses
                chunk_size = 50
                chunks = [json.dumps(addresses[i:i+chunk_size]) for i in range(0, len(addresses), chunk_size)]
            else:
                # Not a list, treat as single chunk
                chunks = [data]
        except Exception:
            # Not JSON, treat as single chunk
            chunks = [data]

        if not print_only:
            c = canvas.Canvas(filename)
            width, height = A4
            qr_size = 44 * mm
            margin = 10 * mm
            cols = 3
            rows = 4
            col_spacing = (width - 2 * margin - cols * qr_size) / (cols - 1)
            row_spacing = (height - 2 * margin - rows * qr_size) / (rows - 1)
            qr_count = 0
            for i, chunk in enumerate(chunks):
                qr = qrcode.QRCode(
                    version=None,  # Let qrcode pick the smallest version that fits
                    error_correction=qrcode.constants.ERROR_CORRECT_L,
                    box_size=10,
                    border=2,
                )
                qr.add_data(chunk)
                qr.make(fit=True)
                img = qr.make_image(fill_color="black", back_color="white")
                row = (qr_count % (cols * rows)) // cols
                col = qr_count % cols
                if qr_count > 0 and qr_count % (cols * rows) == 0:
                    c.showPage()
                x = margin + col * (qr_size + col_spacing)
                y = height - margin - (row + 1) * qr_size - row * row_spacing
                temp_path = f"temp_qr_{i}.png"
                img.save(temp_path)
                c.drawImage(temp_path, x, y, width=qr_size, height=qr_size)
                c.setFont("Helvetica", 10)
                c.drawString(x, y - 8, f"QR {i+1}/{len(chunks)}")
                os.remove(temp_path)
                qr_count += 1
            c.save()
            print(green(f"PDF with QR codes saved to {filename}"))
        else:
            print(yellow("Print-only mode: PDF not saved to file"))
    except Exception as e:
        print(red(f"Error generating PDF: {e}"))
        raise

def generate_encrypted_qr(data: str, password: str, filename: str) -> None:
    """Generate an encrypted QR code for secure air-gapped transfer."""
    try:
        encrypted = encrypt_wallet_data(data, password)
        generate_qr(encrypted, filename)
    except Exception as e:
        print(f"Warning: Could not generate encrypted QR data: {e}")

def generate_p2pkh_addresses(mnemonic: str, passphrase: str, derivation_path: str, count: int = 1000) -> List[str]:
    """Generate P2PKH addresses from the seed."""
    try:
        # Convert mnemonic to seed
        seed = mnemonic_to_seed(mnemonic, passphrase)
        
        # Create master key
        master_key = BIP32PrivateKey.from_seed(seed, Bitcoin)
        
        # Parse derivation path
        path_parts = derivation_path.split('/')
        current_key = master_key
        
        # Derive the path
        for part in path_parts[1:]:  # Skip 'm'
            if part.endswith("'"):
                # For hardened keys, add 0x80000000 to the index
                index = int(part[:-1]) + 0x80000000
                current_key = current_key.child(index)
            else:
                current_key = current_key.child(int(part))
        
        # Generate addresses
        addresses = []
        for i in tqdm(range(count), desc="Generating P2PKH addresses", unit="addr"):
            child_key = current_key.child(i)
            public_key = child_key.public_key
            p2pkh_address = public_key.to_address()
            addresses.append(str(p2pkh_address))
        
        return addresses
    except Exception as e:
        raise Exception(f"Failed to generate P2PKH addresses: {e}")

def find_usb_drives() -> list:
    """
    Finds mounted removable USB drives.
    Returns:
        A list of mount points (paths) for removable drives.
    """
    usb_drives = []
    print(bold_cyan("\nScanning for USB drives..."))
    partitions = psutil.disk_partitions()
    for partition in partitions:
        if 'removable' in partition.opts or partition.device.startswith('/dev/sd'):
            if partition.mountpoint.startswith('/media') or partition.mountpoint.startswith('/mnt'):
                usb_drives.append(partition.mountpoint)
                print(green(f"Found potential USB drive: {partition.device} mounted at {partition.mountpoint}"))
    return usb_drives

def select_usb_drive(drives: list) -> str:
    """
    Prompts the user to select a USB drive from a list.
    Args:
        drives: A list of detected USB drive mount points.
    Returns:
        The path to the selected USB drive, or None if cancelled.
    """
    if not drives:
        print(red("No USB drives found. Please insert a USB drive and ensure it is mounted."))
        return None
    if len(drives) == 1:
        drive_path = drives[0]
        print(yellow(f"\nDetected a single USB drive at: {drive_path}"))
        confirm = input(bold_cyan("Do you want to save all output files here? (y/n): ")).lower()
        if confirm == 'y':
            return drive_path
        else:
            print(red("Operation cancelled by user."))
            return None
    else:
        print(yellow("\nMultiple USB drives detected. Please choose one:"))
        for i, drive in enumerate(drives):
            print(f"{i + 1}: {drive}")
        try:
            choice = int(input(bold_cyan("Enter the number of the drive to use: "))) - 1
            if 0 <= choice < len(drives):
                return drives[choice]
            else:
                print(red("Invalid choice."))
                return None
        except (ValueError, IndexError):
            print(red("Invalid input."))
            return None

def main():
    """Main function."""
    try:
        # Parse command line arguments
        parser = argparse.ArgumentParser(description='BSV Wallet Generator')
        parser.add_argument('--print-only', action='store_true', help='Only print QR codes, do not save files')
        parser.add_argument('--paranoid', action='store_true', help='Enable paranoid mode with additional security checks')
        args = parser.parse_args()

        # Run self-test
        if not run_self_test():
            sys.exit(1)

        # --- NEW: Save Location Selection Logic ---
        available_drives = find_usb_drives()
        show_usb = len(available_drives) > 0
        section_header("Save Location")
        options = []
        if show_usb:
            print("1. USB Drive (recommended for air-gapped systems)")
            options.append("usb")
        print(f"{len(options)+1}. Documents folder")
        options.append("documents")
        print(f"{len(options)+1}. Current directory")
        options.append("current")
        
        default_choice = 1 if show_usb else 0
        choice = input(bold_cyan(f"Enter your choice (1-{len(options)}) [default: {default_choice+1}]: ")).strip() or str(default_choice+1)
        choice = int(choice) - 1
        
        if options[choice] == "usb":
            selected_drive = select_usb_drive(available_drives)
            if not selected_drive:
                print(yellow("No USB drive selected. Defaulting to Documents folder."))
                output_dir = os.path.join(os.path.expanduser("~"), "Documents", "wallet_generation_output")
            else:
                output_dir = os.path.join(selected_drive, "wallet_generation_output")
                print(green(f"Output will be saved to: {output_dir}"))
        elif options[choice] == "documents":
            output_dir = os.path.join(os.path.expanduser("~"), "Documents", "wallet_generation_output")
            print(green(f"Output will be saved to: {output_dir}"))
        else:
            output_dir = "wallet_generation_output"
            print(green(f"Output will be saved to: {os.path.abspath(output_dir)}"))
        # --- END of new logic ---

        # Verify wordlist
        if not verify_wordlist_integrity():
            sys.exit(1)

        # Run security checks
        check_security()
        
        # Prompt for password twice to verify
        password = getpass.getpass(bold_cyan("Enter password to encrypt wallet info: "))
        if not password:
            print(red("Password cannot be empty!"))
            return
        confirm_password = getpass.getpass(bold_cyan("Confirm password: "))
        if password != confirm_password:
            print(red("Passwords do not match!"))
            return
        
        # Prompt for derivation path
        print(bold_cyan("\nChoose derivation path for your wallet:"))
        print("1. ElectrumSV (m/44'/236'/0') [recommended for BSV]")
        print("2. Standard BIP44 (m/44'/0'/0') [legacy/other wallets]")
        path_choice = input(bold_cyan("Enter 1 or 2 [default 1]: ")).strip()
        if path_choice == '2':
            derivation_path = "m/44'/0'/0'"
        else:
            derivation_path = "m/44'/236'/0'"
        
        # Generate wallet
        wallet_info = generate_wallet(derivation_path=derivation_path)
        
        # Encrypt wallet data
        encrypted_data = encrypt_wallet_data(
            wallet_info['mnemonic'],
            wallet_info['passphrase'],
            wallet_info['derivation_path'],
            password
        )
        
        # After determining output_dir, ensure it exists
        os.makedirs(output_dir, exist_ok=True)
        
        # Save encrypted data to the chosen output directory
        if not args.print_only:
            encrypted_file_path = os.path.join(output_dir, "wallet_info_encrypted.txt")
            with open(encrypted_file_path, "w") as f:
                f.write(encrypted_data)
            print(green(f"\nEncrypted wallet data saved to {encrypted_file_path}"))
        
        # Generate QR code for wallet info
        if input(bold_cyan("\nDo you want to generate a QR code PDF with the encrypted wallet info? (y/n): ")).lower() == 'y':
            pdf_path = os.path.join(output_dir, "wallet_info_encrypted.pdf")
            generate_qr_pdf(encrypted_data, pdf_path, args.paranoid, args.print_only)
            print(green(f"✓ Encrypted wallet QR PDF saved: {os.path.basename(pdf_path)}"))

        # Generate P2PKH addresses
        if input(bold_cyan("\nDo you want to generate an unencrypted QR code PDF with 1000 P2PKH addresses? (y/n): ")).lower() == 'y':
            addresses = generate_p2pkh_addresses(wallet_info['mnemonic'], wallet_info['passphrase'], wallet_info['derivation_path'])
            addresses_data = json.dumps(addresses, indent=2)
            
            addresses_json_path = os.path.join(output_dir, "p2pkh_addresses.json")
            addresses_pdf_path = os.path.join(output_dir, "p2pkh_addresses.pdf")

            if not args.print_only:
                with open(addresses_json_path, "w") as f:
                    f.write(addresses_data)
                print(green(f"✓ Addresses saved: {os.path.basename(addresses_json_path)}"))
            
            print("Generating QR codes for addresses...")
            generate_qr_pdf(addresses_data, addresses_pdf_path, args.paranoid, args.print_only)
            print(green(f"✓ Address QR PDF saved: {os.path.basename(addresses_pdf_path)}"))

        # Automatically erase shell and Python history
        secure_erase_histories()
        print(yellow("Shell and Python history erased for your privacy."))
        
        # Secure exit
        secure_exit()

    except KeyboardInterrupt:
        print(yellow("\nOperation cancelled by user."))
        sys.exit(1)
    except Exception as e:
        print(red(f"An error occurred: {e}"))
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main() 