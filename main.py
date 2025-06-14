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
    """Encrypt wallet data using AES-256-GCM"""
    try:
        # Generate a random salt
        salt = get_random_bytes(16)
        
        # Derive key using PBKDF2
        key = PBKDF2(
            password.encode(),
            salt,
            dkLen=32,  # 256 bits
            count=100000,  # Number of iterations
            hmac_hash_module=SHA256
        )
        
        # Prepare data for encryption
        data = json.dumps({
            'mnemonic': mnemonic,
            'passphrase': passphrase,
            'derivation_path': derivation_path
        }).encode()
        
        # Generate a random nonce
        nonce = get_random_bytes(12)
        
        # Create cipher
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        
        # Encrypt data
        ciphertext, tag = cipher.encrypt_and_digest(data)
        
        # Combine all components
        encrypted_data = {
            'version': VERSION,
            'salt': base64.b64encode(salt).decode(),
            'nonce': base64.b64encode(nonce).decode(),
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'tag': base64.b64encode(tag).decode()
        }
        
        return json.dumps(encrypted_data)
        
    except Exception as e:
        raise Exception(f"Encryption failed: {e}")

def decrypt_with_rate_limit(encrypted_data: str, password: str, attempt: int) -> str:
    """Decrypt wallet data with rate limiting"""
    try:
        # Parse encrypted data
        data = json.loads(encrypted_data)
        
        # Check version
        if data.get('version') != VERSION:
            raise ValueError(f"Unsupported version: {data.get('version')}")
        
        # Apply rate limiting
        if attempt > 1:
            delay = min(2 ** (attempt - 1), 32)  # Exponential backoff, max 32 seconds
            time.sleep(delay)
        
        # Decode components
        salt = base64.b64decode(data['salt'])
        nonce = base64.b64decode(data['nonce'])
        ciphertext = base64.b64decode(data['ciphertext'])
        tag = base64.b64decode(data['tag'])
        
        # Derive key
        key = PBKDF2(
            password.encode(),
            salt,
            dkLen=32,
            count=100000,
            hmac_hash_module=SHA256
        )
        
        # Create cipher
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        
        # Decrypt data
        try:
            decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
            return json.loads(decrypted_data)
        except ValueError:
            raise ValueError("Invalid password or corrupted data")
            
    except Exception as e:
        raise Exception(f"Decryption failed: {e}")

def run_self_test() -> bool:
    """Run comprehensive self-test of all functionality"""
    print("\nRunning self-test...")
    tests_passed = True
    
    # Test 1: Entropy generation
    print("\nTest 1: Entropy Generation")
    try:
        entropy = generate_entropy()
        if len(entropy) == 32:
            print("✓ Entropy generation successful")
        else:
            print("✗ Entropy generation failed: incorrect length")
            tests_passed = False
    except Exception as e:
        print(f"✗ Entropy generation failed: {e}")
        tests_passed = False
    
    # Test 2: Mnemonic generation
    print("\nTest 2: Mnemonic Generation")
    try:
        entropy_hex = entropy.hex()
        mnemonic = entropy_to_mnemonic(entropy_hex)
        if len(mnemonic.split()) == 24:
            print("✓ Mnemonic generation successful")
        else:
            print("✗ Mnemonic generation failed: incorrect word count")
            tests_passed = False
    except Exception as e:
        print(f"✗ Mnemonic generation failed: {e}")
        tests_passed = False
    
    # Test 3: Encryption/Decryption
    print("\nTest 3: Encryption/Decryption")
    try:
        test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        test_passphrase = "testpassphrase"
        test_derivation_path = "m/44'/236'/0'"
        test_password = "thisisalongpassword123456789"
        encrypted = encrypt_wallet_data(test_mnemonic, test_passphrase, test_derivation_path, test_password)
        decrypted = decrypt_with_rate_limit(encrypted, test_password, 1)
        if (
            decrypted['mnemonic'] == test_mnemonic and
            decrypted['passphrase'] == test_passphrase and
            decrypted['derivation_path'] == test_derivation_path
        ):
            print("✓ Encryption/Decryption successful")
        else:
            print("✗ Encryption/Decryption failed: data mismatch")
            tests_passed = False
    except Exception as e:
        print(f"✗ Encryption/Decryption failed: {e}")
        tests_passed = False
    
    # Test 4: QR Code Generation
    print("\nTest 4: QR Code Generation")
    try:
        test_qr = "test_qr_data"
        generate_qr(test_qr, "test_qr.png", paranoid=True)
        print("✓ QR code ASCII generation successful (paranoid mode)")
    except Exception as e:
        print(f"✗ QR code generation failed: {e}")
        tests_passed = False
    
    # Test 5: Password Strength
    print("\nTest 5: Password Strength")
    try:
        weak_passwords = ["short", "password123", "qwerty", "12345678"]
        strong_password = "thisisalongpassword123456789"
        
        for pwd in weak_passwords:
            is_valid, _ = check_password_strength(pwd)
            if is_valid:
                print(f"✗ Password strength check failed: accepted weak password '{pwd}'")
                tests_passed = False
                break
        
        is_valid, _ = check_password_strength(strong_password)
        if not is_valid:
            print("✗ Password strength check failed: rejected strong password")
            tests_passed = False
        else:
            print("✓ Password strength check successful")
    except Exception as e:
        print(f"✗ Password strength check failed: {e}")
        tests_passed = False
    
    # Print final results
    print("\nSelf-test results:")
    if tests_passed:
        print("✓ All tests passed successfully!")
    else:
        print("✗ Some tests failed. Please check the output above.")
    
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
    print(bold_cyan("\nRunning security checks..."))
    
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
    print(yellow("\nPlaintext wallet info saved to wallet_info_clear.txt (handle with extreme care!)"))
    
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
    print(bold_cyan("\nExiting securely. Remember to:"))
    print("1. Keep your seed phrase and derivation path safe")
    print("2. Never share your private keys")
    print("3. Consider using a hardware wallet for large amounts")
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

def generate_qr(data: str, filename: str, chunk_size: int = 800) -> None:
    """Generate QR code from data and save to file."""
    try:
        # Split data into smaller chunks if needed
        chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
        if len(chunks) > 1:
            print(f"\nSplitting data into {len(chunks)} QR codes...")
        
        # Create a PDF with multiple pages if needed
        pdf_path = f"{filename}.pdf"
        with canvas.Canvas(pdf_path, pagesize=A4) as c:
            for chunk_num, chunk in enumerate(chunks, 1):
                # Generate QR code
                qr = qrcode.QRCode(
                    version=None,
                    error_correction=qrcode.constants.ERROR_CORRECT_L,
                    box_size=20,
                    border=2
                )
                qr.add_data(chunk)
                qr.make(fit=True)
                
                # Create QR code image
                qr_img = qr.make_image(fill_color="black", back_color="white")
                
                # Convert to PIL Image
                pil_img = qr_img.get_image()
                
                # Save QR code image
                img_path = f"{filename}_chunk{chunk_num}.png"
                pil_img.save(img_path)
                
                # Calculate positions for 3x4 grid
                qr_size = 44 * mm  # 44mm QR code size
                margin = 10 * mm
                spacing_x = (A4[0] - (2 * margin) - (3 * qr_size)) / 2  # Space between QR codes horizontally
                spacing_y = (A4[1] - (2 * margin) - (4 * qr_size)) / 3  # Space between QR codes vertically
                
                # Calculate positions for all 12 QR codes
                positions = []
                for row in range(4):
                    for col in range(3):
                        x = margin + col * (qr_size + spacing_x)
                        y = A4[1] - margin - (row + 1) * qr_size - row * spacing_y
                        positions.append((x, y))
                
                # Draw QR code at the calculated position
                c.drawImage(img_path, positions[chunk_num-1][0], positions[chunk_num-1][1], 
                          width=qr_size, height=qr_size)
                
                # Add address labels
                addresses = json.loads(chunk)
                first_five = addresses[:5]
                last_five = addresses[-5:]
                
                # Draw first 5 addresses
                y_pos = positions[chunk_num-1][1] - 8 * mm  # Increased spacing
                c.setFont("Helvetica-Bold", 8)  # Increased font size and made bold
                c.drawString(positions[chunk_num-1][0], y_pos, "First 5 addresses:")
                c.setFont("Helvetica", 7)  # Slightly smaller for addresses
                for i, addr in enumerate(first_five):
                    y_pos -= 4 * mm  # Increased spacing between addresses
                    c.drawString(positions[chunk_num-1][0], y_pos, f"{i+1}. {addr}")
                
                # Draw last 5 addresses
                y_pos -= 4 * mm  # Extra spacing between sections
                c.setFont("Helvetica-Bold", 8)
                c.drawString(positions[chunk_num-1][0], y_pos, "Last 5 addresses:")
                c.setFont("Helvetica", 7)
                for i, addr in enumerate(last_five):
                    y_pos -= 4 * mm
                    c.drawString(positions[chunk_num-1][0], y_pos, f"{i+1}. {addr}")
                
                # If we've filled a page, start a new one
                if chunk_num % 12 == 0 and chunk_num < len(chunks):
                    c.showPage()
                
                # Clean up temporary image file
                os.remove(img_path)
                
                print(f"Generated QR code {chunk_num}/{len(chunks)}")
        
        print(f"\nQR codes saved to {pdf_path}")
        
    except Exception as e:
        raise Exception(f"Failed to generate QR code: {str(e)}")

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

def generate_qr_pdf(data: str, filename: str, paranoid: bool = False, print_only: bool = False) -> None:
    """Generate QR codes and save them to a PDF."""
    try:
        # print(f"[DEBUG] Attempting to generate PDF: {filename}")
        max_chunk_size = 800  # Reduced chunk size for QR code compatibility
        chunks = [data[i:i + max_chunk_size] for i in range(0, len(data), max_chunk_size)]
        # print(f"[DEBUG] Number of QR chunks: {len(chunks)}")
        if not paranoid and not print_only:
            os.makedirs(QR_DIR, exist_ok=True)
            pdf_path = os.path.join(QR_DIR, f"{os.path.splitext(filename)[0]}.pdf")
            c = canvas.Canvas(pdf_path, pagesize=A4)
            width, height = A4
            
            # Optimized layout for 3 columns with large QR codes
            qr_size = 44 * mm  # Keep the same large QR code size
            margin = 10 * mm   # Reduced margin to fit 3 columns
            cols = 3          # Three columns
            rows = 4          # Adjusted rows to fit larger QR codes
            
            # Calculate spacing
            col_spacing = (width - 2 * margin - cols * qr_size) / (cols - 1)
            row_spacing = (height - 2 * margin - rows * qr_size) / (rows - 1)
            
            page_num = 1
            qr_count = 0
            
            for i, chunk in enumerate(chunks):
                try:
                    qr = qrcode.QRCode(
                        version=1,
                        error_correction=ERROR_CORRECT_L,
                        box_size=20,  # Keep the same box size
                        border=2,
                    )
                    qr.add_data(chunk)
                    qr.make(fit=True)
                    img = qr.make_image(fill_color="black", back_color="white")
                    row = (qr_count % (cols * rows)) // cols
                    col = qr_count % cols
                    if qr_count > 0 and qr_count % (cols * rows) == 0:
                        c.showPage()
                        page_num += 1
                    x = margin + col * (qr_size + col_spacing)
                    y = height - margin - (row + 1) * qr_size - row * row_spacing
                    temp_path = os.path.join(QR_DIR, f"temp_qr_{i}.png")
                    img.save(temp_path)
                    c.drawImage(temp_path, x, y, width=qr_size, height=qr_size)
                    c.setFont("Helvetica", 10)  # Keep the same font size
                    c.drawString(x, y - 8, f"QR {i+1}/{len(chunks)}")
                    os.remove(temp_path)
                    qr_count += 1
                except Exception as e:
                    print(f"Warning: Failed to generate QR code {i+1}: {e}")
                    print("Trying with smaller chunk size...")
                    traceback.print_exc()
                    smaller_chunk = chunk[:400]
                    qr = qrcode.QRCode(
                        version=1,
                        error_correction=ERROR_CORRECT_L,
                        box_size=20,  # Keep the same box size
                        border=2,
                    )
                    qr.add_data(smaller_chunk)
                    qr.make(fit=True)
                    img = qr.make_image(fill_color="black", back_color="white")
                    row = (qr_count % (cols * rows)) // cols
                    col = qr_count % cols
                    if qr_count > 0 and qr_count % (cols * rows) == 0:
                        c.showPage()
                        page_num += 1
                    x = margin + col * (qr_size + col_spacing)
                    y = height - margin - (row + 1) * qr_size - row * row_spacing
                    temp_path = os.path.join(QR_DIR, f"temp_qr_{i}_small.png")
                    img.save(temp_path)
                    c.drawImage(temp_path, x, y, width=qr_size, height=qr_size)
                    c.setFont("Helvetica", 10)  # Keep the same font size
                    c.drawString(x, y - 8, f"QR {i+1}/{len(chunks)} (small)")
                    os.remove(temp_path)
                    qr_count += 1
            # print(f"[DEBUG] Saving PDF to: {pdf_path}")
            c.save()
            # print(f"[DEBUG] PDF saved to: {pdf_path}")
        else:
            print("[DEBUG] Paranoid or print_only mode, not saving PDF.")
        # print(f"[DEBUG] Exiting generate_qr_pdf for {filename}")
    except Exception as e:
        print(f"[ERROR] PDF generation failed: {e}")
        traceback.print_exc()
        # Fallback: try to save a blank PDF for debugging
        try:
            pdf_path = os.path.join(QR_DIR, f"{os.path.splitext(filename)[0]}_blank.pdf")
            c = canvas.Canvas(pdf_path, pagesize=A4)
            c.save()
            # print(f"[DEBUG] Blank PDF saved to: {pdf_path}")
        except Exception as e2:
            print(f"[ERROR] Failed to save blank PDF: {e2}")
            traceback.print_exc()

def decrypt_wallet_info(encrypted_json, password):
    """Decrypt wallet info using the provided password."""
    try:
        data = json.loads(encrypted_json)
        salt = base64.b64decode(data['salt'])
        iv = base64.b64decode(data['iv'])
        ciphertext = base64.b64decode(data['ciphertext'])
        key = scrypt(password, salt, 32, N=2**14, r=8, p=1)
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        decrypted = cipher.decrypt_and_verify(ciphertext[:-16], ciphertext[-16:])
        return decrypted.decode()
    except Exception as e:
        raise Exception(f"Decryption failed: {str(e)}")

def main():
    """Main function."""
    try:
        # Parse command line arguments
        args = parse_arguments()
        
        # Run self-test if requested
        if args.selftest:
            ok = run_self_test()
            sys.exit(0 if ok else 1)
        
        # Verify wordlist integrity
        if not verify_wordlist_integrity():
            print("Error: Wordlist integrity check failed!")
            sys.exit(1)
        
        # Run security checks
        check_security()
        
        # Get password for encryption
        while True:
            password = getpass.getpass(bold_cyan("Enter password to encrypt wallet data: "))
            is_valid, error_msg = check_password_strength(password)
            if is_valid:
                break
            print(f"Password error: {error_msg}")
        
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
        
        # Save encrypted data if not in print-only mode
        if not args.print_only:
            with open("wallet_info.txt", "w") as f:
                f.write(encrypted_data)
            print(green("\nEncrypted wallet data saved to wallet_info.txt"))
        
        # Ask if user wants QR code
        if input(bold_cyan("\nDo you want to generate a QR code with all wallet information? (y/n): ")).lower() == 'y':
            print(bold_cyan("\nGenerating QR code for air-gapped transfer..."))
            qr_data = json.dumps({
                'mnemonic': wallet_info['mnemonic'],
                'passphrase': wallet_info['passphrase'],
                'derivation_path': wallet_info['derivation_path'],
                'version': wallet_info['version']
            })
            # print(f"[DEBUG] Calling generate_qr_pdf for {qr_data[:40]}... (truncated)")
            generate_qr_pdf(qr_data, "wallet_info.pdf", args.paranoid, args.print_only)
            # print(f"[DEBUG] Finished generate_qr_pdf for wallet_info.pdf")
        
        # Ask if user wants P2PKH addresses QR code
        if input(bold_cyan("\nDo you want to generate an unencrypted QR code with 1000 P2PKH addresses? (y/n): ")).lower() == 'y':
            print(bold_cyan("\nGenerating P2PKH addresses..."))
            addresses = generate_p2pkh_addresses(
                wallet_info['mnemonic'],
                wallet_info['passphrase'],
                wallet_info['derivation_path']
            )
            
            # Create QR code with addresses
            addresses_data = json.dumps({
                'addresses': addresses,
                'derivation_path': wallet_info['derivation_path'],
                'count': len(addresses)
            })
            
            if not args.print_only:
                os.makedirs(QR_DIR, exist_ok=True)
                with open(os.path.join(QR_DIR, "p2pkh_addresses.json"), "w") as f:
                    f.write(addresses_data)
                print(f"\nP2PKH addresses saved to {QR_DIR}/p2pkh_addresses.json")
            
            print("Generating QR codes for addresses...")
            generate_qr_pdf(addresses_data, "p2pkh_addresses.pdf", args.paranoid, args.print_only)
        
        print(bold_cyan("\nIMPORTANT: Keep your seed phrase and derivation path safe!"))
        print("1. Write down the seed phrase and keep it in a secure location")
        print("2. Remember your passphrase")
        print("3. Note the derivation path")
        print("4. Never share your private keys")
        print("5. Consider using a hardware wallet for large amounts")
        
        # Automatically erase shell and Python history
        secure_erase_histories()
        print(yellow("Shell and Python history erased for your privacy."))
        # Secure exit
        secure_exit()
        
    except KeyboardInterrupt:
        print(yellow("\nOperation cancelled by user."))
        sys.exit(1)
    except Exception as e:
        print(red(f"Error: {e}"))
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ElectrumSV Seed Tool")
    parser.add_argument("--decrypt", action="store_true", help="Decrypt wallet info from QR code")
    args = parser.parse_args()

    if args.decrypt:
        encrypted_json = input("Paste the encrypted JSON data from the QR code: ")
        password = input("Enter your password: ")
        try:
            decrypted = decrypt_wallet_info(encrypted_json, password)
            print("\nDecrypted wallet info:")
            print(decrypted)
        except Exception as e:
            print(f"Error: {e}")
        exit(0)

    main() 