#!/usr/bin/env python3

import os
import sys
import hashlib
import secrets
from typing import List, Tuple, Optional, Dict
import hmac
import argparse
import json
from bitcoinx import PrivateKey, PublicKey, BIP32PrivateKey, BIP32PublicKey, Network, Bitcoin, bip32_key_from_string
import subprocess
import socket
import random
import shutil
import base64
import getpass
import re
import time
import ctypes
from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Random import get_random_bytes
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import qrcode
from qrcode.constants import ERROR_CORRECT_L

# Add lib directory to Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'lib'))

# Import from local lib directory
from matplotlib_minimal import figure, subplot, tight_layout, savefig, close
from numpy_minimal import array, random_bytes, frombuffer, histogram

# Version information
VERSION = "1.0"

# QR code directory
QR_DIR = "qr_bundle"

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

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a key from the password using PBKDF2."""
    # Use SHA256 for key derivation
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        salt,
        100000,
        dklen=32
    )
    return key

def encrypt_wallet_data(data: str, password: str) -> str:
    """Encrypt wallet data using AES-256-GCM."""
    # Generate a random salt and nonce
    salt = get_random_bytes(16)
    nonce = get_random_bytes(12)
    
    # Derive key from password
    key = derive_key(password, salt)
    
    # Create AES-GCM cipher
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    
    # Encrypt the data
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    
    # Combine salt, nonce, tag, and ciphertext
    encrypted_data = salt + nonce + tag + ciphertext
    
    # Return versioned and base64 encoded result
    return f"{VERSION}:{base64.b64encode(encrypted_data).decode()}"

def decrypt_with_rate_limit(encrypted_data: str, password: str, attempt: int = 1) -> str:
    """Decrypt wallet data with rate limiting to prevent brute force attacks."""
    if attempt > 1:
        time.sleep(2 ** (attempt - 1))  # Exponential backoff
    
    try:
        # Split version and data
        version, data = encrypted_data.split(':', 1)
        if version != VERSION:
            raise ValueError(f"Unsupported version: {version}")
        
        # Decode base64 data
        data = base64.b64decode(data)
        
        # Extract salt, nonce, tag, and ciphertext
        salt = data[:16]
        nonce = data[16:28]
        tag = data[28:44]
        ciphertext = data[44:]
        
        # Derive key from password
        key = derive_key(password, salt)
        
        # Create AES-GCM cipher
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        
        # Decrypt the data
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        
        return plaintext.decode()
    except Exception as e:
        print(f"Error decrypting data: {e}")
        sys.exit(1)

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
        mnemonic = generate_mnemonic(entropy)
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
        test_data = "test_data"
        test_password = "TestPassword123!"
        encrypted = encrypt_wallet_data(test_data, "", "", test_password)
        decrypted = decrypt_with_rate_limit(encrypted, test_password, 1)
        if decrypted == test_data:
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
        if os.path.exists("test_qr.png"):
            os.remove("test_qr.png")
            print("✓ QR code generation successful")
        else:
            print("✗ QR code generation failed: file not created")
            tests_passed = False
    except Exception as e:
        print(f"✗ QR code generation failed: {e}")
        tests_passed = False
    
    # Test 5: Password Strength
    print("\nTest 5: Password Strength")
    try:
        weak_passwords = ["short", "password123", "qwerty", "12345678"]
        strong_password = "StrongP@ssw0rd123!"
        
        for pwd in weak_passwords:
            if check_password_strength(pwd):
                print(f"✗ Password strength check failed: accepted weak password '{pwd}'")
                tests_passed = False
                break
        
        if not check_password_strength(strong_password):
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

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Bitcoin SV HD Wallet Generator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Generate a new wallet
  ./main.py

  # Decrypt an encrypted wallet file
  ./main.py --decrypt wallet_info.txt

  # Run in paranoid mode (ASCII QR only)
  ./main.py --paranoid

  # Run in print-only mode
  ./main.py --print-only

Security Recommendations:
  1. Run this tool on an offline system
  2. Use Xorg instead of Wayland
  3. Copy the tool to internal storage before running
  4. Double-check network connectivity is disabled
  5. Store backups securely and never share your seed phrase
'''
    )
    
    parser.add_argument('--decrypt', metavar='FILE',
                      help='Decrypt an encrypted wallet file')
    parser.add_argument('--entropy', type=int, default=32,
                      help='Entropy length in bytes (default: 32)')
    parser.add_argument('--passphrase', default='',
                      help='Optional passphrase for the wallet')
    parser.add_argument('--derivation_path', default='',
                      help='Optional derivation path for the wallet')
    parser.add_argument('--paranoid', action='store_true',
                      help='Run in paranoid mode (ASCII QR only)')
    parser.add_argument('--print-only', action='store_true',
                      help='Run in print-only mode')
    parser.add_argument('--selftest', action='store_true',
                      help='Run self-test and exit')
    
    return parser.parse_args()

def check_security() -> None:
    """Run security checks before proceeding"""
    print("\nRunning security checks...")
    
    # Check for network connectivity
    try:
        import socket
        socket.create_connection(("8.8.8.8", 53), timeout=1)
        print("⚠️  Warning: Network connection detected. For maximum security, run this script on an air-gapped system.")
    except:
        print("✓ No network connection detected")
    
    # Check for memory locking
    try:
        if ctypes.CDLL('libc.so.6').mlockall(2) == 0:
            print("✓ Memory locking enabled")
        else:
            print("⚠️  Warning: Could not lock memory")
    except:
        print("⚠️  Warning: Could not enable memory locking")
    
    # Check for secure environment
    if os.environ.get('DISPLAY'):
        print("⚠️  Warning: Running in GUI environment. Consider using a terminal-only session.")
    else:
        print("✓ Running in terminal environment")
    
    # Check for root privileges
    if os.geteuid() == 0:
        print("⚠️  Warning: Running as root. Consider running as a normal user.")
    else:
        print("✓ Running as normal user")
    
    print("\nSecurity checks completed.")

def generate_entropy(length: int = 32) -> bytes:
    """Generate cryptographically secure random data."""
    return secrets.token_bytes(length)

def entropy_to_mnemonic(entropy):
    """Convert entropy to mnemonic words using BIP39 word list"""
    with open('wordlist.txt', 'r') as f:
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
    """Generate a new wallet with the specified entropy length, passphrase, and derivation path."""
    # Generate entropy
    entropy = generate_entropy(entropy_length)
    entropy_hex = entropy.hex()
    
    # Convert entropy to mnemonic
    mnemonic = entropy_to_mnemonic(entropy_hex)
    
    # Convert mnemonic to seed
    seed = mnemonic_to_seed(mnemonic, passphrase)
    
    # Convert seed to master key
    master_key = seed_to_master_key(seed)
    
    # Derive addresses
    addresses = derive_addresses(master_key, derivation_path)
    
    return {
        'entropy': entropy_hex,
        'mnemonic': mnemonic,
        'seed': seed.hex(),
        'master_key_hex': master_key.to_hex(),
        'master_key_xprv': master_key.to_extended_key_string(),
        'addresses': addresses,
        'derivation_path': derivation_path
    }

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
    resp = input("\nDo you want to securely erase shell and Python history before exiting? (y/N): ").strip().lower()
    if resp == 'y':
        secure_erase_histories()
    
    # Securely delete any temporary files
    temp_files = [
        'wallet_info.txt',
        'wallet_info.txt.decrypted'
    ]
    for file in temp_files:
        secure_delete(file)
    
    print("\nExiting securely. Remember to:")
    print("1. Keep your seed phrase and derivation path safe")
    print("2. Never share your private keys")
    print("3. Consider using a hardware wallet for large amounts")
    sys.exit(0)
    
def check_password_strength(password: str) -> None:
    """Check if the password meets security requirements."""
    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters long")
    
    # Check for character variety
    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
    
    if not (has_upper and has_lower and has_digit and has_special):
        raise ValueError("Password must contain uppercase, lowercase, numbers, and special characters")
    
    # Check for common patterns
    common_patterns = [
        r'password',
        r'123456',
        r'qwerty',
        r'admin',
        r'welcome',
        r'letmein'
    ]
    for pattern in common_patterns:
        if pattern in password.lower():
            raise ValueError("Password contains common patterns that are not secure")

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

def verify_wordlist_integrity() -> None:
    """Verify the integrity of the wordlist file."""
    WORDLIST_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
    try:
        with open('wordlist.txt', 'rb') as f:
            if hashlib.sha256(f.read()).hexdigest() != WORDLIST_SHA256:
                raise ValueError("Wordlist integrity check failed! The wordlist may have been tampered with.")
    except Exception as e:
        print(f"Error verifying wordlist: {e}")
        sys.exit(1)

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

def generate_qr(data: str, filename: str, paranoid: bool = False, print_only: bool = False) -> None:
    """Generate QR code for air-gapped transfer"""
    try:
        if print_only:
            print(f"\n[PRINT-ONLY MODE] ASCII QR Code for {os.path.basename(filename)}:")
            display_ascii_qr(data)
            return

        if paranoid:
            print(f"\n[PARANOID MODE] ASCII QR Code for {os.path.basename(filename)}:")
            display_ascii_qr(data)
            return

        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(data)
        qr.make(fit=True)
        
        # Create QR code image
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Save QR code
        img.save(filename)
        print(f"\nQR code saved to: {filename}")
        
        # Also display ASCII version
        print(f"\nASCII QR Code for {os.path.basename(filename)}:")
        display_ascii_qr(data)
        
    except Exception as e:
        print(f"\nError generating QR code: {e}")
        print("Falling back to text-based transfer...")
        print("\nText data for manual transfer:")
        print("-" * 40)
        print(data)
        print("-" * 40)

def generate_encrypted_qr(data: str, password: str, filename: str) -> None:
    """Generate an encrypted QR code for secure air-gapped transfer."""
    try:
        encrypted = encrypt_wallet_data(data, password)
        generate_qr(encrypted, filename)
    except Exception as e:
        print(f"Warning: Could not generate encrypted QR data: {e}")

def main():
    """Main function to generate and encrypt wallet data"""
    try:
        # Parse command line arguments
        parser = argparse.ArgumentParser(description='Generate and encrypt wallet data')
        parser.add_argument('--paranoid', action='store_true', help='Paranoid mode: ASCII QR only')
        parser.add_argument('--print-only', action='store_true', help='Print-only mode: No file output')
        parser.add_argument('--selftest', action='store_true', help='Run self-test mode')
        args = parser.parse_args()

        # Run self-test if requested
        if args.selftest:
            ok = run_self_test()
            sys.exit(0 if ok else 1)

        # Check for required dependencies
        check_dependencies()
        
        # Verify wordlist integrity
        if not verify_wordlist_integrity():
            print("Error: Wordlist integrity check failed!")
            sys.exit(1)
            
        # Run security checks
        check_security()

        # Create QR code directory if not in print-only mode
        if not args.print_only:
            os.makedirs(QR_DIR, exist_ok=True)

        # Generate wallet data
        mnemonic, passphrase, derivation_path = generate_wallet_data()
        
        # Get password with strength check
        while True:
            password = getpass.getpass("\nEnter password to encrypt wallet data: ")
            if check_password_strength(password):
                break
            print("Password does not meet security requirements. Please try again.")
        
        # Encrypt wallet data
        encrypted_data = encrypt_wallet_data(mnemonic, passphrase, derivation_path, password)
        
        # Save encrypted data if not in print-only mode
        if not args.print_only:
            with open('wallet_info.txt', 'w') as f:
                f.write(encrypted_data)
            print("\nEncrypted wallet data saved to wallet_info.txt")
        
        # Generate QR codes
        print("\nGenerating QR codes for air-gapped transfer...")
        generate_qr(mnemonic, os.path.join(QR_DIR, 'mnemonic.png'), args.paranoid, args.print_only)
        generate_qr(passphrase, os.path.join(QR_DIR, 'passphrase.png'), args.paranoid, args.print_only)
        generate_qr(derivation_path, os.path.join(QR_DIR, 'derivation_path.png'), args.paranoid, args.print_only)
        
        # Print final instructions
        print("\nIMPORTANT: Keep your seed phrase and derivation path safe!")
        print("1. Write down the seed phrase and keep it in a secure location")
        print("2. Remember your passphrase")
        print("3. Note the derivation path")
        print("4. Never share your private keys")
        print("5. Consider using a hardware wallet for large amounts")
        
        # Ask about secure exit
        if input("\nDo you want to securely erase shell and Python history? (y/n): ").lower() == 'y':
            secure_exit()
            
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main() 