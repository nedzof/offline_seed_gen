#!/usr/bin/env python3

import os
import sys
import json
import time
import base64
import hashlib
import getpass
import argparse
import secrets
import tempfile
import ctypes
from typing import Dict, List, Tuple, Optional
from pathlib import Path

from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
import qrcode
from mnemonic import Mnemonic
import bitcoinx
from bitcoinx import KeyStore, KeyStoreError
import psutil
from zxcvbn import zxcvbn

# Constants
PBKDF2_ITERATIONS = 600000  # OWASP recommended minimum for PBKDF2-HMAC-SHA256
FILES_TO_CLEANUP = []  # Track files for secure cleanup

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
from mnemonic import Mnemonic

# Constants
VERSION = "1.0"
QR_DIR = "qr_bundle"
WORDLIST_FILE = "wordlist.txt"

# Track files for secure cleanup
FILES_TO_CLEANUP = []

# Required dependencies
REQUIRED_DEPS = {
    'Cryptodome': 'pip install pycryptodomex',
    'qrcode': 'pip install qrcode',
    'mnemonic': 'pip install mnemonic',
    'bitcoinx': 'pip install bitcoinx',
    'psutil': 'pip install psutil',
    'zxcvbn': 'pip install zxcvbn'
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
    """
    Encrypt wallet data using AES-GCM with a strong password.
    
    Args:
        mnemonic: The mnemonic phrase
        passphrase: The passphrase
        derivation_path: The derivation path
        password: The encryption password
        
    Returns:
        Base64-encoded encrypted data
    """
    # Generate a random salt
    salt = get_random_bytes(32)
    
    # Derive key from password using PBKDF2
    key = PBKDF2(
        password.encode(),
        salt,
        dkLen=32,
        count=PBKDF2_ITERATIONS,
        hmac_hash_module=hashlib.sha256
    )
    
    # Prepare data for encryption
    data = {
        'mnemonic': mnemonic,
        'passphrase': passphrase,
        'derivation_path': derivation_path
    }
    data_bytes = json.dumps(data).encode()
    
    # Generate a random nonce
    nonce = get_random_bytes(12)
    
    # Create cipher and encrypt
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data_bytes)
    
    # Combine all components
    encrypted = {
        'salt': base64.b64encode(salt).decode(),
        'nonce': base64.b64encode(nonce).decode(),
        'ciphertext': base64.b64encode(ciphertext).decode(),
        'tag': base64.b64encode(tag).decode()
    }
    
    return json.dumps(encrypted)

def decrypt_wallet_info(encrypted_data: str, password: str) -> str:
    """
    Decrypt wallet data using AES-GCM.
    
    Args:
        encrypted_data: Base64-encoded encrypted data
        password: The decryption password
        
    Returns:
        Decrypted wallet data as JSON string
    """
    try:
        # Parse encrypted data
        data = json.loads(encrypted_data)
        salt = base64.b64decode(data['salt'])
        nonce = base64.b64decode(data['nonce'])
        ciphertext = base64.b64decode(data['ciphertext'])
        tag = base64.b64decode(data['tag'])
        
        # Derive key from password
        key = PBKDF2(
            password.encode(),
            salt,
            dkLen=32,
            count=PBKDF2_ITERATIONS,
            hmac_hash_module=hashlib.sha256
        )
        
        # Create cipher and decrypt
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted = cipher.decrypt_and_verify(ciphertext, tag)
        
        return decrypted.decode()
    except Exception as e:
        raise Exception(f"Decryption failed: {str(e)}")

def generate_mnemonic(strength_bits: int = 128, language: str = 'english', entropy: Optional[bytes] = None) -> str:
    """
    Generates a new BIP39 mnemonic phrase using a cryptographically secure source.

    Args:
        strength_bits: The desired entropy strength in bits. Must be a multiple of 32.
                      128 bits = 12 words. 256 bits = 24 words.
        language: The language for the wordlist.
        entropy: (For testing only) Pre-supplied entropy bytes.

    Returns:
        str: A string containing the mnemonic phrase.

    Raises:
        ValueError: If strength_bits is invalid or entropy length is incorrect.
        Exception: If mnemonic generation fails.
    """
    try:
        if entropy is None:
            # Use the 'secrets' module for the highest security
            if strength_bits not in [128, 160, 192, 224, 256]:
                raise ValueError("Strength must be one of 128, 160, 192, 224, or 256 bits")
            entropy = secrets.token_bytes(strength_bits // 8)
        
        elif not isinstance(entropy, bytes) or len(entropy) not in [16, 20, 24, 28, 32]:
            raise ValueError("Provided entropy must be bytes of length 16, 20, 24, 28, or 32.")

        # Use the mnemonic package for BIP39 compliance
        mnemo = Mnemonic(language)
        mnemonic = mnemo.to_mnemonic(entropy)
        
        # Verify the generated mnemonic
        words = mnemonic.split()
        expected_words = strength_bits // 32 * 3  # 12 words for 128 bits, 24 for 256 bits
        if len(words) != expected_words:
            raise ValueError(f"Generated mnemonic has {len(words)} words, expected {expected_words}")
            
        return mnemonic
        
    except Exception as e:
        raise Exception(f"Failed to generate mnemonic: {e}")

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

def verify_mnemonic_backup(mnemonic: str) -> bool:
    """
    Verify that the user has correctly backed up their mnemonic phrase.
    
    Args:
        mnemonic: The original mnemonic phrase
        
    Returns:
        bool: True if verification successful, False otherwise
    """
    # Clear screen
    os.system('cls' if os.name == 'nt' else 'clear')
    
    print(bold_cyan("\n=== Mnemonic Verification ==="))
    print("Please enter your mnemonic phrase to verify your backup.")
    print("Enter each word separated by spaces.")
    print("Type 'exit' to cancel verification.")
    print("=" * 30)
    
    # Get user input
    user_input = input(bold_cyan("Enter your mnemonic phrase: ")).strip().lower()
    
    if user_input.lower() == 'exit':
        return False
    
    # Compare with original mnemonic
    if user_input == mnemonic.lower():
        print(green("\n✓ Verification successful! Your backup is correct."))
        return True
    else:
        print(red("\n✗ Verification failed. The entered phrase does not match."))
        print(yellow("Please try again or restart the process."))
        return False

def generate_wallet(strength_bits: int = 256, passphrase: str = "", derivation_path: str = "m/44'/236'/0'", output_dir: str = ".") -> Dict:
    """
    Generate a new wallet with the specified parameters.
    
    Args:
        strength_bits: Entropy strength in bits (128 for 12 words, 256 for 24 words)
        passphrase: Optional BIP39 passphrase
        derivation_path: BIP32 derivation path
        output_dir: Directory to save wallet files
        
    Returns:
        Dict containing wallet information
    """
    try:
        # Use the secure mnemonic generation function
        mnemonic = generate_mnemonic(strength_bits=strength_bits)
        
        # Verify mnemonic backup
        if not verify_mnemonic_backup(mnemonic):
            raise Exception("Mnemonic verification failed. Please restart the process.")
        
        # Generate seed from mnemonic and passphrase
        seed = mnemonic_to_seed(mnemonic, passphrase)
        
        # Generate master key
        master_key = seed_to_master_key(seed)
        
        # Derive master key and xpub/xprv
        xprv = master_key.to_extended_key_string()
        xpub = master_key.public_key.to_extended_key_string()
        
        # Create wallet info dictionary
        wallet_info = {
            'mnemonic': mnemonic,
            'passphrase': passphrase,
            'derivation_path': derivation_path,
            'xprv': xprv,
            'xpub': xpub,
            'version': VERSION
        }
        
        # Write cleartext info
        clear_path = os.path.join(output_dir, "wallet_info_clear.txt")
        with open(clear_path, "w") as f:
            f.write("*** WARNING: This file contains all sensitive wallet information. ***\n")
            f.write("Write down and store securely.\n\n")
            f.write(f"Mnemonic (seed phrase):\n{wallet_info['mnemonic']}\n\n")
            f.write(f"Passphrase:\n{wallet_info['passphrase']}\n\n")
            f.write(f"Derivation Path:\n{wallet_info['derivation_path']}\n\n")
            f.write(f"Extended Private Key (xprv):\n{wallet_info['xprv']}\n\n")
            f.write(f"Extended Public Key (xpub):\n{wallet_info['xpub']}\n")
        
        # Track file for cleanup
        FILES_TO_CLEANUP.append(clear_path)
        
        print(green(f"✓ Wallet info saved (plaintext: {os.path.basename(clear_path)})"))
        
        return wallet_info
        
    except Exception as e:
        raise Exception(f"Failed to generate wallet: {e}")

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

def secure_exit(exit_code: int = 0) -> None:
    """
    Securely exit the program, cleaning up all sensitive data.
    
    Args:
        exit_code: The exit code to return (0 for success, non-zero for failure)
    """
    try:
        # Securely delete all tracked files
        for file_path in FILES_TO_CLEANUP:
            if os.path.exists(file_path):
                secure_delete(file_path)
        
        # Clear the cleanup list
        FILES_TO_CLEANUP.clear()
        
        # Clear terminal history
        secure_erase_histories()
        
        # Clear environment variables
        os.environ.clear()
        
        # Exit with the specified code
        sys.exit(exit_code)
    except Exception as e:
        print(red(f"Error during secure exit: {str(e)}"))
        sys.exit(1)
    
def check_password_strength(password: str) -> Tuple[bool, str]:
    """
    Check password strength using zxcvbn.
    
    Args:
        password: Password to check
        
    Returns:
        Tuple of (is_strong, feedback_message)
    """
    try:
        results = zxcvbn(password)
        
        # Score: 0-4 (0 is worst, 4 is best)
        if results['score'] < 3:
            feedback = []
            if results['feedback']['warning']:
                feedback.append(results['feedback']['warning'])
            if results['feedback']['suggestions']:
                feedback.extend(results['feedback']['suggestions'])
            
            return False, "\n".join([
                f"Password strength: {results['score']}/4",
                f"Estimated time to crack: {results['crack_times_display']['offline_slow_hashing_1e4_per_second']}",
                *feedback
            ])
        
        return True, f"Password strength: {results['score']}/4"
        
    except ImportError:
        # Fallback to basic checks if zxcvbn is not available
        if len(password) < 15:
            return False, "Password must be at least 15 characters long"
        
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        
        if not all([has_upper, has_lower, has_digit, has_special]):
            return False, "Password must contain uppercase, lowercase, numbers, and special characters"
        
        return True, "Password meets basic requirements"

def secure_delete(path: str, passes: int = 3) -> None:
    """Securely delete a file by overwriting it multiple times before removal."""
    if not os.path.exists(path):
        return

    try:
        file_size = os.path.getsize(path)
        if file_size > 0:
            with open(path, "r+b") as f:
                for _ in range(passes):
                    # Overwrite with random, then zeros, then ones
                    f.seek(0)
                    f.write(secrets.token_bytes(file_size))
                    f.flush(); os.fsync(f.fileno())
                    
                    f.seek(0)
                    f.write(b'\x00' * file_size)
                    f.flush(); os.fsync(f.fileno())
                    
                    f.seek(0)
                    f.write(b'\xff' * file_size)
                    f.flush(); os.fsync(f.fileno())
        
        # Truncate and rename BEFORE the final remove
        os.truncate(path, 0)
        dir_path = os.path.dirname(path)
        if dir_path:
            # Create a random new name within the same directory
            temp_name = os.path.join(dir_path, secrets.token_hex(16))
            os.rename(path, temp_name)
            # Now remove the renamed file
            os.remove(temp_name)
        else:
            # If it's in the current directory, just remove it
            os.remove(path)
            
    except Exception as e:
        print(red(f"Warning: Secure deletion of {path} encountered an issue: {e}"))
        # As a fallback, try a simple remove if the secure method fails
        try:
            os.remove(path)
        except OSError:
            pass

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

def generate_qr_code(data: str, filename: str, error_correction: int = qrcode.constants.ERROR_CORRECT_L) -> None:
    """
    Generate a QR code for the given data.
    
    Args:
        data: Data to encode in QR code
        filename: Output filename
        error_correction: QR code error correction level
    """
    try:
        qr = qrcode.QRCode(
            version=1,
            error_correction=error_correction,
            box_size=10,
            border=4,
        )
        qr.add_data(data)
        qr.make(fit=True)
        
        # Create QR code image
        qr_image = qr.make_image(fill_color="black", back_color="white")
        
        # Save QR code
        qr_image.save(filename)
        
        # Also generate ASCII version for paranoid mode
        ascii_filename = filename.replace('.png', '_ascii.txt')
        with open(ascii_filename, 'w') as f:
            f.write(qr.print_ascii())
            
    except Exception as e:
        print(f"Warning: Could not generate QR code: {e}")

def generate_wallet_qr_codes(wallet_info: Dict, encrypted_data: str, output_dir: str, paranoid: bool = False) -> None:
    """
    Generate QR codes for critical wallet information.
    - Public QR: Contains the extended public key (xpub) for watch-only wallets.
    - Private QR: Contains the fully encrypted wallet data blob.
    """
    section_header("QR Code Generation")

    # 1. Generate QR code for PUBLIC data (xpub)
    public_data = {
        'xpub': wallet_info.get('xpub', ''),
        'derivation_path': wallet_info.get('derivation_path', '')
    }
    public_qr_path = os.path.join(output_dir, "wallet_public_xpub.png")
    generate_qr_code(json.dumps(public_data), public_qr_path)
    FILES_TO_CLEANUP.append(public_qr_path) # Track for cleanup
    print(green(f"✓ Public QR (xpub) saved: {os.path.basename(public_qr_path)}"))

    # 2. Generate QR code for ENCRYPTED private data
    private_qr_path = os.path.join(output_dir, "wallet_encrypted_private.png")
    generate_qr_code(encrypted_data, private_qr_path)
    FILES_TO_CLEANUP.append(private_qr_path) # Track for cleanup
    print(green(f"✓ Encrypted Private QR saved: {os.path.basename(private_qr_path)}"))

    if paranoid:
        print(yellow("\nParanoid mode: ASCII QR versions also saved (_ascii.txt)."))

def main():
    """Main function to run the wallet generation tool."""
    try:
        # Parse command line arguments
        parser = argparse.ArgumentParser(description='Bitcoin SV Wallet Generator')
        parser.add_argument('--print-only', action='store_true', help='Print wallet info without saving')
        parser.add_argument('--paranoid', action='store_true', help='Enable paranoid mode (ASCII QR codes only)')
        parser.add_argument('--decrypt', action='store_true', help='Decrypt wallet info')
        parser.add_argument('--file', type=str, help='Path to encrypted wallet file')
        parser.add_argument('--password', type=str, help='Password for decryption')
        args = parser.parse_args()

        # Check security environment
        check_security()

        # Verify wordlist integrity
        if not verify_wordlist_integrity():
            print(red("Wordlist verification failed. Exiting."))
            sys.exit(1)  # Use sys.exit to avoid erasing history on a simple wordlist error

        # Decryption mode
        if args.decrypt:
            if args.file and args.password:
                # Automated decryption
                try:
                    with open(args.file, 'r') as f:
                        encrypted_data = f.read()
                    decrypted_data = decrypt_wallet_info(encrypted_data, args.password)
                    print(green("\nDecrypted wallet info:"))
                    print(decrypted_data)
                except Exception as e:
                    print(red(f"Decryption failed: {str(e)}"))
                    secure_exit(1)
            else:
                # Interactive decryption
                encrypted_data = input(bold_cyan("\nEnter encrypted wallet data: "))
                password = getpass.getpass(bold_cyan("Enter password: "))
                try:
                    decrypted_data = decrypt_wallet_info(encrypted_data, password)
                    print(green("\nDecrypted wallet info:"))
                    print(decrypted_data)
                except Exception as e:
                    print(red(f"Decryption failed: {str(e)}"))
                    secure_exit(1)
            secure_exit()

        # Password prompt with strength checking
        while True:
            password = getpass.getpass(bold_cyan("\nEnter a strong password for wallet encryption: "))
            is_strong, feedback = check_password_strength(password)
            if is_strong:
                break
            print(red(f"\nPassword is not strong enough: {feedback}"))
            print(yellow("Please try again with a stronger password."))

        # Confirm password
        confirm_password = getpass.getpass(bold_cyan("Confirm password: "))
        if password != confirm_password:
            print(red("Passwords do not match. Exiting."))
            secure_exit(1)

        # Choose derivation path
        print(bold_cyan("\nChoose derivation path:"))
        print("1. m/44'/236'/0'/0/0 (Default BSV path)")
        print("2. m/44'/0'/0'/0/0 (Legacy Bitcoin path)")
        print("3. Custom path")
        choice = input(bold_cyan("Enter choice [1]: ")).strip() or "1"
        
        if choice == "1":
            derivation_path = "m/44'/236'/0'/0/0"
        elif choice == "2":
            derivation_path = "m/44'/0'/0'/0/0"
        else:
            derivation_path = input(bold_cyan("Enter custom derivation path: ")).strip()
            if not derivation_path.startswith("m/"):
                print(red("Invalid derivation path. Must start with 'm/'"))
                secure_exit(1)

        # Prompt for mnemonic length
        print(bold_cyan("\nChoose mnemonic length:"))
        print("1. 12 words (128-bit security, standard)")
        print("2. 24 words (256-bit security, maximum)")
        strength_choice = input(bold_cyan("Enter 1 or 2 [default 2]: ")).strip()
        strength_bits = 128 if strength_choice == '1' else 256

        # Select output directory
        section_header("Output Location")
        output_dir = "." # Default to current directory
        drives = find_usb_drives()
        if drives:
            selected_drive = select_usb_drive(drives)
            if selected_drive:
                # Create a dedicated folder on the USB drive for this wallet
                wallet_folder_name = f"wallet_{time.strftime('%Y%m%d-%H%M%S')}"
                output_dir = os.path.join(selected_drive, wallet_folder_name)
                os.makedirs(output_dir, exist_ok=True)
                print(green(f"✓ All files will be saved to: {output_dir}"))
            else:
                print(red("No output drive selected. Exiting."))
                secure_exit()
        else:
            print(yellow("No USB drive detected. All files will be saved in the current directory."))

        # Generate wallet
        wallet_info = generate_wallet(
            strength_bits=strength_bits,
            derivation_path=derivation_path,
            output_dir=output_dir
        )

        # Encrypt wallet data
        encrypted_data = encrypt_wallet_data(
            wallet_info['mnemonic'],
            wallet_info['passphrase'],
            wallet_info['derivation_path'],
            password
        )
        
        # Save encrypted data
        if not args.print_only:
            encrypted_file = os.path.join(output_dir, "wallet_encrypted.json")
            with open(encrypted_file, 'w') as f:
                f.write(encrypted_data)
            FILES_TO_CLEANUP.append(encrypted_file)
            print(green(f"\n✓ Encrypted wallet data saved to: {encrypted_file}"))

        # Generate QR codes if requested
        if input(bold_cyan("\nDo you want to generate QR codes for wallet info? (y/n): ")).lower() == 'y':
            generate_wallet_qr_codes(wallet_info, encrypted_data, output_dir, args.paranoid)

        # Print wallet info
        print(green("\nWallet Information:"))
        print(f"Mnemonic: {wallet_info['mnemonic']}")
        print(f"Derivation Path: {wallet_info['derivation_path']}")
        print(f"Extended Public Key (xpub): {wallet_info['xpub']}")
        
        if args.print_only:
            print(yellow("\nNote: Wallet data was not saved to disk (--print-only mode)"))
        else:
            print(green("\n✓ Wallet generation complete!"))
            print(yellow("Remember to securely store your password and backup files."))

        secure_exit()

    except KeyboardInterrupt:
        print(yellow("\nOperation cancelled by user."))
        secure_exit(1)
    except Exception as e:
        print(red(f"\nAn error occurred: {str(e)}"))
        secure_exit(1)

if __name__ == "__main__":
    main() 