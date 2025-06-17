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
import ctypes
from typing import Dict, List, Tuple, Optional
import socket
from unicodedata import normalize
from bitcoinx.bip32 import bip32_decompose_chain_string

# Cryptography and Wallet Libraries
from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Random import get_random_bytes
from Cryptodome.Hash import SHA256
from mnemonic import Mnemonic
import bitcoinx
from bitcoinx import BIP32PrivateKey, BIP32PublicKey, Bitcoin

# Utility Libraries
import qrcode
from qrcode.constants import ERROR_CORRECT_L
import psutil
from zxcvbn import zxcvbn

# Constants
PBKDF2_ITERATIONS = 600000  # OWASP recommended minimum for PBKDF2-HMAC-SHA256
FILES_TO_CLEANUP = []  # Track files for secure cleanup

# Try to lock memory pages (requires root on most systems)
try:
    libc = ctypes.CDLL("libc.so.6")
    MCL_CURRENT = 1
    MCL_FUTURE = 2
    libc.mlockall(MCL_CURRENT | MCL_FUTURE)
except:
    pass  # Not critical if it fails

def check_password_strength(password: str) -> Tuple[bool, str]:
    """
    Check password strength using zxcvbn.
    
    Args:
        password: The password to check
        
    Returns:
        Tuple of (is_strong, feedback_message)
    """
    result = zxcvbn(password)
    if result['score'] < 3:
        feedback = []
        if result['feedback']['warning']:
            feedback.append(result['feedback']['warning'])
        if result['feedback']['suggestions']:
            feedback.extend(result['feedback']['suggestions'])
        return False, f"Password too weak. Estimated cracking time: {result['crack_times_display']['offline_fast_hashing_1e10_per_second']}\n" + "\n".join(feedback)
    return True, "Password is strong"

def secure_delete(path: str, passes: int = 3) -> None:
    """
    Securely delete a file by overwriting it multiple times before deletion.
    
    Args:
        path: Path to the file to delete
        passes: Number of overwrite passes (default: 3)
    """
    try:
        if not os.path.exists(path):
            return
            
        # Get file size
        file_size = os.path.getsize(path)
        
        # Open file in binary read-write mode
        with open(path, 'r+b') as f:
            # Multiple overwrite passes
            for _ in range(passes):
                # First pass: random bytes
                f.seek(0)
                f.write(secrets.token_bytes(file_size))
                f.flush()
                os.fsync(f.fileno())
                
                # Second pass: zeros
                f.seek(0)
                f.write(b'\x00' * file_size)
                f.flush()
                os.fsync(f.fileno())
                
                # Third pass: ones
                f.seek(0)
                f.write(b'\xff' * file_size)
                f.flush()
                os.fsync(f.fileno())
            
            # Truncate to zero length
            f.truncate(0)
        
        # Overwrite filename in directory entry
        temp_name = secrets.token_hex(8)
        os.rename(path, temp_name)
        os.remove(temp_name)
        
    except Exception as e:
        print(f"Warning: Secure deletion failed: {str(e)}")
        # Attempt normal deletion as fallback
        try:
            os.remove(path)
        except:
            pass

def secure_erase_histories() -> None:
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
                # Overwrite before removing
                with open(hist_file, 'w') as f:
                    f.write('')
                os.remove(hist_file)
        except Exception:
            pass  # Ignore errors

def secure_exit(exit_code: int = 0) -> None:
    """
    Securely exit the program, cleaning up sensitive data.
    
    Args:
        exit_code: Exit code to return (default: 0 for success)
    """
    try:
        # Securely delete tracked files
        for file_path in FILES_TO_CLEANUP:
            if os.path.exists(file_path):
                secure_delete(file_path)
        FILES_TO_CLEANUP.clear()
        
        # Clear terminal history
        secure_erase_histories()
        
        # Clear environment variables
        os.environ.clear()
        
        sys.exit(exit_code)
    except Exception as e:
        print(f"Error during secure exit: {str(e)}")
        sys.exit(1)

def verify_wordlist_integrity() -> bool:
    """Verifies the integrity of the wordlist file using its SHA256 hash."""
    # This is the official SHA256 hash of the English BIP39 wordlist
    WORDLIST_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
    WORDLIST_FILE = "wordlist.txt"
    try:
        with open(WORDLIST_FILE, 'rb') as f:
            if hashlib.sha256(f.read()).hexdigest() != WORDLIST_SHA256:
                print(f"Error: {WORDLIST_FILE} has an incorrect hash. Please use the official BIP39 English wordlist.")
                return False
        return True
    except FileNotFoundError:
        print(f"Error: {WORDLIST_FILE} not found in the same directory as the script.")
        return False
    except Exception as e:
        print(f"Error verifying wordlist: {e}")
        return False

def check_security() -> None:
    """
    Check the security environment before proceeding.
    """
    # Check for network connectivity
    if psutil.net_if_stats():
        print("Warning: Network interfaces detected. For maximum security, consider running offline.")
    
    # Check for swap usage
    swap = psutil.swap_memory()
    if swap.used > 0:
        print("Warning: Swap memory is in use. This may leave sensitive data in swap files.")
        print("Consider disabling swap or using encrypted swap.")
    
    # Check for running processes
    sensitive_processes = ['wireshark', 'tcpdump', 'fiddler', 'charles']
    for proc in psutil.process_iter(['name']):
        if proc.info['name'].lower() in sensitive_processes:
            print(f"Warning: {proc.info['name']} is running. This may compromise security.")

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

def bip39_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    """Convert a BIP39 mnemonic to a seed."""
    PBKDF2_ROUNDS = 2048
    mnemonic = normalize('NFKD', ' '.join(mnemonic.split()))
    passphrase = normalize('NFKD', passphrase)
    return hashlib.pbkdf2_hmac('sha512', mnemonic.encode('utf-8'),
        b'mnemonic' + passphrase.encode('utf-8'), iterations=PBKDF2_ROUNDS)

def seed_to_master_key(seed: bytes) -> BIP32PrivateKey:
    """Convert a seed to a master key."""
    return BIP32PrivateKey.from_seed(seed, Bitcoin)

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
    
    print("\n=== Mnemonic Verification ===")
    print("Please enter your mnemonic phrase to verify your backup.")
    print("Enter each word separated by spaces.")
    print("Type 'exit' to cancel verification.")
    print("=" * 30)
    
    # Get user input
    user_input = input("Enter your mnemonic phrase: ").strip().lower()
    
    if user_input.lower() == 'exit':
        return False
    
    # Compare with original mnemonic
    if user_input == mnemonic.lower():
        print("\n✓ Verification successful! Your backup is correct.")
        return True
    else:
        print("\n✗ Verification failed. The entered phrase does not match.")
        print("Please try again or restart the process.")
        return False

def get_derivation_path() -> str:
    """
    Get the standard Bitcoin SV BIP44 derivation path.
    
    Returns:
        str: The derivation path in the format m/44'/236'/0'/0/0
    """
    return "m/44'/236'/0'/0/0"  # BSV BIP44 path

def generate_wallet() -> dict:
    """Generate a new wallet."""
    # Generate mnemonic
    mnemonic = generate_mnemonic()
    print(f"\nGenerated mnemonic: {mnemonic}")
    
    # Get derivation path
    derivation_path = get_derivation_path()
    
    # Convert mnemonic to seed
    seed = bip39_to_seed(mnemonic)
    
    # Create master key
    master_key = seed_to_master_key(seed)
    
    # Apply derivation path
    for n in bip32_decompose_chain_string(derivation_path):
        master_key = master_key.child_safe(n)
    
    # Get xprv and xpub
    xprv = master_key.to_extended_key_string()
    xpub = master_key.public_key.to_extended_key_string()
    
    # Generate first 5 receive addresses
    receive_addresses = []
    for i in range(5):
        child_key = master_key.child(0).child(i)
        address = child_key.public_key.to_address()
        receive_addresses.append(address)
    
    # Create wallet info
    wallet_info = {
        'mnemonic': mnemonic,
        'derivation_path': derivation_path,
        'xprv': xprv,
        'xpub': xpub,
        'receive_addresses': receive_addresses
    }
    
    return wallet_info

def encrypt_wallet_data(mnemonic: str, passphrase: str, derivation_path: str, xprv: str, xpub: str, password: str) -> str:
    """
    Encrypt wallet data using AES-GCM with a strong password.
    
    Args:
        mnemonic: The mnemonic phrase
        passphrase: The passphrase
        derivation_path: The derivation path
        xprv: The extended private key
        xpub: The extended public key
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
        hmac_hash_module=SHA256
    )
    
    # Prepare data for encryption
    data = {
        'mnemonic': mnemonic,
        'passphrase': passphrase,
        'derivation_path': derivation_path,
        'xprv': xprv,
        'xpub': xpub
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

def decrypt_wallet_data(encrypted_data: str, password: str) -> dict:
    """
    Decrypt wallet data using AES-GCM.
    
    Args:
        encrypted_data: Base64-encoded encrypted data
        password: The encryption password
        
    Returns:
        dict: Decrypted wallet data
    """
    try:
        # Parse encrypted data
        encrypted = json.loads(encrypted_data)
        
        # Decode components
        salt = base64.b64decode(encrypted['salt'])
        nonce = base64.b64decode(encrypted['nonce'])
        ciphertext = base64.b64decode(encrypted['ciphertext'])
        tag = base64.b64decode(encrypted['tag'])
        
        # Derive key from password
        key = PBKDF2(
            password.encode(),
            salt,
            dkLen=32,
            count=PBKDF2_ITERATIONS,
            hmac_hash_module=SHA256
        )
        
        # Create cipher and decrypt
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        data_bytes = cipher.decrypt_and_verify(ciphertext, tag)
        
        # Parse decrypted data
        wallet_data = json.loads(data_bytes.decode())
        
        # Regenerate receive addresses from xprv
        from bitcoinx.bip32 import bip32_key_from_string
        master_key = bip32_key_from_string(wallet_data['xprv'])
        receive_addresses = []
        
        # Generate first 5 receive addresses
        for i in range(5):
            child_key = master_key.child(0).child(i)
            address = child_key.public_key.to_address()
            receive_addresses.append(address)
        
        # Add receive addresses to wallet data
        wallet_data['receive_addresses'] = receive_addresses
        
        return wallet_data
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")

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
        
    except Exception as e:
        print(f"Warning: Could not generate QR code: {e}")

def generate_wallet_qr_codes(wallet_info: Dict, encrypted_data: str, output_dir: str, paranoid: bool = False) -> None:
    """Generates QR codes for public (xpub) and encrypted private data."""
    # Public QR
    public_data = json.dumps({
        'xpub': wallet_info.get('xpub', ''),
        'derivation_path': wallet_info.get('derivation_path', '')
    })
    public_qr_path = os.path.join(output_dir, "wallet_public_xpub.png")
    generate_qr_code(public_data, public_qr_path)
    FILES_TO_CLEANUP.append(public_qr_path)
    
    # Encrypted Private QR
    private_qr_path = os.path.join(output_dir, "wallet_encrypted_private.png")
    generate_qr_code(encrypted_data, private_qr_path)
    FILES_TO_CLEANUP.append(private_qr_path)

def is_offline() -> bool:
    """
    Check if the system is running offline by attempting to connect to a reliable host.
    
    Returns:
        bool: True if offline, False if online
    """
    try:
        # Try to connect to a reliable host
        socket.create_connection(("8.8.8.8", 53), timeout=1)
        return False
    except OSError:
        return True

def generate_qr_codes(wallet: dict) -> None:
    """
    Generate QR codes for wallet information.
    
    Args:
        wallet: Dictionary containing wallet information
    """
    import qrcode
    import os
    
    # Create qr_codes directory if it doesn't exist
    os.makedirs('qr_codes', exist_ok=True)
    
    # Generate QR code for mnemonic
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(wallet['mnemonic'])
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save('qr_codes/mnemonic.png')
    
    # Generate QR code for xpub
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(wallet['xpub'])
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save('qr_codes/xpub.png')
    
    # Generate QR codes for addresses
    for i, address in enumerate(wallet['receive_addresses']):
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(address)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        img.save(f'qr_codes/address_{i+1}.png')

def main():
    """Main function to run the wallet generator."""
    try:
        # Parse command line arguments
        parser = argparse.ArgumentParser(description='Bitcoin SV Wallet Generator')
        parser.add_argument('--decrypt', action='store_true', help='Decrypt an existing wallet')
        args = parser.parse_args()

        if args.decrypt:
            # Decryption mode
            print("\n=== Wallet Decryption ===")
            
            # Get encrypted data
            if os.path.exists('wallet.encrypted'):
                with open('wallet.encrypted', 'r') as f:
                    encrypted_data = f.read()
            else:
                encrypted_data = input("Enter encrypted wallet data: ")
            
            # Get password
            password = getpass.getpass("Enter wallet password: ")
            if not password:
                raise ValueError("Password cannot be empty")
            
            # Decrypt wallet data
            try:
                wallet_data = decrypt_wallet_data(encrypted_data, password)
                
                # Display decrypted information
                print("\n=== Decrypted Wallet Information ===")
                print(f"Mnemonic: {wallet_data['mnemonic']}")
                print(f"Derivation Path: {wallet_data['derivation_path']}")
                print(f"XPRV: {wallet_data['xprv']}")
                print(f"XPUB: {wallet_data['xpub']}")
                print("\nReceive Addresses:")
                for i, address in enumerate(wallet_data['receive_addresses']):
                    print(f"{i+1}. {address}")
                
                # Generate QR codes for decrypted data
                generate_qr_codes(wallet_data)
                print("\nQR codes generated in: qr_codes/")
                
            except Exception as e:
                print(f"Error: {str(e)}")
                sys.exit(1)
        else:
            # Wallet generation mode
            if not is_offline():
                print("Warning: Network interfaces detected. For maximum security, consider running offline.")
            
            # Generate wallet
            wallet = generate_wallet()
            
            # Get encryption password
            password = getpass.getpass("Enter a strong password for wallet encryption: ")
            if not password:
                raise ValueError("Password cannot be empty")
            
            # Encrypt wallet data
            encrypted_data = encrypt_wallet_data(
                wallet['mnemonic'],
                "",  # No passphrase for now
                wallet['derivation_path'],
                wallet['xprv'],
                wallet['xpub'],
                password
            )
            
            # Save encrypted data
            with open('wallet.encrypted', 'w') as f:
                f.write(encrypted_data)
            
            # Generate QR codes
            generate_qr_codes(wallet)
            
            # Display wallet information
            print("\n=== Wallet Information ===")
            print(f"Derivation Path: {wallet['derivation_path']}")
            print(f"XPRV: {wallet['xprv']}")
            print(f"XPUB: {wallet['xpub']}")
            print("\nReceive Addresses:")
            for i, address in enumerate(wallet['receive_addresses']):
                print(f"{i+1}. {address}")
            print("\nEncrypted wallet data saved to: wallet.encrypted")
            print("QR codes generated in: qr_codes/")
        
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 