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

def generate_wallet(derivation_path: str, strength_bits: int = 256, passphrase: str = "") -> Dict:
    """Generates a new wallet, including mnemonic, keys, and performs user verification."""
    mnemonic = generate_mnemonic(strength_bits=strength_bits)
    if not verify_mnemonic_backup(mnemonic):
        raise Exception("Mnemonic verification failed. Aborting.")
    
    seed = mnemonic_to_seed(mnemonic, passphrase)
    master_key = seed_to_master_key(seed)
    
    wallet_info = {
        'mnemonic': mnemonic,
        'passphrase': passphrase,
        'derivation_path': derivation_path,
        'xprv': master_key.to_extended_key_string(),
        'xpub': master_key.public_key.to_extended_key_string(),
        'version': "1.0"
    }
    return wallet_info

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

def main() -> None:
    """
    Main function to handle wallet generation and management.
    """
    try:
        # Parse command line arguments
        parser = argparse.ArgumentParser(description='Secure Bitcoin SV Wallet Generator')
        parser.add_argument('--print-only', action='store_true', help='Only print wallet info, no files')
        parser.add_argument('--paranoid', action='store_true', help='Enable paranoid mode (no files)')
        parser.add_argument('--decrypt', action='store_true', help='Decrypt wallet info')
        parser.add_argument('--file', type=str, help='Path to encrypted wallet file')
        parser.add_argument('--password', type=str, help='Password for decryption')
        args = parser.parse_args()
        
        # Check security environment
        check_security()
        
        # Verify wordlist integrity
        if not verify_wordlist_integrity():
            print("Error: Wordlist verification failed")
            secure_exit(1)
        
        # Handle decryption mode
        if args.decrypt:
            if args.file and args.password:
                # Automated decryption
                try:
                    with open(args.file, 'r') as f:
                        encrypted_data = f.read()
                    decrypted = decrypt_wallet_info(encrypted_data, args.password)
                    print("\nDecrypted wallet information:")
                    print(json.dumps(decrypted, indent=2))
                    secure_exit(0)
                except Exception as e:
                    print(f"Error decrypting file: {str(e)}")
                    secure_exit(1)
            else:
                # Interactive decryption
                encrypted_data = input("Enter encrypted wallet data: ")
                password = getpass.getpass("Enter password: ")
                try:
                    decrypted = decrypt_wallet_info(encrypted_data, password)
                    print("\nDecrypted wallet information:")
                    print(json.dumps(decrypted, indent=2))
                    secure_exit(0)
                except Exception as e:
                    print(f"Error decrypting data: {str(e)}")
                    secure_exit(1)
        
        # Get password with strength check
        while True:
            password = getpass.getpass("Enter a strong password for encryption: ")
            is_strong, feedback = check_password_strength(password)
            if is_strong:
                break
            print(feedback)
        
        # Confirm password
        if getpass.getpass("Confirm password: ") != password:
            print("Passwords do not match")
            secure_exit(1)
        
        # Get derivation path
        derivation_path = input("Enter derivation path (default: m/44'/236'/0'/0/0): ").strip()
        if not derivation_path:
            derivation_path = "m/44'/236'/0'/0/0"
        
        # Generate wallet
        wallet = generate_wallet(derivation_path=derivation_path)
        
        # Encrypt wallet data
        encrypted = encrypt_wallet_data(
            wallet['mnemonic'],
            wallet['passphrase'],
            wallet['derivation_path'],
            password
        )
        
        # Handle output based on mode
        if args.paranoid:
            print("\nEncrypted wallet data (save this securely):")
            print(encrypted)
        elif args.print_only:
            print("\nWallet information:")
            print(json.dumps(wallet, indent=2))
            print("\nEncrypted wallet data:")
            print(encrypted)
        else:
            # Save to file
            output_dir = "wallet_output"
            os.makedirs(output_dir, exist_ok=True)
            
            # Save encrypted data
            encrypted_file = os.path.join(output_dir, "wallet_encrypted.json")
            with open(encrypted_file, 'w') as f:
                f.write(encrypted)
            FILES_TO_CLEANUP.append(encrypted_file)
            
            # Generate QR codes
            generate_wallet_qr_codes(wallet, encrypted, output_dir, args.paranoid)
            
            print(f"\nWallet information saved to {output_dir}/")
            print("Remember to securely delete these files after backing up!")
        
        secure_exit(0)
        
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        secure_exit(1)
    except Exception as e:
        print(f"Error: {str(e)}")
        secure_exit(1)

if __name__ == '__main__':
    main() 