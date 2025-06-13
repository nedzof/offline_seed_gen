#!/home/caruk/Downloads/electrumsv_seed_tool/bin/python3.10

import os
import sys
import hashlib
import secrets
from typing import List, Tuple, Optional, Dict
import hmac
import argparse
from bitcoinx import PrivateKey, PublicKey, BIP32PrivateKey, BIP32PublicKey, Network, Bitcoin, bip32_key_from_string
import subprocess
import socket
import random
import shutil
import base64
from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Random import get_random_bytes

# Add lib directory to Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'lib'))

# Import from local lib directory
from matplotlib_minimal import figure, subplot, tight_layout, savefig, close
from numpy_minimal import array, random_bytes, frombuffer, histogram

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
    
    # Return base64 encoded result
    return base64.b64encode(encrypted_data).decode()

def decrypt_wallet_data(encrypted_data: str, password: str) -> str:
    """Decrypt wallet data using AES-256-GCM."""
    try:
        # Decode base64 data
        data = base64.b64decode(encrypted_data)
        
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
    
    return parser.parse_args()

def check_security():
    """Perform security checks before running the wallet generator."""
    print("Performing security checks...")
    
    # Check if running from USB
    current_path = os.path.abspath(__file__)
    if '/media/' in current_path or '/mnt/' in current_path:
        print("\n⚠️  WARNING: Script is running from a USB drive!")
        print("For maximum security, please copy the script to internal storage first.")
        print("This prevents potential hardware-level attacks and ensures the OS handles file access properly.")
        response = input("Do you want to continue anyway? (y/n): ").strip().lower()
        if response != 'y':
            sys.exit(1)
    
    # Check display server
    try:
        display_server = os.environ.get('XDG_SESSION_TYPE', '').lower()
        if display_server == 'wayland':
            print("\n⚠️  WARNING: Running under Wayland!")
            print("For maximum security, it's recommended to use Xorg instead.")
            print("Wayland's security model might allow screen capture without user consent.")
            response = input("Do you want to continue anyway? (y/n): ").strip().lower()
            if response != 'y':
                sys.exit(1)
    except Exception as e:
        print(f"Could not determine display server: {e}")
    
    # Check network connectivity
    try:
        # Try to create a socket connection
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect(('8.8.8.8', 53))
        s.close()
        print("\n⚠️  WARNING: Network connection detected!")
        print("For maximum security, please disconnect from all networks before generating a wallet.")
        print("The network icon should show that you are offline.")
        response = input("Do you want to continue anyway? (y/n): ").strip().lower()
        if response != 'y':
            sys.exit(1)
    except socket.error:
        print("✓ Network check passed: No active network connection detected.")
    
    print("\n✓ Security checks completed.")
    print("Remember to:")
    print("1. Keep your system offline during wallet generation")
    print("2. Use a secure, private environment")
    print("3. Store your backup securely")
    print("4. Never share your seed phrase or private keys\n")

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

def generate_wallet(entropy_length: int = 16, passphrase: str = "", derivation_path: str = "m/44'/236'/0'", num_points: int = 100) -> Dict:
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

def get_project_root() -> str:
    return os.path.dirname(os.path.abspath(__file__))

def secure_erase_histories():
    """Securely erase shell and Python history files."""
    import getpass
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
    resp = input("\nDo you want to securely erase shell and Python history before exiting? (y/N): ").strip().lower()
    if resp == 'y':
        secure_erase_histories()
    # Overwrite sensitive variables (best effort)
    globals_to_clear = ['mnemonic', 'seed', 'entropy', 'master_key', 'xprv', 'xpub', 'private_keys', 'addresses']
    for var in globals_to_clear:
        if var in globals():
            globals()[var] = None
    print("Exiting. For maximum privacy, reboot your system now.")
    sys.exit(0)

def main():
    args = parse_arguments()
    
    if args.decrypt:
        password = input("Enter password: ").strip()
        try:
            with open(args.decrypt, 'r') as f:
                encrypted_data = f.read()
            decrypted_data = decrypt_wallet_data(encrypted_data, password)
            print("\nDecrypted wallet information:")
            print(decrypted_data)
        except Exception as e:
            print(f"Error decrypting file: {e}")
            sys.exit(1)
        return
    
    check_security()
    
    # Get derivation path
    print("\nSelect derivation path:")
    print("1. Standard (BIP44, Recommended for most wallets): m/44'/236'/0'")
    print("2. Legacy (ElectrumSV): m/44'/0'/0'")
    choice = input("Enter choice (1/2) [1]: ").strip() or "1"
    derivation_path = "m/44'/236'/0'" if choice == "1" else "m/44'/0'/0'"
    
    # Get passphrase
    passphrase = args.passphrase or input("Enter optional passphrase (press Enter for none): ").strip()
    
    # Generate wallet
    wallet = generate_wallet(
        entropy_length=args.entropy,
        passphrase=passphrase,
        derivation_path=derivation_path
    )
    
    # Display wallet information
    print("\n=== Wallet Information ===")
    print(f"Entropy: {wallet['entropy']}")
    print(f"Mnemonic: {wallet['mnemonic']}")
    print(f"Derivation Path: {wallet['derivation_path']}")
    if passphrase:
        print(f"Passphrase: {passphrase}")
    print("\nFirst 5 addresses:")
    for i, addr in enumerate(wallet['addresses'][:5]):
        print(f"{i+1}. {addr}")
    
    # Save wallet information
    wallet_info = f"""Entropy: {wallet['entropy']}
Mnemonic: {wallet['mnemonic']}
Derivation Path: {wallet['derivation_path']}
Passphrase: {passphrase if passphrase else '(none)'}
Master Key (xprv): {wallet['master_key_xprv']}
"""
    
    # Encrypt and save wallet information
    password = input("\nEnter password to encrypt wallet information: ").strip()
    encrypted_data = encrypt_wallet_data(wallet_info, password)
    
    with open('wallet_info.txt', 'w') as f:
        f.write(encrypted_data)
    
    print("\n✓ Wallet information has been encrypted and saved to wallet_info.txt")
    print("\nIMPORTANT: Please write down and keep safe:")
    print("1. The mnemonic seed phrase (12/24 words)")
    print("2. The derivation path (m/44'/236'/0' or m/44'/0'/0')")
    print("3. The passphrase (if used)")
    print("\nKeep these in a secure location. Anyone with access to these can access your funds.")
    
    secure_exit()

if __name__ == '__main__':
    main() 