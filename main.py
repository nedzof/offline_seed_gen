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

# Add lib directory to Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'lib'))

# Import from local lib directory
from matplotlib_minimal import figure, subplot, tight_layout, savefig, close
from numpy_minimal import array, random_bytes, frombuffer, histogram

def xor_decrypt_file(filename: str, password: str) -> None:
    """Decrypt an XOR-encrypted file using the provided password."""
    try:
        with open(filename, 'r') as f:
            encrypted = f.read()
        decrypted = ''.join(chr(ord(c) ^ ord(password[i % len(password)])) for i, c in enumerate(encrypted))
        output_file = filename + '.decrypted'
        with open(output_file, 'w') as f:
            f.write(decrypted)
        print(f"✓ Decrypted file saved as {output_file}")
    except Exception as e:
        print(f"✗ Error decrypting file: {e}")
        sys.exit(1)

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Bitcoin SV HD Wallet Generator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Generate a new wallet
  ./generate_seed.py

  # Decrypt an encrypted wallet file
  ./generate_seed.py --decrypt wallet_info.txt

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

def derive_addresses(master_key: BIP32PrivateKey, count: int = 10) -> List[str]:
    """Derive addresses using ElectrumSV's derivation path."""
    # ElectrumSV uses m/44'/0'/0' for the first account
    account_key = master_key.child(44 | 0x80000000).child(0 | 0x80000000).child(0 | 0x80000000)
    addresses = []
    for i in range(count):
        # Derive external chain addresses (m/44'/0'/0'/0/i)
        address_key = account_key.child(0).child(i)
        addresses.append(address_key.public_key.to_address().to_string())
    return addresses

def generate_wallet(entropy_length: int = 16, passphrase: str = "", num_points: int = 100) -> Dict:
    """Generate a new wallet with the specified entropy length and passphrase."""
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
    addresses = derive_addresses(master_key)
    
    # Generate visualization
    # plot_wallet_generation(entropy_hex, mnemonic, seed.hex(), master_key.to_hex(), num_points)
    
    return {
        'entropy': entropy_hex,
        'mnemonic': mnemonic,
        'seed': seed.hex(),
        'master_key_hex': master_key.to_hex(),
        'master_key_xprv': master_key.to_extended_key_string(),
        'addresses': addresses
    }

def get_project_root() -> str:
    return os.path.dirname(os.path.abspath(__file__))

def verify_addresses(seed: bytes, master_key: BIP32PrivateKey, addresses_file: str) -> bool:
    """Verify the seed and master key by deriving addresses using ElectrumSV's derivation path."""
    with open(addresses_file, 'r') as f:
        addresses = [line.strip() for line in f.readlines() if line.strip()]
    if len(addresses) != 1000:
        print(f"Warning: addresses.txt contains {len(addresses)} addresses, expected 1000.")
        return False
    
    # Derive addresses from seed and master key using ElectrumSV's derivation path
    master_from_seed = BIP32PrivateKey.from_seed(seed, Bitcoin)
    derived_addresses_seed = derive_addresses(master_from_seed)
    derived_addresses_master = derive_addresses(master_key)
    
    # Compare first 10 addresses
    for i, (derived_seed, derived_master) in enumerate(zip(derived_addresses_seed, derived_addresses_master)):
        print(f"Address {i+1}:")
        print(f"Derived from Seed: {derived_seed}")
        print(f"Derived from Master Key: {derived_master}")
        if derived_seed != derived_master:
            print("Verification failed: Addresses do not match.")
            return False
    
    print("Verification successful: All addresses match.")
    return True

if __name__ == '__main__':
    args = parse_arguments()
    
    # Handle decryption if requested
    if args.decrypt:
        if not os.path.exists(args.decrypt):
            print(f"✗ Error: File {args.decrypt} not found")
            sys.exit(1)
        password = input("Enter encryption password: ").strip()
        xor_decrypt_file(args.decrypt, password)
        sys.exit(0)
    
    # Run security checks first
    check_security()
    
    print("Welcome to the Interactive Wallet Generator!\n")
    # Use command line arguments or defaults
    entropy_length = args.entropy
    passphrase = args.passphrase
    random_data_points = 1000
    project_root = get_project_root()
    wallet = generate_wallet(entropy_length, passphrase, random_data_points)
    # Derive account xpub (m/44'/0'/0')
    master_key = BIP32PrivateKey.from_seed(bytes.fromhex(wallet['seed']), Bitcoin)
    account_key = master_key.child(44 | 0x80000000).child(0 | 0x80000000).child(0 | 0x80000000)
    account_xpub = account_key.public_key.to_extended_key_string()
    print("\n==============================")
    print("      Generated Wallet")
    print("==============================")
    print(f"Entropy:\n{wallet['entropy']}\n")
    print(f"Mnemonic:\n{wallet['mnemonic']}\n")
    print(f"Seed:\n{wallet['seed']}\n")
    print(f"Master Key (hex):\n{wallet['master_key_hex']}\n")
    print(f"Master Key (xprv):\n{wallet['master_key_xprv']}\n")
    print(f"Account XPUB:\n{account_xpub}\n")
    print("------------------------------")
    
    # Format seed words in two columns with numbers
    print("\n📝 Seed Phrase (Write this down carefully):")
    print("------------------------------")
    words = wallet['mnemonic'].split()
    col_width = max(len(word) for word in words) + 4  # Add padding
    for i in range(0, len(words), 2):
        left_word = f"{i+1:2d}. {words[i]}"
        right_word = f"{i+2:2d}. {words[i+1]}" if i+1 < len(words) else ""
        print(f"{left_word:<{col_width}} {right_word}")
    print("------------------------------")
    
    # Format private keys with numbers
    print("\n🔑 Private Keys (Write these down carefully):")
    print("------------------------------")
    print("1. Master Key (xprv):")
    print(f"   {wallet['master_key_xprv']}")
    print("\n2. Account XPUB:")
    print(f"   {account_xpub}")
    print("------------------------------")
    
    # Ask if user wants to save seed and master keys
    save = input("\nDo you want to save the entropy, mnemonic, seed, master keys, and xpub to a txt file? (y/n): ").strip().lower()
    if save == 'y':
        filename = input("Enter filename to save to (default: wallet_info.txt): ").strip() or "wallet_info.txt"
        with open(filename, 'w') as f:
            f.write(f"Entropy: {wallet['entropy']}\n")
            f.write(f"Mnemonic: {wallet['mnemonic']}\n")
            f.write(f"Seed: {wallet['seed']}\n")
            f.write(f"Master Key (hex): {wallet['master_key_hex']}\n")
            f.write(f"Master Key (xprv): {wallet['master_key_xprv']}\n")
            f.write(f"Account XPUB: {account_xpub}\n")
        print(f"Wallet info saved to {filename}")
        encrypt = input("Do you want to encrypt the saved file? (y/n): ").strip().lower()
        if encrypt == 'y':
            password = input("Enter encryption password: ").strip()
            with open(filename, 'r') as f:
                content = f.read()
            encrypted = ''.join(chr(ord(c) ^ ord(password[i % len(password)])) for i, c in enumerate(content))
            with open(filename, 'w') as f:
                f.write(encrypted)
            print(f"File {filename} has been encrypted.")
    else:
        # Generate 3 random indices based on the seed
        seed_bytes = bytes.fromhex(wallet['seed'])
        indices = [int.from_bytes(seed_bytes[i:i+4], 'big') % 12 for i in range(0, 12, 4)][:3]
        
        # Get the words at those indices
        words = wallet['mnemonic'].split()
        verification_words = [words[i] for i in indices]
        
        print("\n⚠️  IMPORTANT: Please verify that you have saved your seed phrase!")
        print("To verify, please select the correct word for each position:")
        
        for i, word in enumerate(verification_words):
            # Generate 3 random options including the correct word
            all_words = set(words)  # Get all unique words
            options = random.sample(list(all_words - {word}), 2)  # Get 2 random different words
            options.append(word)  # Add the correct word
            random.shuffle(options)  # Shuffle the options
            
            print(f"\nPosition {indices[i] + 1}:")
            for j, opt in enumerate(options, 1):
                print(f"{j}. {opt}")
            
            while True:
                try:
                    choice = int(input(f"Select the correct word for position {indices[i] + 1} (1-3): "))
                    if 1 <= choice <= 3:
                        if options[choice-1] == word:
                            print("✓ Correct!")
                            break
                        else:
                            print("✗ Incorrect! Please try again.")
                    else:
                        print("Please enter a number between 1 and 3.")
                except ValueError:
                    print("Please enter a valid number.")
        
        print("\n✓ Verification complete! Please make sure you have securely saved your seed phrase.")
        print("Remember: If you lose your seed phrase, you will lose access to your funds!")

    # Verify addresses
    seed_bytes = bytes.fromhex(wallet['seed'])
    master_key_obj = bip32_key_from_string(wallet['master_key_xprv'])
    # Derive addresses from both seed and master key
    master_from_seed = BIP32PrivateKey.from_seed(seed_bytes, Bitcoin)
    derived_addresses_seed = derive_addresses(master_from_seed)
    derived_addresses_master = derive_addresses(master_key_obj)
    # Verification (less verbose)
    all_match = all(a == b for a, b in zip(derived_addresses_seed, derived_addresses_master))
    if all_match:
        print("\nVerification successful: All addresses match.")
    else:
        print("\nVerification failed: Addresses do not match.")
    # Write 1000 addresses to 'addresses' file
    addresses_1000 = derive_addresses(BIP32PrivateKey.from_seed(bytes.fromhex(wallet['seed']), Bitcoin), 1000)
    with open('addresses', 'w') as f:
        for addr in addresses_1000:
            f.write(addr + '\n') 