#!/home/caruk/Downloads/electrumsv_seed_tool/bin/python3.10

import os
import sys
import hashlib
import secrets
from typing import List, Tuple, Optional, Dict
import hmac
from bitcoinx import PrivateKey, PublicKey, BIP32PrivateKey, BIP32PublicKey, Network, Bitcoin, bip32_key_from_string

# Add lib directory to Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'lib'))

# Import from local lib directory
from matplotlib_minimal import figure, subplot, tight_layout, savefig, close
from numpy_minimal import array, random_bytes, frombuffer, histogram

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
    print("Welcome to the Interactive Wallet Generator!\n")
    # Use default values
    entropy_length = 32
    passphrase = ""
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
    print("First 10 Derived Addresses:")
    for i, addr in enumerate(wallet['addresses'][:10]):
        print(f"{i+1}: {addr}")
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