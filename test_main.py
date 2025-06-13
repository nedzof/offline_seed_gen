#!/usr/bin/env python3

import unittest
import os
import sys
import tempfile
from main import (
    generate_mnemonic,
    mnemonic_to_seed,
    generate_wallet,
    encrypt_wallet_data,
    decrypt_wallet_data,
    check_password_strength,
    verify_wordlist_integrity,
    secure_delete
)

class TestWalletFunctions(unittest.TestCase):
    def setUp(self):
        # Create a temporary directory for test files
        self.test_dir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.test_dir, 'test.txt')
        
        # Test data
        self.test_password = "Test123!@#$%^"
        self.test_data = "test data"
        
        # Create a test wordlist file
        self.wordlist_path = os.path.join(self.test_dir, 'wordlist.txt')
        with open(self.wordlist_path, 'w') as f:
            f.write("abandon\nability\nable\nabout\nabove\nabsent\nabsorb\nabstract\nabsurd\nabuse")

    def tearDown(self):
        # Clean up temporary files
        if os.path.exists(self.test_dir):
            for root, dirs, files in os.walk(self.test_dir, topdown=False):
                for name in files:
                    os.remove(os.path.join(root, name))
                for name in dirs:
                    os.rmdir(os.path.join(root, name))
            os.rmdir(self.test_dir)

    def test_generate_mnemonic(self):
        """Test mnemonic generation"""
        mnemonic = generate_mnemonic()
        self.assertIsInstance(mnemonic, str)
        self.assertTrue(len(mnemonic.split()) >= 12)
        
        # Test with specific entropy
        test_entropy = b'\x00' * 16
        mnemonic = generate_mnemonic(entropy=test_entropy)
        self.assertIsInstance(mnemonic, str)
        self.assertTrue(len(mnemonic.split()) >= 12)

    def test_mnemonic_to_seed(self):
        """Test seed generation from mnemonic"""
        mnemonic = "abandon ability able about above absent absorb abstract absurd abuse"
        seed = mnemonic_to_seed(mnemonic)
        self.assertIsInstance(seed, bytes)
        self.assertEqual(len(seed), 64)

    def test_generate_wallet(self):
        """Test wallet generation"""
        wallet = generate_wallet()
        self.assertIsInstance(wallet, dict)
        self.assertIn('mnemonic', wallet)
        self.assertIn('derivation_path', wallet)
        self.assertIn('address', wallet)
        self.assertIn('private_key', wallet)

    def test_encryption_decryption(self):
        """Test encryption and decryption"""
        # Test encryption
        encrypted = encrypt_wallet_data(self.test_data, self.test_password)
        self.assertIsInstance(encrypted, str)
        self.assertTrue(encrypted.startswith('v1:'))
        
        # Test decryption
        decrypted = decrypt_wallet_data(encrypted, self.test_password)
        self.assertEqual(decrypted, self.test_data)
        
        # Test wrong password
        with self.assertRaises(Exception):
            decrypt_wallet_data(encrypted, "wrong_password")

    def test_password_strength(self):
        """Test password strength checking"""
        # Test strong password
        self.assertTrue(check_password_strength(self.test_password))
        
        # Test weak passwords
        weak_passwords = [
            "short",  # Too short
            "onlylowercase",  # No uppercase
            "ONLYUPPERCASE",  # No lowercase
            "NoNumbers!",  # No numbers
            "NoSpecial123",  # No special characters
            "Password123!",  # Common pattern
            "qwerty123!",  # Common pattern
        ]
        for password in weak_passwords:
            self.assertFalse(check_password_strength(password))

    def test_wordlist_integrity(self):
        """Test wordlist integrity verification"""
        # Test with valid wordlist
        self.assertTrue(verify_wordlist_integrity(self.wordlist_path))
        
        # Test with invalid wordlist
        with open(self.wordlist_path, 'w') as f:
            f.write("invalid\nwordlist")
        self.assertFalse(verify_wordlist_integrity(self.wordlist_path))

    def test_secure_delete(self):
        """Test secure file deletion"""
        # Create test file
        with open(self.test_file, 'w') as f:
            f.write(self.test_data)
        
        # Test secure deletion
        self.assertTrue(os.path.exists(self.test_file))
        secure_delete(self.test_file)
        self.assertFalse(os.path.exists(self.test_file))

if __name__ == '__main__':
    unittest.main() 