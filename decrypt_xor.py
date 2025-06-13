def xor_decrypt_file(filename, password):
    with open(filename, 'r') as f:
        encrypted = f.read()
    decrypted = ''.join(chr(ord(c) ^ ord(password[i % len(password)])) for i, c in enumerate(encrypted))
    with open(filename + '.decrypted', 'w') as f:
        f.write(decrypted)
    print(f"Decrypted file saved as {filename + '.decrypted'}")

if __name__ == '__main__':
    filename = input("Enter the encrypted filename: ").strip()
    password = input("Enter the encryption password: ").strip()
    xor_decrypt_file(filename, password) 