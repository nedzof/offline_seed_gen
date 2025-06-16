# ElectrumSV Seed Tool

**Important:** Always launch the script with `./bin/python3.10 main.py` to ensure all offline Python libraries in the `lib` folder are used. Do not use the system Python unless you have installed all dependencies globally.

A secure, offline tool for generating and managing Bitcoin SV (BSV) wallet seeds with advanced security features.

## Features

- 🔒 **Offline Operation**: Designed to run completely offline for maximum security
- 🎲 **Cryptographically Secure**: Uses system entropy and secure random number generation
- 🔐 **Strong Encryption**: AES-256-GCM encryption for wallet data
- 📱 **QR Code Support**: Generate QR codes for easy air-gapped transfer
- 🧪 **Self-Test Mode**: Comprehensive test suite to verify functionality
- 🔍 **Security Checks**: Runtime security verification
- 🛡️ **Memory Protection**: Secure memory handling and cleanup
- 📝 **Detailed Logging**: Comprehensive operation logging

## Security Features

- **Entropy Generation**: Uses system entropy sources for true randomness
- **Memory Protection**: 
  - Memory locking to prevent swapping
  - Secure memory wiping
  - Protected memory regions
- **Secure Deletion**: 
  - Secure file deletion
  - Shell history cleanup
  - Python history cleanup
- **Password Protection**:
  - Strong password requirements
  - Rate-limited decryption attempts
  - Secure password handling
- **Paranoid Mode**: Optional ASCII-only QR code generation
- **Print-Only Mode**: Optional mode to prevent file writing

## Installation

1. Clone the repository:
```bash
git clone https://github.com/nedzof/offline_seed_gen.git
cd offline_seed_gen
```

2. Install dependencies locally:
```bash
./install_deps.sh
```

## Usage

```bash
./bin/python3.10 main.py
```

- This ensures the script uses the bundled offline Python and all required libraries from the `lib` directory.
- For decryption:

```bash
./bin/python3.10 main.py --decrypt --file /path/to/wallet_info_encrypted.txt --password YOURPASSWORD
```

This will:
1. Perform security checks
2. Generate a new wallet
3. Encrypt the wallet data
4. Save the encrypted data
5. Optionally generate QR codes

### Command Line Options

- `--paranoid`: Run in paranoid mode (ASCII QR only)
- `--print-only`: Run in print-only mode (no file output)
- `--selftest`: Run self-test and exit

### Security Recommendations

1. **Run Offline**: Always run this tool on an offline system
2. **Use Xorg**: Prefer Xorg over Wayland for better security
3. **Internal Storage**: Copy the tool to internal storage before running
4. **Network Check**: Double-check network connectivity is disabled
5. **Secure Storage**: Store backups securely and never share your seed phrase
6. **Password Management**: Use a strong, unique password for encryption
7. **Secure Environment**: Run in a clean, secure environment
8. **Regular Updates**: Keep the tool updated with the latest security patches

## Password Requirements

The tool enforces a simple password requirement:
- Minimum 15 characters in length

## QR Code Generation

The tool can generate QR codes in two modes:
1. **Standard Mode**: Generates both image and ASCII QR codes
2. **Paranoid Mode**: Generates ASCII QR codes only

## Self-Test Mode

Run comprehensive tests with:
```bash
./main.py --selftest
```

Tests include:
- Entropy generation
- Mnemonic generation
- Encryption/Decryption
- QR code generation
- Password strength validation

## File Structure

- `main.py`: Main script
- `install_deps.sh`: Dependency installation script
- `lib/`: Local dependencies
- `qr_bundle/`: Generated QR codes
- `wallet_info.txt`: Encrypted wallet data

## Dependencies

Local dependencies are managed in the `lib` directory:
- `pycryptodomex`: Cryptographic operations
- `qrcode`: QR code generation
- `bitcoinx`: Bitcoin SV operations

## Security Considerations

### Memory Safety
- Memory is locked to prevent swapping
- Sensitive data is securely wiped
- Protected memory regions are used

### File Safety
- Secure file deletion
- History cleanup
- Temporary file handling

### Network Safety
- Offline operation
- Network connectivity checks
- Air-gapped transfer support

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is provided for educational and research purposes only. Use at your own risk. The authors are not responsible for any loss of funds or other damages that may result from the use of this tool.

## Acknowledgments

- ElectrumSV team for inspiration
- Bitcoin SV community for support
- All contributors and testers

## Support

For issues and feature requests, please use the GitHub issue tracker.

## Version History

- 1.0: Initial release
  - Basic wallet generation
  - Encryption support
  - QR code generation
  - Security features
  - Self-test mode 