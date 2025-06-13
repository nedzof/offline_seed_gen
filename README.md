# Bitcoin SV HD Wallet Generator

A portable, offline Bitcoin SV (BSV) hierarchical deterministic (HD) wallet generator compatible with ElectrumSV and BIP39/BIP32 standards.

## Features

- Generates BIP39 mnemonic phrases and BIP32 HD wallets
- Compatible with ElectrumSV
- Runs completely offline
- Portable - includes Python 3.10 binary and dependencies
- No internet connection required
- No virtual environment needed
- Simple XOR encryption for wallet backups
- Security checks for safe operation
- Seed phrase verification
- Formatted output for easy manual recording

## Usage

### Basic Usage

```bash
./main.py
```

This will:
1. Perform security checks
2. Generate a new wallet
3. Display the seed phrase and private keys in a formatted two-column layout
4. Offer options to save the wallet info (with optional encryption)

### Command Line Options

```bash
./main.py --help
```

Available options:
- `--decrypt FILE`: Decrypt an encrypted wallet file
- `--entropy BYTES`: Set entropy length in bytes (default: 32)
- `--passphrase TEXT`: Set an optional passphrase for the wallet

Examples:
```bash
# Generate a new wallet
./main.py

# Generate with custom entropy
./main.py --entropy 64

# Generate with a passphrase
./main.py --passphrase "my secret passphrase"

# Decrypt an encrypted wallet file
./main.py --decrypt wallet_info.txt
```

### Security Recommendations

1. Run this tool on an offline system
2. Use Xorg instead of Wayland
3. Copy the tool to internal storage before running
4. Double-check network connectivity is disabled
5. Store backups securely and never share your seed phrase

## Tails OS Compatibility

This tool is designed to work with Tails OS. When using with Tails:

1. Copy the tool to your persistent storage
2. Run the tool from internal storage (not from USB)
3. Save wallet information to your persistent storage
4. Use the optional encryption when saving sensitive data

## File Structure

```
.
├── bin/
│   └── python3.10
├── lib/
│   ├── bitcoinx_minimal.py
│   ├── matplotlib_minimal.py
│   └── numpy_minimal.py
├── main.py
└── README.md
```

## Security Features

- Entropy visualization
- Security checks for:
  - USB drive execution
  - Display server type
  - Network connectivity
- Optional XOR encryption for saved files
- Seed phrase verification
- Formatted output for accurate manual recording

## Requirements

- 64-bit Linux system
- Xorg display server (not Wayland)
- No internet connection required
- No additional dependencies needed

## License

MIT License

## Author
- [nedzof](https://github.com/nedzof) 