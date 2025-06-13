# offline_seed_gen

A portable, offline Bitcoin SV (BSV) hierarchical deterministic (HD) wallet generator, designed for maximum privacy and security. 

**Tested and compatible with [Tails OS](https://tails.net/)** for secure, ephemeral, or persistent wallet generation.

## Features
- Generates BIP39 mnemonics and BIP32 master keys
- Derives deterministic addresses compatible with ElectrumSV
- No internet required, fully offline and portable
- Optionally saves and encrypts sensitive wallet data
- No virtual environment or pip dependencies required (uses local `lib`)
- Works out-of-the-box on Tails OS and other Linux distros

## Usage
```bash
./bin/python3.10 generate_seed.py
```
- Follow the prompts to save and/or encrypt your wallet info.
- Addresses are printed and verified for determinism.

### Saving to Persistent Storage on Tails OS
1. When prompted to save your wallet info, enter a path in your persistent storage (e.g. `/home/amnesia/Persistent/wallet_info.txt`).
2. You can choose to encrypt the file with a password for extra security.
3. The file will **not** be saved unless you explicitly choose to do so.

### Security
- All sensitive data is handled locally and can be optionally encrypted.
- No data is sent over the internet.
- You can run this tool in Tails' amnesic mode or with persistent storage.

## Requirements
- Python 3.10 (portable, use the provided `bin/python3.10`)
- No internet connection required after initial setup

## Author
- [nedzof](https://github.com/nedzof) 