# offline_seed_gen

A portable, offline Bitcoin SV (BSV) hierarchical deterministic (HD) wallet generator.

## Features
- Generates BIP39 mnemonics and BIP32 master keys
- Derives deterministic addresses compatible with ElectrumSV
- No internet required, fully offline and portable
- Optionally saves and encrypts sensitive wallet data
- No virtual environment or pip dependencies required (uses local `lib`)

## Usage
```bash
./bin/python3.10 generate_seed.py
```
- Follow the prompts to save and/or encrypt your wallet info.
- Addresses are printed and verified for determinism.

## Security
- All sensitive data is handled locally and can be optionally encrypted.
- No data is sent over the internet.

## Requirements
- Python 3.10 (portable, use the provided `bin/python3.10`)

## Author
- [nedzof](https://github.com/nedzof) 