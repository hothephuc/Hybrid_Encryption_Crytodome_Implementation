# Hybrid Encryption System

A secure file exchange system implementing hybrid encryption (RSA + AES) with optional integrity verification. This system provides a robust way to encrypt files using a combination of symmetric and asymmetric encryption, making it both secure and efficient for handling files of various types.

## Features

- **Hybrid Encryption**: 
  - RSA-2048 for key encryption
  - AES-256 for file encryption
  - Secure random key generation

- **File Support**:
  - Text files (.txt)
  - Image files (.png, .jpg, .jpeg)
  - Binary handling for all file types

- **Security Features**:
  - File integrity verification using SHA-256
  - Sender authenticity verification
  - Encrypted hash signing
  - Secure key exchange

- **Command-line Interface**:
  - User-friendly command-line arguments
  - Comprehensive error handling
  - Clear status messages

## System Architecture

```
┌────────────┐    ┌──────────────────┐    ┌────────────┐
│   Sender   │    │  Encrypted Data   │    │ Receiver   │
│            │    │                   │    │            │
│ File       │───>│ 1. Encrypted File │───>│ File       │
│            │    │ 2. Encrypted Key  │    │            │
│ Pub Key    │    │ 3. Integrity Hash │    │ Priv Key   │
└────────────┘    └──────────────────┘    └────────────┘
```

## Requirements

- Python 3.6+
- pycryptodome library

## Installation

1. Clone the repository:
```bash
git clone https://github.com/hothephuc/Hybrid_Encryption_Crytodome_Implementation-
cd hybrid-encryption
```

2. Install required packages:
```bash
pip install pycryptodome
```

## Usage

### 1. Generate Keys

Generate both receiver and sender keypairs:
```bash
python keygen.py --generate_sender_keys
```

This will create:
- receiver_pub_key.pub
- receiver_private_key.key
- sender_pub_key.pub
- sender_private_key.key

### 2. Encrypt Files

Basic encryption:
```bash
python encryptor.py \
    --receiver_pub_key=receiver_pub_key.pub \
    --input_file=file_to_encrypt.txt \
    --output_encrypted_file=encrypted_file.txt \
    --output_encrypted_symmetric_key=encrypted_key.key
```

With integrity verification:
```bash
python encryptor.py \
    --receiver_pub_key=receiver_pub_key.pub \
    --input_file=file_to_encrypt.txt \
    --output_encrypted_file=encrypted_file.txt \
    --output_encrypted_symmetric_key=encrypted_key.key \
    --sender_private_key=sender_private_key.key
```

### 3. Decrypt Files

Basic decryption:
```bash
python decryptor.py \
    --receiver_private_key=receiver_private_key.key \
    --encrypted_key=encrypted_key.key \
    --input_file=encrypted_file.txt \
    --output_decrypted_file=decrypted_file.txt
```

With integrity verification:
```bash
python decryptor.py \
    --receiver_private_key=receiver_private_key.key \
    --encrypted_key=encrypted_key.key \
    --input_file=encrypted_file.txt \
    --output_decrypted_file=decrypted_file.txt \
    --sender_pub_key=sender_pub_key.pub
```

## Security Details

- **RSA Key Size**: 2048 bits
- **AES Key Size**: 256 bits
- **AES Mode**: EAX (provides confidentiality and authenticity)
- **Hash Algorithm**: SHA-256
- **Key Exchange**: RSA-OAEP padding

## File Type Support

Currently supported file types:
- Text files (.txt)
- PNG images (.png)
- JPEG images (.jpg, .jpeg)

The system performs file type verification both during encryption and decryption to ensure proper handling of different file formats.

## Error Handling

The system includes comprehensive error handling for:
- Invalid file types
- File access issues
- Cryptographic operation failures
- Key format issues
- Integrity verification failures

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

This project was developed as part of the CSC15106 – Knowledge Engineering Seminar, Department of Knowledge Engineering, 2024.
