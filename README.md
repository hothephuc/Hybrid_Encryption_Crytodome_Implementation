
# Hybrid Encryption System

A secure file encryption system implementing hybrid encryption (RSA + AES) with support for file integrity verification. This system allows for secure file transfer by combining the advantages of both asymmetric (RSA) and symmetric (AES) encryption.

## Features

- 🔐 Hybrid encryption combining RSA and AES
- 📝 Support for multiple file types (text, images, audio)
- ✅ File integrity verification
- 🔑 Automatic key generation and management
- 🛡️ File type verification for added security
- 📦 Support for WAV, MP3, PNG, JPEG, and text files

## Table of Contents

- [Installation](#installation)
- [Requirements](#requirements)
- [Usage](#usage)
  - [Key Generation](#key-generation)
  - [File Encryption](#file-encryption)
  - [File Decryption](#file-decryption)
- [Security Features](#security-features)
- [Technical Details](#technical-details)
- [Contributing](#contributing)
- [License](#license)

## Installation

```bash
# Clone the repository
git clone https://github.com/hothephuc/Hybrid_Encryption_Crytodome_Implementation
cd Hybrid_Encryption_Crytodome_Implementation

# Install required packages
pip install pycryptodome
```

## Requirements

- Python 3.6+
- pycryptodome library

## Usage

### Key Generation

Generate RSA key pairs for encryption/decryption:

```bash
python generate_keys.py --bits 2048 --generate_sender_keys
```

Options:

- `--bits`: Key size in bits (default: 2048)
- `--generate_sender_keys`: Optional flag to generate sender keys for integrity verification

### File Encryption

Encrypt a file using the receiver's public key:

```bash
python encrypt.py \
  --receiver_pub_key receiver_pub_key.pub \
  --input_file myfile.txt \
  --output_encrypted_file myfile.encrypted \
  --output_encrypted_symmetric_key symmetric.key \
  --sender_private_key sender_private_key.key
```

Required arguments:

- `--receiver_pub_key`: Receiver's public key file
- `--input_file`: File to encrypt
- `--output_encrypted_file`: Output encrypted file
- `--output_encrypted_symmetric_key`: Output file for encrypted symmetric key

Optional arguments:

- `--sender_private_key`: Sender's private key for integrity verification

### File Decryption

Decrypt a file using the receiver's private key:

```bash
python decrypt.py \
  --receiver_private_key receiver_private_key.key \
  --encrypted_key symmetric.key \
  --input_file myfile.encrypted \
  --output_decrypted_file myfile_decrypted.txt \
  --sender_pub_key sender_pub_key.pub
```

Required arguments:

- `--receiver_private_key`: Receiver's private key file
- `--encrypted_key`: Encrypted symmetric key file
- `--input_file`: Encrypted file to decrypt
- `--output_decrypted_file`: Output decrypted file

Optional arguments:

- `--sender_pub_key`: Sender's public key for integrity verification

## Security Features

1. **Hybrid Encryption**

   - RSA (2048-bit default) for key exchange
   - AES-256 in EAX mode for file encryption
   - Secure random key generation
2. **File Integrity**

   - SHA-256 hashing
   - Digital signatures using sender's private key
   - Verification using sender's public key
3. **File Type Verification**

   - Validates file types before processing
   - Supports common formats (WAV, MP3, PNG, JPEG, TXT)
   - Prevents unauthorized file type manipulation

## Technical Details

### Encryption Process

1. Generate random AES symmetric key
2. Encrypt symmetric key with receiver's RSA public key
3. Encrypt file data with AES key
4. Generate and encrypt file hash if sender's private key is provided

### Decryption Process

1. Decrypt symmetric key using receiver's RSA private key
2. Decrypt file data using symmetric key
3. Verify file integrity if sender's public key is provided
4. Validate file type and extension

### Supported File Types

- Text files (.txt)
- Images (.png, .jpg, .jpeg)
- Audio files (.wav, .mp3)

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Make your changes
4. Run tests if available
5. Commit your changes (`git commit -am 'Add new feature'`)
6. Push to the branch (`git push origin feature/improvement`)
7. Create a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Security Considerations

- Keep private keys secure and never share them
- Use appropriate key sizes (minimum 2048 bits for RSA)
- Verify file integrity when possible
- Always validate file types before processing
- Consider additional security measures for production use

## Disclaimer

This system is provided as-is. While it implements strong encryption algorithms, proper security audit is recommended before use in production environments.
