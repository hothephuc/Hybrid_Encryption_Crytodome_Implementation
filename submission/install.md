# Installation Guide

This guide provides step-by-step instructions to install and run the secure file encryption system.

## System Requirements

- Python 3.7 or higher
- pip (Python package manager)
- 50MB free disk space
- Operating System: Windows, macOS, or Linux

## Installation Steps

1. **Create a Virtual Environment** (recommended)

   ```bash
   # Windows
   python -m venv venv
   .\venv\Scripts\activate

   # macOS/Linux
   python3 -m venv venv
   source venv/bin/activate
   ```
2. **Install Required Package**

   ```bash
   pip install pycryptodome
   ```
3. **Download Source Files**
   Create a new directory and save these files:

   - `keygen.py` - For generating RSA keys
   - `encryptor.py` - For encrypting files
   - `decryptor.py` - For decrypting files

## Quick Start Guide

1. **Generate Keys**

   ```bash
   # Basic key generation
   python keygen.py

   # With integrity verification (recommended)
   python keygen.py --generate_sender_keys
   ```
2. **Encrypt a File**

   ```bash
   python encryptor.py \
       --receiver_pub_key receiver_pub_key.pub \
       --input_file myfile.txt \
       --output_encrypted_file encrypted.bin \
       --output_encrypted_symmetric_key key.bin \
       --sender_private_key sender_private_key.key
   ```
3. **Decrypt a File**

   ```bash
   python decryptor.py \
       --receiver_private_key receiver_private_key.key \
       --encrypted_key key.bin \
       --input_file encrypted.bin \
       --output_decrypted_file decrypted.txt \
       --sender_pub_key sender_pub_key.pub
   ```

## Verification

To verify the installation:

1. Generate test keys:

   ```bash
   python keygen.py --generate_sender_keys
   ```
2. Create a test file:

   ```bash
   echo "Hello, World!" > test.txt
   ```
3. Encrypt the test file:

   ```bash
   python encryptor.py \
       --receiver_pub_key receiver_pub_key.pub \
       --input_file test.txt \
       --output_encrypted_file test.bin \
       --output_encrypted_symmetric_key test_key.bin
   ```
4. Decrypt the test file:

   ```bash
   python decryptor.py \
       --receiver_private_key receiver_private_key.key \
       --encrypted_key test_key.bin \
       --input_file test.bin \
       --output_decrypted_file test_decrypted.txt
   ```
5. Compare the files:

   ```bash
   # Windows
   type test_decrypted.txt

   # macOS/Linux
   cat test_decrypted.txt
   ```

   You should see "Hello, World!"

## Troubleshooting

### Common Installation Issues

1. **PyCryptodome Installation Fails**

   ```bash
   # Windows solution
   pip install --upgrade pip
   pip install pycryptodome --no-cache-dir

   # macOS/Linux solution
   pip3 install pycryptodome
   ```
2. **Python Version Error**

   ```bash
   # Check Python version
   python --version
   # If < 3.7, install newer Python version
   ```
3. **Permission Errors**

   ```bash
   # Windows: Run as Administrator
   # macOS/Linux
   chmod +x *.py
   ```

### Getting Help

If you encounter issues:

1. Verify Python version requirements
2. Ensure all dependencies are installed
3. Check file permissions
4. Make sure all source files are in the same directory

For additional support, verify:

- PyCryptodome installation: `pip show pycryptodome`
- Python path: `python -c "import sys; print(sys.path)"`
- File permissions: `ls -l` (macOS/Linux) or `dir` (Windows)
