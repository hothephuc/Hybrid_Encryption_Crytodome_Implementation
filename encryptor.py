from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
import argparse
import os
import imghdr
import wave
import mimetypes

class FileTypeVerifier:
    """Class to handle file type verification"""
    
    @staticmethod
    def is_valid_wav(file_path):
        """Verify if file is a valid WAV file"""
        try:
            with wave.open(file_path, 'rb') as wave_file:
                # Check basic WAV parameters
                params = wave_file.getparams()
                return params.nframes > 0 and params.nchannels > 0
        except Exception:
            return False

    @staticmethod
    def is_valid_mp3(file_path):
        """Verify if file is a valid MP3 file"""
        try:
            with open(file_path, 'rb') as f:
                # Check for ID3v2 or MPEG frame sync
                header = f.read(3)
                return header.startswith(b'ID3') or header.startswith(b'\xff\xfb')
        except Exception:
            return False

    @staticmethod
    def is_valid_image(file_path):
        """Verify if file is a valid image"""
        try:
            img_type = imghdr.what(file_path)
            return img_type in ['png', 'jpeg']
        except Exception:
            return False

    @staticmethod
    def verify_file_type(file_path):
        """Verify if file is a supported type and return the file type"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        _, ext = os.path.splitext(file_path)
        ext = ext.lower()

        # Define supported extensions
        supported_types = {
            'text': ['.txt'],
            'image': ['.png', '.jpg', '.jpeg'],
            'audio': ['.wav', '.mp3']
        }

        # Check text files
        if ext in supported_types['text']:
            return 'text'

        # Check image files
        if ext in supported_types['image']:
            if FileTypeVerifier.is_valid_image(file_path):
                return 'image'

        # Check audio files
        if ext in supported_types['audio']:
            if ext == '.wav' and FileTypeVerifier.is_valid_wav(file_path):
                return 'audio/wav'
            elif ext == '.mp3' and FileTypeVerifier.is_valid_mp3(file_path):
                return 'audio/mp3'

        supported_extensions = [ext for types in supported_types.values() for ext in types]
        raise ValueError(f"Unsupported or invalid file type: {ext}. Supported types: {', '.join(supported_extensions)}")

def encrypt_file(receiver_pub_key_path, input_file_path, output_encrypted_file_path, 
                output_encrypted_symmetric_key_path, sender_private_key_path=None):
    """Encrypt a file using hybrid encryption."""
    
    # Verify file type
    file_type = FileTypeVerifier.verify_file_type(input_file_path)
    print(f"Processing {file_type} file: {input_file_path}")
    
    # Read receiver's public key
    with open(receiver_pub_key_path, 'rb') as f:
        receiver_pub_key = RSA.import_key(f.read())
    
    # Generate random symmetric key
    symmetric_key = get_random_bytes(32)  # 256-bit key for AES
    
    # Encrypt symmetric key with receiver's public key
    cipher_rsa = PKCS1_OAEP.new(receiver_pub_key)
    encrypted_symmetric_key = cipher_rsa.encrypt(symmetric_key)
    
    # Save encrypted symmetric key
    with open(output_encrypted_symmetric_key_path, 'wb') as f:
        f.write(encrypted_symmetric_key)
    
    # Read and encrypt the input file
    cipher_aes = AES.new(symmetric_key, AES.MODE_EAX)
    
    with open(input_file_path, 'rb') as f:
        data = f.read()
    
    # Store the original file type for later verification
    file_type_header = file_type.encode('utf-8')
    file_type_length = len(file_type_header).to_bytes(2, byteorder='big')
    
    # Encrypt the file with file type information
    ciphertext, tag = cipher_aes.encrypt_and_digest(file_type_length + file_type_header + data)
    
    # Save the encrypted file along with the nonce and tag
    with open(output_encrypted_file_path, 'wb') as f:
        [f.write(x) for x in (cipher_aes.nonce, tag, ciphertext)]
    
    # Handle integrity verification if sender's private key is provided
    if sender_private_key_path:
        with open(sender_private_key_path, 'rb') as f:
            sender_private_key = RSA.import_key(f.read())
        
        # Calculate hash of original file
        file_hash = SHA256.new(data)
        
        # Encrypt hash with sender's private key
        cipher_rsa_sender = PKCS1_OAEP.new(sender_private_key)
        encrypted_hash = cipher_rsa_sender.encrypt(file_hash.digest())
        
        # Save encrypted hash
        hash_path = output_encrypted_file_path + '.hash'
        with open(hash_path, 'wb') as f:
            f.write(encrypted_hash)
        print("Generated file integrity hash")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Encrypt a file using hybrid encryption')
    parser.add_argument('--receiver_pub_key', required=True, help='Receiver public key file')
    parser.add_argument('--input_file', required=True, help='Input file to encrypt')
    parser.add_argument('--output_encrypted_file', required=True, help='Output encrypted file')
    parser.add_argument('--output_encrypted_symmetric_key', required=True, help='Output encrypted symmetric key')
    parser.add_argument('--sender_private_key', help='Sender private key for integrity verification (optional)')
    args = parser.parse_args()
    
    encrypt_file(args.receiver_pub_key, args.input_file, args.output_encrypted_file,
                args.output_encrypted_symmetric_key, args.sender_private_key)
