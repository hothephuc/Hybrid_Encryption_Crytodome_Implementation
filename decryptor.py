from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
import argparse
import os
import wave
import imghdr
from encryptor import FileTypeVerifier

def decrypt_file(receiver_private_key_path, encrypted_key_path, input_file_path, 
                output_decrypted_file_path, sender_pub_key_path=None):
    """Decrypt a file using hybrid encryption."""
    
    # Verify output file type (basic extension check)
    _, ext = os.path.splitext(output_decrypted_file_path)
    ext = ext.lower()
    
    # Read receiver's private key
    with open(receiver_private_key_path, 'rb') as f:
        private_key = RSA.import_key(f.read())
    
    # Read encrypted symmetric key
    with open(encrypted_key_path, 'rb') as f:
        encrypted_symmetric_key = f.read()
    
    # Decrypt symmetric key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    symmetric_key = cipher_rsa.decrypt(encrypted_symmetric_key)
    
    # Read the encrypted file
    with open(input_file_path, 'rb') as f:
        nonce = f.read(16)
        tag = f.read(16)
        ciphertext = f.read()
    
    # Decrypt the file
    cipher_aes = AES.new(symmetric_key, AES.MODE_EAX, nonce)
    decrypted_data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    
    # Extract file type information
    file_type_length = int.from_bytes(decrypted_data[:2], byteorder='big')
    file_type = decrypted_data[2:2+file_type_length].decode('utf-8')
    actual_data = decrypted_data[2+file_type_length:]
    
    print(f"Decrypting {file_type} file to: {output_decrypted_file_path}")
    
    # Verify file extension matches the original file type
    expected_extensions = {
        'text': ['.txt'],
        'image': ['.png', '.jpg', '.jpeg'],
        'audio/wav': ['.wav'],
        'audio/mp3': ['.mp3']
    }
    
    valid_extensions = expected_extensions.get(file_type, [])
    if ext not in valid_extensions:
        print(f"Warning: Output file extension {ext} may not match the original file type {file_type}")
    
    # Save the decrypted file
    with open(output_decrypted_file_path, 'wb') as f:
        f.write(actual_data)
    
    # Verify file integrity if sender's public key is provided
    if sender_pub_key_path:
        try:
            # Read sender's public key
            with open(sender_pub_key_path, 'rb') as f:
                sender_pub_key = RSA.import_key(f.read())
            
            # Calculate hash of decrypted file
            file_hash = SHA256.new(actual_data)
            
            # Read encrypted hash
            hash_path = input_file_path + '.hash'
            with open(hash_path, 'rb') as f:
                encrypted_hash = f.read()
            
            # Decrypt hash with sender's public key
            cipher_rsa_sender = PKCS1_OAEP.new(sender_pub_key)
            original_hash = cipher_rsa_sender.decrypt(encrypted_hash)
            
            # Verify hashes match
            if original_hash == file_hash.digest():
                print("FILE IS VALID - Integrity check passed")
                print("FILE IS VALID - Verified to be from the original sender")
            else:
                print("FILE IS INVALID - File may have been tampered with")
        except FileNotFoundError:
            print("FILE INTEGRITY UNKNOWN - Hash file not found")
        except Exception as e:
            print(f"FILE INTEGRITY UNKNOWN - Error during verification: {str(e)}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Decrypt a file using hybrid encryption')
    parser.add_argument('--receiver_private_key', required=True, help='Receiver private key file')
    parser.add_argument('--encrypted_key', required=True, help='Encrypted symmetric key file')
    parser.add_argument('--input_file', required=True, help='Input encrypted file')
    parser.add_argument('--output_decrypted_file', required=True, help='Output decrypted file')
    parser.add_argument('--sender_pub_key', help='Sender public key for integrity verification (optional)')
    args = parser.parse_args()
    
    decrypt_file(args.receiver_private_key, args.encrypted_key, args.input_file,
                args.output_decrypted_file, args.sender_pub_key)