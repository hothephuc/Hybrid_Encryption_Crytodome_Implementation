from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import argparse

def generate_rsa_keypair(bits=2048, prefix='receiver'):
    """Generate RSA key pair and save to files with given prefix."""
    # Generate key pair
    key = RSA.generate(bits)
    
    # Save private key
    with open(f'{prefix}_private_key.key', 'wb') as f:
        f.write(key.export_key('PEM'))
    
    # Save public key
    with open(f'{prefix}_pub_key.pub', 'wb') as f:
        f.write(key.publickey().export_key('PEM'))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Generate RSA key pairs')
    parser.add_argument('--bits', type=int, default=2048, help='Key size in bits')
    parser.add_argument('--generate_sender_keys', action='store_true', 
                        help='Generate keys for sender (for integrity verification)')
    args = parser.parse_args()
    
    # Generate receiver keys
    generate_rsa_keypair(args.bits, 'receiver')
    print("Generated receiver keys: receiver_pub_key.pub, receiver_private_key.key")
    
    # Generate sender keys if requested
    if args.generate_sender_keys:
        generate_rsa_keypair(args.bits, 'sender')
        print("Generated sender keys: sender_pub_key.pub, sender_private_key.key")
