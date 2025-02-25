import argparse
import os
from des_test import DES, CBC, PAD_PKCS5

class TripleDES:
    def __init__(self, key, IV=None, pad=None, padmode=PAD_PKCS5):
        if len(key) not in [16, 24]:
            raise ValueError("Invalid 3DES key size. Must be 16 or 24 bytes long.")

        self.IV = IV if IV else os.urandom(8)  # Generate random IV if not provided
        self.key1 = DES(key[:8], CBC, self.IV, pad, padmode)  # First 8 bytes (K1)
        self.key2 = DES(key[8:16], CBC, self.IV, pad, padmode)  # Second 8 bytes (K2)
        self.key3 = DES(key[:8] if len(key) == 16 else key[16:], CBC, self.IV, pad, padmode)  # K3 = K1 (if 16-byte key) or last 8 bytes (if 24-byte key)

    def encrypt(self, data):
        data = self.key1.encrypt(data)
        data = self.key2.decrypt(data)
        return self.key3.encrypt(data)

    def decrypt(self, data):
        data = self.key3.decrypt(data)
        data = self.key2.encrypt(data)
        return self.key1.decrypt(data)

def main():
    parser = argparse.ArgumentParser(description="Triple DES encryption and decryption CLI tool (CBC mode only).")
    parser.add_argument("mode", choices=["encrypt", "decrypt"], help="Mode of operation")
    parser.add_argument("key", type=str, help="Encryption key (16 or 24 bytes in hex)")
    parser.add_argument("data", type=str, help="Data to encrypt (plain text) or decrypt (hex format)")
    parser.add_argument("--iv", type=str, help="Initialization Vector (IV) in hex (required for decryption)")
    
    args = parser.parse_args()
    
    try:
        key = bytes.fromhex(args.key)
        if len(key) not in [16, 24]:
            raise ValueError("Invalid 3DES key size. Must be 16 or 24 bytes long.")
    except ValueError as e:
        print(f"Error: {e}")
        return

    IV = bytes.fromhex(args.iv) if args.iv else None  # Convert IV from hex if provided

    tdes = TripleDES(key, IV=IV)

    if args.mode == "encrypt":
        print("Plaintext: ", args.data)
        data = args.data.encode()  # Convert plaintext to bytes
        print("Plaintext (Hex): ", data.hex())
        encrypted = tdes.encrypt(data)
        print("Encrypted (Hex):", encrypted.hex())
        print("IV (Hex):", tdes.IV.hex())  # Display IV for CBC mode encryption

    else:  # Decrypt mode
        if not args.iv:
            print("Error: IV must be provided in hex for CBC decryption.")
            return
        
        try:
            data = bytes.fromhex(args.data)  # Convert hex to bytes
        except ValueError:
            print("Error: Invalid ciphertext format. Must be in hex.")
            return

        decrypted = tdes.decrypt(data)
        try:
            print("Decrypted (Text):", decrypted.decode())  # Convert bytes back to string
        except UnicodeDecodeError:
            print("Decrypted (Raw Bytes):", decrypted.hex())  # If not valid UTF-8, show raw bytes

if __name__ == "__main__":
    main()
