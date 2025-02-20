import argparse
from des_encrypt_decrypt import DES, ECB, CBC, PAD_PKCS5

class TripleDES:
    def __init__(self, key, mode=ECB, IV=None, pad=None, padmode=PAD_PKCS5):
        if len(key) not in [16, 24]:
            raise ValueError("Invalid 3DES key size. Must be 16 or 24 bytes long.")
        
        self.key1 = DES(key[:8], mode, IV, pad, padmode)
        self.key2 = DES(key[8:16], mode, IV, pad, padmode)
        self.key3 = DES(key[:8] if len(key) == 16 else key[16:], mode, IV, pad, padmode)

    def encrypt(self, data):
        data = self.key1.encrypt(data)
        data = self.key2.decrypt(data)
        return self.key3.encrypt(data)

    def decrypt(self, data):
        data = self.key3.decrypt(data)
        data = self.key2.encrypt(data)
        return self.key1.decrypt(data)

def main():
    parser = argparse.ArgumentParser(description="Triple DES encryption and decryption CLI tool.")
    parser.add_argument("mode", choices=["encrypt", "decrypt"], help="Mode of operation")
    parser.add_argument("key", type=str, help="Encryption key (16 or 24 bytes in hex)")
    parser.add_argument("data", type=str, help="Data to encrypt/decrypt (hex format)")
    parser.add_argument("--cbc", action="store_true", help="Use CBC mode instead of ECB")
    
    args = parser.parse_args()
    key = bytes.fromhex(args.key)
    data = bytes.fromhex(args.data)
    mode = CBC if args.cbc else ECB
    
    tdes = TripleDES(key, mode=mode)
    
    if args.mode == "encrypt":
        result = tdes.encrypt(data)
        print("Encrypted:", result.hex())
    else:
        result = tdes.decrypt(data)
        print("Decrypted:", result.hex())

if __name__ == "__main__":
    main()
