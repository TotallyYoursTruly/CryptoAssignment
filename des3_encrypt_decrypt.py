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
