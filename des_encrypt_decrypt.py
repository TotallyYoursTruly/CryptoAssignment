import sys

# Modes of encryption
ECB = 0
CBC = 1

# Padding modes
PAD_NORMAL = 1
PAD_PKCS5 = 2

class DES:
    def __init__(self, key, mode=ECB, IV=None, pad=None, padmode=PAD_NORMAL):
        if len(key) != 8:
            raise ValueError("Invalid DES key size. Key must be exactly 8 bytes long.")
        self.block_size = 8
        self.key = key
        self.mode = mode
        self.IV = IV if IV else b"\0" * self.block_size
        self.pad = pad
        self.padmode = padmode

    def _padData(self, data):
        if self.padmode == PAD_NORMAL:
            pad_len = self.block_size - (len(data) % self.block_size)
            if self.pad:
                return data + (pad_len * self.pad)
            else:
                raise ValueError("Data must be a multiple of 8 bytes. Provide a padding character.")
        elif self.padmode == PAD_PKCS5:
            pad_len = self.block_size - (len(data) % self.block_size)
            return data + bytes([pad_len] * pad_len)
        return data

    def _unpadData(self, data):
        if self.padmode == PAD_PKCS5:
            pad_len = data[-1]
            return data[:-pad_len]
        return data.rstrip(self.pad) if self.pad else data

    def encrypt(self, data):
        data = self._padData(data)
        return data[::-1]  # Placeholder for real DES encryption

    def decrypt(self, data):
        decrypted_data = data[::-1]  # Placeholder for real DES decryption
        return self._unpadData(decrypted_data)
