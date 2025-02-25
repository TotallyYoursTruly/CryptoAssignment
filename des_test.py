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
        blocks = [data[i:i+self.block_size] for i in range(0, len(data), self.block_size)]
        encrypted_blocks = []
        prev_cipher = self.IV

        for block in blocks:
            if self.mode == CBC:
                block = bytes(a ^ b for a, b in zip(block, prev_cipher))
            encrypted_block = block[::-1]  # Placeholder for real DES encryption
            encrypted_blocks.append(encrypted_block)
            prev_cipher = encrypted_block

        return b"".join(encrypted_blocks)

    def decrypt(self, data):
        blocks = [data[i:i+self.block_size] for i in range(0, len(data), self.block_size)]
        decrypted_blocks = []
        prev_cipher = self.IV

        for block in blocks:
            decrypted_block = block[::-1]  # Placeholder for real DES decryption
            if self.mode == CBC:
                decrypted_block = bytes(a ^ b for a, b in zip(decrypted_block, prev_cipher))
            decrypted_blocks.append(decrypted_block)
            prev_cipher = block

        decrypted_data = b"".join(decrypted_blocks)
        return self._unpadData(decrypted_data)
