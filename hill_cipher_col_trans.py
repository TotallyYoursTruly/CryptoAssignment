import numpy as np
import string

def text_to_numbers(text):
    return [string.ascii_uppercase.index(char) for char in text]

def numbers_to_text(numbers):
    return ''.join(string.ascii_uppercase[num] for num in numbers)

def pad_text(text, size=3, pad_char='X'):
    while len(text) % size != 0:
        text += pad_char
    return text

def generate_column_order(key_word):
    sorted_key = sorted(list(enumerate(key_word)), key=lambda x: x[1])
    return [i for i, _ in sorted_key]

def encrypt_hill(plaintext, key_matrix):
    plaintext = plaintext.upper().replace(" ", "")
    plaintext = pad_text(plaintext, size=3)
    
    plaintext_numbers = text_to_numbers(plaintext)
    
    key_matrix = np.array(key_matrix)
    ciphertext_numbers = []
    
    for i in range(0, len(plaintext_numbers), 3):
        block = np.array(plaintext_numbers[i:i+3]).reshape(3, 1)
        encrypted_block = np.dot(key_matrix, block) % 26
        ciphertext_numbers.extend(encrypted_block.flatten())
    
    return numbers_to_text(ciphertext_numbers)

def decrypt_hill(ciphertext, key_matrix):
    key_matrix = np.array(key_matrix)
    determinant = int(np.round(np.linalg.det(key_matrix)))
    determinant_inverse = pow(determinant, -1, 26)
    key_inverse = (determinant_inverse * np.round(determinant * np.linalg.inv(key_matrix)).astype(int)) % 26
    
    ciphertext_numbers = text_to_numbers(ciphertext)
    plaintext_numbers = []
    
    for i in range(0, len(ciphertext_numbers), 3):
        block = np.array(ciphertext_numbers[i:i+3]).reshape(3, 1)
        decrypted_block = np.dot(key_inverse, block) % 26
        plaintext_numbers.extend(decrypted_block.flatten())
    
    return numbers_to_text(plaintext_numbers)

def columnar_transposition_encrypt(text, key_word):
    key_order = generate_column_order(key_word)
    num_cols = len(key_word)
    num_rows = -(-len(text) // num_cols)  # Ceiling division
    
    matrix = [['X'] * num_cols for _ in range(num_rows)]
    
    index = 0
    for r in range(num_rows):
        for c in range(num_cols):
            if index < len(text):
                matrix[r][c] = text[index]
                index += 1
    
    ciphertext = "".join("".join(row[c] for row in matrix) for c in key_order)
    return ciphertext



def columnar_transposition_decrypt(ciphertext, key_word):
    key_order = generate_column_order(key_word)
    num_cols = len(key_word)
    num_rows = -(-len(ciphertext) // num_cols)  # Ceiling division
    
    matrix = [[''] * num_cols for _ in range(num_rows)]
    
    index = 0
    for col in sorted(range(num_cols), key=lambda k: key_order[k]):  # Sort to read correctly
        for row in range(num_rows):
            if index < len(ciphertext):
                matrix[row][col] = ciphertext[index]
                index += 1
    
    plaintext = "".join("".join(row) for row in matrix).rstrip('X')
    return plaintext


# Example Usage
key_matrix = [[6, 24, 1], [13, 16, 10], [20, 17, 15]]
transposition_key = "HILL"
plaintext = "HELLOHILL"

hill_ciphertext = encrypt_hill(plaintext, key_matrix)
final_ciphertext = columnar_transposition_encrypt(hill_ciphertext, transposition_key)

decrypted_transposed = columnar_transposition_decrypt(final_ciphertext, transposition_key)
decrypted_text = decrypt_hill(decrypted_transposed, key_matrix)

print(f"Plaintext: {plaintext}")
print(f"Hill Ciphertext: {hill_ciphertext}")
print(f"Final Ciphertext (After Transposition): {final_ciphertext}")
print(f"Decrypted Transposition: {decrypted_transposed}")
print(f"Decrypted: {decrypted_text}")