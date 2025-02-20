import random
import string
from sympy import mod_inverse

# Function to compute the greatest common divisor (GCD)
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


# Function to check if a number is prime
def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0:
            return False
    return True

# Function to generate a prime number
def generate_prime(bits=8):
    while True:
        num = random.randint(2**(bits-1), 2**bits - 1)
        if is_prime(num):
            return num

# Function to generate RSA key pair
def generate_keys():
    p = generate_prime(8)  
    q = generate_prime(8)

    while p == q:  
        q = generate_prime(8)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = random.randrange(2, phi)
    while gcd(e, phi) != 1:  
        e = random.randrange(2, phi)

    d = mod_inverse(e, phi)

    return ((e, n), (d, n))  

# Encoding dictionary (mapped alphabet, num to dict)
ALPHABET = {char: f"{i:02}" for i, char in enumerate(string.ascii_uppercase)} # Alphabet to 0-25
ALPHABET.update({str(i): f"{i+26:02}" for i in range(10)})  # Numbers 0-9 mapped to 26-36
ALPHABET[" "] = "36"  # mapped space to 36

# Reverse mapping for decryption
REVERSE_ALPHABET = {v: k for k, v in ALPHABET.items()}


def text_to_numeric_encoding(text):
    return "".join(ALPHABET[char] for char in text.upper() if char in ALPHABET)

def split_numeric_value(numeric_string, chunk_size=4):
    """Split numeric string into fixed-size chunks, padding with space if needed."""
    if len(numeric_string) % 4 != 0:
        numeric_string += "36"  # Append space padding if the length isn't a multiple of 4
    return [numeric_string[i:i+chunk_size].zfill(4) for i in range(0, len(numeric_string), chunk_size)]

def numeric_to_text(numeric_string):
    """Convert decrypted numeric values back to text, handling padding issues."""
    numeric_string = numeric_string.zfill(4)  # Ensure proper padding
    try:
        return "".join(REVERSE_ALPHABET[numeric_string[i:i+2]] for i in range(0, len(numeric_string), 2))
    except KeyError:
        return "?"  # Fallback for bit out of 'ALPHABET' range

def encrypt_numeric(numbers, key):
    e, n = key
    return [pow(int(num), e, n) for num in numbers]

def decrypt_numeric(numbers, key):
    d, n = key
    return [f"{pow(num, d, n):04}" for num in numbers]  

def introduce_bit_error(ciphertext, error_rate=0.1):
    """Introduce bit errors into the ciphertext."""
    corrupted_cipher = []
    
    for num in ciphertext:
        binary = f"{num:016b}"  # Convert to 16-bit binary
        binary_list = list(binary)

        # Flip bits randomly based on error rate
        for i in range(len(binary_list)):
            if random.random() < error_rate:
                binary_list[i] = '1' if binary_list[i] == '0' else '0'

        # Convert back to integer
        corrupted_num = int("".join(binary_list), 2)
        corrupted_cipher.append(corrupted_num)

    return corrupted_cipher

def compare_decryption(original, corrupted):
    """Compare original decrypted text with corrupted decrypted text."""
    differences = sum(1 for o, c in zip(original, corrupted) if o != c)
    return differences, (differences / len(original)) * 100


# Generate RSA keys
public_key, private_key = generate_keys()
print(f"Public Key: {public_key}")
print(f"Private Key: {private_key}")

# Encrypt a message

#plaintext = "THIS IS A TESTTTT1234asas" 
plaintext = input("Enter Plaintext: ")
encoded_text = text_to_numeric_encoding(plaintext)
split_list = split_numeric_value(encoded_text)

print(split_list)

encrypted_message = encrypt_numeric(split_list, public_key)
print(f"Encrypted: {encrypted_message}")

# Decrypt the message
decrypted_numbers = decrypt_numeric(encrypted_message, private_key)
decrypted_text = "".join(numeric_to_text(num) for num in decrypted_numbers)

print(f"Decrypted: {decrypted_text}")
print(f"Decrypted num: {decrypted_numbers}")

#print(ALPHABET)


# Introduce bit errors
corrupted_ciphertext = introduce_bit_error(encrypted_message, error_rate=0.1)
decrypted_corrupted_numbers = decrypt_numeric(corrupted_ciphertext, private_key)
decrypted_corrupted_text = "".join(numeric_to_text(num) for num in decrypted_corrupted_numbers)

# Compare results
bit_errors, error_percentage = compare_decryption(decrypted_text, decrypted_corrupted_text)


print(f"Corrupted Encrypted: {corrupted_ciphertext}")
print(f"Decrypted (with bit errors): {decrypted_corrupted_text}")
print(f"Number of altered characters: {bit_errors}")
print(f"Error percentage: {error_percentage:.2f}%")
