CLASSICAL CIPHERS:

plaintext -> hill cipher (encrypt) -> columnar transposition (encrypt) -> ciphertext 

ciphertext -> columnar transposition (decrypt) -> hill cipher (decrypt) -> plaintext


implementation only mapped A-Z (lowercase will be converted to uppercases), not including 1-0 and such
hill ciphers implementation requires multiple of 3 bytes (3 character) to encrypt, if plaintext % 3 > 0, padding x will be added

example (with 3 characters) (space will be ignored):

enter plaintext:  hello hill

transpos key: HILL
Plaintext: hello hill
Hill Ciphertext: TFJTVRLAS
Final Ciphertext (After Transposition): TVSFRXJLXTAX
Decrypted Transposition: TFJTVRLAS
Decrypted: HELLOHILL

example (not multiple of 3 characters):

enter plaintext:  hello hil

transpos key: HILL
Plaintext: hello hil
Hill Ciphertext: TFJTVRXQQ
Final Ciphertext (After Transposition): TVQFRXJXXTQX
Decrypted Transposition: TFJTVRXQQ
Decrypted: HELLOHILX




MODERN CIPHERS (HYBRID):
3des_test1.py (triple DES implementation) requires des_test.py (base DES implementation) to run.

assume interaction between ALICE and BOB

BOB had a text encrypted with 3DES (CBC) sent by ALICE, but only ALICE had the key and the iv to decrypt sent text. 

Sending the key via unsecured channel were risky, so they both agrees to use RSA:

BOB generate key pair, gives his public key to ALICE, ALICE encrypts the key with BOB's public key and send the encrypted key to BOB via unsecured channel, BOB decrypts the key with his private key, and gain the key & iv to the original ALICE's encrypted text



example:

3DES side

3DES requires key to be in 16 or 24 bytes (16 bytes will be 2-key, 24 bytes will be 3-key)
ALICE encrypts text 'hello bob'
the key were in hex '0123456789abcdef0123456789abcdeffedcba9876543210' , 2 hex = 1 byte, so 32 hex = 16 bytes
as it was CBC mode, iv were required, but in this case, iv will be generated randomly

calling des3_test1.py in terminal:

syntax: des3_test1.py [encrypt | decrypt] [key] [data] [--iv for decrypt] [iv]

des3_test1.py encrypt 0123456789abcdef0123456789abcdeffedcba9876543210 "hello bob"

output of the program:
Plaintext:  hello bob
Plaintext (Hex):  68656c6c6f20626f62
Encrypted (Hex): f6185b9d937b24d1d6237c949a5c1f94
IV (Hex): b94117fff27b7a99

ALICE sent the ciphertext to BOB : f6185b9d937b24d1d6237c949a5c1f94, the key and IV will be used later in RSA


RSA side

BOB wants the key & iv to the ciphertext, so BOB generates key pair to be used in RSA

Public Key: (41221, 46367)
Private Key: (13357, 46367)

BOB sent the public key to ALICE
ALICE send the key and iv to BOB encrypted with BOB's public key 
the plaintext in RSA will be converted to numeral, 

Alphabet 'A-Z' to 0-25
Number '0-9' mapped to 26-36
Space to 37

the encrypt operation will be then performed on the numerals

calling rsa_encrypt_decrypt.py in terminal:
Enter Plaintext:  key 0123456789abcdef0123456789abcdeffedcba9876543210 iv b94117fff27b7a99

plaintext converted to numeral: ['1004', '2436', '2627', '2829', '3031', '3233', '3435', '0001', '0203', '0405', '2627', '2829', '3031', '3233', '3435', '0001', '0203', '0405', '0504', '0302', '0100', '3534', '3332', '3130', '2928', '2726', '3608', '2136', '0135', '3027', '2733', '0505', '0528', '3301', '3300', '3535']
Encrypted numeral: [6727, 27766, 43645, 23326, 12251, 9158, 33987, 1, 23355, 44777, 43645, 23326, 12251, 9158, 33987, 1, 23355, 44777, 38314, 42450, 40528, 31735, 27340, 39216, 10646, 1319, 26338, 17755, 25747, 28524, 45416, 16823, 13104, 34997, 801, 9766]

the ciphertext (Encrypted numeral) of the RSA will be sent to BOB by ALICE
BOB will decrypt the ciphertext using his private key

Private Key: (13357, 46367) -> Encrypted numeral = Decrypted numeral
Decrypted numeral: ['1004', '2436', '2627', '2829', '3031', '3233', '3435', '0001', '0203', '0405', '2627', '2829', '3031', '3233', '3435', '0001', '0203', '0405', '0504', '0302', '0100', '3534', '3332', '3130', '2928', '2726', '3608', '2136', '0135', '3027', '2733', '0505', '0528', '3301', '3300', '3535']
convert Decrypted numeral to plaintext
Decrypted: KEY 0123456789ABCDEF0123456789ABCDEFFEDCBA9876543210 IV B94117FFF27B7A99

3DES side (decrypt)

BOB will use the key and iv that he gets from RSA earlier to decrypt the 3des-encrypted ciphertext

calling des3_test1.py

syntax: des3_test1.py [decrypt] [key] [ciphertext] [--iv] [iv]

des3_test1.py decrypt 0123456789abcdef0123456789abcdeffedcba9876543210 f6185b9d937b24d1d6237c949a5c1f94 --iv b94117fff27b7a99

output: 

Decrypted (Text): hello bob
            
