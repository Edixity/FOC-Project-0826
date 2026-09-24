"""
A2 - Block cipher: AES-256 in GCM mode (library implementation).

Interface (shared with the rest of the group / benchmark):
    generate_key() -> bytes
    encrypt(key, data) -> bytes      # returns nonce + ciphertext + auth tag
    decrypt(key, blob) -> bytes      # raises InvalidTag if the data was changed or key is wrong

Install:  pip install cryptography

"""
#Import statements
#----------------------------------------------------------------------------------------------#
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag



#function definition
#---------------------------------------------------------------------------------------------#
#nonce meaning the random number that is used once
NONCE_SIZE = 12  

def generate_key() -> bytes:
    #creates a random 256-bit secret key
    return AESGCM.generate_key(bit_length=256)


def encrypt(key: bytes, data: bytes) -> bytes:
    #  new random nonce everytime 
    nonce = os.urandom(NONCE_SIZE)
    # result = nonce + encrypted data + auth tag
    return nonce + AESGCM(key).encrypt(nonce, data, None)


def decrypt(key: bytes, blob: bytes) -> bytes:
    # first 12 bytes are the nonce, the rest is the ciphertext
    nonce, ciphertext = blob[:NONCE_SIZE], blob[NONCE_SIZE:]
    # raises Invalid Tag if the key is wrong or data was changed
    return AESGCM(key).decrypt(nonce, ciphertext, None)

def run_tests(key, message, blob):
    # test 1: decrypt gives back the original message
    assert decrypt(key, blob) == message
    print("[PASS] decrypt(encrypt(m)) == m")
 
    # test 2: works for different sizes
    for size in (0, 1, 15, 16, 17, 1024, 1024 * 1024):
        m = os.urandom(size)
        assert decrypt(key, encrypt(key, m)) == m
    print("[PASS] sizes 0, 1, 15, 16, 17 bytes, 1 KB, 1 MB")
 
    # test 3: same message gives different ciphertext each time
    assert encrypt(key, message) != encrypt(key, message)
    print("[PASS] same message encrypts differently each time (random nonce)")
 
    # test 4: wrong key is rejected
    try:
        decrypt(generate_key(), blob)
        print("[FAIL] wrong key accepted")
    except InvalidTag:
        print("[PASS] wrong key rejected")
 
    # test 5: changed data is rejected
    tampered = bytearray(blob)
    tampered[-1] ^= 1  # flip one bit
    try:
        decrypt(key, bytes(tampered))
        print("[FAIL] tampering not detected")
    except InvalidTag:
        print("[PASS] tampered ciphertext rejected (authentication tag)")

#main program
#-------------------------------------------------------------------------------------------------#
if __name__ == "__main__":
    key = generate_key()
    message = b"UPTM SANGAT AMAZING WOOOOOOOOOOOOO"
    blob = encrypt(key, message)

    #show output
    print("Key (hex)        :", key.hex())
    print("Plaintext        :", message)
    print("Ciphertext (hex) :", blob.hex())
    print("Decrypted        :", decrypt(key, blob))

    #TEST 1: Decrypt gives back the orignal message
    assert decrypt(key, blob) == message
    print("[PASS] decrypt(encrypt(m)) == m")

    #TEST 2: test to see if it works for different sizes
    for size in (0, 1, 15, 16, 17, 1024, 1024 * 1024):   
        m = os.urandom(size)
        assert decrypt(key, encrypt(key, m)) == m
    print("[PASS] sizes 0, 1, 15, 16, 17 bytes, 1 KB, 1 MB")

    #TEST 3: same message gives different cypher text each time
    assert encrypt(key, message) != encrypt(key, message)
    print("[PASS] same message encrypts differently each time (random nonce)")


    #TEST 4: wrng key is rejected
    try:
        decrypt(generate_key(), blob); print("[FAIL] wrong key accepted")
    except InvalidTag:
        print("[PASS] wrong key rejected")

    #TEST 5: changed data is rejected
    tampered = bytearray(blob); tampered[-1] ^= 1
    try:
        decrypt(key, bytes(tampered)); print("[FAIL] tampering not detected")
    except InvalidTag:
        print("[PASS] tampered ciphertext rejected (authentication tag)")
#-------------------------------------------------------------------------------------#

#Prompt
if __name__ == "__main__":
    key = generate_key()
    print("AES-256-GCM demo")
    print("Key (hex):", key.hex())
 
    while True:
        # ask the user for a message
        text = input("\nType a message to encrypt (or q to quit): ")
        if text.lower() == "q":
            break
        message = text.encode()
 
        # encrypt, then decrypt it back
        blob = encrypt(key, message)
        print("Plaintext        :", message)
        print("Ciphertext (hex) :", blob.hex())
        print("Decrypted        :", decrypt(key, blob))
 
        # optional: run the tests on this message
        if input("Run the tests? (y/n): ").lower() == "y":
            run_tests(key, message, blob)



# ---------------------------------------------------------------
# NOTES: where this code comes from (references)
# ---------------------------------------------------------------
# Code pattern (AESGCM, generate_key, encrypt, decrypt, InvalidTag, 12-byte nonce):
#   Python Cryptographic Authority. "Authenticated encryption" (AESGCM).
#   Cryptography documentation.
#   https://cryptography.io/en/latest/hazmat/primitives/aead/
#
# Random nonce with os.urandom (use the OS random generator, not the random module):
#   Python Cryptographic Authority. "Random number generation".
#   Cryptography documentation.
#   https://cryptography.io/en/latest/random-numbers.html
#
# About GCM mode (authenticated encryption, 96-bit nonce, auth tag):
#   Dworkin, M. (2007). Recommendation for Block Cipher Modes of Operation:
#   Galois/Counter Mode (GCM) and GMAC. NIST Special Publication 800-38D.
#   https://doi.org/10.6028/NIST.SP.800-38D
#
# Our own work: putting the nonce in front of the ciphertext (nonce + ciphertext + tag)
# and the 5 tests in the main program.
#
# (All links accessed 24 September 2026)