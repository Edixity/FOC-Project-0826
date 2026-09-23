import random

# Key generation
def generate_key(length=16):
    return [random.randint(0, 255) for _ in range(length)]

# RC4-like keystream generator
def rc4_keystream(key, n):
    S = list(range(256))
    j = 0
    # Key Scheduling Algorithm (KSA)
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    # Pseudo-Random Generation Algorithm (PRGA)
    i = j = 0
    keystream = []
    for _ in range(n):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        keystream.append(S[(S[i] + S[j]) % 256])
    return keystream

# XOR encryption/decryption
def xor_cipher(data, keystream):
    return [d ^ k for d, k in zip(data, keystream)]

# --- Main Program ---
# User enters message
message = input("Enter your message: ")

# Convert message to ASCII values
plaintext = [ord(c) for c in message]

# Generate key and keystream
key = generate_key()
keystream = rc4_keystream(key, len(plaintext))

# Encrypt
ciphertext = xor_cipher(plaintext, keystream)

# Decrypt
decrypted = xor_cipher(ciphertext, keystream)
decrypted_message = ''.join(chr(c) for c in decrypted)

# Display results
print("\n--- Stream Cipher Demo ---")
print("Original Message:", message)
print("Ciphertext (numeric):", ciphertext)
print("Decrypted Message:", decrypted_message)
