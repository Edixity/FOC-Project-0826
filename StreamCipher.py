import random

# Key Generation (128-bit / 16-byte key)
def generate_key(length=16):
    return [random.randint(0, 255) for _ in range(length)]

# Simplified RC4 Keystream Generator
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

# XOR Encryption / Decryption Mechanism
def xor_cipher(data, keystream):
    return [d ^ k for d, k in zip(data, keystream)]

# Main Execution Flow
if __name__ == "__main__":
    message = input("Enter your message: ")
    plaintext = [ord(c) for c in message]
    
    key = generate_key(16)
    keystream = rc4_keystream(key, len(plaintext))
    
    ciphertext = xor_cipher(plaintext, keystream)
    decrypted = xor_cipher(ciphertext, keystream)
    decrypted_message = "".join(chr(c) for c in decrypted)
    
    print("\n--- Stream Cipher Demo ---")
    print("Original Message :", message)
    print("Ciphertext (Hex) :", [hex(x) for x in ciphertext])
    print("Decrypted Message:", decrypted_message)
