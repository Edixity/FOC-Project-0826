import os
import random
import time

# ==========================================
# PART A1: SIMPLIFIED RC4 STREAM CIPHER
# ==========================================

def generate_rc4_key(length=16):
    """Generates a random 128-bit (16-byte) key."""
    return [random.randint(0, 255) for _ in range(length)]

def rc4_keystream(key, n):
    """Key Scheduling Algorithm (KSA) and Pseudo-Random Generation Algorithm (PRGA)."""
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
    return bytes(keystream)

def rc4_process(key, data):
    """Performs XOR operation between byte data and generated keystream."""
    keystream = rc4_keystream(key, len(data))
    return bytes([d ^ k for d, k in zip(data, keystream)])


# ==========================================
# PERFORMANCE TESTING (STREAM CIPHER ONLY)
# ==========================================

def benchmark_stream_cipher(file_label, data, key):
    """Measures encryption and decryption runtime for RC4 in milliseconds."""
    # Measure Encryption Time
    start_enc = time.perf_counter()
    encrypted = rc4_process(key, data)
    end_enc = time.perf_counter()
    
    # Measure Decryption Time
    start_dec = time.perf_counter()
    decrypted = rc4_process(key, encrypted)
    end_dec = time.perf_counter()

    # Convert seconds to milliseconds
    enc_time_ms = (end_enc - start_enc) * 1000
    dec_time_ms = (end_dec - start_dec) * 1000

    # Verification check to confirm correctness
    assert decrypted == data, f"Decryption failed for {file_label}!"

    print(f"RC4   | {file_label:<10} | Encrypt: {enc_time_ms:10.4f} ms | Decrypt: {dec_time_ms:10.4f} ms")


if __name__ == "__main__":
    # Create test datasets as required in Part B1
    file_1kb = os.urandom(1024)                 # 1 KB file
    file_100kb = os.urandom(100 * 1024)         # 100 KB file
    file_1mb = os.urandom(1024 * 1024)          # 1 MB file

    # Generate 128-bit secret key
    rc4_key = generate_rc4_key(16)

    print("=" * 65)
    print("      STREAM CIPHER (RC4) PERFORMANCE TESTING")
    print("=" * 65)

    # Benchmark each file size
    benchmark_stream_cipher("1 KB File", file_1kb, rc4_key)
    benchmark_stream_cipher("100 KB File", file_100kb, rc4_key)
    benchmark_stream_cipher("1 MB File", file_1mb, rc4_key)

    print("=" * 65)
