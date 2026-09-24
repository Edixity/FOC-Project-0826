# B - Performance test for the ciphers (works for any cipher with the shared interface)
# Each cipher file must have: generate_key(), encrypt(key, data), decrypt(key, blob)
# Run: python b_benchmark.py

import os
import time
import csv
import statistics
import importlib

# ---- 1. which ciphers to test (name shown in results, file name without .py) ----
CIPHERS = [
    ("AES-256-GCM", "aes_cipher"),
]

# ---- 2. settings ----
SIZES = [1024, 100 * 1024, 1024 * 1024]  # bytes: 1 KB, 100 KB, 1 MB
REPEATS = 7  # run each test this many times, then take the median


def label(size):
    # turn bytes into a readable name like 1 KB or 10 MB
    if size >= 1024 * 1024:
        return f"{size // (1024 * 1024)} MB"
    return f"{size // 1024} KB"


def time_it(func):
    # run func once and return how many seconds it took
    start = time.perf_counter()
    func()
    return time.perf_counter() - start


def measure(func):
    # warm-up run (not counted), then REPEATS timed runs, return the median
    func()
    times = [time_it(func) for _ in range(REPEATS)]
    return statistics.median(times)


def test_cipher(name, module):
    key = module.generate_key()
    rows = []
    for size in SIZES:
        data = os.urandom(size)
        blob = module.encrypt(key, data)

        # check it is correct before timing it
        assert module.decrypt(key, blob) == data

        enc_time = measure(lambda: module.encrypt(key, data))
        dec_time = measure(lambda: module.decrypt(key, blob))
        mb = size / (1024 * 1024)

        rows.append({
            "cipher": name,
            "size": label(size),
            "enc_ms": enc_time * 1000,
            "dec_ms": dec_time * 1000,
            "enc_MBps": mb / enc_time,
            "dec_MBps": mb / dec_time,
            "overhead_bytes": len(blob) - size,  # extra bytes added (nonce, tag, padding)
        })
    # also time key generation
    key_time = measure(module.generate_key)
    return rows, key_time


if __name__ == "__main__":
    all_rows = []

    for name, module_name in CIPHERS:
        # skip a cipher if its file is not found
        try:
            module = importlib.import_module(module_name)
        except ModuleNotFoundError:
            print(f"[SKIP] {name}: file '{module_name}.py' not found")
            continue

        print(f"\nTesting {name} ...")
        rows, key_time = test_cipher(name, module)
        all_rows.extend(rows)

        # print a table for this cipher
        print(f"{'Size':<8}{'Encrypt ms':>12}{'Decrypt ms':>12}"
              f"{'Enc MB/s':>11}{'Dec MB/s':>11}{'Overhead':>10}")
        for r in rows:
            print(f"{r['size']:<8}{r['enc_ms']:>12.3f}{r['dec_ms']:>12.3f}"
                  f"{r['enc_MBps']:>11.1f}{r['dec_MBps']:>11.1f}{r['overhead_bytes']:>9}B")
        print(f"Key generation: {key_time * 1000:.4f} ms")

    # save everything to a CSV file (open it in Excel to make charts for the report)
    if all_rows:
        with open("benchmark_results.csv", "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=all_rows[0].keys())
            writer.writeheader()
            writer.writerows(all_rows)
        print("\nSaved results to benchmark_results.csv")