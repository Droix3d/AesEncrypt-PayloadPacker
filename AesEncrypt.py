from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import sys

if len(sys.argv) < 2:
    print("Uso: python3 aestiny.py <archivo>")
    print("Ejemplo: python3 aestiny.py beacon.bin")
    sys.exit(1)

input_file = sys.argv[1]
output_file = input_file.replace(".bin", "_encrypted.bin")


key = get_random_bytes(32)  # AES-256 = 32 bytes
iv = get_random_bytes(16)   # IV = 16 bytes


print(f"[*] Leyendo: {input_file}")
with open(input_file, "rb") as f:
    plaintext = f.read()

print(f"[*] Tamaño original: {len(plaintext)} bytes")

# AES-256-CBC
print("[*] Encriptando...")
cipher = AES.new(key, AES.MODE_CBC, iv)
padded_plaintext = pad(plaintext, AES.block_size, style='pkcs7')
ciphertext = cipher.encrypt(padded_plaintext)

# Save File
print(f"[*] Guardando: {output_file}")
with open(output_file, "wb") as f:
    f.write(ciphertext)

# Print format -> C
print("\n[+] KEY (32 bytes):")
print("BYTE pKey[32] = {")
for i in range(0, len(key), 16):
    chunk = key[i:i+16]
    print("    " + ", ".join(f"0x{b:02X}" for b in chunk) + ",")
print("};")

print("\n[+] IV (16 bytes):")
print("BYTE pIv[16] = {")
for i in range(0, len(iv), 16):
    chunk = iv[i:i+16]
    print("    " + ", ".join(f"0x{b:02X}" for b in chunk) + ",")
print("};")

print(f"\n[+] Encrypted size: {len(ciphertext)} bytes")
print(f"[+] File saved: {output_file}")
