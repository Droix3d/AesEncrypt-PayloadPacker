# AesEncrypt-PayloadPacker

A lightweight C and Python project demonstrating secure payload transport, **AES-256-CBC runtime decryption via native Windows CNG (Cryptography Next Generation)**, and safe in-memory execution using advanced memory protections (`NoRWX` style transition).

---

## Features

* **HTTPS Secure Retrieval:** Downloads encrypted raw data dynamically from a remote endpoint using native Windows WinINet/WinHTTP APIs.
* **Native Cryptographic API:** Leverages Windows CNG (`bcrypt.dll`) dynamically to perform AES-256-CBC decryption without relying on external, signature-heavy cryptographic libraries.
* **Runtime Memory Management:** Allocates, decrypts, and executes payloads safely directly within dynamic heap memory utilizing Windows API memory protections (`VirtualAlloc` / `VirtualProtect`).

---

## Technical Overview: Decryption Mechanism (`DecryptAES`)

The decryption core utilizes dynamic API resolution to load cryptographic services and process buffers securely:

* **Dynamic API Resolution:** Resolves essential functions from `bcrypt.dll` at runtime via `LoadLibraryA` and `GetProcAddress` to minimize static imports and avoid standard cryptographic signatures.
* **Provider & Key Context Initialization:** Opens the AES algorithm provider using `BCryptOpenAlgorithmProvider`, configures the chaining mode to CBC (`BCRYPT_CHAIN_MODE_CBC`), and generates the symmetric key object using a $32$-byte key.
* **Two-Pass Decryption Routine:** Executes `BCryptDecrypt` on the ciphertext twice—the first pass automatically computes the exact required plaintext size (`cbPlainText`) handling PKCS#7 block padding, and the second pass executes the actual decryption into a fresh heap buffer.
* **Cleanup & Validation:** Destroys key handles, closes algorithm providers, and returns the verified clean plaintext pointer along with its net size for execution.

---
