# AesEncrypt-PayloadPacker

A lightweight C and Python project demonstrating secure payload transport, AES-256-CBC decryption at runtime using a minimal cryptographic library (`tiny-aes`), and in-memory execution.

---

## Features

* **HTTPS Secure Retrieval:** Downloads encrypted raw data dynamically from a remote endpoint using native Windows WinINet/WinHTTP APIs.
* **Lightweight Cryptography:** Implements AES-256 in Cipher Block Chaining (CBC) mode using an optimized, header-only implementation (`aes.h`).
* **Runtime Memory Management:** Allocates, decrypts, and executes payloads safely directly within dynamic heap memory utilizing Windows API memory protections (`VirtualAlloc` / `VirtualProtect`).

---

## Technical Overview: Decryption Mechanism (`AesTinyDecrypt`)

The decryption core handles runtime buffer processing through the following implementation steps:

* **Validation & Alignment Check:** Verifies that all pointers, parameters, keys, and Initialization Vector (IV) structures are present, and ensures the ciphertext size is a strict multiple of the AES block size ($16$ bytes).
* **Buffer Allocation & Copy:** Allocates a dynamic heap buffer matching the ciphertext size and duplicates the encrypted payload data into it.
* **Context Initialization & Decryption:** Initializes the AES context structure (`AES_ctx`) using a $32$-byte key and a $16$-byte IV via `AES_init_ctx_iv`, executing in-place buffer decryption via `AES_CBC_decrypt_buffer`.
* **Padding Strip & Final Size Calculation:** Reads the final byte of the decrypted stream to determine padding length (`bPadLen`), validates it, and resolves the true unpadded plaintext size before returning the clean payload pointer for execution.

---

