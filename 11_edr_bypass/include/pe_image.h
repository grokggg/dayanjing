#ifndef PE_IMAGE_H
#define PE_IMAGE_H

#include <stddef.h>
#include <stdint.h>

#pragma pack(push, 1)

struct pe_dos_hdr {
    uint16_t e_magic;
    uint8_t  _pad0[58];
    uint32_t e_lfanew;
};

struct pe_file_hdr {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

struct pe_data_dir {
    uint32_t VirtualAddress;
    uint32_t Size;
};

struct pe_opt_hdr {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOSVersion;
    uint16_t MinorOSVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;           /* @96  */
    uint32_t LoaderFlags;                /* @104 */
    uint32_t NumberOfRvaAndSizes;        /* @108 */
    struct pe_data_dir DataDirectory[16]; /* @112, 16*8 = 128B -> ends @240 */
};

_Static_assert(sizeof(struct pe_opt_hdr) == 240,
               "PE64 OptionalHeader must be exactly 240 bytes");
_Static_assert(offsetof(struct pe_opt_hdr, DataDirectory) == 112,
               "DataDirectory must start at offset 112");
_Static_assert(offsetof(struct pe_opt_hdr, DataDirectory[16]) == 240,
               "DataDirectory[16] must end at offset 240 (== sizeof)");

/*
 * 关键不变量：
 *   1)  sizeof(struct pe_opt_hdr) == 240，DataDirectory[16] 必须内联在结构体内。
 *       曾把 DataDirectory 写在结构体之外，导致 sizeof == 112，解析时 section
 *       表被错位读取，PE 解析返回 -9、解析出 -9 条 Zw 函数。
 *   2)  内存布局（mock 测试 test_direct_syscall.c）：
 *        0x000  DOS header (e_lfanew @ 0x3C = 0x80)
 *        0x080  "PE\0\0" signature
 *        0x084  FileHeader (20 bytes)                     -> ends 0x098
 *        0x098  OptionalHeader (240 bytes)                -> ends 0x188
 *        0x188  Section table (1 section, 40 bytes)      -> ends 0x1B0
 *        0x1B0  Export Directory / .text raw data
 */

struct pe_sec_hdr {
    char    Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};

struct pe_export_dir {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint32_t Name;
    uint32_t Base;
    uint32_t NumberOfFunctions;
    uint32_t NumberOfNames;
    uint32_t AddressOfFunctions;
    uint32_t AddressOfNames;
    uint32_t AddressOfNameOrdinals;
};

#pragma pack(pop)

#define PE_SIGNATURE     0x00004550U
#define PE_MAGIC_32PLUS  0x020B
#define PE_MACHINE_AMD64 0x8664

uint32_t pe_rva_to_fileoff(uint32_t rva,
                           const struct pe_sec_hdr *secs,
                           uint16_t nsec,
                           size_t fsize);

#endif
