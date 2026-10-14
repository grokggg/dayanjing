#!/usr/bin/env python3
"""
build_real_pe.py
================
构造 PE32+ DLL（AMD64）用于验证 direct_syscall.c 的解析逻辑。

设计：
  - 单一 bytearray 缓冲 `buf`，所有内容按**绝对文件偏移**写入
  - 最后 buf = buf[:filesize] 截断写出
  - 导出函数含：4 个 Zw+ 真实函数 + 1 个 Nt+ 别名 + 1 个前向导出
  - 每个 Zw+ 函数体：B8 SSN 90 C3

用法：
  python3 build_real_pe.py out.dll
"""
import sys, struct

# ---- 节表布局 (name, RVA, PointerToRawData, VirtualSize) ----
SECTIONS = [
    (".text",   0x1000, 0x1000, 0x0200),
    (".rdata",  0x2000, 0x0400, 0x0800),
    (".data",   0x3000, 0x0800, 0x0400),
]
# 节起始文件偏移（按 PointerToRawData 升序）
SEC_FILE_OFF = {".text": 0x1000, ".rdata": 0x0400, ".data": 0x0800}

def r2f(rva):
    """RVA -> 文件偏移"""
    for name, va, raw, vsz in SECTIONS:
        if va <= rva < va + vsz:
            return raw + (rva - va)
    raise SystemExit(f"RVA {rva:#x} 不在任何节内")

# ---- 导出函数 (name, ordinal, ssn, is_forward) ----
EXPORTS = [
    ("ZwQuerySystemInformation",   1, 0x36, False),
    ("ZwOpenProcess",              2, 0x26, False),
    ("ZwClose",                    3, 0x0F, False),
    ("ZwAllocateVirtualMemory",    4, 0x18, False),
    ("NtQuerySystemInformation",   5, 0x36, False),   # 别名，应被去重跳过
    ("ZwForwarder",                6, 0x00, True),    # 前向导出，应被跳过
]
BASE = 1

# ---- RVA 预留（必须互不重叠）----
# 导出目录 40 字节：0x2000 - 0x2027
# AddressOfFunctions (6*4=24)：0x2030 - 0x2047
# AddressOfNames    (5*4=20)：0x2050 - 0x2063
# AddressOfNameOrdinals (5*2=10)：0x2070 - 0x2079
# 函数名（最长 24 字节 + \0）：0x2080 起
# Forwarder 字符串：0x2100 起
# DLL 名：0x2120 起
RVA_ED   = 0x2000   # 导出目录 (40 bytes, ends at 0x2027)
RVA_AF   = 0x2030   # AddressOfFunctions (24 bytes, ends at 0x2047)
RVA_AN   = 0x2050   # AddressOfNames (20 bytes, ends at 0x2063)
RVA_AO   = 0x2070   # AddressOfNameOrdinals (10 bytes, ends at 0x2079)
RVA_NM   = 0x2080   # 函数名起始
RVA_FWD  = 0x2100   # forwarder 字符串
RVA_DLL  = 0x2120   # DLL 名

def main():
    buf = bytearray(0x4000)

    def w(off, b):
        buf[off:off+len(b)] = b

    # ===== 头部 =====
    # DOS
    struct.pack_into("<H", buf, 0x00, 0x5A4D)          # e_magic
    struct.pack_into("<I", buf, 0x3C, 0x40)            # e_lfanew
    # NT 签名
    w(0x40, b"PE\0\0")
    # FILE_HEADER
    struct.pack_into("<H", buf, 0x44, 0x8664)          # Machine
    struct.pack_into("<H", buf, 0x46, 3)               # NumberOfSections
    struct.pack_into("<I", buf, 0x48, 0x12345678)     # TimeDateStamp
    struct.pack_into("<I", buf, 0x4C, 0)              # PointerToSymbolTable
    struct.pack_into("<I", buf, 0x50, 0)              # NumberOfSymbols
    struct.pack_into("<H", buf, 0x54, 112 + 16*8)     # SizeOfOptionalHeader
    struct.pack_into("<H", buf, 0x56, 0x0022)          # Characteristics

    # OPTIONAL_HEADER64
    o = 0x58
    struct.pack_into("<H", buf, o+0,  0x20B)           # Magic
    struct.pack_into("<B", buf, o+2,  14)              # MajorLinkerVersion
    struct.pack_into("<B", buf, o+3,  0)
    struct.pack_into("<I", buf, o+4,  0x0200)          # SizeOfCode
    struct.pack_into("<I", buf, o+8,  0x0800)          # SizeOfInitializedData
    struct.pack_into("<I", buf, o+12, 0)               # SizeOfUninitializedData
    struct.pack_into("<I", buf, o+16, 0x1000)         # AddressOfEntryPoint
    struct.pack_into("<I", buf, o+20, 0x1000)         # BaseOfCode
    struct.pack_into("<Q", buf, o+24, 0x180000000)    # ImageBase
    struct.pack_into("<I", buf, o+32, 0x1000)         # SectionAlignment
    struct.pack_into("<I", buf, o+36, 0x0200)         # FileAlignment
    struct.pack_into("<H", buf, o+40, 10)             # MajorOSVersion
    struct.pack_into("<H", buf, o+42, 0)
    struct.pack_into("<H", buf, o+44, 0)
    struct.pack_into("<H", buf, o+46, 0)
    struct.pack_into("<H", buf, o+48, 10)             # MajorSubsystemVersion
    struct.pack_into("<H", buf, o+50, 0)
    struct.pack_into("<I", buf, o+52, 0)              # Win32VersionValue
    struct.pack_into("<I", buf, o+56, 0x5000)         # SizeOfImage
    struct.pack_into("<I", buf, o+60, 0x0400)         # SizeOfHeaders
    struct.pack_into("<I", buf, o+64, 0)              # CheckSum
    struct.pack_into("<H", buf, o+68, 3)              # Subsystem
    struct.pack_into("<H", buf, o+70, 0x0100)         # DllCharacteristics
    struct.pack_into("<Q", buf, o+72, 0x40000)        # SizeOfStackReserve
    struct.pack_into("<Q", buf, o+80, 0x4000)         # SizeOfStackCommit
    struct.pack_into("<Q", buf, o+88, 0x100000)       # SizeOfHeapReserve
    struct.pack_into("<Q", buf, o+96, 0x1000)         # SizeOfHeapCommit
    struct.pack_into("<I", buf, o+104, 0)             # LoaderFlags
    struct.pack_into("<I", buf, o+108, 16)            # NumberOfRvaAndSizes
    assert o + 112 == 0x58 + 112 == 0xC8              # 数据目录起始 = 0xC8

    # 数据目录（16 项）
    dd = 0xC8
    struct.pack_into("<I", buf, dd+0,  RVA_ED)        # 导出表 RVA
    struct.pack_into("<I", buf, dd+4,  40)            # 导出表 Size
    for i in range(1, 16):
        struct.pack_into("<I", buf, dd+i*8,   0)
        struct.pack_into("<I", buf, dd+i*8+4, 0)

    # 节表（3 项）
    st = dd + 16*8
    for i, (name, va, raw, vsz) in enumerate(SECTIONS):
        s = st + i*40
        w(s, name.encode().ljust(8, b"\x00"))
        struct.pack_into("<I", buf, s+8,  vsz)
        struct.pack_into("<I", buf, s+12, va)
        actual = {".text":0x200,".rdata":0x800,".data":0x400}[name.strip('\x00')]
        struct.pack_into("<I", buf, s+16, actual)
        struct.pack_into("<I", buf, s+20, raw)
        struct.pack_into("<I", buf, s+24, 0)
        struct.pack_into("<I", buf, s+28, 0)
        struct.pack_into("<H", buf, s+32, 0)
        struct.pack_into("<H", buf, s+34, 0)
        if name.strip() == ".text":
            ch = 0x60000020
        elif name.strip() == ".data":
            ch = 0xC0000040
        else:
            ch = 0x40000040
        struct.pack_into("<I", buf, s+36, ch)

    # ===== 函数体（.text 节，RVA 0x1000 起）=====
    code_rva = {}
    cursor = 0x1000
    for name, ord_, ssn, fwd in EXPORTS:
        if fwd:
            continue
        code_rva[name] = cursor
        off = r2f(cursor)
        struct.pack_into("<B",  buf, off,   0xB8)
        struct.pack_into("<I",  buf, off+1, ssn)
        struct.pack_into("<B",  buf, off+5, 0x90)
        struct.pack_into("<B",  buf, off+6, 0xC3)
        cursor += 7

    # ===== 导出表（.rdata 节）=====
    # 导出目录
    ed = r2f(RVA_ED)
    struct.pack_into("<I", buf, ed+0,  0)
    struct.pack_into("<I", buf, ed+4,  0x12345678)
    struct.pack_into("<H", buf, ed+8,  0)
    struct.pack_into("<H", buf, ed+10, 0)
    struct.pack_into("<I", buf, ed+12, RVA_DLL)
    struct.pack_into("<I", buf, ed+16, BASE)
    struct.pack_into("<I", buf, ed+20, len(EXPORTS))
    struct.pack_into("<I", buf, ed+24, len([e for e in EXPORTS if not e[3]]))
    struct.pack_into("<I", buf, ed+28, RVA_AF)
    struct.pack_into("<I", buf, ed+32, RVA_AN)
    struct.pack_into("<I", buf, ed+36, RVA_AO)

    # 名称字符串 RVA 计算（按字典序）
    name_sorted = sorted([e[0] for e in EXPORTS if not e[3]], key=str.lower)
    name_rva = {}
    nc = RVA_NM
    for n in name_sorted:
        name_rva[n] = nc
        nc += len(n) + 1

    # AddressOfFunctions
    af = r2f(RVA_AF)
    for name, ord_, ssn, fwd in EXPORTS:
        if fwd:
            struct.pack_into("<I", buf, af, RVA_FWD)
        else:
            struct.pack_into("<I", buf, af, code_rva[name])
        af += 4

    # AddressOfNames
    an = r2f(RVA_AN)
    for n in name_sorted:
        struct.pack_into("<I", buf, an, name_rva[n])
        an += 4

    # AddressOfNameOrdinals
    ao = r2f(RVA_AO)
    for n in name_sorted:
        idx = [i for i, e in enumerate(EXPORTS) if e[0] == n][0]
        struct.pack_into("<H", buf, ao, idx)
        ao += 2

    # DLL 名
    w(r2f(RVA_DLL), b"test_ntdll.dll\0")
    # 函数名
    for n in name_sorted:
        w(r2f(name_rva[n]), n.encode() + b"\0")
    # Forwarder 字符串
    w(r2f(RVA_FWD), b"NTDLL.OtherFunc\0")

    # ===== 调试：追踪导出目录区域 =====
    print(f"  [DEBUG] ed={r2f(RVA_ED):#x} buf[ed+28:ed+40] = {buf[r2f(RVA_ED)+28:r2f(RVA_ED)+40].hex()}")

    # ===== 写出 =====
    filesize = 0x4000
    with open(sys.argv[1] if len(sys.argv) > 1 else "/tmp/test_ntdll.dll", "wb") as fp:
        fp.write(buf[:filesize])

    print(f"[+] PE32+ DLL 已生成")
    print(f"    头部大小 = {st + 120 - 0x40} 字节 (DOS+NT+Optional+DataDir+3节表)")
    print(f"    OptionalHeader 到数据目录 = 112 字节")
    print(f"    预期解析结果（Zw+ 真实函数，跳过 Nt 别名与前向导出）:")
    for name, ord_, ssn, fwd in EXPORTS:
        if fwd or name.startswith("Nt"):
            continue
        exp_ord = ord_ - 1 + BASE
        print(f"      {name:32s} ordinal={exp_ord:2d}  SSN={ssn:#04x}")
    print(f"    预期条数 = 4")

if __name__ == "__main__":
    main()
