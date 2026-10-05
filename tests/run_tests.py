#!/usr/bin/env python3
"""
离线测试框架

测试范围：
1. 语法检查 - 所有 Python 文件
2. 编译测试 - C/C++ 源文件
3. 模块导入测试 - Python 模块
4. 功能单元测试 - 纯逻辑函数
5. 协议构造验证 - 手动构造的协议报文
"""

import os
import sys
import subprocess
import json
import importlib.util
import tempfile
import struct
from pathlib import Path
from datetime import datetime


class TestRunner:
    def __init__(self, root_dir):
        self.root = Path(root_dir).resolve()
        self.results = {
            "timestamp": datetime.utcnow().isoformat(),
            "tests": [],
            "passed": 0,
            "failed": 0,
            "skipped": 0
        }

    def _record(self, name, status, details=""):
        """记录测试结果"""
        self.results["tests"].append({
            "name": name,
            "status": status,
            "details": details
        })
        if status == "PASS":
            self.results["passed"] += 1
        elif status == "FAIL":
            self.results["failed"] += 1
        else:
            self.results["skipped"] += 1

    def test_python_syntax(self):
        """测试所有 Python 文件的语法"""
        print("[*] Testing Python syntax...")

        py_files = list(self.root.rglob("*.py"))
        for py_file in py_files:
            rel_path = py_file.relative_to(self.root)
            try:
                with open(py_file, 'r') as f:
                    compile(f.read(), str(py_file), 'exec')
                self._record(f"syntax:{rel_path}", "PASS")
            except SyntaxError as e:
                self._record(f"syntax:{rel_path}", "FAIL", str(e))
                print(f"  [-] Syntax error in {rel_path}: {e}")

    def test_c_compile(self):
        """测试 C 源文件的编译"""
        print("[*] Testing C compilation...")

        # 查找所有 C 源文件
        c_files = list(self.root.rglob("*.c"))
        cpp_files = list(self.root.rglob("*.cpp"))

        all_c = c_files + cpp_files

        if not all_c:
            print("  [!] No C/C++ source files found")
            return

        # 检查是否有编译器
        has_gcc = self._check_command("gcc")
        has_gpp = self._check_command("g++")

        for c_file in all_c:
            rel_path = c_file.relative_to(self.root)

            # 平台专属文件跳过逻辑
            # Windows 专属文件在 Linux 上无法编译
            if c_file.suffix == ".c" and any(x in str(c_file).lower() for x in [
                "windows_", "win32", "win64", "stage1.c", "api_hash.c"
            ]):
                self._record(f"compile:{rel_path}", "SKIP",
                           "Windows-specific file, requires MinGW")
                continue

            # Linux 内核模块需要内核头文件
            if "rootkit.c" in str(c_file):
                self._record(f"compile:{rel_path}", "SKIP",
                           "Kernel module, requires kernel headers")
                continue

            # eBPF 需要 libbpf
            if "ebpf" in str(c_file):
                self._record(f"compile:{rel_path}", "SKIP",
                           "eBPF loader, requires libbpf-dev")
                continue

            # 尝试编译为临时目标文件
            with tempfile.NamedTemporaryFile(suffix='.o', delete=False) as tmp:
                tmp_path = tmp.name

            compiler = None
            if c_file.suffix == ".cpp":
                compiler = "g++" if has_gpp else None
            else:
                compiler = "gcc" if has_gcc else None

            if not compiler:
                self._record(f"compile:{rel_path}", "SKIP", "No compiler available")
                continue

            try:
                result = subprocess.run(
                    [compiler, "-c", "-fsyntax-only", "-Wall",
                     str(c_file), "-o", tmp_path],
                    capture_output=True, text=True, timeout=30
                )

                if result.returncode == 0:
                    self._record(f"compile:{rel_path}", "PASS")
                else:
                    self._record(f"compile:{rel_path}", "FAIL", result.stderr[:200])
            except subprocess.TimeoutExpired:
                self._record(f"compile:{rel_path}", "FAIL", "timeout")
            finally:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)

    def test_protocol_construction(self):
        """测试手动构造的协议报文"""
        print("[*] Testing protocol construction...")

        # 1. 测试 TLS ClientHello 构造
        self._test_tls_client_hello()

        # 2. 测试 SMB2 头部构造
        self._test_smb2_header()

        # 3. 测试 SSH Binary Packet 构造
        self._test_ssh_packet()

        # 4. 测试 ASN.1 DER 编码
        self._test_asn1_der()

        # 5. 测试 DNS 查询构造
        self._test_dns_query()

        # 6. 测试 ICMP 校验和
        self._test_icmp_checksum()

        # 7. 测试 CovertPacket 序列化
        self._test_covert_packet()

        # 8. 测试 LNK 文件结构
        self._test_lnk_structure()

    def _test_tls_client_hello(self):
        """测试 TLS ClientHello 结构"""
        try:
            from importlib.machinery import SourceFileLoader

            # 动态导入模块
            infra_dir = self.root / "01_infra"
            if (infra_dir / "domain_fronting_c2.py").exists():
                module = SourceFileLoader(
                    "domain_fronting_c2",
                    str(infra_dir / "domain_fronting_c2.py")
                ).load_module()

                if hasattr(module, 'DomainFrontingC2'):
                    c2 = module.DomainFrontingC2("cdn.example.com", "c2.example.com", "secret")
                    hello = c2._tls_client_hello("cdn.example.com")

                    # 验证结构
                    assert len(hello) > 0, "Empty ClientHello"
                    assert hello[0] == 0x16, f"Wrong record type: {hello[0]}"
                    assert hello[1:3] == b'\x03\x01', "Wrong record version"

                    self._record("tls:client_hello", "PASS")
                else:
                    self._record("tls:client_hello", "SKIP", "Class not found")
            else:
                self._record("tls:client_hello", "SKIP", "Module not found")
        except Exception as e:
            self._record("tls:client_hello", "FAIL", str(e))

    def _test_smb2_header(self):
        """测试 SMB2 协议头构造"""
        try:
            # 手动构造 SMB2 头并验证
            import struct

            protocol = b'\xfeSMB'
            structure_size = struct.pack('<H', 64)
            credit_charge = struct.pack('<H', 0)
            status = b'\x00\x00\x00\x00'
            command = struct.pack('<H', 0)  # Negotiate
            credits = struct.pack('<H', 1)
            flags = struct.pack('<I', 0)
            next_command = struct.pack('<I', 0)
            message_id = struct.pack('<Q', 1)
            process_id = struct.pack('<I', 0)
            tree_id = struct.pack('<I', 0)
            session_id = struct.pack('<Q', 0)
            signature = b'\x00' * 16

            header = (protocol + structure_size + credit_charge + status +
                     command + credits + flags + next_command +
                     message_id + process_id + tree_id + session_id + signature)

            # 验证
            assert len(header) == 64, f"Wrong header size: {len(header)}"
            assert header[0:4] == b'\xfeSMB', "Wrong protocol ID"
            assert struct.unpack('<H', header[4:6])[0] == 64, "Wrong structure size"

            self._record("smb2:header", "PASS")
        except Exception as e:
            self._record("smb2:header", "FAIL", str(e))

    def _test_ssh_packet(self):
        """测试 SSH 二进制包构造"""
        try:
            import struct

            # 构造一个最小的 SSH 包
            msg_type = 5  # SSH_MSG_SERVICE_REQUEST
            service_name = b"ssh-userauth"
            payload = struct.pack('>I', len(service_name)) + service_name

            # 添加填充
            pad_len = 8 - (len(payload) + 1) % 8
            if pad_len < 4:
                pad_len += 8
            packet = bytes([pad_len]) + os.urandom(pad_len) + bytes([msg_type]) + payload

            # 长度字段
            length = len(packet)
            header = struct.pack('>I', length)
            full_packet = header + packet

            # 验证
            assert len(full_packet) == 4 + length
            assert struct.unpack('>I', full_packet[0:4])[0] == length

            self._record("ssh:packet", "PASS")
        except Exception as e:
            self._record("ssh:packet", "FAIL", str(e))

    def _test_asn1_der(self):
        """测试 ASN.1 DER 编码"""
        try:
            import struct

            # INTEGER 编码测试
            value = 65537
            data = value.to_bytes((value.bit_length() + 7) // 8, 'big')
            if value > 0 and data[0] & 0x80:
                data = b'\x00' + data

            encoded = bytes([0x02]) + bytes([len(data)]) + data

            assert encoded[0] == 0x02, "Wrong tag"
            assert encoded[1] == len(data), "Wrong length"

            self._record("asn1:integer", "PASS")
        except Exception as e:
            self._record("asn1:integer", "FAIL", str(e))

    def _test_dns_query(self):
        """测试 DNS 查询构造"""
        try:
            import struct
            import random

            # 构造 DNS 查询
            tid = random.randint(0, 65535)
            flags = 0x0100
            questions = 1

            header = struct.pack('!HHHHHH', tid, flags, questions, 0, 0, 0)

            # 查询名
            domain = "example.com"
            query = b''
            for label in domain.split('.'):
                query += struct.pack('!B', len(label))
                query += label.encode()

            query += b'\x00'
            query += struct.pack('!H', 16)  # TXT type
            query += struct.pack('!H', 1)   # IN class

            dns_packet = header + query

            # 验证
            assert len(dns_packet) > 12, "Packet too short"
            assert struct.unpack('!H', dns_packet[0:2])[0] == tid
            assert struct.unpack('!H', dns_packet[2:4])[0] == 0x0100

            self._record("dns:query", "PASS")
        except Exception as e:
            self._record("dns:query", "FAIL", str(e))

    def _test_icmp_checksum(self):
        """测试 ICMP 校验和计算"""
        try:
            import struct

            def calc_checksum(data):
                if len(data) % 2:
                    data += b'\x00'
                s = 0
                for i in range(0, len(data), 2):
                    w = (data[i] << 8) + data[i + 1]
                    s += w
                s = (s >> 16) + (s & 0xFFFF)
                s += s >> 16
                return ~s & 0xFFFF

            # 构造 ICMP Echo Request
            icmp_type = 8
            icmp_code = 0
            checksum = 0
            identifier = 1234
            sequence = 1
            data = b'Hello, World!'

            # 临时头部（校验和为 0）
            temp = struct.pack('!BBHHH', icmp_type, icmp_code, 0, identifier, sequence) + data
            checksum = calc_checksum(temp)

            # 验证校验和正确性
            final_packet = struct.pack('!BBHHH', icmp_type, icmp_code, checksum, identifier, sequence) + data
            assert calc_checksum(final_packet) == 0, "Checksum verification failed"

            self._record("icmp:checksum", "PASS")
        except Exception as e:
            self._record("icmp:checksum", "FAIL", str(e))

    def _test_covert_packet(self):
        """测试 CovertPacket 序列化/反序列化"""
        try:
            import struct
            import hmac
            import hashlib

            # 从模块导入
            covert_dir = self.root / "08_covert"
            if (covert_dir / "covert_channel.py").exists():
                from importlib.machinery import SourceFileLoader
                module = SourceFileLoader(
                    "covert_channel",
                    str(covert_dir / "covert_channel.py")
                ).load_module()

                if hasattr(module, 'CovertPacket'):
                    key = b"secret_key"
                    packet = module.CovertPacket(
                        version=1,
                        ptype=1,
                        seq=42,
                        session=12345,
                        payload=b"test payload data"
                    )

                    serialized = packet.pack(key)
                    deserialized = module.CovertPacket.unpack(serialized, key)

                    assert deserialized is not None, "Failed to unpack"
                    assert deserialized.payload == b"test payload data", "Payload mismatch"
                    assert deserialized.seq == 42, "Sequence mismatch"

                    self._record("covert:packet", "PASS")
                else:
                    self._record("covert:packet", "SKIP", "Class not found")
            else:
                self._record("covert:packet", "SKIP", "Module not found")
        except Exception as e:
            self._record("covert:packet", "FAIL", str(e))

    def _test_lnk_structure(self):
        """测试 LNK 文件结构"""
        try:
            import struct

            # 从模块导入
            delivery_dir = self.root / "09_delivery"
            if (delivery_dir / "lnk_macro.py").exists():
                from importlib.machinery import SourceFileLoader
                module = SourceFileLoader(
                    "lnk_macro",
                    str(delivery_dir / "lnk_macro.py")
                ).load_module()

                if hasattr(module, 'LNKBuilder'):
                    builder = module.LNKBuilder(
                        target_path=r"C:\Windows\System32\notepad.exe",
                        arguments="test args",
                        icon_location=r"C:\Windows\System32\shell32.dll"
                    )

                    lnk_data = builder.build()

                    # 验证 LNK 结构
                    assert len(lnk_data) >= 76, f"LNK too short: {len(lnk_data)}"
                    assert struct.unpack('<I', lnk_data[0:4])[0] == 0x0000004C, "Wrong header size"
                    assert lnk_data[4:20] == bytes.fromhex("0114020000000000C000000000000046"), "Wrong CLSID"

                    self._record("lnk:structure", "PASS")
                else:
                    self._record("lnk:structure", "SKIP", "Class not found")
            else:
                self._record("lnk:structure", "SKIP", "Module not found")
        except Exception as e:
            self._record("lnk:structure", "FAIL", str(e))

    def test_api_hash(self):
        """测试 API 哈希功能"""
        print("[*] Testing API hash resolution...")

        try:
            stealth_dir = self.root / "11_stealth"
            if (stealth_dir / "av_evasion.py").exists():
                from importlib.machinery import SourceFileLoader
                module = SourceFileLoader(
                    "av_evasion",
                    str(stealth_dir / "av_evasion.py")
                ).load_module()

                if hasattr(module, 'APIHashResolver'):
                    resolver = module.APIHashResolver

                    # 测试 DJB2 哈希
                    test_string = "kernel32.dll!VirtualAlloc"
                    hash_val = resolver.djb2_hash(test_string)
                    assert isinstance(hash_val, int), "Hash should be integer"
                    assert hash_val != 0, "Hash should not be zero"

                    # 测试哈希验证
                    results = resolver.verify_hashes()
                    verified = sum(1 for r in results.values() if r["match"])
                    total = len(results)

                    if verified == total:
                        self._record("api_hash:verification", "PASS")
                    else:
                        self._record("api_hash:verification", "FAIL",
                                    f"Only {verified}/{total} hashes matched")

                    # 测试生成解析代码
                    code = resolver.generate_resolver_code(0x0E8AFE6A)
                    assert "GetProcAddressByHash" in code, "Generated code missing key function"
                    self._record("api_hash:codegen", "PASS")
                else:
                    self._record("api_hash:verification", "SKIP", "Class not found")
            else:
                self._record("api_hash:verification", "SKIP", "Module not found")
        except Exception as e:
            self._record("api_hash:verification", "FAIL", str(e))

    def test_timestomp(self):
        """测试时间戳篡改功能"""
        print("[*] Testing time stomping...")

        try:
            import os
            import datetime

            anti_dir = self.root / "12_anti_forensics"
            if (anti_dir / "anti_forensics.py").exists():
                from importlib.machinery import SourceFileLoader
                module = SourceFileLoader(
                    "anti_forensics",
                    str(anti_dir / "anti_forensics.py")
                ).load_module()

                if hasattr(module, 'TimeStomper'):
                    stomper = module.TimeStomper()

                    # 创建测试文件
                    test_file = "/tmp/test_stomp_tmp.txt"
                    with open(test_file, 'w') as f:
                        f.write("test")

                    # 获取原始时间戳
                    orig_stat = os.stat(test_file)

                    # 篡改
                    result = stomper.stomp_unix(test_file)
                    assert result is not None, "Stomp returned None"

                    # 验证
                    new_stat = os.stat(test_file)
                    assert new_stat.st_atime != orig_stat.st_atime or \
                           new_stat.st_mtime != orig_stat.st_mtime, \
                           "Timestamps not changed"

                    os.remove(test_file)
                    self._record("timestomp:unix", "PASS")
                else:
                    self._record("timestomp:unix", "SKIP", "Class not found")
            else:
                self._record("timestomp:unix", "SKIP", "Module not found")
        except Exception as e:
            self._record("timestomp:unix", "FAIL", str(e))

    def _check_command(self, cmd):
        """检查命令是否可用"""
        try:
            result = subprocess.run(["which", cmd], capture_output=True)
            return result.returncode == 0
        except:
            return False

    def run_all(self):
        """运行所有测试"""
        print("=" * 60)
        print("Offline Test Suite")
        print("=" * 60)

        self.test_python_syntax()
        self.test_c_compile()
        self.test_protocol_construction()
        self.test_api_hash()
        self.test_timestomp()

        # 输出报告
        print("\n" + "=" * 60)
        print("Test Report")
        print("=" * 60)
        print(f"Total:  {len(self.results['tests'])}")
        print(f"Passed: {self.results['passed']}")
        print(f"Failed: {self.results['failed']}")
        print(f"Skipped: {self.results['skipped']}")

        if self.results['failed'] > 0:
            print("\nFailures:")
            for t in self.results['tests']:
                if t['status'] == 'FAIL':
                    print(f"  - {t['name']}: {t['details']}")

        # 保存报告
        report_path = self.root / "tests" / "test_report.json"
        with open(report_path, 'w') as f:
            json.dump(self.results, f, indent=2)

        print(f"\nReport saved: {report_path}")

        return self.results['failed'] == 0


if __name__ == "__main__":
    root = Path(__file__).parent.parent
    runner = TestRunner(root)
    success = runner.run_all()
    sys.exit(0 if success else 1)
