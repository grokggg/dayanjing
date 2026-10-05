#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模块 02: 侦察层 —— 原始套接字 TCP SYN 扫描 + JA3 指纹

第一性原理实现:
    - 手工构造 IP 头与 TCP 头，绕过内核 TCP 栈，实现真正的半连接扫描
    - 手工解析 ClientHello 字节流，计算 JA3 指纹 (MD5)

依赖: 仅标准库 + 原始套接字权限 (Linux 需 CAP_NET_RAW / root)
"""

import socket
import struct
import time
import random
import os
import threading
from concurrent.futures import ThreadPoolExecutor


# ============================ SYN 扫描器 ============================ #
class RawSYNScanner:
    """从零构造 IP/TCP 头，发送 SYN 并依据回包判断端口状态。"""

    def __init__(self, source_ip: str, source_port: int = None):
        self.src_ip = source_ip
        self.src_port = source_port or random.randint(1024, 65535)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        self.sock.setblocking(False)
        self.open_ports = []
        self._lock = threading.Lock()

    @staticmethod
    def _checksum(data: bytes) -> int:
        """Internet Checksum (RFC 1071)。"""
        if len(data) % 2:
            data += b'\x00'
        s = sum((data[i] << 8) + data[i + 1] for i in range(0, len(data), 2))
        while s >> 16:
            s = (s & 0xFFFF) + (s >> 16)
        return (~s) & 0xFFFF

    def _ip_header(self, dst_ip: str, tcp_len: int) -> bytes:
        ver_ihl = (4 << 4) | 5
        total_len = 20 + tcp_len
        ip = struct.pack('!BBHHHBBH4s4s',
                         ver_ihl, 0, total_len, random.randint(0, 65535),
                         0x4000, 64, socket.IPPROTO_TCP, 0,
                         socket.inet_aton(self.src_ip), socket.inet_aton(dst_ip))
        csum = self._checksum(ip)
        return struct.pack('!BBHHHBBH4s4s',
                           ver_ihl, 0, total_len, random.randint(0, 65535),
                           0x4000, 64, socket.IPPROTO_TCP, csum,
                           socket.inet_aton(self.src_ip), socket.inet_aton(dst_ip))

    def _tcp_header(self, dst_ip: str, dst_port: int, seq: int, flags: int) -> bytes:
        pseudo = socket.inet_aton(self.src_ip) + socket.inet_aton(dst_ip) + \
                 b'\x00' + b'\x06' + struct.pack('!H', 20)
        tcp = struct.pack('!HHIIBBHHH',
                          self.src_port, dst_port, seq, 0, (5 << 4), flags,
                          65535, 0, 0)
        csum = self._checksum(pseudo + tcp)
        return struct.pack('!HHIIBBHHH',
                           self.src_port, dst_port, seq, 0, (5 << 4), flags,
                           65535, csum, 0)

    def scan(self, dst_ip: str, dst_port: int, timeout: float = 2.0) -> str:
        """扫描单端口。返回 'open' / 'closed' / 'filtered'。"""
        seq = random.randint(0, 0xFFFFFFFF)
        tcp = self._tcp_header(dst_ip, dst_port, seq, 0x02)   # SYN
        ip = self._ip_header(dst_ip, len(tcp))
        self.sock.sendto(ip + tcp, (dst_ip, dst_port))

        start = time.time()
        while time.time() - start < timeout:
            try:
                pkt = self.sock.recv(1024)
            except BlockingIOError:
                continue
            ihl = (pkt[0] & 0x0F) * 4
            tcp_data = pkt[ihl:]
            src_p, dst_p, s, a, off_flags = struct.unpack('!HHIIH', tcp_data[:14])
            if dst_p != self.src_port:
                continue
            flags = off_flags & 0x1FF
            if flags & 0x12 == 0x12:                         # SYN+ACK
                # 回 RST 结束半连接
                self._send_rst(dst_ip, dst_port, a, seq + 1)
                with self._lock:
                    self.open_ports.append((dst_ip, dst_port))
                return 'open'
            if flags & 0x04:
                return 'closed'
        return 'filtered'

    def _send_rst(self, dst_ip, dst_port, seq, ack):
        tcp = self._tcp_header(dst_ip, dst_port, seq, 0x04)
        self.sock.sendto(self._ip_header(dst_ip, len(tcp)) + tcp, (dst_ip, dst_port))

    def scan_range(self, dst_ip: str, ports, workers: int = 500):
        with ThreadPoolExecutor(max_workers=workers) as ex:
            list(ex.map(lambda p: self.scan(dst_ip, p), ports))
        return self.open_ports

    def close(self):
        self.sock.close()


# ============================ JA3 指纹 ============================ #
class JA3:
    """手工解析 ClientHello 并计算 JA3 (MD5)。"""

    @staticmethod
    def fingerprint(hello: bytes):
        p = 5 + 4                                   # 跳过 record + handshake header
        p += 2                                      # version
        p += 32                                     # random
        sid_len = hello[p]; p += 1 + sid_len
        cs_len = struct.unpack('!H', hello[p:p + 2])[0]; p += 2
        ciphers = []
        for i in range(0, cs_len, 2):
            ciphers.append(str(struct.unpack('!H', hello[p + i:p + i + 2])[0]))
        p += cs_len
        co_len = hello[p]; p += 1 + co_len
        ext_len = struct.unpack('!H', hello[p:p + 2])[0]; p += 2
        exts, curves, fmts = [], [], []
        end = p + ext_len
        while p < end:
            t = struct.unpack('!H', hello[p:p + 2])[0]; p += 2
            el = struct.unpack('!H', hello[p:p + 2])[0]; p += 2
            exts.append(str(t))
            if t == 0x000a:                          # supported_groups
                cl = struct.unpack('!H', hello[p + 2:p + 4])[0]
                for i in range(0, cl, 2):
                    curves.append(str(struct.unpack('!H', hello[p + 4 + i:p + 6 + i])[0]))
                p += 4 + cl
            elif t == 0x000b:                        # ec_point_formats
                for i in range(hello[p + 1]):
                    fmts.append(str(hello[p + 2 + i]))
                p += 2 + hello[p + 1]
            else:
                p += el
        raw = f"{struct.unpack('!H', hello[9:11])[0]},{'-'.join(ciphers)}," \
              f"{'-'.join(exts)},{'-'.join(curves)},{'-'.join(fmts)}"
        return hashlib.md5(raw.encode()).hexdigest(), raw


if __name__ == "__main__":
    s = RawSYNScanner("127.0.0.1")
    print("scan 80:", s.scan("127.0.0.1", 80))
    s.close()
