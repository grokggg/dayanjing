#!/usr/bin/env python3
"""
DNS 隧道公网下行验证器。

背景：上行（implant -> 公网递归解析器）已实测可达，不需要自有域名。
下行（C2 -> implant）必须经过**自有权威域**的 NS 委托链，
没有域名就无从验证 —— 这是客观资源限制，不是代码缺陷。

本工具在**你持有域名**时把下行链路一次验清：

  1. 查 <zone> 的 NS，确认委托指向你的权威服务器
  2. 直接向该权威服务器发一条隧道查询（绕过递归），确认它能应答 TXT
  3. 再走公网递归解析器发同一条查询，确认应答能穿透回来

用法:
    python3 dns_down_check.py --zone ex.example --auth 1.2.3.4 \\
        --resolver 8.8.8.8 --session deadbeef [--qname <自定义>]

退出码: 0=下行可用  1=不可用  2=参数/环境问题
"""

import argparse
import os
import random
import socket
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))


def build_query(qname, tid=None):
    """RFC 1035 查询报文：QNAME + QTYPE=TXT(16) + QCLASS=IN(1)"""
    if tid is None:
        tid = random.randint(0, 0xFFFF)
    out = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    for lbl in qname.split("."):
        if not lbl:
            continue
        b = lbl.encode()
        if len(b) > 63:
            raise ValueError("标签超 63 字节: " + lbl)
        out += bytes([len(b)]) + b
    out += b"\x00"
    out += struct.pack(">HH", 16, 1)
    return tid, out


def parse_name(pkt, off):
    labels = []
    while True:
        if off >= len(pkt):
            return None, off
        n = pkt[off]
        if n == 0:
            return ".".join(labels), off + 1
        if n & 0xC0:
            return None, off        # 压缩指针，本工具不展开
        off += 1
        labels.append(pkt[off:off + n].decode("latin1"))
        off += n


def send_recv(server, pkt, timeout=4.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, (server, 53))
        data, _ = s.recvfrom(4096)
        return data
    finally:
        s.close()


def rcode_of(pkt):
    if len(pkt) < 4:
        return None
    return pkt[3] & 0x0F


def ancount_of(pkt):
    if len(pkt) < 12:
        return 0
    return struct.unpack(">H", pkt[6:8])[0]


def txt_of(pkt):
    """取第一条 TXT 记录的文本"""
    if len(pkt) < 12:
        return None
    qd = struct.unpack(">H", pkt[4:6])[0]
    off = 12
    for _ in range(qd):
        _, off = parse_name(pkt, off)
        if off is None:
            return None
        off += 4
    an = struct.unpack(">H", pkt[6:8])[0]
    for _ in range(an):
        _, off = parse_name(pkt, off)
        if off is None or off + 10 > len(pkt):
            return None
        typ, cls, ttl, rdlen = struct.unpack(">HHIH", pkt[off:off + 10])
        off += 10
        if typ == 16:
            return pkt[off:off + rdlen].decode("latin1", "replace")
        off += rdlen
    return None


def query_ns(zone, resolver):
    """查 zone 的 NS 记录"""
    tid, pkt = build_query(zone, None)
    pkt = pkt[:4] + struct.pack(">HHHH", 1, 0, 0, 0)[:2] + pkt[6:]
    # 改 QTYPE 为 NS(2)
    body = pkt[:-4]
    pkt = body + struct.pack(">HH", 2, 1)
    try:
        r = send_recv(resolver, pkt)
    except Exception as e:
        print(f"[FAIL] 查 NS 失败: {e}")
        return []
    if len(r) < 12:
        return []
    qd = struct.unpack(">H", r[4:6])[0]
    off = 12
    for _ in range(qd):
        _, off = parse_name(r, off)
        if off is None:
            return []
        off += 4
    ns = []
    an = struct.unpack(">H", r[6:8])[0]
    for _ in range(an):
        _, off = parse_name(r, off)
        if off is None or off + 10 > len(r):
            break
        typ, _cls, _ttl, rdlen = struct.unpack(">HHIH", r[off:off + 10])
        off += 10
        if typ == 2:
            nm, _ = parse_name(r, off)
            if nm:
                ns.append(nm)
        off += rdlen
    return ns


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--zone", required=True, help="已委托给你的权威域，如 t.example.com")
    ap.add_argument("--auth", required=True, help="你的权威服务器 IP")
    ap.add_argument("--resolver", default="8.8.8.8", help="公网递归解析器")
    ap.add_argument("--session", default="deadbeef")
    ap.add_argument("--qname", default=None)
    a = ap.parse_args()

    qname = a.qname or f"0.0.0.{a.session}.{a.zone}"
    print(f"[*] 隧道查询名: {qname}")
    if len(qname) > 253:
        print("[FAIL] QNAME 超 253 字节")
        return 2

    print(f"\n[1/3] 委托检查：向 {a.resolver} 查 {a.zone} 的 NS")
    ns = query_ns(a.zone, a.resolver)
    if not ns:
        print("[FAIL] 查不到 NS —— 域名未委托或解析器不通")
        return 1
    print(f"      NS = {ns}")
    # 权威服务器 IP 需出现在 NS 的解析结果里
    hit = False
    for n in ns:
        try:
            for info in socket.getaddrinfo(n, 53, proto=socket.IPPROTO_UDP):
                if info[4][0] == a.auth:
                    hit = True
        except Exception:
            pass
    if not hit:
        print(f"[WARN] NS 列表未解析到 {a.auth} —— 委托可能尚未生效")
    else:
        print(f"[PASS] NS 已指向 {a.auth}")

    print(f"\n[2/3] 直连权威 {a.auth} 发隧道查询")
    try:
        _, pkt = build_query(qname)
        r = send_recv(a.auth, pkt)
        rc = rcode_of(r)
        print(f"      rcode={rc} ancount={ancount_of(r)} txt={txt_of(r)!r}")
        if rc == 0:
            print("[PASS] 权威端应答正常（下行数据可捎带）")
        else:
            print(f"[FAIL] 权威端 rcode={rc}")
            return 1
    except Exception as e:
        print(f"[FAIL] 直连权威失败: {e}")
        return 1

    print(f"\n[3/3] 经公网递归 {a.resolver} 走完整委托链")
    try:
        _, pkt = build_query(qname)
        r = send_recv(a.resolver, pkt, timeout=6.0)
        rc = rcode_of(r)
        print(f"      rcode={rc} ancount={ancount_of(r)} txt={txt_of(r)!r}")
        if rc == 0 and ancount_of(r) > 0:
            print("[PASS] 下行经公网递归可达 —— 隧道双向贯通")
            return 0
        print("[FAIL] 公网递归未返回有效应答")
        return 1
    except Exception as e:
        print(f"[FAIL] 公网递归查询失败: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
