#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""capture_hs_msgs.py —— 抓取真实 TLS 客户端发出的「后续握手消息」

为什么需要它
=====================================================================
上一轮做的 ClientHello 结构化变异只覆盖了握手的第一个消息。而握手
后半段的消息（ClientKeyExchange 等）同样是明文、同样由解析器先行
处理，同样能被畸形报文打穿 —— 而且它们从未被结构化变异覆盖过。

字节级变异（test_tls_hs.c）碰不到它们，原因和 ClientHello 那一轮
一样：长度字段一翻转就先被长度检查挡下，根本到不了解析器。要造出
「格式自洽但语义刁钻」的报文，必须从真实报文出发按结构做手术。

本文件做的事：
    起一个 TCP 中转（MITM），真实客户端（openssl s_client）连中转，
    中转把流量转发给真实服务端，同时把双向字节流原样落盘。

为什么要 MITM 而不是让客户端直连服务端：
    直连拿不到线路字节。而后续握手消息在 CCS 之后就被加密了，只有
    在加密之前的那一小段是明文可解析的 —— 必须整段抓下来才能定位。

用法：
    python3 scripts/capture_hs_msgs.py <listen_port> <server_port> \
                                       <out_cs.bin> <out_sc.bin>

它只负责抓，不负责解析。解析在 gen_hs_struct.py 里做。
=====================================================================
"""
import os
import socket
import sys
import threading
import time

BUF = 65536


def pump(a, b, sink):
    """把 a 的字节搬到 b，同时写进 sink。返回搬了多少字节。"""
    total = 0
    try:
        while True:
            d = a.recv(BUF)
            if not d:
                break
            sink.append(d)
            total += len(d)
            b.sendall(d)
    except OSError:
        pass
    return total


def main():
    if len(sys.argv) != 5:
        sys.exit("usage: capture_hs_msgs.py <listen> <server> <out_cs> <out_sc>")
    listen_port = int(sys.argv[1])
    server_port = int(sys.argv[2])
    out_cs, out_sc = sys.argv[3], sys.argv[4]

    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", listen_port))
    ls.listen(1)
    ls.settimeout(30)
    print("[CAP] 监听 127.0.0.1:%d -> 转发 :%d" % (listen_port, server_port),
          flush=True)

    try:
        cli, _ = ls.accept()
    except socket.timeout:
        print("[CAP] 等待客户端超时", flush=True)
        return 1

    up = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    up.connect(("127.0.0.1", server_port))
    print("[CAP] 客户端已连入，开始抓取", flush=True)

    cs, sc = [], []
    t1 = threading.Thread(target=pump, args=(cli, up, cs))
    t2 = threading.Thread(target=pump, args=(up, cli, sc))
    t1.start()
    t2.start()

    # 抓取窗口：握手 + 一次应用数据往返。到点即收，不等对端。
    time.sleep(6)
    for s in (cli, up):
        try:
            s.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            s.close()
        except OSError:
            pass
    t1.join(2)
    t2.join(2)

    csb = b"".join(cs)
    scb = b"".join(sc)
    with open(out_cs, "wb") as f:
        f.write(csb)
    with open(out_sc, "wb") as f:
        f.write(scb)
    print("[CAP] C->S %d 字节 -> %s" % (len(csb), out_cs), flush=True)
    print("[CAP] S->C %d 字节 -> %s" % (len(scb), out_sc), flush=True)
    if len(csb) == 0:
        print("[CAP][FATAL] C->S 为空：客户端根本没发东西", flush=True)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
