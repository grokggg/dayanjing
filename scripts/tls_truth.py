#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""结构化变异真值探测的公共基础设施。

由 gen_ch_struct.py（ClientHello 47 例）与 gen_cke_struct.py
（ClientKeyExchange 17 例）共用。抽取的动机不是"重复代码不好看"：

    这两份实现此前是逐字复制的。一旦有人在某一侧修了探测逻辑（例如端口
    被占时的重试、判据的收紧），另一侧不会跟着变，而两边各自跑出的期望值
    仍然"全绿" —— 于是同一套真值体系里存在两套口径，差异静默累积。

    真值文件是固化的（头文件里写死的常量）。口径分叉不会被任何人发现，
    只会表现为"某个用例的期望值和另一组不一致"，而那时没人知道该信哪个。

判定口径（两处共用，必须一致）：
    REJECT   对端主动发了告警（ct==21）
    TOLERATE 对端回了握手消息且未发告警
    UNKNOWN  对端没给任何可判定的反应 —— 绝不猜成 REJECT

    为什么 UNKNOWN 不猜：早先在 CH 侧手写过 47 例期望值，其中只有 1 例
    （握手体长度 +10）猜错，但足以把"两边完全一致"记成缺陷，引着人去改
    一段本来正确的代码。猜对率 98% 也不够，因为错的那一例直接产出一个
    假缺陷。

起不来 vs 判不出：
    probe_openssl 返回 None 只表示【服务端没起来/连不上】—— 那是环境问题，
    上层必须换端口重试，绝不许落成 UNKNOWN 或 ANY。历史上 CKE 侧正是把
    None 映射成 ANY 并继续生成，把一次端口冲突永久写成了"本例不做断言"，
    一条真实分歧就此消失且无任何报错。
"""
import os
import socket
import struct
import subprocess
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "25_tls", "tests", "data")

# s_server 的启动参数。两处必须完全一致：套件、曲线、版本任一不同，测出来
# 的就不是"同一个 OpenSSL 的行为"，两侧的期望值也就不可比。
#   -no_dhe   ：不加它 s_server 会先生成 2048 位临时 DH 参数才 bind，表现为
#               客户端连不上，与被测代码无关。
#   -naccept 1：只服务一个连接就退出，避免残留监听者占住端口。
SERVER_CMD = ["openssl", "s_server", "-accept", "%(port)d",
              "-cert", os.path.join(DATA, "leaf.pem"),
              "-key", os.path.join(DATA, "leaf.key"),
              "-tls1_2", "-cipher", "ECDHE-RSA-AES128-GCM-SHA256",
              "-curves", "X25519", "-no_dhe", "-quiet", "-naccept", "1"]


def port_free(port):
    """这个端口上有没有别的监听者。

    为什么不能只靠"连得上就算就绪"：
        若端口被上一次被强杀留下的 s_server 占着，连接会立刻成功，我们就
        把报文发给了一个【不属于本次探测】的服务端，拿它的反应当真值。实
        测过这个失败形态：占住端口后 probe 返回 UNKNOWN，因为它连的是那
        个外部监听者。

    两个监听者不能共存于同一 addr:port（SO_REUSEADDR 也不允许），所以
    "能不能 bind" 正好等价于"有没有别的监听者"。
    """
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def next_free_port(start, window=512):
    """从 start 起找第一个没有监听者的端口。找不到返回 None。"""
    for i in range(window):
        p = start + i
        if p > 65535:
            break
        if port_free(p):
            return p
    return None


def classify_records(buf):
    """按记录层逐条走，把对端的反应归成 REJECT / TOLERATE / UNKNOWN。

    两条判据：
        ct==21 且长度 >= 2  -> REJECT（对端主动告警）
        见过 ct==22         -> TOLERATE（回了握手消息且没告警）
        什么都没有          -> UNKNOWN

    只看"有没有告警"是不够的：对端可能因为记录没收齐而静默等待，那既不
    是接受也不是拒绝。UNKNOWN 必须由调用方显式处理（记 ANY 并打印 WARN，
    或在 --check 模式下报漂移），不许被当成 REJECT。
    """
    off = 0
    saw_hs = False
    while off + 5 <= len(buf):
        ct = buf[off]
        ln = struct.unpack(">H", buf[off + 3:off + 5])[0]
        if ct == 21 and ln >= 2:
            return "REJECT"
        if ct == 22:
            saw_hs = True
        off += 5 + ln
    return "TOLERATE" if saw_hs else "UNKNOWN"


def probe_openssl(payload, port, read_timeout=1.5, classify=classify_records):
    """起一个真实 s_server，把 payload 原样发过去，返回判定字符串。

    read_timeout 两侧不同（CH 1.5s / CKE 2.0s），故做成参数而不是统一值：
        统一值会改变实测结果 —— 对端可能在超时窗口末尾才发告警，"收到告警"
        与"没收到"是两种截然不同的期望值。改它会让已固化的头文件整体漂移，
        而那种漂移看起来像发现了 47 个新缺陷。

    返回：
        "REJECT" / "TOLERATE" / "UNKNOWN"  —— 拿到了反应
        "UNKNOWN" 也用于"发送失败"          —— 连接建了但没发出去，同样无结论
        None                                —— 服务端没起来或连不上（换端口重试）
    """
    cmd = [a % {"port": port} if "%(port)d" in a else a for a in SERVER_CMD]
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, preexec_fn=os.setsid)
    try:
        s = None
        for _ in range(60):
            # s_server 自己退出了 —— 多半是 bind 失败（端口被占），也可能是
            # 证书/套件不可用。任何一种都不能拿"连不上"冒充真值。
            if p.poll() is not None:
                return None
            try:
                s = socket.create_connection(("127.0.0.1", port), 0.5)
                break
            except OSError:
                time.sleep(0.05)
        if s is None:
            return None
        s.settimeout(1.5)
        try:
            # 输入必须与喂给我们服务端的一模一样，不多发也不少发。
            # 不对称的输入会让两边不在比同一件事 —— 这个坑在 CKE 侧犯过一次：
            # 给 OpenSSL 多发了一条 CCS + 垃圾 Finished，结果"已接受"的信号
            # 来自后续字节，而我们这边直接 EOF。对称比判据精致更重要。
            s.sendall(payload)
        except OSError:
            return "UNKNOWN"
        buf = b""
        t0 = time.time()
        while time.time() - t0 < read_timeout:
            try:
                d = s.recv(65536)
                if not d:
                    break
                buf += d
            except (socket.timeout, OSError):
                break
        s.close()
    finally:
        # 必须按进程组杀：-naccept 1 让 s_server 服务完就退出，但它也可能
        # 一直等着；残留监听者会占住端口，下一次探测就打到它身上（见
        # port_free 的说明）。
        try:
            os.killpg(os.getpgid(p.pid), 9)
        except OSError:
            pass
        try:
            p.wait(2)
        except Exception:
            pass
    return classify(buf)


def probe_openssl_retry(payload, base_port, read_timeout=1.5, tries=8,
                        classify=classify_records):
    """端口被占就换一个再测，测不出来返回 None（绝不落成 UNKNOWN/ANY）。

    为什么先扫描空闲端口再起 s_server，而不是盲目 +1 去试：
        每次试错都要等 s_server bind 失败并退出，代价远高于一次 bind 探测。
        端口连续被占一段（并发回归各占一片）时，盲试很快耗尽次数 —— 实测
        占满 300 个连续端口时，盲试版 16 次全部耗尽，CH 直接 FATAL 失败。
    """
    port = base_port
    for _ in range(tries):
        port = next_free_port(port)
        if port is None:
            return None
        v = probe_openssl(payload, port, read_timeout, classify)
        if v is not None:
            return v
        port += 1
    return None


def openssl_available():
    """真值探测的前置条件。缺 openssl 或缺证书时返回 (False, 原因)。

    为什么单独拎出来：--check 要能区分"真值漂移"与"测不了"。
        都归为失败 -> 无 openssl 的环境里回归一直红，最后被人加个 || true
                      关掉；
        都归为通过 -> 等于什么都没验。
    所以让调用方拿到明确原因，自己决定记 SKIP 还是 FAIL。
    """
    try:
        v = subprocess.run(["openssl", "version"], capture_output=True,
                           text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return False, "openssl 不可用"
    if v.returncode != 0:
        return False, "openssl version 返回 %d" % v.returncode
    for f in ("leaf.pem", "leaf.key"):
        if not os.path.exists(os.path.join(DATA, f)):
            return False, "缺少证书文件 %s" % f
    return True, v.stdout.strip()
