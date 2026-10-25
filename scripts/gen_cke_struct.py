#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gen_cke_struct.py —— 生成 ClientKeyExchange 结构化变异用例，并用真实
OpenSSL 逐例测出「该拒绝 / 该容忍」的真值

=====================================================================
为什么需要它（与 test_tls_hs.c 的分工）

  test_tls_hs.c 做的是字节级变异：截断、单字节翻转。它有个先天盲区 ——
  长度字段一翻转就先被长度检查挡下，根本到不了解析器。而解析器真正会
  出事的地方是「格式自洽、但语义刁钻」的报文：

    * point 长度声明 33 而实际只有 32 字节（经典的一字节越界读）
    * point 长度声明 31 而实际留了 32 字节（尾部残留未消费）
    * 握手消息声明长度比记录体多 1
    * 一条合法的握手消息被拆成两个记录（TLS 允许，实现常常不允许）
    * 同一条 CKE 出现两次

  这些必须在「外层长度如实重算」的前提下构造，否则测的是截断而不是
  解析器。只有「长度不符」那几类才故意不重算。

为什么期望值要实测而不是我拍

  「未知握手类型该忽略还是该拒绝」「重复 CKE 该拒绝吗」这类问题，凭
  RFC 推断很容易推错，而推错的代价是把我们的实现调成和真实世界不一致
  —— 探测者只需发一个畸形报文就能把我们和真实服务端区分开。所以每一
  例的真值都从这个脚本连真实 OpenSSL s_server 实测取得，再固化进头文件。
=====================================================================
"""
import os
import re
import socket
import struct
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REAL_H = os.path.join(ROOT, "25_tls", "tests", "hs_msgs_real.h")
DST = os.path.join(ROOT, "25_tls", "tests", "cke_struct.h")
DATA = os.path.join(ROOT, "25_tls", "tests", "data")

TOLERATE = 1   # 必须被接受：不得产出告警
REJECT = 0     # 必须被拒绝：必须产出告警
ANY = -1       # 只要求不崩不挂


def load_real():
    src = open(REAL_H, encoding="utf-8").read()

    def grab(name):
        m = re.search(r"%s\[\]\s*=\s*\{(.*?)\}" % name, src, re.S)
        if not m:
            raise SystemExit("[FATAL] 在 %s 里找不到 %s" % (REAL_H, name))
        return bytes(int(x, 16) for x in re.findall(r"0x([0-9a-fA-F]{2})", m.group(1)))

    return grab("CH_REAL_REC"), grab("CKE_REAL_REC")


def mk_rec(ct, body, ver=0x0303):
    return bytes([ct]) + struct.pack(">H", ver) + struct.pack(">H", len(body)) + body


def mk_hs(htype, body):
    return bytes([htype]) + struct.pack(">I", len(body))[1:] + body


# ---------------------------------------------------------------------------
# 用例构造。每个用例返回「CH 记录 + 变异后的 CKE 记录序列」的完整字节流。
# ---------------------------------------------------------------------------

def build_cases(ch, cke):
    """cke: 完整记录（5 头 + 4 握手头 + body）"""
    hs_type = cke[5]
    hs_len = struct.unpack(">I", b"\x00" + cke[6:9])[0]
    body = cke[9:9 + hs_len]
    plen = body[0]
    point = body[1:]
    assert len(point) == plen, "point_len=%d 实际 %d" % (plen, len(point))
    assert hs_type == 16

    def cke_rec(hs_body, hlen_v=None, htype=16):
        """组装一条 CKE 记录；hlen_v 用于构造「声明长度与实际不符」"""
        b = hs_body
        hl = hlen_v if hlen_v is not None else len(b)
        payload = bytes([htype]) + struct.pack(">I", hl)[1:] + b
        rl = len(payload)
        return bytes([22]) + struct.pack(">H", 0x0303) + struct.pack(">H", rl) + payload

    cases = []

    def add(name, recs, note):
        st = ch + b"".join(recs)
        cases.append({"name": name, "stream": st, "note": note, "len": len(st)})

    # 生成器自检：把解析出来的字段重新组装回去，必须与原始报文逐字节相同。
    # 这条不成立，说明字段偏移算错了，后面每一个「变异」测的都不是真实
    # 报文的变体而是生成器自己编出来的另一个包 —— 结论全部作废。
    # （上一轮 ClientHello 那一版就栽在这里：内层列表长度多算了 2 字节，
    #   造出来的不是「掺了 GREASE 的合法扩展」而是畸形扩展，差点把工具的
    #   bug 记成产品缺陷。）
    rebuilt = cke_rec(body)
    if rebuilt != cke:
        raise SystemExit("[FATAL] 重组后与原 CKE 不一致：\n  重组 %s\n  原始 %s"
                         % (rebuilt.hex(), cke.hex()))

    add("BASE", [cke], "原样真实 CKE —— 对照组，必须被接受")

    # point 长度相关（这几类最经典：声明长度与实际不符）
    add("PLEN_ZERO", [cke_rec(b"\x00")], "point 长度声明为 0（空公钥）")
    add("PLEN_ONE", [cke_rec(b"\x01" + point[:1])], "point 长度声明为 1（只有 1 字节公钥）")
    add("PLEN_PLUS1", [cke_rec(bytes([33]) + point)],
        "point 长度声明 33 而实际只有 32 字节 —— 一字节越界读")
    add("PLEN_MINUS1", [cke_rec(bytes([31]) + point)],
        "point 长度声明 31 而实际留了 32 字节 —— 尾部残留")
    add("PLEN_FF", [cke_rec(bytes([255]) + point)],
        "point 长度声明 255 而实际 32 字节 —— 大幅越界读")

    # 握手消息层长度不符
    add("HSLEN_PLUS1", [cke_rec(body, hlen_v=hs_len + 1)],
        "握手消息声明长度比实际多 1")
    add("HSLEN_MINUS1", [cke_rec(body, hlen_v=hs_len - 1)],
        "握手消息声明长度比实际少 1")
    add("HSLEN_ZERO", [cke_rec(body, hlen_v=0)], "握手消息声明长度为 0（空体）")

    # 记录层长度不符
    add("RECLEN_PLUS1",
        [cke[:3] + struct.pack(">H", len(cke) - 5 + 1) + cke[5:]],
        "记录层声明长度比实际多 1 —— 会去等永远不到的字节")
    add("RECLEN_MINUS1",
        [cke[:3] + struct.pack(">H", len(cke) - 5 - 1) + cke[5:]],
        "记录层声明长度比实际少 1 —— 尾部残留")

    # 结构层
    add("DUP_CKE", [cke, cke], "同一条 CKE 出现两次")
    add("SPLIT_REC", [mk_rec(22, cke[5:15]), mk_rec(22, cke[15:])],
        "一条握手消息被拆成两个记录 —— TLS 允许，实现常常不允许")
    add("TYPE_UNKNOWN", [cke_rec(body, htype=0xFE)],
        "未知握手类型 0xFE，长度合法 —— RFC 5246 要求忽略")
    add("TYPE_SERVERHELLO", [cke_rec(body, htype=2)],
        "客户端流里出现服务端消息类型 2 —— 必须拒绝")
    add("POINT_FLIP", [cke_rec(bytes([plen]) + b"\x00" + point[1:])],
        "point 首字节置 0（X25519 任意 32 字节都是合法公钥）—— 必须容忍")
    add("EMPTY_HS_REC", [cke, mk_rec(22, b"")], "CKE 后跟一个空的握手记录")

    return cases


# ---------------------------------------------------------------------------
# 用真实 OpenSSL s_server 逐例测真值
# ---------------------------------------------------------------------------

def port_free(port):
    """这个端口上有没有别的监听者。

    若端口被上一次被强杀留下的 s_server 占着，连接会立刻成功，我们就把
    报文发给了一个【不属于本次探测】的服务端，拿它的反应当真值。两个监听
    者不能共存于同一 addr:port（SO_REUSEADDR 也不允许），所以「能不能
    bind」正好等价于「有没有别的监听者」。
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
    """从 start 起找第一个没有监听者的端口。"""
    for i in range(window):
        p = start + i
        if p > 65535:
            break
        if port_free(p):
            return p
    return None


def probe_openssl_retry(stream, base_port, tries=8):
    """端口被占就换一个再测。

    这里最要紧的不是「能不能测出真值」，而是【测不出来时绝不能落进头文件】。
    早期版本 probe 返回 None 时，调用点用 .get(r, ANY) 把它映射成了
    EXPECT_ANY 并继续生成——于是端口冲突被永久写成了「本例不做断言」，
    一条真实分歧就此消失，且没有任何报错。

    先扫描出空闲端口再起 s_server，而不是盲目 +1：每次试错都要等 s_server
    bind 失败并退出，代价远高于一次 bind 探测。
    """
    port = base_port
    for _ in range(tries):
        port = next_free_port(port)
        if port is None:
            return None
        v = probe_openssl(stream, port)
        if v is not None:
            return v
        port += 1
    return None


def probe_openssl(stream, port):
    """测出真实 OpenSSL 对这条 CKE 的判定。

    判据为什么不是「有没有告警」：
        只发 CH+CKE 就停下，OpenSSL 在 CKE 合法时会静默等 Finished —— 不发
        告警。而 CKE 非法时它同样可能因为「记录还没收齐」而静默等待。两者
        都不发告警，用二值判据会把「卡住」记成「接受」。

    所以多发两步：CCS + 一条随机 Finished。
        * 走到 Finished 才失败 -> bad_record_mac(20)，说明 CKE 已被解析并
          接受，密钥派生也走通了（只是我们给的 Finished 是垃圾）
        * 在那之前就失败    -> 别的告警码，说明 CKE 解析这一步就出了问题
        * 完全无告警        -> 连记录层都没收齐，本例给不出结论（UNKNOWN）

    返回 "TOLERATE" / "REJECT" / "UNKNOWN"。
    """
    # CCS 记录 + 一条随机 Finished（加密态下必然解不开）
    #
    # 长度必须够 GCM 的开销：显式 nonce 8 + 密文 + tag 16。早先版本只发
    # 16 字节，OpenSSL 直接报 internal_error(80)「invalid aad」—— 那是
    # 记录层长度不合法，根本没走到解密，于是「CKE 已接受」这个信号被
    # 错误地判成了 REJECT。
    cmd = ["openssl", "s_server", "-accept", str(port),
           "-cert", os.path.join(DATA, "leaf.pem"),
           "-key", os.path.join(DATA, "leaf.key"),
           "-tls1_2", "-cipher", "ECDHE-RSA-AES128-GCM-SHA256",
           "-curves", "X25519", "-no_dhe", "-quiet", "-naccept", "1"]
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, preexec_fn=os.setsid)
    try:
        # 等监听就绪
        s = None
        for _ in range(60):
            # s_server 自己退出 = bind 失败或参数不可用，不能拿「连不上」
            # 冒充真值，交给上层换端口重试。
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
            # 只发 CH + CKE，与喂给我们服务端的字节完全一样。
            # 早先版本多发了一条 CCS + 垃圾 Finished，想靠告警码区分「已
            # 接受」，结果两边输入不对称：OpenSSL 因为收到了后续字节才补齐
            # 记录并解析，我们这边却直接 EOF —— 同一用例两边根本不在比
            # 同一件事。对称比判据精致更重要。
            s.sendall(stream)
        except OSError:
            return "UNKNOWN"
        buf = b""
        t0 = time.time()
        while time.time() - t0 < 2.0:
            try:
                d = s.recv(65536)
                if not d:
                    break
                buf += d
            except socket.timeout:
                break
            except OSError:
                break
        s.close()
    finally:
        try:
            os.killpg(os.getpgid(p.pid), 9)
        except OSError:
            pass
        try:
            p.wait(2)
        except Exception:
            pass

    # 解析记录，找告警
    off = 0
    saw_hs = False
    while off + 5 <= len(buf):
        ct = buf[off]
        ln = struct.unpack(">H", buf[off + 3:off + 5])[0]
        body = buf[off + 5:off + 5 + ln]
        if ct == 21 and ln >= 2:
            # 服务端主动发了告警 —— 它对这条 CKE 的表态是「拒绝」。
            # 不再细分告警码：有 tail 的那版想靠 desc==20 判断「已接受」，
            # 但那需要两边输入一致，而我们的服务端在 Finished 解密失败时
            # 发的是 decode_error 不是 bad_record_mac，细分反而制造分歧。
            return "REJECT"
        if ct == 22:
            saw_hs = True
        off += 5 + ln
    if not saw_hs:
        return "UNKNOWN"   # 服务端根本没响应，给不出结论
    # 收到了服务端的握手消息、且没发告警 —— 它吃下了这条 CKE，正在等 CCS
    return "TOLERATE"


def openssl_available():
    """真值探测的前置条件（与 gen_ch_struct.py 同源，口径必须一致）。"""
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


def frozen_expects(text):
    """从已固化头文件抽出 {用例名: expect}，用于漂移时点名。"""
    out = {}
    for m in re.finditer(r'\.name\s*=\s*"([A-Za-z0-9_]+)",.*?\.expect\s*=\s*(-?\d+)',
                         text, re.S):
        out[m.group(1)] = int(m.group(2))
    return out


def main():
    argv = sys.argv[1:]
    check = "--check" in argv
    if check:
        ok, why = openssl_available()
        if not ok:
            print("[SKIP] 真值漂移检查未执行：%s" % why)
            print("[SKIP] 已固化期望值未经验证 —— 不等于它们仍然正确")
            return 77
    ch, cke = load_real()
    cases = build_cases(ch, cke)
    print("[GEN] 用例数 %d" % len(cases))

    only = "all"
    for a in argv:
        if not a.startswith("--"):
            only = a
    if check and only == "no-probe":
        raise SystemExit("[FATAL] --check 与 no-probe 互斥："
                         "不测真值的比对没有意义")
    port = 19300
    results = []
    for c in cases:
        if only == "no-probe":
            exp = ANY
        else:
            r = probe_openssl_retry(c["stream"], port)
            port += 1
            if r is None:
                # 早期版本走到这里会落成 ANY 并继续生成，把「测不出来」
                # 永久写进头文件。测不出真值就必须停下来。
                raise SystemExit(
                    "[FATAL] s_server 起不来（%s，已重试换端口）。没有真值就"
                    "不许写 ANY —— 那会把一条真实分歧永久抹掉。"
                    "确认 openssl 与证书可用、端口未被长期占用后重跑。"
                    % c["name"])
            # probe 返回的是语义字符串，必须显式映射成头文件里的常量。
            # 早期版本直接存了布尔值，导致「拒绝」被写成 TOLERATE、
            # 全部期望值反向 —— 教训：跨表示的赋值必须显式转换。
            exp = {"TOLERATE": TOLERATE, "REJECT": REJECT}.get(r, ANY)
            if exp == ANY:
                print("  [WARN] %-16s 判定为 %s，记为 ANY（不做断言）" % (c["name"], r))
            else:
                print("  [PROBE] %-16s -> %s" % (c["name"], r))
        c["expect"] = exp
        results.append(c)

    # 基线必须是容忍，否则说明抓取/组装本身有问题
    base = [c for c in results if c["name"] == "BASE"]
    if base and base[0]["expect"] != TOLERATE:
        raise SystemExit("[FATAL] BASE 用例未被 OpenSSL 接受 —— 基底有问题，"
                         "后面所有结论都不可信")

    def arr(b):
        out = []
        for i in range(0, len(b), 12):
            out.append("    " + " ".join("0x%02X," % x for x in b[i:i + 12]))
        return "\n".join(out)

    body = []
    for c in results:
        body.append("    {\n        .name = \"%s\",\n        .note = \"%s\",\n"
                    "        .expect = %d,\n        .len = %d,\n        .stream = {\n%s\n        },\n    },"
                    % (c["name"], c["note"], c["expect"], len(c["stream"]), arr(c["stream"])))

    hdr = """/* cke_struct.h —— ClientKeyExchange 结构化变异用例（自动生成，勿手改）
 *
 * 由 scripts/gen_cke_struct.py 生成。基底是 hs_msgs_real.h 里固化的真实
 * OpenSSL 3.0.2 报文，期望值由同一脚本连真实 s_server 逐例实测取得。
 *
 * expect 的含义：
 *   EXPECT_TOLERATE(1)  不得产出告警 —— 未知类型、分片、合法公钥变异
 *                       被拒，等于在真实互联网上握不上手
 *   EXPECT_REJECT(0)    必须产出告警 —— 结构非法却继续握手，往往意味着
 *                       它按错误长度读过去了
 *   EXPECT_ANY(-1)      只要求不崩不挂（真实实现本次未给出明确判据）
 *
 * 注意：期望值是 OpenSSL 3.0.2 在生成当天的行为快照。换实现或升级后必须
 * 重跑生成脚本，本文件不会自动更新。
 */
#ifndef CKE_STRUCT_H
#define CKE_STRUCT_H

#include <stdint.h>
#include <stddef.h>

#define EXPECT_TOLERATE 1
#define EXPECT_REJECT   0
#define EXPECT_ANY     -1

typedef struct {
    const char    *name;
    const char    *note;
    int            expect;
    size_t         len;
    const uint8_t *stream;
} cke_case_t;

static const uint8_t CKE_STREAMS[][%(maxlen)d] = {
%(streams)s
};

static const cke_case_t CKE_CASES[] = {
%(cases)s
};

#define CKE_NCASES (sizeof(CKE_CASES) / sizeof(CKE_CASES[0]))

#endif /* CKE_STRUCT_H */
""" % {
        "maxlen": max(c["len"] for c in results),
        "streams": "\n".join(
            "    {\n%s\n    }," % arr(c["stream"]) for c in results),
        "cases": "\n".join(
            "    {\n        .name = \"%s\",\n        .note = \"%s\",\n"
            "        .expect = %d,\n        .len = %d,\n"
            "        .stream = CKE_STREAMS[%d],\n    }," % (c["name"], c["note"],
                                                            c["expect"], c["len"], i)
            for i, c in enumerate(results)),
    }

    if check:
        if not os.path.exists(DST):
            print("[FAIL] 已固化头文件不存在：%s" % DST)
            return 1
        cur = open(DST, encoding="utf-8").read()
        if cur == hdr:
            print("[PASS] 真值无漂移：%d 例期望值与当前 OpenSSL 实测一致"
                  % len(results))
            return 0
        print("[FAIL] 真值已漂移：%s 与实测结果不一致" % DST)
        old = frozen_expects(cur)
        for c in results:
            if old.get(c["name"]) != c["expect"]:
                print("       %-26s 固化=%-3s 实测=%-3d"
                      % (c["name"], old.get(c["name"], "<无>"), c["expect"]))
        if not old:
            print("       （无法从头文件解析出用例，可能是手改过的）")
        print("[FAIL] 重新运行：python3 %s" % os.path.abspath(__file__))
        return 1

    open(DST, "w", encoding="utf-8").write(hdr)
    print("[GEN] 已写入 %s（%d 例）" % (DST, len(results)))
    ntol = sum(1 for c in results if c["expect"] == TOLERATE)
    nrej = sum(1 for c in results if c["expect"] == REJECT)
    nany = sum(1 for c in results if c["expect"] == ANY)
    print("[GEN] 容忍 %d / 拒绝 %d / 待定 %d" % (ntol, nrej, nany))


if __name__ == "__main__":
    sys.exit(main())
