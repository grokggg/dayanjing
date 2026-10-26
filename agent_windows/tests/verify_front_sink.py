#!/usr/bin/env python3
"""verify_front_sink.py — 域前置（front://）出口守卫

为什么必须单独一个守卫：
    front:// 的失效形态是"功能全绿、能力归零"——请求照发、响应照收、
    BODY 照收 512 字节，唯独真实目标以明文出现在 SNI 里。所有连通性
    断言都会通过，只有站在 TLS 终结点上看 SNI、看线路字节才能区分。

本守卫起一个真实 TLS 服务端当作"前置节点"（front_probe），让 camd 以
front:// 出口回传，然后从服务端侧断言七件事：

  SNI            == 前置域          加密外只能看见前置域
  HOST_REAL      == 1               真实目标确实在内层 Host 生效
  HOST_FRONT     == 0               没把前置域误写成 Host（两者未串味）
  BODY           > 0                画面真的送达（不是空请求）
  WIRE_REAL      == 0               线路字节不含真实目标 ← 域前置成立
  WIRE_FRONT     == 1               正向对照：前置域在线路上可见
  WIRE_N         > 0                取证缓冲确实记录到字节

WIRE_FRONT 不可省：若扫描压根没记录到字节，"WIRE_REAL==0" 就是假阴性。

同时做两条静态断言：守住"front_domain 取自前置域"与"两域名不得相同"——
这两处一旦被改，运行时断言仍可能全绿（域名相同时前置退化成直通）。

退出码：0 = 全过；1 = 有断言失败；77 = 环境不具备（无法判定）。
"""
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)                       # agent_windows
REPO = os.path.dirname(ROOT)                       # dayanjing

CAMD = os.path.join(ROOT, "build", "linux", "camd")
PROBE = os.path.join(ROOT, "build", "linux", "front_probe")
TLSDATA = os.path.join(REPO, "25_tls", "tests", "data")
SRC = os.path.join(ROOT, "src", "cam_daemon.c")

FRONT = "front.test"
REAL = "c2.real.example"
KEY = "00112233445566778899aabbccddeeffffeeddccbbaa99887766554433221100"

passed = failed = 0


def check(cond, msg):
    global passed, failed
    if cond:
        passed += 1
        print("[PASS] " + msg)
    else:
        failed += 1
        print("[FAIL] " + msg)
    return bool(cond)


def ensure_hosts():
    """front.test / c2.real.example 需解析到回环，否则无法在本地建连。"""
    try:
        txt = open("/etc/hosts").read()
    except OSError:
        return False
    missing = [h for h in (FRONT, REAL) if h not in txt]
    if not missing:
        return True
    try:
        with open("/etc/hosts", "a") as f:
            for h in missing:
                f.write("127.0.0.1 %s\n" % h)
        return True
    except OSError:
        return False


def run_once(port, extra_args, use_ca=True):
    """跑一次 camd -> front_probe，返回 (probe 输出字典, camd 返回码)。"""
    p = subprocess.Popen(
        [PROBE, str(port), REAL, FRONT, TLSDATA],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(0.4)
    args = [CAMD, "--backend", "mock", "--batches", "1", "--no-persist",
            "--key", KEY, "--sink", "front://%s:%d" % (FRONT, port),
            "--front-host", REAL] + extra_args
    if use_ca:
        args += ["--ca", os.path.join(TLSDATA, "ca.pem")]
    try:
        c = subprocess.run(args, capture_output=True, text=True, timeout=90)
        rc = c.returncode
    except subprocess.TimeoutExpired:
        rc = -999
    out, err = p.communicate(timeout=90)
    kv = {}
    for line in out.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            kv[k.strip()] = v.strip()
    if not kv:
        print("  [probe stderr] " + (err or "(空)")[:400])
    return kv, rc


def main():
    for f in (CAMD, PROBE):
        if not os.path.exists(f):
            print("[环境] 缺产物: %s —— 无法判定" % f)
            return 77
    if not os.path.exists(os.path.join(TLSDATA, "ca.pem")):
        print("[环境] 缺证书数据: %s —— 无法判定" % TLSDATA)
        return 77
    if not ensure_hosts():
        print("[环境] 无法把 %s / %s 解析到回环 —— 无法判定" % (FRONT, REAL))
        return 77

    port = 19900 + (os.getpid() % 200)
    kv, rc = run_once(port, [])

    print("=== 域前置出口（front://）正向 ===")
    check(rc == 0, "camd 以 front:// 跑通（rc=%d）" % rc)
    check(kv.get("SNI") == FRONT,
          "① 服务端在 TLS 终结点看到的 SNI == 前置域（实得 %s）" % kv.get("SNI"))
    check(kv.get("HOST_REAL") == "1",
          "② 解密后的请求里 Host 是真实目标（内层生效）")
    check(kv.get("HOST_FRONT") == "0",
          "②' 请求里没有把前置域写成 Host（两者未串味）")
    check(kv.get("BODY", "0").isdigit() and int(kv["BODY"]) > 0,
          "③ 画面确实送达（BODY=%s 字节）" % kv.get("BODY"))
    check(kv.get("WIRE_REAL") == "0",
          "④ 线路全部字节中不含真实目标（域前置成立）")
    check(kv.get("WIRE_FRONT") == "1",
          "④' 正向对照：前置域在线路上可见（证明扫描有效，非假阴性）")
    check(kv.get("WIRE_N", "0").isdigit() and int(kv["WIRE_N"]) > 0,
          "④'' 取证缓冲确实记录到线路字节（%s 字节）" % kv.get("WIRE_N"))

    print("=== 静态守卫（防运行时断言被绕过） ===")
    try:
        src = open(SRC).read()
    except OSError:
        src = ""
    check("fc.front_domain = s->host" in src,
          "S1 SNI 取自前置域（不得取自 front_host）")
    check("strcmp(s->front_host, s->host) == 0" in src,
          "S2 存在两域名不得相同的守卫（front_host 与前置域相同即拒绝）")

    print("=== 结果: %d pass, %d fail ===" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
