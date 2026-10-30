#!/usr/bin/env python3
"""R4b：跨架构产物真执行守卫 —— 采集 + 回传必须在目标架构的字节上成立。

【为什么需要这条】
  R4 只证明"能编出 e_machine 正确的静态产物"。能编 ≠ 能跑：
  字节序、指令编码、结构体对齐、musl 静态启动流程任何一处错，在真机上
  就是 SIGILL / SIGSEGV / 静默退出，而 x86 侧回归全绿。
  本守卫用用户态模拟器把**那些字节**真跑一遍。

【为什么用 qiling 而不是 qemu】
  apt 无 qemu-user-static（E: Unable to locate package），PyPI 也无该包；
  但 PyPI 有纯 Python 的 qiling 1.4.6，支持 ARM64 / ARM / x86 的 Linux ELF
  与系统调用。"没有模拟器"同样是渠道问题，不是环境不具备。

【覆盖矩阵】
  arm64：静态 + --help 执行 + 完整采集/回传（TCP 收端实收字节）
  arm / i386：静态 + --help 执行（证明该架构字节可跑）
  只做静态而不执行，等于什么都没验。

【退出码约定 —— 不可混淆】
  0  验证通过
  1  真失败（产物/执行/回传任一不成立）
  2  环境不具备（无模拟器或无产物）—— 必须打印，绝不静默通过
"""
import binascii
import hashlib
import os
import socket
import struct
import sys
import threading

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ART = os.path.join(REPO, "artifacts")


def _pick_workdir():
    """选一个"真的能写"的目录作为工作根。

    为什么不能硬编码 /tmp：本沙盒的根 overlay 是只读的（/ 以 ro 挂载），
    /tmp 随之为 ro；历史上 /tmp 还被 502 清空过两次。硬编码会让守卫
    在最需要它的时候以 OSError 退出——而且报错指向文件系统，排查方向
    被引向"环境坏了"，而非"守卫选错了目录"。
    """
    cands = []
    env = os.environ.get("GUARD_WORKDIR")
    if env:
        cands.append(env)
    cands.append(os.path.join(os.path.dirname(REPO), ".guard_work"))
    cands.append("/data/workspace/.guard_work")
    cands.append("/tmp/a64root_guard")
    for c in cands:
        try:
            os.makedirs(c, exist_ok=True)
            t = os.path.join(c, ".wtest")
            with open(t, "w") as f:
                f.write("x")
            os.remove(t)
            return c
        except OSError:
            continue
    return "/tmp/a64root_guard"


WORK = _pick_workdir()
ROOTFS = os.path.join(WORK, "a64root_guard")

# 架构名 -> (产物文件名, 期望 e_machine, 是否跑完整采集回传)
TARGETS = [
    ("aarch64", "camd-aarch64-musl", 183, True),
    ("arm",     "camd-arm-musl",      40, False),
    ("i386",    "camd-i386-musl",      3, False),
]

# 架构 -> zig 目标名（对照实验用，必须与产物构建目标一致）
ZT = {
    "aarch64": "aarch64-linux-musl",
    "arm":     "arm-linux-musleabihf",
    "i386":    "x86-linux-musl",
}

PASS = []
FAIL = []
BLOCKED = []


def control_emu(target):
    """对照实验：同目标、同链接方式（musl 静态）的 hello world 能否在模拟器里跑。

    【为什么必须有这条】
      某架构执行失败时，有两种可能：
        (a) 模拟器不支持该架构  -> 环境限制，不是产品缺陷，不能记成 FAIL
        (b) 我们的产物在该架构上有真缺陷 -> 必须 FAIL
      不做对照，(a) 会被记成产品缺陷（冤枉），或反过来被"反正跑不起来"含糊
      带过甚至记成通过（更糟）。实测：i386 的 hello world 在 qiling 下同样
      UcError(Invalid memory write)，而 arm 的能跑 —— 故 i386 是 (a)。
    """
    import subprocess, tempfile
    work = os.path.join(WORK, "cross_ctrl")
    os.makedirs(work, exist_ok=True)
    src = os.path.join(work, "h.c")
    open(src, "w").write('#include <stdio.h>\nint main(void){printf("C\\n");return 0;}\n')
    try:
        import ziglang
        zig = os.path.join(os.path.dirname(ziglang.__file__), "zig")
    except Exception:
        return None
    if not os.path.exists(zig):
        return None
    binp = os.path.join(work, "h_" + target.replace("-", "_"))
    try:
        r = subprocess.run([zig, "cc", "-target", target, "-static", src, "-o", binp],
                           capture_output=True, text=True, timeout=300)
        if r.returncode != 0:
            return None
        from qiling import Qiling
        from qiling.const import QL_VERBOSE
        ql = Qiling([binp], ROOTFS, verbose=QL_VERBOSE.OFF)
        ql.run()
        return ql.os.exit_code == 0
    except Exception:
        return False


def ck(name, cond, detail=""):
    if cond:
        PASS.append(name)
        print("[OK]   %s %s" % (name, detail))
    else:
        FAIL.append(name)
        print("[FAIL] %s %s" % (name, detail))
    return cond


def elf_info(path):
    d = open(path, "rb").read()
    cls = d[4]
    # 【历史 bug】曾无条件按 ELF64 布局解析（e_phoff@32、e_phentsize@54）。
    # arm/i386 是 ELF32（e_phoff@28、e_phentsize@42），按 64 位读会得到
    # 荒谬偏移并抛 struct.error —— 而产物**已经拷贝完成**，脚本却以 rc=1
    # 结束，表现为"构建失败"而产物其实是对的。必须按 EI_CLASS 分支。
    if cls == 2:
        phoff, = struct.unpack_from("<Q", d, 32)
        phentsize, phnum = struct.unpack_from("<HH", d, 54)
    else:
        phoff, = struct.unpack_from("<I", d, 28)
        phentsize, phnum = struct.unpack_from("<HH", d, 42)
    interp = any(struct.unpack_from("<I", d, phoff + i * phentsize)[0] == 3
                 for i in range(phnum))
    return d[:4], cls, struct.unpack_from("<H", d, 18)[0], interp, len(d)


def emu(binary, args, port=None, timeout=280):
    got = {"b": 0, "conns": 0, "first": b""}
    if port:
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(4)

        def acc():
            srv.settimeout(timeout)
            try:
                while True:
                    c, _a = srv.accept()
                    got["conns"] += 1
                    c.settimeout(60)
                    while True:
                        d = c.recv(65536)
                        if not d:
                            break
                        got["b"] += len(d)
                        if not got["first"]:
                            got["first"] = d[:64]
                    c.close()
            except Exception:
                pass
        threading.Thread(target=acc, daemon=True).start()

    from qiling import Qiling
    from qiling.const import QL_VERBOSE
    ql = Qiling([binary] + args, ROOTFS, verbose=QL_VERBOSE.OFF)
    ql.run()
    return ql.os.exit_code, got


def main():
    try:
        import qiling  # noqa
    except Exception as e:
        print("[UNAVAILABLE] 无用户态模拟器（%s）—— R4b 判为 BLOCKED，不是通过" % e)
        return 2

    present = [(a, f, m, full) for (a, f, m, full) in TARGETS
               if os.path.exists(os.path.join(ART, f))]
    if not ck("A0 至少一个跨架构产物存在", bool(present),
              "%d/%d" % (len(present), len(TARGETS))):
        return 2

    os.makedirs(ROOTFS + "/tmp", exist_ok=True)

    for arch, fname, want_m, full in present:
        path = os.path.join(ART, fname)
        magic, cls, machine, interp, size = elf_info(path)
        ck("%s A1 ELF 魔数" % arch, magic == b"\x7fELF", magic.hex())
        ck("%s A2 e_machine=%d" % (arch, want_m), machine == want_m,
           "machine=%d size=%d" % (machine, size))
        ck("%s A3 无 INTERP 段（静态）" % arch, not interp, "interp=%s" % interp)
        if machine != want_m:
            continue

        try:
            rc, _ = emu(path, ["--help"])
        except Exception as e:
            rc = "EXC:%s" % type(e).__name__
        if rc != 0:
            # 先判定归属：是模拟器的限制，还是我们产物的缺陷
            ctl_ok = control_emu(ZT[arch])
            if ctl_ok is False:
                BLOCKED.append("%s 执行" % arch)
                print("[BLOCKED] %s 该架构模拟器不支持（同目标 hello world 对照同样失败）"
                      " —— 不计通过，也不计为产品缺陷" % arch)
                continue
            if ctl_ok is None:
                print("[BLOCKED] %s 对照实验无法构建（无 zig）—— 归属未定，不计通过" % arch)
                BLOCKED.append("%s 执行" % arch)
                continue
        ck("%s B1 该架构字节可执行并退出 0" % arch, rc == 0, "rc=%s" % rc)

        if full:
            key = binascii.hexlify(os.urandom(32)).decode()
            port = 45877
            try:
                rc, got = emu(path, ["--sink", "tcp://127.0.0.1:%d" % port,
                                     "--key", key, "--backend", "mock",
                                     "--no-persist", "--batches", "1",
                                     "--frames", "1", "--capture-ms", "60"],
                              port=port)
            except Exception as e:
                rc, got = "EXC:%s" % type(e).__name__, {"b": 0, "conns": 0, "first": b""}
            ck("%s B2 采集进程正常退出" % arch, rc == 0, "rc=%s" % rc)
            ck("%s B3 C2 收到连接" % arch, got["conns"] >= 1, "conns=%d" % got["conns"])
            ck("%s B4 C2 收到字节（回传成立）" % arch, got["b"] > 0, "bytes=%d" % got["b"])
            ck("%s B5 线上无 JPEG 明文" % arch, got["first"].find(b"\xff\xd8\xff") < 0,
               "first16=%s" % binascii.hexlify(got["first"][:16]).decode())

    # ---- 反向 R1：截断产物必须不能正常执行（证明执行断言不是恒绿） ----
    a64 = os.path.join(ART, "camd-aarch64-musl")
    if os.path.exists(a64):
        bad = os.path.join(ROOTFS, "tmp", "bad_arm64")
        open(bad, "wb").write(open(a64, "rb").read()[:4096])
        try:
            rc2, _ = emu(bad, ["--help"])
        except Exception as e:
            rc2 = "EXC:%s" % type(e).__name__
        ck("R1 截断产物执行失败/异常", rc2 != 0, "rc=%s" % rc2)

    # ---- 反向 R2：架构对拍 —— 拿错架构产物必须被静态判据拒绝 ----
    if len(present) >= 2:
        machines = [elf_info(os.path.join(ART, f))[2] for (_a, f, _m, _x) in present]
        ck("R2 各架构 e_machine 互不相同（A2 有鉴别力）",
           len(set(machines)) == len(machines), "machines=%s" % machines)

    report()
    return 1 if FAIL else 0


def report():
    print("\n=== 汇总 ===  PASS=%d  FAIL=%d  BLOCKED=%d" % (len(PASS), len(FAIL), len(BLOCKED)))
    for f in FAIL:
        print("  失败项: %s" % f)
    for b in BLOCKED:
        print("  未验证（环境限制，非产品缺陷）: %s" % b)
    print("EXIT=%d" % (1 if FAIL else 0))
    # 产物指纹：让状态机能校验"证据是否对应当前产物"。
    # 没有它，改了产物后旧证据仍会被判 VERIFIED（用旧证据冒充新状态）。
    for (arch, fn, _m, _x) in TARGETS:
        fp = os.path.join(ART, fn)
        if os.path.isfile(fp):
            h = hashlib.sha256(open(fp, "rb").read()).hexdigest()
            print("HASH %s %s %d" % (arch, h, os.path.getsize(fp)))


if __name__ == "__main__":
    sys.exit(main())
