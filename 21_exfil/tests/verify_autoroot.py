#!/usr/bin/env python3
"""一键脚本回归上下文自动假根 —— 正向 + 反向验证。

背景：真实根污染此前只能事后点名（check_realroot_pollution.py），而污染已经
发生。本守卫验证"未显式 PREFIX + 回归标记 + root"时前置切假根。

判据刻意收窄（见 onekey.sh 注释）：非 root 走 USER_MODE，不在此列。
"""
import os, re, socket, subprocess, sys, tempfile, threading, shutil

ROOT = "/data/workspace/dayanjing"
GUARD = os.path.join(ROOT, "scripts/check_realroot_pollution.py")
NAME = "sysupdate"
CAMD = os.path.join(ROOT, "agent_windows/build/linux/camd")
MAKE_ONEKEY = os.path.join(ROOT, "21_exfil/make_onekey.py")
OK_SH = os.path.join(tempfile.gettempdir(), "ok_autoroot_%d.sh" % os.getpid())

fails = []
def chk(cond, label, detail=""):
    print(("[OK] " if cond else "[FAIL] ") + label + (("  -- " + detail) if detail else ""))
    if not cond:
        fails.append(label)

class C2:
    def __init__(self):
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.port = self.srv.getsockname()[1]
        self.srv.listen(8)
        self.total = 0; self.conns = 0; self.stop = False
        threading.Thread(target=self.loop, daemon=True).start()
    def loop(self):
        while not self.stop:
            try:
                c, _ = self.srv.accept()
            except OSError:
                break
            self.conns += 1
            threading.Thread(target=self.rd, args=(c,), daemon=True).start()
    def rd(self, c):
        try:
            while True:
                b = c.recv(65536)
                if not b:
                    break
                self.total += len(b)
        except Exception:
            pass
        finally:
            c.close()
    def close(self):
        self.stop = True
        try:
            self.srv.close()
        except Exception:
            pass

def genkey():
    return subprocess.run(["od", "-An", "-tx1", "-N32", "/dev/urandom"],
                          stdout=subprocess.PIPE).stdout.decode().replace(" ", "").replace("\n", "")

def guard_rc():
    r = subprocess.run([sys.executable, GUARD], stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, cwd=ROOT)
    return r.returncode, r.stdout.decode(errors="replace")

def run(cmd, env_extra=None, uid=None, home=None):
    env = dict(os.environ)
    env.pop("PREFIX", None)
    if env_extra:
        # 值为 None 表示显式清除该变量，而非置为空串。
        # 本守卫自身常在回归入口内运行（入口导出 DAYNANJING_REGRESSION=1），
        # 若 R1 组（生产路径）继承了它，install 会被自动切成假根：
        # R1-b 判"未触发自动假根"必然失败，且真实根从未被污染 -> R1-c
        # 的守卫 rc 恒为 0、R1-e 天然绿。三处同时失真，而失败信息只指向
        # 断言本身。故"生产路径"必须显式清标记，不能依赖调用方环境。
        for k, v in env_extra.items():
            if v is None:
                env.pop(k, None)
            else:
                env[k] = v
    if home:
        env["HOME"] = home
    if uid is not None:
        cmd = ["setpriv", "--reuid=%d" % uid, "--regid=%d" % uid, "--clear-groups"] + cmd
    return subprocess.run(cmd, env=env, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, timeout=180)

def main():
    if not os.path.exists(CAMD):
        chk(False, "前置: camd 产物存在", CAMD); return 1
    r = subprocess.run([sys.executable, MAKE_ONEKEY, "amd64=" + CAMD, "-o", OK_SH],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if r.returncode != 0:
        chk(False, "前置: 生成一键脚本", r.stdout.decode(errors="replace")[-300:]); return 1
    os.chmod(OK_SH, 0o755)

    key = genkey()

    # ================= 正向：root + 回归标记 + 未指定 PREFIX =================
    print("=== 正向：root + DAYNANJING_REGRESSION（未指定 PREFIX）===")
    c2 = C2()
    r = run(["sh", OK_SH, "install", "--c2", "127.0.0.1:%d" % c2.port,
             "--backend", "v4l2", "--key", key],
            env_extra={"DAYNANJING_REGRESSION": "1"})
    out = r.stdout.decode(errors="replace")
    c2.close()
    chk(r.returncode == 0, "F1 install rc=0", "rc=%d" % r.returncode)
    chk("自动切假根" in out, "F2 触发自动切假根（WARN 可见）")
    m = re.search(r"自动切假根 (\S+)", out)
    chk(bool(m), "F3 能取到自动假根路径")
    pfx = m.group(1) if m else ""
    conf = os.path.join(pfx, "etc/%s/%s.conf" % (NAME, NAME))
    bind = os.path.join(pfx, "usr/local/bin/%s" % NAME)
    chk(os.path.isfile(conf), "F4 假根内配置文件已写入", conf)
    chk(os.path.isfile(bind), "F5 假根内二进制已安装", bind)
    grc, gout = guard_rc()
    # 只打印 rc 时，"守卫报警了"和"守卫为什么报警"是两件事，排查者只看到
    # rc=1，方向被指向 autoroot 自己——而它多半不是污染源。失败必带落点。
    chk(grc == 0, "F6 真实根未被污染（守卫 rc=0）",
        "guard_rc=%d" % grc if grc == 0 else "guard_rc=%d\n%s" % (grc, gout))
    chk(c2.total > 0, "F7 功能未受损：C2 实收字节 > 0", "total=%d conns=%d" % (c2.total, c2.conns))

    # 卸载：同一标记下应派生同一 PREFIX，能清掉
    r = run(["sh", OK_SH, "uninstall"], env_extra={"DAYNANJING_REGRESSION": "1"})
    chk(r.returncode == 0, "F8 uninstall rc=0", "rc=%d" % r.returncode)
    chk(not os.path.exists(conf) and not os.path.exists(bind),
        "F9 卸载后假根内落点已清", "%s / %s" % (conf, bind))
    grc, gout = guard_rc()
    chk(grc == 0, "F10 卸载后真实根仍干净（守卫 rc=0）",
        "guard_rc=%d" % grc if grc == 0 else "guard_rc=%d\n%s" % (grc, gout))

    # ================= 反向 R1：无回归标记 → 必须写真根 ======================
    print("=== 反向 R1：root 且无 DAYNANJING_REGRESSION（生产路径）===")
    c2 = C2()
    r = run(["sh", OK_SH, "install", "--c2", "127.0.0.1:%d" % c2.port,
             "--backend", "v4l2", "--key", key],
            env_extra={"DAYNANJING_REGRESSION": None})
    out = r.stdout.decode(errors="replace")
    c2.close()
    chk(r.returncode == 0, "R1-a install rc=0", "rc=%d" % r.returncode)
    chk("自动切假根" not in out, "R1-b 未触发自动假根（生产部署不得被误切）")
    grc, gout = guard_rc()
    chk(grc == 1, "R1-c 真实根被污染（守卫必须 rc=1 点名）", "guard_rc=%d" % grc)
    r = run(["sh", OK_SH, "uninstall"],
            env_extra={"DAYNANJING_REGRESSION": None})
    chk(r.returncode == 0, "R1-d uninstall rc=0", "rc=%d" % r.returncode)
    grc, _ = guard_rc()
    chk(grc == 0, "R1-e 卸载后真实根恢复干净（守卫 rc=0）", "guard_rc=%d" % grc)

    # ================= 反向 R2：非 root + 标记 → 不得切假根 =================
    print("=== 反向 R2：uid=65534 + 标记（用户级降级不受影响）===")
    home = tempfile.mkdtemp(prefix="uhome")
    os.chmod(home, 0o777)
    c2 = C2()
    r = run(["sh", OK_SH, "install", "--c2", "127.0.0.1:%d" % c2.port,
             "--backend", "v4l2", "--key", key],
            env_extra={"DAYNANJING_REGRESSION": "1"}, uid=65534, home=home)
    out = r.stdout.decode(errors="replace")
    c2.close()
    chk(r.returncode == 0, "R2-a install rc=0", "rc=%d" % r.returncode)
    chk("切换用户级部署" in out, "R2-b 仍走用户级降级（USER_MODE）")
    chk("自动切假根" not in out, "R2-c 非 root 不得被切成假根")
    grc, _ = guard_rc()
    chk(grc == 0, "R2-d 真实根未被污染（守卫 rc=0）", "guard_rc=%d" % grc)
    r = run(["sh", OK_SH, "uninstall"], uid=65534, home=home)
    chk(r.returncode == 0, "R2-e uninstall rc=0", "rc=%d" % r.returncode)
    shutil.rmtree(home, ignore_errors=True)

    print("======== %d 项失败 ========" % len(fails))
    for f in fails:
        print("   " + f)
    return 1 if fails else 0

if __name__ == "__main__":
    sys.exit(main())
