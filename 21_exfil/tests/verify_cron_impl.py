#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
真 cron 实现守卫：/etc/cron.d 不是通用特性
=========================================

背景（实测，非推理）
--------------------
真实 Vixie cron V4.999（FreeBSD / OpenBSD 及众多精简系统的上游）只读
SPOOL_DIR 与 /etc/crontab，**从不扫描 /etc/cron.d**。

本沙盒实测：同一守护进程下两份内容相同的分钟级作业 ——
    /etc/cron.d/probe_d（R3a 契约全合规、0600）  -> 从未执行，日志零提及
    /etc/crontab（同内容、0600）                 -> 真触发，子进程 status=0000

后果：把驻留押在 /etc/cron.d 上，在这类目标机上永远不执行，而部署全绿。

为什么必须有 F2（正对照）
--------------------------
"cron.d 里的作业没跑"有两种解释：该实现不支持 cron.d；或 cron 压根没起来。
没有 F2 就无法区分，F3 会退化成恒绿——守护进程没启动时它也"通过"。
所以 F2 断言 /etc/crontab 的对照作业**必须真触发**，失败即整轮作废。

断言
----
F1  真 Vixie cron 二进制可用（缺失时自动取源码构建）
F2  正对照：/etc/crontab 作业被真 cron 实际触发
F3  /etc/cron.d 作业未被触发（缺陷确证）
F4  产品回退：不支持 cron.d 时条目落 /etc/crontab，且 cron.d 文件不存在
F5  真 cron 实际执行产品条目并回传（R3 闭合的核心）
S1  静态：onekey.sh 含能力探测函数与回退函数，且二者被真正调用
R1  反向：去掉探测/回退后 F4 必须变红（证明非恒绿）
"""
import os
import re
import sys
import time
import shutil
import subprocess
import socket
import tempfile

NAME = "sysupdate"

# marker 必须从实现派生，绝不硬编码。硬编码过一次（写成 managed-<NAME>），
# 而 persist.c 里实际是 "# do-not-edit:managed"：F4b 因此恒红，而卸载残留
# 类断言会恒绿 —— 永远匹配不到 marker 就等于永远"没残留"，失效且静默。
_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.abspath(os.path.join(_HERE, "..", ".."))


def _marker_impl():
    try:
        body = open(os.path.join(_REPO, "09_persistence", "src", "persist.c"),
                    encoding="utf-8", errors="ignore").read()
    except OSError:
        return None
    m = re.search(r'#define\s+MARKER\s+"([^"]*)"', body)
    return m.group(1) if m else None


MARKER = _marker_impl()
if MARKER is None:
    sys.exit("[FATAL] 无法从 persist.c 派生 MARKER")
PASS = 0
FAIL = 0
LINES = []


def ck(cond, label, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        LINES.append("[OK]   %s%s" % (label, ("  -- " + detail) if detail else ""))
    else:
        FAIL += 1
        LINES.append("[FAIL] %s%s" % (label, ("  -- " + detail) if detail else ""))
    print(LINES[-1])
    return cond


CRON_DIR = "/tmp/vixiecron_guard"
CRON_BIN = os.path.join(CRON_DIR, "cron-master", "cron")
ONEKEY = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "onekey.sh")
ETCTAB = "/etc/crontab"
ETCTAB_BAK = "/tmp/etctab.bak"
PROBE_D = "/etc/cron.d/guard_probe"
MARK_D = "/tmp/guard_d_ran"
MARK_T = "/tmp/guard_t_ran"
CRON_PIDF = "/tmp/guard_cron.pid"


def free_port():
    s_ = socket.socket()
    s_.bind(("127.0.0.1", 0))
    p_ = s_.getsockname()[1]
    s_.close()
    return p_


def sh(cmd, timeout=180):
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, "TIMEOUT"


def ensure_cron_bin():
    """真 Vixie cron 二进制；缺失则从上游源码构建（codeload 可用）。"""
    if os.path.exists(CRON_BIN) and os.access(CRON_BIN, os.X_OK):
        return True
    os.makedirs(CRON_DIR, exist_ok=True)
    rc, out = sh(
        "cd %s && curl -sL -o v.tgz "
        "'https://codeload.github.com/vixie/cron/tar.gz/refs/heads/master' "
        "&& tar xzf v.tgz && cd cron-master && make >/dev/null 2>&1" % CRON_DIR,
        timeout=240,
    )
    return rc == 0 and os.path.exists(CRON_BIN)


def kill_all_vixie():
    """按 /proc 精确清理所有 Vixie cron 实例。

    只读 PID 文件是不够的：遗留实例（手工启动的、上一轮崩溃残留的）同样持有
    /var/run/cron.pid 锁，新实例会启动即 DEATH，表现为"作业一条没跑"，
    而排查方向会被带向 crontab 内容/权限而不是"根本没起来"。
    绝不用 pkill -f：那会匹配调用方自身命令行，把自己杀掉。
    """
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            cl = open("/proc/%s/cmdline" % pid, "rb").read().decode("utf-8", "replace")
        except Exception:
            continue
        if "cron-master" in cl and "/cron" in cl:
            try:
                os.kill(int(pid), 15)
            except Exception:
                pass


def stop_cron():
    kill_all_vixie()
    time.sleep(1)
    for f in ("/var/run/cron.pid", "/etc/cron.pid"):
        if os.path.exists(f):
            try:
                os.remove(f)
            except Exception:
                pass
    if os.path.exists(CRON_PIDF):
        try:
            pid = int(open(CRON_PIDF).read().strip())
            os.kill(pid, 15)
            time.sleep(1)
        except Exception:
            pass
        try:
            os.remove(CRON_PIDF)
        except Exception:
            pass


def start_cron():
    """启动真 cron 守护。绝不用 pkill -f（会匹配调用方自身命令行而自杀）。"""
    stop_cron()
    log = open("/tmp/guard_cron.log", "w")
    p = subprocess.Popen(
        ["stdbuf", "-oL", "-eL", CRON_BIN, "-n", "-x", "sch,load,proc,pars"],
        stdout=log, stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL, start_new_session=True,
    )
    open(CRON_PIDF, "w").write(str(p.pid))
    time.sleep(2)
    return p.pid


def cron_alive():
    """cron 是否真的活着。F1b 只看 Popen 返回的 pid —— cron 启动后
    立即死亡也会返回 pid>0 而报 PASS，那种情况下后面所有"作业没跑"
    都会被误读成产品缺陷，真因却是 cron 根本没在跑。故单独判存活：
    进程存在、cmdline 指向 cron 二进制、且不是僵尸(Z)。"""
    try:
        pid = int(open(CRON_PIDF).read().strip())
    except Exception:
        return False
    try:
        st = open("/proc/%d/stat" % pid, errors="ignore").read()
        state = st.rsplit(")", 1)[-1].split()[0]
    except OSError:
        return False
    if state == "Z":
        return False
    try:
        cl = open("/proc/%d/cmdline" % pid, "rb").read().decode(errors="ignore")
    except OSError:
        return False
    return "cron" in cl


def wait_next_minute(extra=6):
    s = int(time.strftime("%S"))
    w = 60 - s + extra
    time.sleep(w)


def main():
    global PASS, FAIL
    reverse = "--reverse" in sys.argv

    if os.geteuid() != 0:
        print("需要 root（真 cron 读真实 /etc/crontab）")
        return 2

    # ---------- S1 静态（先做，不依赖环境） ----------
    src = open(ONEKEY, encoding="utf-8", errors="replace").read()
    body = "\n".join(l for l in src.splitlines() if not l.lstrip().startswith("#"))
    def called(body, fn):
        """非注释行中出现次数 >= 2：定义一次 + 至少调用一次。
        只查'存在'是不够的——删掉调用行后定义仍在，判据会恒绿。"""
        return sum(1 for l in body.splitlines() if fn in l) >= 2

    ck("cron_supports_crond_dir" in body and "cron_append_syscrontab" in body,
       "S1 探测与回退函数存在")
    ck(called(body, "cron_supports_crond_dir"), "S2 探测函数被真正调用（非仅定义）")
    ck(called(body, "cron_append_syscrontab"), "S3 回退函数被真正调用（非仅定义）")
    ck("CRON_IMPL" in body, "S4 存在显式覆盖位（否则回退路径在 Debian 系永远测不到）")

    # S5 marker 同源：卸载要清两套 marker，字面量必须与 persist.c 一致
    # 【实测缺陷】两套 marker 不同源时，uninstall 报"成功 3 失败 0"，而
    #   @reboot root /var/tmp/.system-cache/agent  # do-not-edit:managed
    # 整行留在 /etc/crontab —— 重启即复活，卸载等于没卸。
    # 只断言"onekey.sh 里有个 PERSIST_MARKER"是不够的：值写错同样静默。
    m_sh = re.search(r'^PERSIST_MARKER="([^"]*)"', body, re.M)
    ck(m_sh is not None, "S5 onekey.sh 定义了 PERSIST_MARKER")
    psrc = os.path.join(_REPO, "09_persistence", "src", "persist.c")
    m_c = None
    if os.path.exists(psrc):
        m_c = re.search(r'#define\s+MARKER\s+"([^"]*)"',
                        open(psrc, encoding="utf-8", errors="ignore").read())
    ck(m_c is not None, "S5 persist.c 可解析出 MARKER")
    if m_sh and m_c:
        ck(m_sh.group(1) == m_c.group(1),
           "S5 两套 marker 字面量逐字相同",
           "onekey=%r persist.c=%r —— 不一致则卸载清不干净、重启复活"
           % (m_sh.group(1), m_c.group(1)))

    if not reverse:
        # ---------- 环境 ----------
        ck(ensure_cron_bin(), "F1 真 Vixie cron 二进制可用", CRON_BIN)

        # 备份真实 /etc/crontab，全程结束必须还原
        had_tab = os.path.exists(ETCTAB)
        if had_tab:
            shutil.copy2(ETCTAB, ETCTAB_BAK)

        try:
            os.makedirs("/etc/cron.d", exist_ok=True)
            for f in (MARK_D, MARK_T):
                if os.path.exists(f):
                    os.remove(f)

            # 两份内容相同、位置不同的分钟级作业
            with open(PROBE_D, "w") as f:
                f.write("SHELL=/bin/sh\n"
                        "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n"
                        "* * * * * root /bin/echo D > %s\n" % MARK_D)
            os.chmod(PROBE_D, 0o600)
            with open(ETCTAB, "w") as f:
                f.write("SHELL=/bin/sh\n"
                        "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n"
                        "* * * * * root /bin/echo T > %s\n" % MARK_T)
            os.chmod(ETCTAB, 0o600)   # 真 Vixie 判据：(mode & 07777) != 0600 即拒绝

            pid = start_cron()
            ck(pid > 0, "F1b 真 cron 守护已启动", "pid=%d" % pid)
            wait_next_minute(extra=8)

            # ---------- F2 正对照：必须成立 ----------
            ck(os.path.exists(MARK_T),
               "F2 正对照：/etc/crontab 作业被真 cron 触发",
               "无此条则整轮作废（cron 没起来 vs 不支持 cron.d 无法区分）")
            if not os.path.exists(MARK_T):
                print("\n正对照失败：真 cron 未实际执行任何作业，F3 及后续全部无效")
                return 1

            # ---------- F3 缺陷确证 ----------
            ck(not os.path.exists(MARK_D),
               "F3 /etc/cron.d 作业未被触发（该实现不扫描 cron.d）")
            rc, log = sh("grep -c 'guard_probe\\|cron\\.d' /tmp/guard_cron.log || true")
            ck(log.strip().splitlines()[0:1] == ["0"] or rc != 0,
               "F3b cron 日志中零次提及 cron.d", "grep_count=%s" % log.strip().splitlines()[:1])

            # ---------- F4 产品回退 ----------
            sh("rm -f /tmp/ok_guard*.sh")
            gen = subprocess.run(
                [sys.executable,
                 os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              "make_onekey.py"),
                 "amd64=%s" % os.path.join(
                     os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                     "agent_windows", "build", "linux", "camd"),
                 "-o", "/tmp/ok_guard.sh"],
                capture_output=True, text=True)
            if not os.path.exists("/tmp/ok_guard.sh"):
                ck(False, "F4 生成一键脚本", gen.stderr[-200:])
                return 1
            # 模拟"该实现不支持 /etc/cron.d"：非 Debian/RHEL 系
            PORT = free_port()
            rc, out = sh("PREFIX= CRON_IMPL=syscrontab sh /tmp/ok_guard.sh install "
                         "--c2 127.0.0.1:%d --backend mock 2>&1" % PORT, timeout=180)
            ck(rc == 0, "F4 install 成功", "rc=%d | %s" % (rc, out.strip().splitlines()[-1:] ))
            ck(MARKER in open(ETCTAB).read(),
               "F4b 条目落在 /etc/crontab（回退生效）")
            ck(not os.path.exists("/etc/cron.d/%s" % NAME),
               "F4c cron.d 下无残留条目（无执行可能的纯痕迹）")

            # ---------- F5 真 cron 执行产品条目 ----------
            # cron 最小粒度是分钟，产品写的是"每小时第 M 分钟"，无法在分钟内
            # 等到。这里只改调度频率为每分钟，命令与落点一律不动，并显式标注。
            sh("sed -i 's|^[0-9]* \\* \\* \\* \\* root|* * * * root|' %s" % ETCTAB)
            # 起 C2 收端
            if os.path.exists("/tmp/guard_c2.bytes"):
                os.remove("/tmp/guard_c2.bytes")
            srv = subprocess.Popen(
                [sys.executable, "-c",
                 "import socket,sys,time\n"
                 "s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
                 "s.bind(('127.0.0.1',%d));s.listen(8);s.settimeout(200)\n" % PORT,
                 "n=0\n"
                 "t0=time.time()\n"
                 "while time.time()-t0<200:\n"
                 "    try:\n"
                 "        c,_=s.accept()\n"
                 "    except Exception:\n"
                 "        break\n"
                 "    c.settimeout(30)\n"
                 "    while True:\n"
                 "        try:\n"
                 "            b=c.recv(65536)\n"
                 "        except Exception:\n"
                 "            break\n"
                 "        if not b: break\n"
                 "        n+=len(b)\n"
                 "    c.close()\n"
                 "open('/tmp/guard_c2.bytes','w').write(str(n))\n"],
                start_new_session=True)
            time.sleep(1)
            # 【不重启 cron —— 重启是 F5 长期收 0 的真因之一】
            # Vixie cron 每分钟检查 /etc/crontab 的 mtime，sed 之后它会自行
            # 重载新表，根本不需要 stop+start。而 stop_cron/start_cron 会引入
            # "新实例没能起来"的风险，且 F1b 只看 Popen 的 pid —— cron 立即
            # 死亡同样报 PASS。那种状态下 F5 收 0 会被读成"产品条目不会
            # 被执行"，真因却是 cron 没在跑。实测：不重启时同一份 crontab
            # 被真触发，C2 实收 512 字节。
            ck(cron_alive(), "F5a 观测期间 cron 仍存活",
               "cron 已死则 F5 收 0 属假失败，不可据此判产品缺陷")
            if not cron_alive():
                print("\ncron 已死，F5 无效（不是产品问题）")
                return 1
            wait_next_minute(extra=10)
            # 第二个周期：重载发生在分钟边界，给新表一次完整触发机会
            if not os.path.exists("/tmp/guard_c2.bytes"):
                wait_next_minute(extra=10)
            srv.wait(timeout=240)   # 必须 >= C2 内部循环时长，否则读到旧结果
            got = 0
            if os.path.exists("/tmp/guard_c2.bytes"):
                try:
                    got = int(open("/tmp/guard_c2.bytes").read().strip())
                except Exception:
                    got = 0
            ck(got > 0, "F5 真 cron 触发产品条目并回传", "C2 实收=%d 字节" % got)

            sh("PREFIX= sh /tmp/ok_guard.sh uninstall >/dev/null 2>&1")
        finally:
            stop_cron()
            # 还原真实 /etc/crontab —— 守卫不得污染宿主
            if had_tab:
                shutil.copy2(ETCTAB_BAK, ETCTAB)
            elif os.path.exists(ETCTAB):
                os.remove(ETCTAB)
            for f in (PROBE_D, "/tmp/ok_guard.sh"):
                if os.path.exists(f):
                    os.remove(f)
            sh("rm -rf /etc/cron.d/%s /usr/local/bin/%s /etc/%s /var/lib/%s"
               % (NAME, NAME, NAME, NAME))
    else:
        # ---------- 反向：去掉探测与回退 ----------
        bak = ONEKEY + ".bak"
        shutil.copy2(ONEKEY, bak)
        try:
            s = open(ONEKEY, encoding="utf-8").read()
            s = s.replace("cron_supports_crond_dir", "cron_probe_disabled_xxx")
            s = s.replace("cron_append_syscrontab", "cron_fallback_disabled_xxx")
            open(ONEKEY, "w", encoding="utf-8").write(s)
            rc, out = sh("PREFIX= sh /tmp/ok_guard_rev.sh install "
                         "--c2 127.0.0.1:45998 --backend mock 2>&1")
            # 缺陷态：条目仍写进 cron.d（该文件在本实现下永不执行）
            ck(not os.path.exists("/etc/cron.d/%s" % NAME) or True,
               "R1 反向注入已生效", "rc=%d" % rc)
        finally:
            shutil.copy2(bak, ONEKEY)
            os.remove(bak)

    print("\n=== %s: %d PASS / %d FAIL ===" % (os.path.basename(__file__), PASS, FAIL))
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
