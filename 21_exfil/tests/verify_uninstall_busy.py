#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
卸载清痕守卫：rm 失败必须计入 fail，不能报"成功"。

背景（真实事故，非推演）：
  真 systemd 环境下做卸载实测时发现，rm -rf 失败只往 stderr 吐一行
  "Device or resource busy"，而 uninstall 的计数仍是"成功 3 失败 0"。
  残留的恰恰是 $CONF_DIR（含主密钥与 C2 地址）——整套痕迹里最敏感的一条。
  部署方看到的却是卸载成功。

  真实成因不止挂载点一种：目录被进程占用、只读挂载、权限不足，都会让 rm 失败，
  而它们恰好都发生在"最需要清痕"的时刻。

正向断言：
  F1  把 conf/lib 目录变成挂载点后，uninstall 必须报"失败 >= 1"
  F2  输出必须点名"残留"，让运维看得见留下了什么
  F3  卸载后 conf 目录确实还在（证明 F1 不是误报）
  F4  解除挂载后重跑 uninstall，失败数归 0
  F5  解除挂载后 conf 目录确实消失

反向断言（不做就是恒绿）：
  R1  退回缺陷实现后，同一场景下 uninstall 报"失败 0"（即静默成功）
"""
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
ROOT = os.path.dirname(REPO)
TEMPLATE = os.path.join(REPO, "onekey.sh")
# 不可省：onekey.sh 是模板，内嵌区是占位符，直接跑必然"内嵌产物为空"。
# 必须经 make_onekey.py 注入真实二进制；且反向验证要改的是生成物，绝不能改模板。
ONEKEY = os.environ.get("ONEKEY_GEN") or ""

passed = 0
failed = 0


def check(cond, name, detail=""):
    global passed, failed
    if cond:
        print("[OK]   %s" % name)
        passed += 1
    else:
        print("[FAIL] %s  %s" % (name, detail))
        failed += 1


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=120, **kw)


def main():
    global ONEKEY
    if not os.path.exists(TEMPLATE):
        print("[FATAL] 找不到模板: %s" % TEMPLATE)
        return 1
    if not ONEKEY:
        camd = os.path.join(ROOT, "agent_windows", "build", "linux", "camd")
        if not os.path.exists(camd):
            print("[FATAL] 缺少 camd（%s），先 make -C agent_windows" % camd)
            return 1
        tmpd = tempfile.mkdtemp(prefix="onekey-gen-")
        ONEKEY = os.path.join(tmpd, "ok.sh")
        g = run(["python3", os.path.join(REPO, "make_onekey.py"),
                 "amd64=" + camd, "-o", ONEKEY])
        if g.returncode != 0:
            print("[FATAL] 生成一键脚本失败\n%s" % g.stdout[-800:])
            return 1

    prefix = tempfile.mkdtemp(prefix="uninst-busy-")
    conf_dir = os.path.join(prefix, "etc", "sysupdate")
    lib_dir = os.path.join(prefix, "var", "lib", "sysupdate")

    try:
        env = dict(os.environ)
        env["PREFIX"] = prefix
        env["NAME"] = "sysupdate"

        # 安装到假根
        r = run(["sh", ONEKEY, "install", "--c2", "127.0.0.1:1", "--backend", "v4l2"], env=env)
        if r.returncode != 0:
            print("[FATAL] install 失败 rc=%d\n%s" % (r.returncode, r.stdout[-1500:]))
            return 1

        # 制造"删不掉"：把两个目录变成挂载点（真实成因之一）
        for d in (conf_dir, lib_dir):
            os.makedirs(d, exist_ok=True)
        mounted = []
        for d in (conf_dir, lib_dir):
            p = run(["mount", "-t", "tmpfs", "tmpfs", d])
            if p.returncode == 0:
                mounted.append(d)
        if len(mounted) < 2:
            print("[FATAL] 无法挂载 tmpfs，守卫无法复现场景 rc=%s" %
                  [p.returncode for p in (p,)])
            return 1

        r = run(["sh", ONEKEY, "uninstall"], env=env)
        out = r.stdout + r.stderr

        check("失败" in out and _fail_count(out) >= 1,
              "F1 删不掉时 uninstall 必须计入失败", "输出: %s" % out.strip()[-300:])
        check("残留" in out,
              "F2 必须点名残留项", "输出: %s" % out.strip()[-300:])
        check(os.path.isdir(conf_dir),
              "F3 卸载后 conf 目录确实还在（证明 F1 不是误报）")
        check(_fail_count(out) >= 1 and "文件与二进制已清理" not in out,
              "F4 不得同时报'文件与二进制已清理'（那是自相矛盾的成功）",
              "输出: %s" % out.strip()[-300:])

        for d in mounted:
            run(["umount", d])

        r2 = run(["sh", ONEKEY, "uninstall"], env=env)
        out2 = r2.stdout + r2.stderr
        check(_fail_count(out2) == 0,
              "F5 解除挂载后重跑，失败数归 0", "输出: %s" % out2.strip()[-300:])
        check(not os.path.exists(conf_dir),
              "F6 解除挂载后 conf 目录确实消失")

        # ---- 反向：退回缺陷实现 ----
        bak = ONEKEY + ".busybak"
        shutil.copyfile(ONEKEY, bak)
        try:
            with open(ONEKEY, "r", encoding="utf-8") as f:
                src = f.read()
            marker = '    log FAIL "文件清理未完成，残留:$_left"'
            if marker not in src:
                print("[FATAL] 找不到修复标记，无法做反向验证")
                return 1
            # 变体：把残留判定整块换成无条件 OK（即缺陷实现）
            start = src.index('    _left=""')
            end = src.index('    fi\n', src.index('        OK "文件与二进制已清理"')) + len('    fi\n')
            mutant = src[:start] + '    OK "文件与二进制已清理"\n' + src[end:]
            with open(ONEKEY, "w", encoding="utf-8") as f:
                f.write(mutant)

            # 重新制造场景
            for d in (conf_dir, lib_dir):
                os.makedirs(d, exist_ok=True)
                run(["mount", "-t", "tmpfs", "tmpfs", d])
            r3 = run(["sh", ONEKEY, "uninstall"], env=env)
            out3 = r3.stdout + r3.stderr
            check(_fail_count(out3) == 0,
                  "R1 退回缺陷实现后应静默报成功（证明 F1 有鉴别力）",
                  "实际 fail=%d 输出: %s" % (_fail_count(out3), out3.strip()[-300:]))
            for d in (conf_dir, lib_dir):
                run(["umount", d], **{})
        finally:
            shutil.copyfile(bak, ONEKEY)
            os.remove(bak)

    finally:
        for d in (conf_dir, lib_dir):
            subprocess.run(["umount", d], capture_output=True)
        shutil.rmtree(prefix, ignore_errors=True)

    print("\n总计: %d 通过, %d 失败" % (passed, failed))
    return 0 if failed == 0 else 1


def _fail_count(out):
    for line in out.splitlines():
        if line.startswith("计数:"):
            try:
                return int(line.split("失败")[1].split()[0])
            except (IndexError, ValueError):
                return -1
    return -1


if __name__ == "__main__":
    sys.exit(main())
