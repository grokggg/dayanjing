#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
守卫：卸载必须清掉 systemd 单元文件，无论 systemd 是否在运行。

为什么必须有这个守卫
--------------------
install 阶段单元文件是照写不误的（渲染 + 静态校验后落盘，与 systemd 是否
运行无关）。而卸载阶段此前把「删单元文件」和「systemctl 是否可用」绑在了
同一个分支里：HAVE_SYSTEMD=0 时整个分支被跳过，单元文件留在盘上，却打印
"systemd 不可用，跳过"——看起来是成功。

卸载的目的就是清除痕迹，而单元文件恰是最显眼的一条：0644，含服务名与
ExecStart 的绝对路径。管理员扫一眼 /etc/systemd/system/ 就能发现异常服务，
而这台机器明明已经"卸载"过了。

最危险的失效形态是"看着干净其实留着"：uninstall 计数 3 成功 0 失败，运维
据此认为无残留。所以本守卫必须真 install 再真 uninstall，然后逐条查落点，
不能只静态扫脚本源码。

判据分两组：
  正向 F*：install → 断言单元确已写入（前提）→ uninstall → 六落点全无
  反向 R*：把「无条件删单元」那一行去掉，退回"只在 HAVE_SYSTEMD=1 分支里
           删"的旧写法，F 组必须变红（否则 F 组是恒绿的）

前提断言不可省：若 install 压根没写单元，"卸载后单元不存在"恒为真，是假阴性。
"""

import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
EXFIL = os.path.dirname(HERE)
ROOT = os.path.dirname(EXFIL)
NAME = "sysupdate"

PASS = []
FAIL = []


def check(cond, name, detail=""):
    if cond:
        PASS.append(name)
        print("[PASS] " + name)
    else:
        FAIL.append(name)
        print("[FAIL] " + name + (("  -- " + detail) if detail else ""))
    return cond


def fatal(msg):
    print("[FATAL] " + msg)
    sys.exit(2)


def find_camd():
    """二进制缺失必须 FATAL。缺产物时若混入通过数，就是拿"没验证"冒充
    "验证通过"。"""
    p = os.path.join(ROOT, "agent_windows/build/linux/camd")
    if os.path.isfile(p) and os.access(p, os.X_OK):
        return p
    return None


def build_onekey(camd, out):
    r = subprocess.run(
        [sys.executable, os.path.join(EXFIL, "make_onekey.py"),
         "amd64=" + camd, "-o", out],
        capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        fatal("生成一键脚本失败: " + (r.stderr or r.stdout).strip()[:200])
    return out


def landing(prefix):
    """六个落点，全部由 PREFIX + NAME 派生。必须用伪装后的真名 sysupdate，
    不能用 camd——伪装生效时旧名一律查不到，会把"没查对"误读成"已清理"。"""
    return {
        "conf_dir": os.path.join(prefix, "etc", NAME),
        "lib_dir": os.path.join(prefix, "var", "lib", NAME),
        "bin": os.path.join(prefix, "usr", "local", "bin", NAME),
        "cron": os.path.join(prefix, "etc", "cron.d", NAME),
        "unit": os.path.join(prefix, "etc", "systemd", "system", NAME + ".service"),
        "lock": os.path.join(prefix, "var", "lock", NAME + ".lock"),
    }


def run(script, *args, timeout=300):
    return subprocess.run(["sh", script] + list(args),
                          capture_output=True, text=True, timeout=timeout)


def main():
    camd = find_camd()
    if not camd:
        fatal("找不到 camd 二进制（agent_windows/build/linux/camd）——"
              "先 make -C agent_windows")

    tmp = tempfile.mkdtemp(prefix="vuu_")
    try:
        good = os.path.join(tmp, "good.sh")
        build_onekey(camd, good)

        # ================= 正向 =================
        pfx = os.path.join(tmp, "root")
        os.makedirs(pfx, exist_ok=True)
        L = landing(pfx)

        r1 = run(good, "install", "--prefix", pfx,
                 "--c2", "127.0.0.1:9", "--backend", "v4l2")
        check(r1.returncode == 0, "F1 install 在假根下成功",
              "rc=%d %s" % (r1.returncode, (r1.stdout or "").strip()[-120:]))
        check(os.path.exists(L["unit"]),
              "F2 前提：install 确实写入了单元文件",
              "单元文件不存在，后续清理断言会是假阴性")
        check(os.path.exists(L["conf_dir"]),
              "F3 前提：install 确实写入了配置目录",
              "配置目录不存在")

        r2 = run(good, "uninstall", "--prefix", pfx)
        check(r2.returncode == 0, "F4 uninstall 成功",
              "rc=%d %s" % (r2.returncode, (r2.stdout or "").strip()[-120:]))

        for key in ("conf_dir", "lib_dir", "bin", "cron", "unit", "lock"):
            p = L[key]
            check(not os.path.exists(p), "F5 卸载后无残留: " + key,
                  "仍存在 " + p)

        # ================= 反向 =================
        # 去掉"无条件删单元"那一行，退回旧写法。
        # 必须精准命中 do_uninstall 函数体内的那一行。
        # 脚本里 rm -f "$UNIT" 不止一处：install 阶段 systemd 驻留失败回滚
        # 也会删单元。若按"全文第一个匹配"注入，删掉的是回滚那处，uninstall
        # 里的清理原封不动，反向验证于是显示"缺陷态也没残留"，守卫看起来
        # 通过了而实际上什么都没验到——这比失败更危险。
        src = open(good, "r", encoding="utf-8", errors="replace").read()
        lines = src.split("\n")
        start = None
        for i, ln in enumerate(lines):
            if ln.startswith("do_uninstall()"):
                start = i
                break
        if start is None:
            fatal("反向注入失败：找不到 do_uninstall 函数")
        removed = 0
        for j in range(start, len(lines)):
            # 判据放宽为前缀匹配：该行加了 2>/dev/null 后缀（卸载失败静默的修复）。
            # 若仍按全等匹配，反向注入永远命中不到，守卫会退化成恒绿——
            # 这正是"工具静默失效而报告一切正常"的典型形态。
            if lines[j].strip().startswith('rm -f "$UNIT"'):
                lines[j] = None
                removed += 1
                break
        if removed == 0:
            fatal("反向注入失败：do_uninstall 内找不到「删单元」那一行，"
                  "守卫无法证明自己有鉴别力")
        out_lines = [ln for ln in lines if ln is not None]
        bad = os.path.join(tmp, "bad.sh")
        open(bad, "w", encoding="utf-8").write("\n".join(out_lines))

        pfx2 = os.path.join(tmp, "root2")
        os.makedirs(pfx2, exist_ok=True)
        L2 = landing(pfx2)
        run(bad, "install", "--prefix", pfx2,
            "--c2", "127.0.0.1:9", "--backend", "v4l2")
        run(bad, "uninstall", "--prefix", pfx2)

        check(os.path.exists(L2["unit"]),
              "R1 缺陷态下单元文件残留",
              "缺陷态却没残留 —— F5 组可能是恒绿的")
        check(os.path.exists(L2["unit"]) and
              not os.path.exists(L["unit"]),
              "R2 守卫确有鉴别力（修复态已清、缺陷态残留）",
              "两种状态下结果相同，说明守卫没在起作用")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("\n--- 计数: 通过 %d  失败 %d ---" % (len(PASS), len(FAIL)))
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
