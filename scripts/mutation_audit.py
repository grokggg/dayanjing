#!/usr/bin/env python3
"""
变异审计（常态化）：把"此前声称已修复"的缺陷逐个变异回退，验证测试是否真能捕获。

  CAUGHT   = 测试失败/挂起 -> 修复真的被防回归保护住了
  SURVIVED = 测试仍全绿    -> 该用例证明不了任何事，是真实缺口
  ERROR    = 变异没生效/构建失败/锚点失效 -> 审计本身失效，必须修脚本

设计要点（都是此前用代价换来的）：

1. 锚点失效不再是 SKIP，而是 ERROR。
   变异锚点会随代码演进失效。若像旧版那样记 SKIP，这个变异就永久腐烂，
   而报告上永远"0 存活"——表面一切正常，实际审计面在缩小。这是静默降级。

2. 变异必须校验"真的改了"。
   只判断 old 在不在源码里不够：replace 可能命中注释、可能命中另一处。
   改为校验文件哈希确实变化，并对锚点做唯一性检查。

3. 恢复必须用 git 校验。
   旧版用 .mutbak 覆盖回去，若中途被杀会留下变异代码，下一次构建就带着缺陷。
   改为 finally 中恢复后比对 git hash-object，不一致即报错。

4. 挂起不能被当成 CAUGHT。
   subprocess 超时返回 -999，旧版判 CAUGHT —— 碰巧对了，但报告里看不出是挂起
   还是真失败，会掩盖"测试挂起且无人知晓"。单独记 HANG。

5. 工作区必须干净。
   变异会改源码再恢复。若有未提交改动，恢复会把它一起弄丢。

用法：
  python3 scripts/mutation_audit.py            # 全量
  python3 scripts/mutation_audit.py --sample 2 # 抽样（常态化用，控制耗时）
  python3 scripts/mutation_audit.py --only M1,M4
"""
import os, sys, shutil, subprocess, hashlib, random

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ---------------------------------------------------------------- 变异集合
# old 必须是**实现中的真实代码行**，不能是注释里的文字。
# unique=False 时表示源码中有多处，全部替换（all_occurrences）。
MUTATIONS = [
    {
        "id": "M1",
        "desc": "25_deploy: 关闭组装摘要校验（篡改的制品也能 seal）",
        "file": "25_deploy/src/drop.c",
        "old": "if (crypto_constant_time_eq(d, a->digest, DP_DIGEST_LEN) == 0)",
        "new": "if (0)",
        "mod": "25_deploy",
        "bin": "build/test_drop",
    },
    {
        "id": "M2",
        "desc": "19_defense: ptrace 回退为在调用进程自身执行（植入体自伤挂死）",
        "file": "19_defense/src/debug.c",
        "old": "pid = fork();",
        "new": "pid = 0;",
        "mod": "19_defense",
        "bin": "build/test_defense",
    },
    {
        "id": "M3",
        "desc": "20_packer: 入口 nop 垫恒为 0（首字节变回跨构建恒定签名）",
        "file": "20_packer/src/poly.c",
        "old": "int npad = (int)rnd(p, 3);",
        "new": "int npad = 0;",
        "mod": "20_packer",
        "bin": "build/test_poly",
        "all_occurrences": True,
    },
    {
        "id": "M4",
        "desc": "25_deploy: 未 seal 也允许组装（投送不全就执行）",
        "file": "25_deploy/src/drop.c",
        "old": "if (!a->sealed) return DP_ERR_INCOMPLETE;",
        "new": "if (0)",
        "mod": "25_deploy",
        "bin": "build/test_drop",
    },
    {
        "id": "M5",
        "desc": "agent_windows: 去掉对抗闸门（不安全环境也会采集/回传/驻留）",
        "file": "agent_windows/src/implant_main.c",
        "old": "if (h->defend(h->defend_ud) != 0) return IMW_ERR_UNSAFE;",
        "new": "if (0)",
        "mod": "agent_windows",
        "bin": "build/winshim/test_implant_main",
        # 必须显式指定：agent_windows 的默认目标 all 只建 $(TEST_BINS)，
        # 不含 winshim。不指定的话审计跑的是陈旧二进制，结果毫无意义
        # （曾据此得出 M5 SURVIVED 的假结论）。
        #
        # 用 winshim-build 而不是 winshim：后者在 recipe 里直接跑测试，
        # 变异生效时 make 非零退出，会被记成"构建失败"而非 CAUGHT ——
        # 把"测试抓到了"掩盖成"构建坏了"。这里要的是测试结果由 run_one
        # 独立判定，所以只建不跑。
        "target": "winshim-build",
    },
    {
        "id": "M6",
        "desc": "17_loader: PE32+ TLS 回调偏移改回 +20（TLS 回调静默丢失）",
        "file": "17_loader/src/reflect.c",
        "old": "cb_va = ld_rd64(img->buf + off + 24u);",
        "new": "cb_va = ld_rd64(img->buf + off + 20u);",
        "mod": "17_loader",
        "bin": "build/test_loader",
    },
]


def sh(cmd, cwd, timeout=900):
    try:
        p = subprocess.run(cmd, shell=True, cwd=cwd, timeout=timeout,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return p.returncode, p.stdout.decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        return -999, ""


def heal():
    """启动时自愈：恢复上一次被强杀留下的变异。

    finally 在 SIGKILL 下不执行——实测中进程被杀后 .mutbak 与变异代码同时
    留在工作区，下一次构建就带着人为注入的缺陷跑，且无人知晓。
    所以每次启动先扫一遍残留备份并还原。
    """
    healed = []
    for dirpath, _dirs, files in os.walk(ROOT):
        if "/.git" in dirpath or "/build" in dirpath:
            continue
        for fn in files:
            if fn.endswith(".mutbak"):
                bak = os.path.join(dirpath, fn)
                orig = bak[: -len(".mutbak")]
                shutil.move(bak, orig)
                healed.append(os.path.relpath(orig, ROOT))
    return healed


def files_clean(files):
    """只校验将被变异的文件本身干净。

    早期版本要求整个工作区干净，结果审计脚本自己没提交就跑不起来——
    守卫反而挡住了正常使用。真正需要保护的是变异目标文件：它有未提交
    改动时，审计产生的构建产物会被误认为对应那份改动。
    """
    dirty = []
    for f in files:
        rc, out = sh("git status --porcelain -- '%s'" % f, ROOT, 60)
        if rc != 0 or out.strip():
            dirty.append(f)
    return dirty


def blob_hash(path):
    """用 git 的对象哈希，与仓库判定一致，避免自己算错。"""
    rc, out = sh("git hash-object '%s'" % path, ROOT, 60)
    return out.strip() if rc == 0 else None


def build(mod, target=None):
    d = os.path.join(ROOT, mod)
    # 不 clean：变异只改一个 .c，增量重建即可。
    # 旧版每次 make clean 是全量重编，是上一轮审计超时的直接原因。
    cmd = "make -s %s 2>&1 | tail -8" % target if target else "make -s 2>&1 | tail -8"
    rc, out = sh(cmd, d, 900)
    return rc, out


def run_one(m):
    path = os.path.join(ROOT, m["file"])
    if not os.path.exists(path):
        return (m["id"], "ERROR", "文件不存在（变异集合已腐烂）")

    with open(path, "r", encoding="utf-8") as f:
        src = f.read()

    n = src.count(m["old"])
    if n == 0:
        return (m["id"], "ERROR", "锚点失效：未找到 %r —— 变异已不再测任何东西" % m["old"][:50])
    if n > 1 and not m.get("all_occurrences"):
        return (m["id"], "ERROR", "锚点出现 %d 次但未声明 all_occurrences，替换目标不明确" % n)

    before_hash = blob_hash(path)
    bak = path + ".mutbak"
    shutil.copy2(path, bak)
    try:
        mutated = src.replace(m["old"], m["new"]) if m.get("all_occurrences") \
            else src.replace(m["old"], m["new"], 1)
        with open(path, "w", encoding="utf-8") as f:
            f.write(mutated)

        # 校验变异真的生效（哈希必须变）。不校验的话，old==new 之类会让
        # 审计静默变成"什么都没测但报告 CAUGHT"。
        if blob_hash(path) == before_hash:
            return (m["id"], "ERROR", "变异未改变文件内容（old/new 相同？）")

        rc, out = build(m["mod"], m.get("target"))
        if rc != 0:
            return (m["id"], "ERROR", "构建失败: %s" % out.strip()[:160])

        binpath = os.path.join(ROOT, m["mod"], m["bin"])
        if not os.path.exists(binpath):
            return (m["id"], "ERROR", "测试二进制不存在: %s" % m["bin"])

        trc, tout = sh("./" + m["bin"], os.path.join(ROOT, m["mod"]), 600)
        if trc == -999:
            return (m["id"], "HANG", "测试超时无输出 —— 挂起，不是被捕获")
        if not tout.strip():
            return (m["id"], "HANG", "测试零输出 —— 疑似挂起/被杀，退出码 %d 不可信" % trc)
        if trc == 0:
            return (m["id"], "SURVIVED", "测试仍全绿 —— 该缺陷无法被捕获")
        fails = [l for l in tout.splitlines() if "FAIL" in l]
        return (m["id"], "CAUGHT", "失败 %d 项, 例: %s" %
                (len(fails), fails[0][:80].strip() if fails else "rc=%d" % trc))
    finally:
        shutil.move(bak, path)
        after = blob_hash(path)
        if after != before_hash:
            # 恢复失败必须显式报错：否则下一次构建就带着变异代码。
            print("[FATAL] %s 恢复失败: %s -> %s，请检查工作区" % (m["id"], before_hash, after))
            sys.exit(2)


def main():
    h = heal()
    if h:
        print("[HEAL] 恢复了上次被强杀残留的变异: %s" % ", ".join(h))

    args = [a for a in sys.argv[1:]]
    sel = None
    sample = None
    for i, a in enumerate(args):
        if a == "--only" and i + 1 < len(args):
            sel = set(args[i + 1].split(","))
        if a == "--sample" and i + 1 < len(args):
            sample = int(args[i + 1])

    pool = MUTATIONS
    if sel:
        pool = [m for m in pool if m["id"] in sel]
    if sample and sample < len(pool):
        random.seed()  # 每次抽样不同，长期看覆盖全部
        pool = random.sample(pool, sample)

    dirty = files_clean([m["file"] for m in pool])
    if dirty:
        print("[FATAL] 以下文件有未提交改动，变异会造成混淆：%s" % ", ".join(dirty))
        sys.exit(2)

    results = []
    print("=== 变异审计（逐条，超时也能保留已完成部分）===", flush=True)
    for m in pool:
        r = run_one(m)
        results.append(r)
        print("[%-8s] %s : %s" % (r[0], r[1], r[2]), flush=True)

    print("\n=== 变异审计结果 ===")

    survived = [r for r in results if r[1] == "SURVIVED"]
    errors = [r for r in results if r[1] in ("ERROR", "HANG")]
    print("\n存活(用例证明不了任何事) = %d" % len(survived))
    print("审计失效/挂起           = %d" % len(errors))
    print("捕获                    = %d" % len([r for r in results if r[1] == "CAUGHT"]))

    # SURVIVED 是真缺口；ERROR/HANG 是审计或测试基建的问题，同样不能放过。
    sys.exit(1 if (survived or errors) else 0)


if __name__ == "__main__":
    main()
