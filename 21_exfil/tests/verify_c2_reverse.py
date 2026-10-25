#!/usr/bin/env python3
"""setup-c2.sh 反向验证：证明守卫不是恒绿的。

每一条都注入一个真实故障，断言运维命令**必须**变红。只跑正向（start 成功、
收到字节）证明不了任何事——恒绿守卫看起来和健康守卫一模一样。

  R1 端口被占 → start 必须失败，绝不能"看似在听"
  R2 stop 之后 camd 再发 → 收端必须是 0 字节（证明 stop 真的停了）
  R3 TLS 模式下明文客户端 → 必须被拒（证明 TLS 真的生效，不是摆设）
"""
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SETUP = os.path.join(HERE, "..", "setup-c2.sh")
CAMD = "/data/workspace/dayanjing/agent_windows/build/linux/camd"
KEY = "000102030405060708090a0b0c0d0e0f" + "101112131415161718191a1b1c1d1e1f"

fails = []


def check(cond, msg):
    print(("  [PASS] " if cond else "  [FAIL] ") + msg)
    if not cond:
        fails.append(msg)


def free_port(base=23000):
    for i in range(200):
        p = base + i
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", p))
            return p
        except OSError:
            pass
        finally:
            s.close()
    raise RuntimeError("no free port")


def r1_port_busy():
    print("\n--- R1 端口被占，start 必须失败 ---")
    port = free_port()
    # 用普通 socket 占住端口，模拟"环境里已有别的服务"
    holder = socket.socket()
    holder.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    holder.bind(("127.0.0.1", port))
    holder.listen(1)
    try:
        T = tempfile.mkdtemp()
        env = dict(os.environ)
        env["PORT"] = str(port)
        env["OUT"] = os.path.join(T, "inbox")
        r = subprocess.run(["sh", SETUP, "start"], capture_output=True, timeout=40, env=env)
        print("start rc=%d" % r.returncode)
        print("stderr: %s" % r.stderr.decode(errors="replace").strip()[:200])
        check(r.returncode != 0, "端口被占时 start 必须失败（不得留下'看似在听'的假象）")
        check("占用" in r.stderr.decode(errors="replace"), "失败原因应点名端口占用")
        # 关键：不得留下 PID 文件，否则后续 stop 会去杀别人的进程
        pf = os.path.join(T, "inbox", "c2.pid")
        check(not os.path.exists(pf), "失败后不得留下 PID 文件（否则 stop 会杀错进程）")
        shutil.rmtree(T, ignore_errors=True)
    finally:
        holder.close()


def r2_stopped_no_data():
    print("\n--- R2 stop 之后，camd 再发必须是 0 字节 ---")
    port = free_port(23100)
    T = tempfile.mkdtemp()
    inbox = os.path.join(T, "inbox")
    root = os.path.join(T, "root")
    os.makedirs(root, exist_ok=True)
    env = dict(os.environ)
    env["PORT"] = str(port)
    env["OUT"] = inbox

    r = subprocess.run(["sh", SETUP, "start"], capture_output=True, timeout=40, env=env)
    if r.returncode != 0:
        check(False, "前置：start 应成功")
        shutil.rmtree(T, ignore_errors=True)
        return
    subprocess.run(["sh", SETUP, "stop"], capture_output=True, timeout=30, env=env)
    # 确认真的停了
    s = socket.socket()
    s.settimeout(1)
    alive = True
    try:
        s.connect(("127.0.0.1", port))
    except Exception:
        alive = False
    finally:
        s.close()
    check(not alive, "stop 后端口不可连接")

    p = subprocess.run([CAMD, "--sink", "tcp://127.0.0.1:%d" % port, "--backend", "mock",
                        "--key", KEY, "--root", root, "--batches", "1", "--frames", "1"],
                       capture_output=True, timeout=60)
    print("camd rc=%d（无收端时建连失败，预期非 0）" % p.returncode)
    check(p.returncode != 0, "无收端时 camd 必须失败，不得静默'成功'")
    shutil.rmtree(T, ignore_errors=True)


def r3_tls_rejects_plain():
    print("\n--- R3 TLS 模式下明文客户端必须被拒 ---")
    T = tempfile.mkdtemp()
    cert = os.path.join(T, "cert.pem")
    key = os.path.join(T, "key.pem")
    r = subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=c2"],
        capture_output=True, timeout=60)
    if r.returncode != 0:
        print("[SKIP] 无法生成自签证书：%s" % r.stderr.decode(errors="replace")[:150])
        shutil.rmtree(T, ignore_errors=True)
        return

    port = free_port(23200)
    inbox = os.path.join(T, "inbox")
    env = dict(os.environ)
    env["PORT"] = str(port)
    env["OUT"] = inbox

    r = subprocess.run(["sh", SETUP, "start", "--cert", cert, "--key", key],
                       capture_output=True, timeout=40, env=env)
    print("start(TLS) rc=%d" % r.returncode)
    print(r.stdout.decode(errors="replace").strip()[:200])
    if r.returncode != 0:
        check(False, "前置：TLS start 应成功")
        shutil.rmtree(T, ignore_errors=True)
        return

    # 明文客户端：送一段随机字节，服务端做 TLS 握手必然失败，
    # 因此收端必须**一个字节都没记进账**。
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        s.sendall(os.urandom(2048))
        time.sleep(0.6)
        s.close()
    except Exception as e:
        print("明文连接异常: %r" % e)

    lg = os.path.join(inbox, "c2.log")
    logged = ""
    if os.path.exists(lg):
        logged = open(lg, errors="replace").read()
    check("TLS 握手失败" in logged, "明文客户端应被记为 TLS 握手失败（证明 TLS 真生效）")

    stp = os.path.join(inbox, "stats.json")
    if os.path.exists(stp):
        import json
        st = json.load(open(stp))
        print("明文尝试后统计: 字节=%d 连接=%d" % (st.get("total_bytes", 0),
                                                st.get("connections", 0)))
        check(st.get("total_bytes", 0) == 0,
              "明文数据不得计入收端（TLS 必须挡住非 TLS 客户端）")
    else:
        check(False, "统计文件应存在")
    subprocess.run(["sh", SETUP, "stop"], capture_output=True, timeout=30, env=env)
    shutil.rmtree(T, ignore_errors=True)


def main():
    print("=== setup-c2.sh 反向验证 ===")
    r1_port_busy()
    r2_stopped_no_data()
    r3_tls_rejects_plain()
    print("\ntotal fail=%d" % len(fails))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
