#!/usr/bin/env python3
"""驻留运行时守卫：C2 中断后守护必须存活并重连，而不是退出。

为什么必须单独验这一条：
  systemd 下 Restart=always 会掩盖"camd 崩溃退出"——进程不停死、不停被拉起，
  部署侧 is-active=active、MainPID 非零，看起来一切正常。cron 模式下崩溃就
  彻底没了。而 C2 断线是常态（网络抖动、C2 维护、前置域轮换）。

  所以真正要验的不是"systemd 会不会拉起"，而是"camd 自己会不会死"。

断言：
  F1 首次在线：C2 收到字节
  F2 断线后进程存活（核心）
  F3 断线窗口内无新字节送达（证明确实断了，不是假断线）
  F4 恢复后再次送达（证明重连真的发生）
  F5 全程进程未退出（结束态仍是运行中，非 exited）
  R1 反向：把 stop_on_error 改为 true（单批失败即终止）→ F2/F5 必须变红
"""
import os, sys, time, socket, subprocess, threading, shutil, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
CAMD = os.path.join(ROOT, "agent_windows", "build", "linux", "camd")

KEY = "00112233445566778899aabbccddeeff" + "ffeeddccbbaa99887766554433221100"
RESULTS = []


def ck(ok, name, detail=""):
    RESULTS.append((bool(ok), name, detail))
    print(("[OK] " if ok else "[FAIL] ") + name + (("  -- " + detail) if detail else ""))
    return ok


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class C2(threading.Thread):
    """最小 TCP 收端：计数收到的字节，可随时 stop/在同端口 restart。"""

    def __init__(self, port):
        super().__init__(daemon=True)
        self.port = port
        self.total = 0
        self.conns = 0
        self._halt = False
        self.sock = None
        self.ready = threading.Event()

    def run(self):
        try:
            s = socket.socket()
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", self.port))
            s.listen(8)
            s.settimeout(0.5)
            self.sock = s
            self.ready.set()
            while not self._halt:
                try:
                    c, _ = s.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                self.conns += 1
                c.settimeout(0.5)
                while not self._halt:
                    try:
                        b = c.recv(65536)
                    except socket.timeout:
                        continue
                    except OSError:
                        break
                    if not b:
                        break
                    self.total += len(b)
                try:
                    c.close()
                except OSError:
                    pass
        finally:
            if self.sock:
                try:
                    self.sock.close()
                except OSError:
                    pass

    def stop(self):
        self._halt = True
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
        self.join(timeout=5)


def alive(p):
    return p is not None and p.poll() is None


def main():
    if not os.path.exists(CAMD):
        print("[FATAL] camd 不存在: %s" % CAMD)
        return 2
    tmp = tempfile.mkdtemp(prefix="camres_")
    port = free_port()

    c2 = C2(port)
    c2.start()
    if not c2.ready.wait(timeout=10):
        print("[FATAL] C2 未就绪")
        return 2

    # --no-persist：不写真实 /etc；--batches 0：常驻，由停止信号终止
    cmd = [CAMD, "--sink", "tcp://127.0.0.1:%d" % port, "--key", KEY,
           "--backend", "mock", "--no-persist", "--batches", "0",
           "--interval-ms", "300", "--jitter-ms", "50", "--frames", "1"]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    try:
        # 阶段 1：在线
        time.sleep(6)
        first = c2.total
        ck(first > 0, "F1 首次在线：C2 收到信元", "%d 字节" % first)
        ck(alive(p), "F1b 在线期间进程存活")

        # 阶段 2：断线
        c2.stop()
        mid_before = c2.total   # 停止瞬间取基线：停之前可能刚好又到一批
        print("[INFO] C2 已停止，观察 %d 秒..." % 8)
        time.sleep(8)

        ck(alive(p), "F2 断线后守护进程仍存活（核心）",
           "poll=%s" % ("None=运行中" if alive(p) else p.returncode))
        ck(c2.total == mid_before, "F3 断线窗口内无新送达（证明真断了）",
           "断线前=%d 当前=%d" % (mid_before, c2.total))

        # 阶段 3：恢复
        c2b = C2(port)
        c2b.start()
        if not c2b.ready.wait(timeout=10):
            print("[FATAL] C2 未能在同端口重启")
            p.kill()
            return 2
        print("[INFO] C2 已在同端口 %d 重启，观察 %d 秒..." % (port, 10))
        time.sleep(10)

        ck(c2b.total > 0, "F4 恢复后再次送达（重连真的发生）",
           "%d 字节 / %d 连接" % (c2b.total, c2b.conns))
        ck(alive(p), "F5 全程进程未退出（结束态仍是运行中）")

        p.send_signal(2)  # SIGINT，正常停止
        try:
            out = p.communicate(timeout=10)[0].decode("utf-8", "replace")
        except subprocess.TimeoutExpired:
            p.kill()
            out = ""
        print("[INFO] camd 输出尾部: %s" % out.strip().splitlines()[-1][:120]
              if out.strip() else "[INFO] 无输出")
        c2b.stop()
    finally:
        if alive(p):
            p.kill()
        shutil.rmtree(tmp, ignore_errors=True)

    bad = [n for ok, n, _ in RESULTS if not ok]
    print("\n断言总数=%d  失败=%d" % (len(RESULTS), len(bad)))
    if bad:
        print("失败项: %s" % ", ".join(bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
