"""
DAYANJING v4 — seq_in 贯通与跨重启重放防护自测
==============================================

被解除的限制：
    session_cache 的条目格式里一直有 seq_in 字段，但落缓存时传的是**常量 0**，
    resume_session 也**从不读取**它 —— 该字段语义悬空。

    这留下一个真实的安全洞：ReplayWindow 是纯内存的，服务端重启后窗口为空。
    会话可经 session_cache 落盘恢复，此时植入体重连送来的**旧序号会被当作
    new 接受** —— 重放防护在重启后整体失效。而缓存里明明存着 seq_in，
    只是没人用它重建窗口基线。

本测试验证四件事：
    1. seq_in 在收到上行帧后真实推进（不再是常量 0）
    2. seq_in 落进缓存并被读回（含 -1 的 +1 偏移规范化）
    3. resume 后重放旧序号被拒 —— **核心反证**
    4. resume 后新序号仍被接受（保守拒收没有误伤正常流量）

运行：python3 tests/test_seq_in.py
"""

import os
import sys
import struct
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server import C2Server, SessionState
from protocol.messages import (
    MSG_HELLO, MSG_WELCOME, MSG_FINISHED, MSG_HEARTBEAT,
)
from frame import SealedEnvelope, ReplayWindow, ReplayKey, ROLE_CLIENT
from key_derivation import derive_pair, derive_session, HKDF_SALT_REG_LEN
from crypto_layer import sha256
from session_cache import SessionCache

PSK = b"\x42" * 16
SALT_REG = os.urandom(HKDF_SALT_REG_LEN)
SERVER_ID = b"\x01" * 16
IMPLANT_ID = "impl-seq-001"
GENERATION = 1

failures = []
total = 0


def check(name, cond, detail=""):
    global total
    total += 1
    if cond:
        print(f"[PASS] {name}")
    else:
        print(f"[FAIL] {name} {detail}")
        failures.append(f"{name} {detail}")


def info(msg):
    print(f"[INFO] {msg}")


# ---------------------------------------------------------------------------
# ReplayWindow.seed 单元行为
# ---------------------------------------------------------------------------

def test_seed():
    rw = ReplayWindow(capacity=64)
    key = ReplayKey("impl-a", 1)

    check("seed 前：序号 5 被接受", rw.accept(key, 5) == ReplayWindow.ACCEPTED)
    check("seed 前：序号 5 重放被拒", rw.accept(key, 5) == ReplayWindow.REPLAY)

    rw2 = ReplayWindow(capacity=64)
    rw2.seed(key, 5)
    check("seed(5) 后：序号 5 被判重放", rw2.accept(key, 5) == ReplayWindow.REPLAY)
    check("seed(5) 后：序号 3（窗口内）被判重放",
          rw2.accept(key, 3) == ReplayWindow.REPLAY)
    check("seed(5) 后：序号 6（新）被接受", rw2.accept(key, 6) == ReplayWindow.ACCEPTED)

    # 离谱值防御：未做 +1 偏移规范化的 2**64-1 不得触发天文数字枚举
    rw3 = ReplayWindow(capacity=64)
    rw3.seed(key, (1 << 64) - 1)
    check("seed 拒绝离谱值（不枚举天文区间）",
          rw3.accept(key, 100) == ReplayWindow.ACCEPTED)

    # 负值（-1 = 尚未收到）不得改变窗口
    rw4 = ReplayWindow(capacity=64)
    rw4.seed(key, -1)
    check("seed(-1) 不改变窗口基线", rw4.accept(key, 0) == ReplayWindow.ACCEPTED)


# ---------------------------------------------------------------------------
# session_cache 的 seq_in 规范化（+1 偏移）
# ---------------------------------------------------------------------------

def test_cache_offset():
    master = os.urandom(32)
    cache = SessionCache(master, SERVER_ID, ttl=3600)

    cache.put("impl-b", 1, os.urandom(16), os.urandom(16),
              seq_out=7, seq_in=-1, cell_send_ctr=0, cell_recv_ctr=0)
    ent = cache.get("impl-b")
    check("seq_in=-1 往返后仍为 -1（未被 & mask 变成 2**64-1）",
          ent["seq_in"] == -1, f"got {ent['seq_in']}")
    check("seq_out 往返一致", ent["seq_out"] == 7)

    cache.put("impl-c", 1, os.urandom(16), os.urandom(16),
              seq_out=3, seq_in=5, cell_send_ctr=1, cell_recv_ctr=2)
    ent2 = cache.get("impl-c")
    check("seq_in=5 往返一致", ent2["seq_in"] == 5, f"got {ent2['seq_in']}")


# ---------------------------------------------------------------------------
# 服务端级：握手 -> 上行帧 -> 落盘 -> 重启 -> resume -> 重放被拒
# ---------------------------------------------------------------------------

class Client:
    """最小客户端：握手 + 发上行帧。"""

    def __init__(self):
        km = derive_pair(PSK, SALT_REG)
        self._k_server_hold = km.k_server_hold
        self.transcript = b""
        self.envelope = None
        self.seq = 0

    def hello(self):
        raw = struct.pack("<I", MSG_HELLO) + IMPLANT_ID.encode()
        self.transcript += raw
        return raw

    def on_welcome(self, raw):
        self.transcript += raw
        fin = struct.pack("<I", MSG_FINISHED) + b"finished-proof"
        self.transcript += fin
        hh = sha256(self.transcript)
        k_c2s, k_s2c, _ = derive_session(
            self._k_server_hold, hh, SERVER_ID, IMPLANT_ID, GENERATION)
        self.envelope = SealedEnvelope(k_c2s, k_s2c, ROLE_CLIENT)
        return fin

    def frame(self, msg_type, payload, seq=None):
        """编码一个上行帧。seq 为 None 时自增，否则用指定值（造重放）。"""
        if seq is None:
            s = self.seq
            self.seq += 1
        else:
            s = seq
        return self.envelope.encode(s, msg_type, payload)


def run_handshake(srv, client, sent):
    """握手并消费 WELCOME。sent 必须是该实例**专属**的发送列表。"""
    srv.on_bytes(IMPLANT_ID, GENERATION, client.hello())
    if not sent:
        return False
    welcome = sent.pop(0)
    fin = client.on_welcome(welcome)
    srv.on_bytes(IMPLANT_ID, GENERATION, fin)
    return True


def test_server_resume_replay():
    """服务端握手 -> 上行帧 -> 落盘 -> 重启 -> resume -> 重放被拒。

    每个服务端实例必须用**独立的**发送列表：复用同一个列表会让后者
    pop 到前一个实例残留的心跳回执，客户端据此算出的 transcript 与
    服务端不一致 -> 验签失败 -> 连接被 drop。那样"重放被拒"会是假阳性
    （实际是验签失败），根本没测到重放窗口。
    """
    tmpdir = tempfile.mkdtemp(prefix="dayanjing_seqin_")
    path = os.path.join(tmpdir, "cache.bin")
    master = os.urandom(32)

    # ---------- 第一个服务端实例：握手 + 3 个上行帧 ----------
    sent1, closed1 = [], []
    srv1 = C2Server(PSK, SALT_REG, SERVER_ID,
                    cache=SessionCache(master, SERVER_ID, ttl=3600),
                    cache_path=path)
    srv1.register_transport(lambda i, r: sent1.append(r),
                            lambda i: closed1.append(i))

    client = Client()
    if not run_handshake(srv1, client, sent1):
        check("握手完成", False)
        return

    sess1 = srv1._sessions.get(IMPLANT_ID)
    check("会话已建立", sess1 is not None)
    if sess1 is None:
        return
    check("seq_in 初始为 -1（尚未收到上行帧）", sess1.seq_in == -1,
          f"got {sess1.seq_in}")

    for _ in range(3):
        srv1.on_bytes(IMPLANT_ID, GENERATION,
                      client.frame(MSG_HEARTBEAT, b"ping"))

    check("收到 3 帧后 seq_in == 2", sess1.seq_in == 2, f"got {sess1.seq_in}")
    check("上行帧未被误判（连接未关闭）", len(closed1) == 0,
          f"closed={len(closed1)}")
    info(f"第一个实例：seq_out={sess1.seq_out} seq_in={sess1.seq_in}")

    srv1.save_cache()
    check("缓存已落盘", os.path.exists(path))

    # ---------- 模拟重启：同 master 的新实例，从磁盘加载 ----------
    sent3, closed3 = [], []
    srv3 = C2Server(PSK, SALT_REG, SERVER_ID,
                    cache=SessionCache(master, SERVER_ID, ttl=3600),
                    cache_path=path)
    srv3.register_transport(lambda i, r: sent3.append(r),
                            lambda i: closed3.append(i))

    n = srv3._cache.load(path)
    check("从磁盘加载缓存条目", n >= 1, f"loaded={n}")
    check("resume_session 成功", srv3.resume_session(IMPLANT_ID))

    sess3 = srv3._sessions.get(IMPLANT_ID)
    check("resume 后 session 存在", sess3 is not None)
    if sess3 is None:
        return
    check("resume 后 seq_in 继承自断点（==2）", sess3.seq_in == 2,
          f"got {sess3.seq_in}")
    check("resume 后标记为 resumed", sess3.resumed)

    # ---------- 核心反证：重连后重放旧序号必须被拒 ----------
    # 先用新序号证明链路本身是通的（否则下面的"被拒"可能是验签失败）
    n_closed = len(closed3)
    srv3.on_bytes(IMPLANT_ID, GENERATION,
                  client.frame(MSG_HEARTBEAT, b"ping", seq=9))
    check("新序号 seq=9 被接受（链路可用，非验签失败）",
          len(closed3) == n_closed, f"closed {n_closed} -> {len(closed3)}")

    n_closed = len(closed3)
    srv3.on_bytes(IMPLANT_ID, GENERATION,
                  client.frame(MSG_HEARTBEAT, b"ping", seq=2))
    check("重启后重放 seq=2 被拒（重放防护未失效）",
          len(closed3) > n_closed, f"closed {n_closed} -> {len(closed3)}")
    info(f"重放被拒：关闭记录数={len(closed3)}")

    # ---------- 保守拒收不得误伤窗口外的更大序号 ----------
    sent4, closed4 = [], []
    srv4 = C2Server(PSK, SALT_REG, SERVER_ID,
                    cache=SessionCache(master, SERVER_ID, ttl=3600),
                    cache_path=path)
    srv4.register_transport(lambda i, r: sent4.append(r),
                            lambda i: closed4.append(i))
    srv4._cache.load(path)
    check("第二次 resume 成功", srv4.resume_session(IMPLANT_ID))
    sess4 = srv4._sessions.get(IMPLANT_ID)
    n_closed = len(closed4)
    srv4.on_bytes(IMPLANT_ID, GENERATION,
                  client.frame(MSG_HEARTBEAT, b"ping", seq=20))
    check("窗口外新序号 seq=20 仍被接受（保守拒收未误伤）",
          len(closed4) == n_closed, f"closed {n_closed} -> {len(closed4)}")
    if sess4 is not None:
        info(f"新帧处理后 seq_in={sess4.seq_in}")

    try:
        os.remove(path)
        os.rmdir(tmpdir)
    except OSError:
        pass


def main():
    print("=== seq_in 贯通与跨重启重放防护 ===")
    test_seed()
    test_cache_offset()
    test_server_resume_replay()
    print(f"\n=== result: {total - len(failures)} pass, {len(failures)} fail ===")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
