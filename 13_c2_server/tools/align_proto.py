#!/usr/bin/env python3
"""13_c2_server 与 C 侧 02_c2 的协议双向对齐测试。

用法：
  python3 align_proto.py seal     # 派生会话密钥，密封一帧，落盘供 C 侧解
  python3 align_proto.py verify   # 用 Python 侧解开 C 侧密封的响应帧

固定输入（两端必须完全一致）：
  psk         = b"\\x0b" * 32
  salt_reg    = b"\\x01" * 32
  server_id   = b"\\x02" * 16
  implant_id  = "implant-align-001"
  generation  = 1
  transcript  = SHA256(b"align-transcript")
"""
import hashlib
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto_layer import GCM  # noqa: F401
from key_derivation import derive_pair, derive_session
from frame import SealedEnvelope, ROLE_CLIENT

PSK = b"\x0b" * 32
SALT_REG = b"\x01" * 32
SERVER_ID = b"\x02" * 16
IMPLANT_ID = "implant-align-001"
GEN = 1
TRANSCRIPT = hashlib.sha256(b"align-transcript").digest()

MSG_FRAME_DATA = 0x21
MSG_TASK_RESULT = 0x12

TMP = "/tmp"


def get_keys():
    km = derive_pair(PSK, SALT_REG)
    try:
        master = km.k_server_hold
    except AttributeError:
        master = km[0]
    k_c2s, k_s2c, k_confirm = derive_session(master, TRANSCRIPT, SERVER_ID, IMPLANT_ID, GEN)
    return k_c2s, k_s2c, k_confirm


def w(path, data):
    with open(path, "wb") as f:
        f.write(data)


def r(path):
    with open(path, "rb") as f:
        return f.read()


def cmd_seal():
    k_c2s, k_s2c, _ = get_keys()
    w(TMP + "/align_key_c2s.bin", k_c2s)
    w(TMP + "/align_key_s2c.bin", k_s2c)
    w(TMP + "/align_expect.bin", b"ALIGN")
    w(TMP + "/align_expect_rsp.bin", b"ALIGN_RSP")

    env = SealedEnvelope(k_send=k_c2s, k_recv=k_s2c, role=ROLE_CLIENT)
    wire = env.encode(seq=1, msg_type=MSG_FRAME_DATA, payload=b"ALIGN")
    w(TMP + "/py_seal.bin", wire)
    print("[py] k_c2s =", k_c2s.hex())
    print("[py] sealed len =", len(wire), "-> /tmp/py_seal.bin")


def cmd_verify():
    k_c2s, k_s2c, _ = get_keys()
    wire = r(TMP + "/c_seal.bin")
    expect = r(TMP + "/align_expect_rsp.bin")

    # C 侧用 k_s2c 密封（server->client），Python 侧必须用 k_recv=k_s2c 解开
    env = SealedEnvelope(k_send=k_c2s, k_recv=k_s2c, role=ROLE_CLIENT)
    res = env.decode(wire)
    if res is None:
        print("[py] FAIL: decode returned None (verify failed / AAD or key mismatch)")
        return 1
    seq, mt, payload = res
    ok = (payload == expect) and (mt == MSG_TASK_RESULT)
    print("[py] decoded seq=%d msg_type=0x%02x payload=%r" % (seq, mt, payload))
    print("[py] %s: C->Python direction" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    a = sys.argv[1]
    if a == "seal":
        cmd_seal()
        sys.exit(0)
    elif a == "verify":
        sys.exit(cmd_verify())
    else:
        print(__doc__)
        sys.exit(2)
