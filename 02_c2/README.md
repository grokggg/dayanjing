# 02_c2 — 外层 wire 信封 + 握手 + 会话密钥派生

## 职责裁定（与 01_proto 的分界）

`02_c2` 的 `c2_frame` 是 **wire 格式的唯一权威**：
- AEAD 封装（机密性 + 完整性）
- `seq` 单调递增防重放
- AAD 13 字节，与 Python 侧 `13_c2_server/frame.py` 逐字节一致

`01_proto` 只做内层应用帧（见 `01_proto/README.md`），不做加密。
分层集成证据：`tests/proto_c2_layering.c`（15/15 PASS）。

## 历史缺陷修复

- 早期 Python `_build_aad` 比 C 侧多一个 role 字节（14 vs 13），导致双向验签必然失败。已删除 role 字节，两端统一 13 字节。
- `c2_frame_seal` 曾把 payload 长度当成明文 Envelope 长度分配密文缓冲，`gctr` 多写 20 字节造成堆溢出。已修。
