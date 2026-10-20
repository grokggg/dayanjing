# 01_proto — 内层应用帧

## 职责裁定（与 02_c2 的分界，已由 tests/proto_c2_layering.c 钉死）

| 层 | 模块 | 负责 | 不负责 |
|---|---|---|---|
| 内层应用帧 | `01_proto` | `frame_hdr` + payload + CRC32，应用级分帧与完整性自检 | 加密、防重放 |
| 外层 wire 信封 | `02_c2` (`c2_frame`) | AEAD 机密性/完整性、seq 防重放 | 应用级分帧 |

两者**不再重叠**：`01_proto` 不加密，`02_c2` 不做应用分帧。

数据流：

```
应用数据 → frame_pack (01_proto) → 内层帧字节
        → c2_frame_seal (02_c2)   → wire 字节 → 网络
网络 → c2_frame_open (02_c2) → 内层帧字节
    → frame_unpack (01_proto)    → 应用数据
```

## 已完成单元

- 单元 1：帧头 + pack/unpack + CRC32（9/9 PASS）

## 历史缺陷修复

- `frame_calc_crc` 原声明为 `const struct frame *` 但文档称"写入 `f->crc`"，二者矛盾导致编码侧无法自检。
  现改为非 const 并真正写回；纯计算逻辑抽为内部 `crc_of()`，`frame_pack`/`frame_verify_crc` 仍可用 const 上下文。
