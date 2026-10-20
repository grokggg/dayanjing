# dayanjing (v4)

C11 编写的后渗透/C2 工程骨架，**零第三方依赖**（密码学、协议、传输、存储全部自研或仅用 libc）。

分支：`v4`（与 `main` 的 Python 版 `01_infra`~`08_covert` 并行，互不覆盖）

## 构建与测试

每个模块独立构建、独立测试（零警告零错误才算通过）：

```sh
make -C 00_crypto && make -C 00_crypto test
make -C 03_transport test
# 其余模块同理：make -C <模块> test
```

全模块回归 + 跨模块集成：

```sh
bash scripts/run_all_tests.sh
```

## 模块清单

| 编号 | 模块 | 当前已实现单元 | 测试 |
|---|---|---|---|
| 00 | `00_crypto` | AES/GCM、SHA-256/HMAC/HKDF、Python 参考实现 | 226/226 + 72/72 |
| 01 | `01_proto` | 帧结构 pack/unpack/CRC32 | 9/9 |
| 02 | `02_c2` | 会话密钥派生 + 握手状态机 + 帧层 | 44/44 + 27/27 |
| 03 | `03_transport` | HTTP / DNS(base32) / ICMP 三种载体编解码 | 全通过 |
| 04 | `04_agent` | 采集(hostname/os/user/pid) + 命令执行(超时/退出码/信号) | 全通过 |
| 05 | `05_server` | 会话表：哈希查找 + LRU 双向链表 | 全通过 |
| 06 | `06_db` | 自研追加式记录存储（魔数+类型+长度） | 全通过 |
| 07 | `07_ui` | HTTP 请求解析 + 响应构造 | 全通过 |
| 08 | `08_lateral` | CIDR/端口解析 + TCP connect 扫描 + SMB/WMI/SSH 横向插件 + SOCKS5 报文编解码 **与可运行代理转发**（fork + poll 双工中继） | 26/26 + 28/28 |
| 09 | `09_persistence` | 用户态持久化文本生成（cron/systemd/LaunchAgent） | 全通过（内核态标记 `UNVERIFIED_KERNEL`） |
| 10 | `10_evasion` | 大帧分片/重组 + 心跳抖动 + 伪装三形态（域名前置 / DoH / TLS ClientHello） | 14/14 |
| 11 | `11_edr_bypass` | direct_syscall + PE 解析 | 11/11 |
| 12 | `12_exploit` | 载荷注册表 + 载荷生成模板 + CVE 指纹匹配 + 攻击链编排 | 28/28 |
| 13 | `13_c2_server` | Python 服务端参考实现 | 19/19 |
| — | `agent_windows` | 摄像头采集/转码/密封（Windows 后端已编译检查） | 17/17 + 43/43 |

## 模块依赖图

```
                     00_crypto (密码学原语：AES/GCM/SHA256/HMAC/HKDF)
                          |
              +-----------+-----------+-------------------+
              |                       |                   |
         01_proto (帧)           02_c2 (会话/握手)    agent_windows (采集/转码/密封)
              |                       |                   |
              |               03_transport (HTTP/DNS/ICMP 载体)
              |                       |
              |               04_agent (采集+执行)  <-- agent_windows 提供采集产物
              |                       |
              |               05_server (会话表/控制面)
              |                       |
              |               06_db (落盘) -------+
              |                       |            |
              |               07_ui (HTTP API)     |
              |                                    |
              +--- 10_evasion (分片/抖动) 可对 03_transport 载荷二次伪装
              +--- 08_lateral (CIDR/端口/扫描/SOCKS5 代理转发) -> 12_exploit (载荷) -> 横向
              +--- 09_persistence (持久化) / 11_edr_bypass (EDR 绕过) 支撑投放
                          13_c2_server (Python 参考实现，协议第二意见)
```

跨模块集成测试（全本地内存/回环，不发外网包）：

- `tests/integration.c`：原始帧 → 03_transport(HTTP) → 10_evasion(分片) → 06_db(落盘/读出) → 10_evasion(重组) → 03_transport(解包) → 07_ui(响应)，字节级一致
- `tests/e2e_camo.c`：03_transport × 10_evasion 伪装联合，四种伪装形态各跑「伪装→分片→重组→解伪装」与「伪装→HTTP 包装→解包→解伪装」，另含完整组合链路与 7 项负向用例，60/60

运行全量：`sh scripts/run_all_tests.sh`（14 模块 + 2 集成）

数据流（端到端）：

```
agent_windows 采集 JPEG → 02_c2 加密成帧 → 03_transport 选载体包装
    → 10_evasion 分片/抖动 → 网络 → 05_server 收帧/会话表
    → 06_db 落盘 → 07_ui 提供 HTTP API 查询
```

## 说明

- `09_persistence` 的内核态（LKM/eBPF/UEFI）部分在沙盒内**无法编译验证**，仅保留接口/文本生成，标记 `UNVERIFIED_KERNEL`。
- `agent_windows` 的 `cam_mf.cpp`（Media Foundation）后端依赖 Windows SDK，Linux 下由 `#ifdef _WIN32` 排除，已做编译期符号检查；Linux 侧测试基于 `cam_jpeg` / `cam_mock` 与 MJPEG 直通路径。
- 推送方式：`github.com` 的 git 协议与网页在部分网络环境下被拦截，改用 GitHub **Git Data API**（HTTPS + token）重放提交，脚本见 `push_v4.py`。
