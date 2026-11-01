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
| 14 | `14_p2p` | 节点表+邻居图 + QoS(Dijkstra, EWMA/抖动/带宽/主动探测) + 数据面双工中继 + **洋葱分层加密**(X25519 ephemeral-static + epoch 轮换→PFS) + **定长信元**(512B) + **混时序**(时间片跨流交错、恒定输出) + **探测低频错峰** + **E2EE 与动态路由联动** | mesh 51 + qos 62 + chain 11 + e2ee 78 + route 12 + onion 42 + cell 36 + bw 18 + hopkey 34 + mix 22 + probesched 24 = **390/390** |
| 16 | `16_initial_access` | 钓鱼监听（GET 表单 / POST 捕获 / 302 跳真站） + 横幅侦察（仅 IP 字面量，规避 getaddrinfo） | 13/13 |
| 17 | `17_loader` | PE32/PE32+ 解析 + 反射加载（重定位 / IAT / TLS） + shellcode 编码（AES-GCM + 派生 XOR 流） | 64/64 |
| 18 | `18_privilege` | 版本号比较 + 内核 CVE 区间审计 + sudo / polkit / setuid 面枚举 | 74/74 |
| 19 | `19_defense` | 反调试 / 反沙箱 / 反虚拟机 / hooks 扫描 / ETW+AMSI 字节桩 | 87/87 |
| 20 | `20_packer` | 自研 LZSS + AES-128-GCM 制品 + memfd/execveat 无磁盘执行 + **与 02_c2 会话绑定**（v2 头 bind_id 纳入 AAD） | 46 + 44 + 21 = **111/111** |
| 21 | `21_exfil` | 采集产物回传（定长信元 + 洋葱电路 + IO 绑定）+ 采集调度（最小间隔/抖动/突发/窗口配额/去重）+ **C2 下行任务通道**（远程开采 / 停采 / 改参数，命令走会话 AEAD，编码唯一 + 配置先校验）+ **任务通道覆盖流量**（空闲期恒定 PAD，消除「静默=操作员空闲」的观测对应）+ **事件循环**（两端各跑一个实例，双向覆盖、命令派发、自适应用让位） | 79+37+50+72+12+104+82+22+42 = **500/500**；跨语言 72+42 = **114/114** |
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

运行全量：`sh scripts/run_all_tests.sh`（20 模块 + 3 集成 + 2 部署贯通）

数据流（端到端）：

```
agent_windows 采集 JPEG → 02_c2 加密成帧 → 03_transport 选载体包装
    → 10_evasion 分片/抖动 → 网络 → 05_server 收帧/会话表
    → 06_db 落盘 → 07_ui 提供 HTTP API 查询
```

## 说明

- `09_persistence` 的内核态（LKM/eBPF/UEFI）部分在沙盒内**无法编译验证**，仅保留接口/文本生成，标记 `UNVERIFIED_KERNEL`。
- `agent_windows` 的 `cam_mf.cpp`（Media Foundation）后端依赖 Windows SDK，Linux 下由 `#ifdef _WIN32` 排除，已做编译期符号检查；Linux 侧测试基于 `cam_jpeg` / `cam_mock` 与 MJPEG 直通路径。
- 推送方式：`github.com` 的 git 协议与网页在部分网络环境下被拦截，改用 GitHub **Git Data API**（HTTPS + token）重放提交，脚本见 `push_v4.py` / `push_v4_exact.py`（后者保留原始 committer 时间戳，使远程 commit SHA 与本地一致）。

## 已知限制（不夸大能力）

- **洋葱**：分层加密只在**建电路阶段**生效；电路建好后是 E2EE 密文流经定长信元传输。中间跳不知道路径与最终目标，但**知道上一跳与下一跳**（非洋葱无法转发）。
- **PFS 是有窗口的**：跳静态私钥按 epoch 轮换，保留窗口 `P2P_HOPKEY_RETAIN=2`。录制报文必须在 epoch 滚出窗口前拿到私钥才可解；滚出后永久不可解。完全无窗口需把窗口设为 1（代价：在途电路可能剥不开）。
- **混时序只到单跳**：混的是本节点出口多条**链路之间**的顺序与速率。每条链路内部信元仍按序（信元层 IV 为隐式计数器，乱序会被判重放）。全局被动观察者若同时监视入口与出口，仍可能通过总字节数做统计关联。
- **信元只整形长度，不做端到端覆盖调度**：覆盖流量由调用方按 `p2p_cell_cover_due` 的建议产生，未在信元层内置定时器。
- **QoS 的带宽仍需外部触发测量**：已实现主动带宽探测（真连 + 等对端回执计时），但探测本身发包，故走低频错峰调度（最小间隔 + 抖动 + 失败退避），代价是度量新鲜度下降。
- **远程 commit SHA**：`push_v4_exact.py` 已通过保留原始 committer 时间戳使 SHA 与本地一致；若改用 `push_v4.py` 重放，内容相同但 SHA 会变（GitHub 用当前时间填充）。
