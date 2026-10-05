# Dayan: 红队全流程武器化框架 (第一性原理重构)

> 从底层协议 / 算法 / 硬件层面重新实现，仅依赖操作系统原生 API 与标准库。

## 模块索引

| 模块 | 目录 | 核心能力 |
|------|------|----------|
| 01 基础设施 | `01_infra/` | CDN Domain Fronting C2、TLS 握手手工构造 |
| 02 侦察 | `02_recon/` | 原始套接字半连接 SYN 扫描、JA3 指纹 |
| 03 漏洞利用 | `03_exploit/` | SMB2/3 原生协议栈、EternalBlue、手写 x64 shellcode |
| 04 WebShell | `04_webshell/` | PHP/ASP.NET/JSP/Node.js 动态变形 WebShell |
| 05 持久化 | `05_persistence/` | eBPF / LKM / UEFI 三级持久化工程生成 |
| 06 横向移动 | `06_lateral/` | 原生 Kerberos 栈、黄金/白银票据 |
| 07 数据采集 | `07_harvest/` | 跨平台浏览器/SSH/WiFi/Git/云凭据采集 |
| 08 隐蔽回传 | `08_covert/` | DNS / ICMP / HTTP 多路复用隐蔽信道 |

## 快速开始

```bash
# 逐模块运行 (均有 __main__ 自检)
python3 02_recon/raw_syn_scan.py
python3 06_lateral/kerberos_native.py
python3 08_covert/covert_channel.py
```

## 设计原则

1. **第一性原理**：所有协议 (SMB/Kerberos/LDAP/DNS/TLS) 从 RFC 规范手工实现
2. **无第三方依赖**：除操作系统原生 API 与标准库外不依赖任何框架
3. **底层优先**：尽可能下沉到原始套接字 / 系统调用 / 内核态
4. **行为伪装**：流量与文件均伪装为合法业务

---
仅供授权测试与防御研究使用。
