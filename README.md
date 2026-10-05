# dayanjing - 完整攻击框架 v2

## 架构

```
dayanjing/
├── 01_infra/            # C2 基础设施（Domain Fronting）
├── 02_recon/            # 原始 TCP SYN 扫描 + JA3 指纹
├── 03_exploit/          # SMB/EternalBlue 漏洞利用
├── 04_webshell/         # JIT 动态变形 WebShell
├── 05_persistence/      # 持久化（C 源码 + eBPF + LKM）
├── 06_lateral/          # Kerberos 原生协议栈
├── 07_harvest/          # 凭据采集
├── 08_covert/           # 隐蔽数据回传
├── 09_delivery/         # 投递模块（HTML Smuggling / LNK / BadUSB）
├── 10_stager/           # 原生远程执行（SMB / WMI / SSH）
├── 11_stealth/          # 免杀绕过（API 哈希 / 加壳 / 签名伪造）
├── 12_anti_forensics/   # 反取证（日志清除 / 时间戳 / USN）
├── build/               # 统一构建系统
└── tests/               # 离线测试框架
```

## 模块功能对照

| 功能 | 模块 | 实现状态 |
|------|------|----------|
| 初始投递（鱼叉/水坑/BadUSB） | 09_delivery/ | ✅ |
| 远程执行（SMB/WMI/SSH） | 10_stager/ | ✅ |
| 摄像头采集（MF/V4L2） | 05_persistence/ | ✅ |
| 进程伪装（进程名/LKM 隐藏） | 05_persistence/rootkit.c | ✅ |
| 持久化（注册表/计划任务/systemd/eBPF/LKM） | 05_persistence/ | ✅ |
| 隐蔽传输（DNS/HTTP/ICMP） | 08_covert/ | ✅ |
| 免杀绕过（API 哈希/加壳/签名） | 11_stealth/ | ✅ |
| 反取证（日志/时间戳/USN） | 12_anti_forensics/ | ✅ |

## 构建

```bash
# 交叉编译 Windows
make windows

# 编译 Linux
make linux

# 编译 Python 模块
make pyc

# 打包
make package

# 运行测试
make test
```

## 测试

```bash
python3 tests/run_tests.py
```

测试覆盖：
- Python 语法检查
- C/C++ 编译检查
- 协议构造验证（TLS/SMB2/SSH/ASN.1/DNS/ICMP/CovertPacket/LNK）
- API 哈希验证
- 时间戳篡改验证

## 依赖

### Linux 构建
- gcc / g++
- mingw-w64（交叉编译 Windows）
- libbpf-dev（eBPF loader）
- libelf-dev

### Windows 构建
- Visual Studio Build Tools 或 MinGW-w64
- Windows SDK（Media Foundation, Task Scheduler）

## 版本

- v1: 基础框架（8 个 Python 模块）
- v2: 工程级框架（12 个模块 + C 源码 + 构建系统 + 测试框架）
