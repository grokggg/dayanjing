# agent_windows — Windows 摄像头采集 Agent

## 状态：骨架完成，待 Windows 真机验证

本模块当前是 **Linux 沙盒可编译、可测试**的骨架，完整采集逻辑需 Windows 真机实机验证。

## 架构

```
┌─────────────────────────────────────────────────────┐
│                 C2 任务下发                          │
│         (13_c2_server / SealedEnvelope)              │
└──────────────────────┬──────────────────────────────┘
                       │ 加密指令: "capture_frame"
                       ▼
┌─────────────────────────────────────────────────────┐
│             任务处理器 (camera_task)                  │
│  - 解析指令、限时采集、交付加密帧                     │
└──────────────────────┬──────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────┐
│              CameraSource 接口层                     │
│  open / capture / close / enumerate / check_perm     │
└──────┬───────────────────────────────┬──────────────┘
       │                               │
┌──────┴────────┐                ┌─────┴─────────────┐
│ MFCameraSource│                │   MockCameraSource │
│ (Windows 真机)│                │   (测试/沙盒)      │
│  Media Fdn COM│                │   喂伪造帧         │
└───────────────┘                └───────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────┐
│              转码层 (cam_jpeg.c)                     │
│  MJPEG 直通(校验 FFD8/FFD9)  |  YUYV→RGB→JFIF      │
│  NV12/RGB24 → 待扩展                                  │
└──────────────────────┬──────────────────────────────┘
                       │ 合法 JPEG 字节
                       ▼
┌─────────────────────────────────────────────────────┐
│         00_crypto GCM 密封 → 上传                    │
│         明文帧不出进程、不落盘                        │
└─────────────────────────────────────────────────────┘
```

## 已验证

| 验证项 | 结果 |
|--------|------|
| C 代码 Linux gcc 编译 (`-Wall -Wextra -Wpedantic`) | ✅ 通过 |
| C 端转码自测 (`test_transcode.c`) | ✅ 18/18 |
| Python 集成测试 (`test_camera.py`) | ✅ 11/11 |
| 采集→GCM 密封→解密往返 | ✅ 通过 |
| 密文篡改 GCM 拒绝 | ✅ 通过 |
| MJPEG 直通（合法帧交付 / 非法帧拒绝） | ✅ 通过 |
| YUYV→JPEG 转码（输出合法 JFIF 结构） | ✅ 通过 |
| 连续帧唯一性（C 端独立 buffer，不复用） | ✅ 通过 |
| 权限前提检测接口 (`check_permission`) | ✅ 接口就位 |

## v2 缺陷修复对照

| v2 缺陷 | 本模块的处理 |
|---------|--------------|
| `ReadSample` 只调一次，无流控 | 接口层定义 capture 循环契约；MF 后端待实现时须处理 `ENDOFSTREAM`/`ENDOFMEDIA` |
| 不枚举原生格式、直接设 `GUID_ContainerFormatJpeg` | `CameraSource` 接口要求 open 时完成格式协商，MJPEG 优先 |
| **YUYV 未转码，把 YUV 当 JPEG 写** | `cam_frame_to_jpeg` 强制校验 MJPEG 合法性；YUYV 走 `yuyv_to_rgb` + `encode_gray_jpeg` |
| 裸 `ioctl` cleanup，被打断时泄漏 | 接口定义 `close` 为必须释放句柄；MF 后端用 RAII/C++ 析构或 `__try/__finally` 保底 |
| 无权限判定 | `check_permission()` 接口 + CapabilityAccessManager 读取（待实现） |
| 无传输层，写本地文件 | 帧经 `00_crypto` GCM 密封后上传，明文不出进程 |

## 已知约束（不承诺绕过，如实记录）

1. **指示灯是固件级约束。** 多数现代 Windows 设备的摄像头指示灯由固件直接控制，
   软件无法关闭。本模块不承诺静默，只承诺"按需短时触发、立即释放句柄"
   （`cam_config_t.capture_ms` 控制采集窗口）。若目标硬件无指示灯，属硬件差异。

2. **沙盒无摄像头设备。** `/dev/video*` 不存在，Linux 沙盒与阿里云实例均无法做
   实机采集测试。Mock 桩只能验证协议链路和转码逻辑，MF 后端的实机行为必须
   在 Windows 真机上验证。

3. **灰度 JPEG 是工程近似。** `encode_gray_jpeg` 采用"灰度原样量化"而非完整
   DCT，体积较大、非彩色。目标场景要求彩色/高压缩率时，应在 Windows 真机
   链接 WIC 或 libjpeg-turbo，接口不变。

4. **`is_jpeg()` 校验强度有限。** 当前仅检查 `FFD8` 头 + `FFD9` 尾，伪造帧可
   绕过。更严格方案是在交付前做完整 JPEG 解码验证（minijpeg 或 WIC）。
   这是**设计已知项**，非已实现防护。

5. **当前编译环境无 `mingw-w64`。** 无法交叉编译 Windows `.exe/.dll`。需在
   Windows 真机或装好交叉编译工具链的 Linux 环境编译 MF 后端。

## 下一步（待执行）

### 高优先级
- [ ] **Media Foundation 后端 (`cam_mf.cpp`)**
  - 实现 `IMFSourceReader` 的初始化、格式枚举与协商
  - 格式优先级：MJPEG > NV12 > YUYV422
  - `ReadSample` 循环处理 `ENDOFSTREAM` / `ENDOFMEDIA`
  - `IMFMediaBuffer::Lock` 取帧，`IMFSample::GetSampleTime` 取 PTS
  - COM 生命周期：CoInitializeEx + CoUninitialize，智能指针管理
  - 被中断时（`__finally` / RAII）保证释放 Media Source / Reader

- [ ] **CapabilityAccessManager 权限检测 (`cam_perm_win.cpp`)**
  - 读取 `HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam`
  - 解析 `LastUsedTimeStop` / `Value`（Allow/Deny）
  - 输出当前进程是否被授权

- [ ] **交叉编译工具链**
  - 安装 `mingw-w64`，CMake 配置 Windows target
  - 产出 `libcamera.dll` + agent 可执行文件

### 中优先级
- [ ] **WIC / libjpeg-turbo 彩色 JPEG 编码**，替换灰度近似
- [ ] **完整 JPEG 解码验证**，强化 `is_jpeg()` 防伪造帧
- [ ] **任务处理器**对接 `13_c2_server`，C2 下发 `capture_frame` 指令触发采集
- [ ] **上传确认 + 重试**，失败帧不入队堆积

### 低优先级
- [ ] 多摄像头选择（enumerate 已返回多设备，待 UI/指令支持）
- [ ] 帧率/分辨率动态调整
- [ ] 采集窗口结束后立即释放句柄（缩短指示灯窗口）的量化测试

## 文件清单

```
agent_windows/
├── include/
│   └── camera.h           # CameraSource 接口、帧格式、错误码定义
├── src/
│   ├── cam_mock.c         # 虚拟源（测试/沙盒用，返回独立 buffer）
│   └── cam_jpeg.c         # 转码层：MJPEG 直通校验 + YUYV→JFIF
├── tests/
│   └── test_camera.py     # Python 集成测试（采集+密封全链路）
├── tools/
│   └── test_transcode.c   # C 端转码自测
└── README.md              # 本文件
```

## 编译与测试

```bash
# C 代码编译验证（Linux）
gcc -std=c99 -Wall -Wextra -I include src/cam_mock.c src/cam_jpeg.c \
    tools/test_transcode.c -o test_transcode
./test_transcode

# Python 集成测试
python3 tests/test_camera.py -v
```
