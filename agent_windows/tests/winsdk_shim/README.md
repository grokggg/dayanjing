# winsdk_shim

## 这是什么

Windows SDK 的最小等价声明 + 可运行 mock Media Foundation。
用途是让 `src/cam_mf.cpp`（Windows 专用）在 Linux 下能被 `g++`
**真实编译并真跑**，从而在没有 Windows 工具链的环境里验证它。

**不是产品代码，不参与部署。**

## 为什么需要它

MinGW 交叉工具链在本沙盒不可得：

- `apt-get install mingw-w64` → apt 源全部 403
- GitHub release 下载 → `github.com` / `objects.githubusercontent.com` 403
- `musl.cc` / `sourceforge.net` → 403

出口白名单仅放行 `api.github.com`。所以真机交叉编译此路不通，
改用 shim 做等价验证。

## 覆盖与不覆盖

| 覆盖 | 不覆盖 |
|---|---|
| 语法、类型、调用契约 | Windows Media Foundation 的真实设备行为 |
| 格式协商逻辑（MJPEG 优先链、分辨率匹配） | 真实摄像头硬件 |
| 取帧、时间戳换算、缓冲区持有 | 注册表真实语义（mock 为已授权） |
| COM 生命周期（Startup/Shutdown 配对） | UTF-16 编码（WCHAR 用 4 字节 wchar_t） |

## 保真度要点

- `HRESULT` 是 `int32_t`。真机 Windows 的 `long` 是 32 位，
  `0xC00D36B9` 为负数。若 shim 里定义成 64 位 `long`，该值变正数，
  `FAILED()` 会失效 → 掩盖真实缺陷。**这是 shim 最容易出错的一处。**
- `MF_MT_FRAME_SIZE` 在 mock 中存为 `UINT64`（真机语义），
  因此 `GetUINT32` 对它必须失败。这是暴露真实缺陷的关键设计。

## 抓出的真实缺陷

`cam_mf.cpp` 此前从未被任何编译器检查过。经 shim 编译 + 逻辑运行，抓出：

| # | 缺陷 | 后果 | 严重度 |
|---|---|---|---|
| 1 | `GetUINT32(MF_MT_FRAME_SIZE)` 读 packed `UINT64` | 宽高恒为 0：指定分辨率时协商永远失败，**摄像头根本打不开**；不指定时写 0×0 却返回成功（假成功） | 致命 |
| 2 | `SetUINT32` + 16/16 打包设置 `FRAME_SIZE` | 与读取端不对称，写入的分辨率仍是错的 | 致命 |
| 3 | `ZeroMemory` 对已构造的 `mf_priv`（含 `std::vector`/`ComPtr`） | 破坏已构造子对象，UB。GCC `-Wclass-memaccess` 告警 | 高 |
| 4 | `mf_close` 无条件 `MFShutdown()` | 从未 open 的实例 close 一次，关掉整个进程的 MF，同进程其他采集实例失效 | 高 |
| 5 | RGB24 按 `'RGB '` 匹配，真机 `MFVideoFormat_RGB24` 的 `Data1` 是 20 | RGB24 设备永远被判 UNKNOWN，无法采集 | 中 |
| 6 | 多字符字面量 `'GPJM'` 等 | 取值是实现定义的，换编译器会静默变值；GCC/MSVC 均告警 | 中 |
| 7 | 死变量 `sid_sz` | 无 | 低 |

修复后：`make winshim` → 19/19 PASS，编译零警告零错误。

## 用法

```bash
make winshim          # 构建并运行，19/19
make winshim-build    # 只构建
```

产物在 `build/winshim/`（已被 `make clean` 清除，不入库）。

## 测试注入接口

见 `wsdk_test.h`。测试用 `wsdk_set_native_formats()` 注入假设备的
原生格式表，再用 `wsdk_last_set_subtype()` / `wsdk_last_set_framesize()`
取证 `SetCurrentMediaType` 实际写入了什么 —— 这是验证"协商结果是否正确"
的关键，只看 `open()` 返回值会被假成功骗过。
