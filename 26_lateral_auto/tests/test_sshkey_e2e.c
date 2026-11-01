/*
 * 凭据层 -> 持久化层 端到端真实性验证
 *
 * 为什么必须有这个测试：
 *   持久化层若写死 "ssh-rsa " 类型前缀去接凭据层产出的 ed25519 blob，
 *   OpenSSH 会拒绝整行。后果是"驻留项装上了、看起来成功、但永远登不进去"——
 *   消耗一次写入动作、留下痕迹、零收益，比不装更糟。
 *   本测试用真实 ssh-keygen -l 解析落盘文件，是"该驻留项可认证"的唯一硬证据。
 *
 * 为什么不能用假 ssh 验证：
 *   假程序忽略参数照常返回 0，任何类型错配都不会暴露。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "persist.h"
#include "lateral_auto.h"

static int fails = 0, passes = 0;
static void ck(int c, const char *name) {
    if (c) { passes++; printf("[PASS] %s\n", name); }
    else   { fails++;  printf("[FAIL] %s\n", name); }
}

/* 用真实 ssh-keygen -l 解析文件，返回其输出的指纹串；失败返回空 */
static int real_fingerprint(const char *file, char *out, size_t cap)
{
    char cmd[1024], line[1024];
    FILE *f;
    snprintf(cmd, sizeof cmd, "ssh-keygen -l -E sha256 -f '%s' 2>/dev/null", file);
    f = popen(cmd, "r");
    if (!f) return -1;
    out[0] = '\0';
    if (fgets(line, sizeof line, f)) {
        /* 形如: 256 SHA256:xxxx comment (ED25519) */
        char *p = strstr(line, "SHA256:");
        if (p) {
            size_t i = 0;
            while (p[i] && p[i] != ' ' && p[i] != '\n' && i + 1 < cap) {
                out[i] = p[i]; i++;
            }
            out[i] = '\0';
        }
    }
    pclose(f);
    return out[0] ? 0 : -1;
}

int main(int argc, char **argv)
{
    char root[512], keydir[512], pub[1024], binp[512], ak[1024];
    char realfp[128];
    lat_cred_t cred;
    int meth[3];
    const char *base = argc > 1 ? argv[1] : "/tmp";

    snprintf(root,   sizeof root,   "%s/.lat_sshkey_e2e", base);
    snprintf(keydir, sizeof keydir, "%s/keys", root);
    mkdir(root, 0700);
    mkdir(keydir, 0700);

    /* 1. 真实生成 ed25519 密钥对 */
    memset(&cred, 0, sizeof cred);
    ck(lat_cred_gen(keydir, "agent_key", "dayanjing", &cred) == 0,
       "真实 ssh-keygen 生成 ed25519 密钥对");
    ck(cred.owned == 1, "标记为自有密钥");

    /* 2. 读公钥整行 */
    ck(lat_cred_pubkey(&cred, pub, sizeof pub) == 0, "读取公钥行");
    ck(strncmp(pub, "ssh-ed25519 ", 12) == 0, "公钥行带正确类型前缀(ssh-ed25519)");

    /* 3. 注入持久化层 */
    ck(persist_sshkey_pubkey(pub) == 0, "持久化层接受完整公钥行");

    /* 4. 安装驻留 */
    ck(persist_linux_ensure(root, binp, sizeof binp, meth, 3) >= 0,
       "linux_ensure 成功");
    ck(meth[2] == 1, "sshkey 驻留项已安装");

    /* 5. 落盘文件必须能被真实 OpenSSH 解析 */
    {
        const char *home = getenv("HOME");
        snprintf(ak, sizeof ak, "%s%s/.ssh/authorized_keys",
                 root, (home && *home) ? home : "/root");
    }
    ck(real_fingerprint(ak, realfp, sizeof realfp) == 0,
       "真实 ssh-keygen -l 能解析落盘 authorized_keys");
    ck(strcmp(realfp, cred.fp) == 0, "OpenSSH 解析指纹 == 凭据层自算指纹");

    printf("[INFO] 自算=%s\n[INFO] 解析=%s\n", cred.fp, realfp);

    /* 6. 卸载后该项消失（幂等清理） */
    ck(persist_uninstall(PERSIST_SSHKEY, root, NULL) == 0, "卸载 sshkey 成功");
    ck(persist_installed(root, PERSIST_SSHKEY) == 0, "卸载后 sshkey 不在位");

    printf("=== result: %d pass, %d fail ===\n", passes, fails);
    return fails ? 1 : 0;
}
