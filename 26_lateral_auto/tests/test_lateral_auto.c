/* 26_lateral_auto 测试 —— 真实 ssh-keygen / 真实 ssh 客户端交叉验证 */
#include "lateral_auto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <time.h>

static int pass = 0, fail = 0;

#define CHECK(cond, msg) do {                              \
        if (cond) { printf("[PASS] %s\n", msg); pass++; }  \
        else      { printf("[FAIL] %s\n", msg); fail++; }  \
    } while (0)

/* argv blob 是 NUL 分隔的串序列，strstr 只会看到第一个串 */
static int argv_has(const char *blob, size_t len, const char *sub)
{
    size_t i = 0;
    while (i < len) {
        const char *cur = blob + i;
        if (strstr(cur, sub) == cur || strstr(cur, sub) != NULL) {
            /* 子串必须完整落在该串内 */
            size_t l = strlen(cur);
            const char *hit = strstr(cur, sub);
            if (hit && (size_t)(hit - cur) <= l) return 1;
        }
        i += strlen(cur) + 1;
    }
    return 0;
}

static long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int write_file(const char *p, const char *c)
{
    FILE *f = fopen(p, "w");
    if (!f) return -1;
    fputs(c, f);
    fclose(f);
    return 0;
}

static int read_file(const char *p, char *out, size_t cap)
{
    FILE *f = fopen(p, "r");
    size_t n;
    if (!f) return -1;
    n = fread(out, 1, cap - 1, f);
    out[n] = '\0';
    fclose(f);
    return 0;
}

static int count_lines(const char *p)
{
    FILE *f = fopen(p, "r");
    int n = 0;
    char buf[4096];
    if (!f) return -1;
    while (fgets(buf, sizeof(buf), f)) n++;
    fclose(f);
    return n;
}

/* 用真实 ssh-keygen 取指纹，与我们的实现比对 */
static int real_fp(const char *pubpath, char *out, size_t cap)
{
    char cmd[600];
    FILE *pp;
    char line[512];

    snprintf(cmd, sizeof(cmd), "ssh-keygen -l -E sha256 -f %s 2>/dev/null",
             pubpath);
    pp = popen(cmd, "r");
    if (!pp) return -1;
    out[0] = '\0';
    if (fgets(line, sizeof(line), pp)) {
        /* 格式: "256 SHA256:xxxx comment (ED25519)" */
        char *sp = strchr(line, ' ');
        if (sp) {
            char *fp = sp + 1;
            char *ep = strchr(fp, ' ');
            if (ep) *ep = '\0';
            snprintf(out, cap, "%s", fp);
        }
    }
    pclose(pp);
    return out[0] ? 0 : -1;
}

int main(void)
{
    char dir[] = "/tmp/lat_test_XXXXXX";
    char kpath[LAT_PATH_MAX];
    char pubpath[LAT_PATH_MAX + 4];
    lat_cred_t cred;
    char buf[4096];

    if (!mkdtemp(dir)) { printf("mkdtemp failed\n"); return 1; }

    /* ---- 1. 真实生成 ---- */
    snprintf(kpath, sizeof(kpath), "%s/id_ed25519", dir);
    CHECK(lat_cred_gen(dir, "id_ed25519", "lat-test", &cred) == 0,
          "ssh-keygen 真实生成密钥对");
    {
        struct stat st;
        snprintf(pubpath, sizeof(pubpath), "%s.pub", kpath);
        CHECK(stat(kpath, &st) == 0 && stat(pubpath, &st) == 0,
              "私钥与公钥文件均存在");
    }

    /* ---- 2. 指纹与真实 ssh-keygen 交叉验证（硬证据） ---- */
    {
        char rfp[LAT_FP_MAX];
        if (real_fp(pubpath, rfp, sizeof(rfp)) == 0) {
            CHECK(strcmp(cred.fp, rfp) == 0, "指纹与 ssh-keygen -l 逐字符一致");
            if (strcmp(cred.fp, rfp) != 0)
                printf("       ours=%s\n       real=%s\n", cred.fp, rfp);
        } else {
            printf("[SKIP] 无法调用 ssh-keygen -l\n");
        }
    }

    /* ---- 3. 公钥读取 ---- */
    CHECK(lat_cred_pubkey(&cred, buf, sizeof(buf)) == 0 &&
          strncmp(buf, "ssh-ed25519", 11) == 0, "公钥读取且类型正确");

    /* ---- 4. 扫描 ---- */
    {
        lat_cred_t found[8];
        size_t n = 0;
        char sshdir[600];
        char mv[2048];
        snprintf(sshdir, sizeof(sshdir), "%s/.ssh", dir);
        if (system((snprintf(mv, sizeof(mv), "mkdir -p %s && cp %s %s.pub %s",
                             sshdir, kpath, kpath, sshdir),
                    mv)) != 0)
            printf("[SKIP] 无法建立 .ssh 目录\n");
        CHECK(lat_cred_scan(dir, found, 8, &n) == 0 && n >= 1,
              "扫描到私钥");
        if (n >= 1) {
            CHECK(strcmp(found[0].fp, cred.fp) == 0, "扫描指纹与生成指纹一致");
            CHECK(found[0].owned == 0, "扫描到的凭据不标记为本框架所有");
        }
        CHECK(cred.owned == 1, "生成的凭据标记为本框架所有");
    }

    /* ---- 5. known_hosts 解析 ---- */
    {
        char p[512];
        char hosts[16][LAT_HOST_MAX];
        size_t n = 0;
        snprintf(p, sizeof(p), "%s/known_hosts", dir);
        write_file(p,
            "# comment\n"
            "10.0.0.5 ssh-ed25519 AAAAC3NzaTest1\n"
            "db01,10.0.0.6 ssh-rsa AAAAB3NzaTest2\n"
            "|1|abcdef|ghijkl ssh-ed25519 AAAAC3NzaHashed\n"
            "@cert-authority *.example.com ssh-rsa AAAAB3NzaCA\n"
            "[fe80::1]:2222 ssh-ed25519 AAAAC3NzaV6\n"
            "jump.internal ssh-ed25519 AAAAC3NzaJump\n");
        CHECK(lat_target_known_hosts(p, hosts, 16, &n) == 0, "known_hosts 解析成功");
        {
            int has_hashed = 0, has_ca = 0;
            for (size_t i = 0; i < n; i++) {
                if (strncmp(hosts[i], "|1|", 3) == 0) has_hashed = 1;
                if (strstr(hosts[i], "example.com")) has_ca = 1;
            }
            CHECK(!has_hashed, "hashed 条目被跳过");
            CHECK(!has_ca, "@cert-authority 的通配段被跳过");
            {
                int has5 = 0, has6 = 0, hasv6 = 0;
                for (size_t i = 0; i < n; i++) {
                    if (strcmp(hosts[i], "10.0.0.5") == 0) has5 = 1;
                    if (strcmp(hosts[i], "10.0.0.6") == 0) has6 = 1;
                    if (strcmp(hosts[i], "fe80::1") == 0) hasv6 = 1;
                }
                CHECK(has5 && has6, "逗号分隔的两个主机都被取出");
                CHECK(hasv6, "[host]:port 形式的 IPv6 主机被取出");
            }
        }
    }

    /* ---- 6. ssh_config 解析 ---- */
    {
        char p[512];
        char hosts[16][LAT_HOST_MAX];
        size_t n = 0;
        snprintf(p, sizeof(p), "%s/ssh_config", dir);
        write_file(p,
            "Host web01 web02\n"
            "    HostName 10.0.1.10\n"
            "Host *.example.com\n"
            "    User admin\n"
            "Host !bad db03\n"
            "    Port 2222\n"
            "HostName should-not-match\n");
        CHECK(lat_target_ssh_config(p, hosts, 16, &n) == 0, "ssh_config 解析成功");
        {
            int w1 = 0, w2 = 0, d3 = 0, wild = 0;
            for (size_t i = 0; i < n; i++) {
                if (strcmp(hosts[i], "web01") == 0) w1 = 1;
                if (strcmp(hosts[i], "web02") == 0) w2 = 1;
                if (strcmp(hosts[i], "db03") == 0) d3 = 1;
                if (strstr(hosts[i], "example.com")) wild = 1;
            }
            CHECK(w1 && w2, "同一 Host 行的两个主机都被取出");
            CHECK(d3, "含取反标记的段中有效主机仍被取出");
            CHECK(!wild, "通配符段被跳过");
        }
    }

    /* ---- 7. hosts 文件 ---- */
    {
        char p[512];
        char hosts[16][LAT_HOST_MAX];
        size_t n = 0;
        snprintf(p, sizeof(p), "%s/hosts", dir);
        write_file(p,
            "127.0.0.1 localhost\n"
            "::1 localhost ip6-localhost\n"
            "10.0.0.20 gitlab.internal git\n"
            "10.0.0.21 ci01\n");
        CHECK(lat_target_hosts_file(p, hosts, 16, &n) == 0, "hosts 文件解析成功");
        {
            int lo = 0, gl = 0, ci = 0;
            for (size_t i = 0; i < n; i++) {
                if (strcmp(hosts[i], "localhost") == 0) lo = 1;
                if (strcmp(hosts[i], "gitlab.internal") == 0) gl = 1;
                if (strcmp(hosts[i], "ci01") == 0) ci = 1;
            }
            CHECK(!lo, "localhost 与回环地址被跳过");
            CHECK(gl && ci, "内网主机与别名被取出");
        }
    }

    /* ---- 8. argv 构造：三条硬规则 ---- */
    {
        lat_ssh_opt_t o;
        char blob[2048];
        size_t len;
        memset(&o, 0, sizeof(o));
        o.host = "10.0.0.5"; o.user = "root"; o.port = 2222;
        o.remote_cmd = "id"; o.connect_timeout_ms = 3000;
        o.key_path = kpath;
        len = lat_ssh_argv(&o, blob, sizeof(blob));
        CHECK(len > 0, "argv 构造成功");
        CHECK(argv_has(blob, len, "BatchMode=yes"), "argv 含 BatchMode=yes");
        CHECK(argv_has(blob, len, "UserKnownHostsFile=/dev/null"),
              "argv 含 UserKnownHostsFile=/dev/null");
        CHECK(argv_has(blob, len, "StrictHostKeyChecking=no"),
              "argv 含 StrictHostKeyChecking=no");
        CHECK(argv_has(blob, len, "ConnectTimeout=3"), "argv 含 ConnectTimeout");
        CHECK(argv_has(blob, len, "IdentitiesOnly=yes") &&
              argv_has(blob, len, kpath), "提供私钥时带 IdentitiesOnly 与 -i");
        CHECK(argv_has(blob, len, "root@10.0.0.5"), "目标为 user@host");
        CHECK(argv_has(blob, len, "2222"), "端口被传递");
    }

    /* ---- 9. ConnectTimeout 非正被强制（硬规则 2） ---- */
    {
        lat_ssh_opt_t o;
        char blob[2048];
        memset(&o, 0, sizeof(o));
        o.host = "h"; o.user = "u"; o.remote_cmd = "id";
        o.connect_timeout_ms = 0;             /* 非法值 */
        {
            size_t l2 = lat_ssh_argv(&o, blob, sizeof(blob));
            CHECK(l2 > 0 && argv_has(blob, l2, "ConnectTimeout=1"),
                  "ConnectTimeout<=0 被强制为 1（不挂死）");
        }
    }

    /* ---- 10. 真实 fork/exec：argv 传递与输出捕获 ---- */
    {
        char fake[512];
        lat_ssh_opt_t o;
        char out[LAT_OUT_MAX];
        snprintf(fake, sizeof(fake), "%s/fake_ssh", dir);
        write_file(fake, "#!/bin/sh\n"
                         "echo \"ARGV:$*\"\n"
                         "echo \"KEY:$SSH_AUTH_SOCK\"\n"
                         "exit 0\n");
        chmod(fake, 0755);
        memset(&o, 0, sizeof(o));
        o.host = "10.0.0.5"; o.user = "root"; o.port = 22;
        o.remote_cmd = "id"; o.connect_timeout_ms = 1000;
        CHECK(lat_ssh_exec(&o, fake, out, sizeof(out), 5000) == 0,
              "执行器返回成功（注入的假 ssh）");
        CHECK(strstr(out, "BatchMode=yes") != NULL, "argv 真实传递给执行器");
        CHECK(strstr(out, "root@10.0.0.5") != NULL, "user@host 真实传递");
    }

    /* ---- 11. 非零退出被区分 ---- */
    {
        char fake[512];
        lat_ssh_opt_t o;
        char out[LAT_OUT_MAX];
        snprintf(fake, sizeof(fake), "%s/fail_ssh", dir);
        write_file(fake, "#!/bin/sh\necho denied\nexit 3\n");
        chmod(fake, 0755);
        memset(&o, 0, sizeof(o));
        o.host = "h"; o.user = "u"; o.remote_cmd = "id";
        o.connect_timeout_ms = 1000;
        CHECK(lat_ssh_exec(&o, fake, out, sizeof(out), 5000) == 3,
              "非零退出码被原样返回（不是笼统失败）");
    }

    /* ---- 12. 硬超时 ---- */
    {
        char fake[512];
        lat_ssh_opt_t o;
        char out[LAT_OUT_MAX];
        long t0;
        snprintf(fake, sizeof(fake), "%s/slow_ssh", dir);
        write_file(fake, "#!/bin/sh\nsleep 30\n");
        chmod(fake, 0755);
        memset(&o, 0, sizeof(o));
        o.host = "h"; o.user = "u"; o.remote_cmd = "id";
        o.connect_timeout_ms = 1000;
        t0 = now_ms();
        {
            int rc = lat_ssh_exec(&o, fake, out, sizeof(out), 1500);
            long dt = now_ms() - t0;
            CHECK(rc == -2, "挂起的 ssh 被硬超时终止（返回 -2）");
            CHECK(dt < 10000, "硬超时及时返回（未等到子进程自然结束）");
        }
    }

    /* ---- 13. 真实 /usr/bin/ssh 接受我们的命令行 ---- */
    {
        lat_ssh_opt_t o;
        char out[LAT_OUT_MAX];
        memset(&o, 0, sizeof(o));
        o.host = "127.0.0.1"; o.user = "root"; o.port = 1;  /* 必然拒绝连接 */
        o.remote_cmd = "id"; o.connect_timeout_ms = 1000;
        o.key_path = kpath;
        lat_ssh_exec(&o, "/usr/bin/ssh", out, sizeof(out), 8000);
        if (strstr(out, "Bad configuration option") != NULL)
            printf("       ssh 输出: %s\n", out);
        CHECK(strstr(out, "Bad configuration option") == NULL,
              "真实 ssh 客户端未报配置项错误（命令行被接受）");
        {
            int is_usage = strstr(out, "usage: ssh") != NULL;
            CHECK(!is_usage, "真实 ssh 客户端未报用法错误");
        }
    }

    /* ---- 14. 散布幂等（真实 shell 执行两次） ---- */
    {
        char pub[1024];
        char cmd[4096];
        char fakehome[512];
        char ak[600];
        int  n1, n2;
        CHECK(lat_cred_pubkey(&cred, pub, sizeof(pub)) == 0, "取得公钥用于散布");
        CHECK(lat_spread_cmd(pub, "test-marker", cmd, sizeof(cmd)) > 0,
              "散布命令构造成功");
        snprintf(fakehome, sizeof(fakehome), "%s/home", dir);
        {
            char sh[1024];
            snprintf(sh, sizeof(sh), "mkdir -p %s", fakehome);
            if (system(sh) != 0) printf("[SKIP] 无法建立假 HOME\n");
        }
        {
            /*
             * 命令本身含单引号（printf '%s %s'），绝不能再用 sh -c '...'
             * 包裹 —— 单引号会提前闭合，命令被截断。改为写脚本文件执行。
             */
            char script[1024];
            char run[2048];
            snprintf(script, sizeof(script), "%s/spread.sh", dir);
            write_file(script, cmd);
            snprintf(run, sizeof(run), "HOME=%s /bin/sh %s", fakehome, script);
            if (system(run) != 0) printf("[SKIP] 散布命令执行失败\n");
            snprintf(ak, sizeof(ak), "%s/.ssh/authorized_keys", fakehome);
            n1 = count_lines(ak);
            if (system(run) != 0) printf("[SKIP] 第二次散布执行失败\n");
            n2 = count_lines(ak);
            CHECK(n1 == 1 && n2 == 1, "散布幂等：执行两次仍只有一行");
            if (!(n1 == 1 && n2 == 1))
                printf("       n1=%d n2=%d\n", n1, n2);
        }
    }

    /* ---- 15. 散布拒绝含危险字符的公钥（注入防护） ---- */
    {
        char cmd[4096];
        CHECK(lat_spread_cmd("ssh-ed25519 AAAA'; rm -rf /; #", "m",
                             cmd, sizeof(cmd)) == 0,
              "含单引号的公钥被拒绝（防命令注入）");
        CHECK(lat_spread_cmd("ssh-ed25519 AAAA$(id)", "m",
                             cmd, sizeof(cmd)) == 0,
              "含 $() 的公钥被拒绝");
    }

    /* ---- 16. 编排：全成功 ---- */
    {
        char fake[512];
        const char *hosts[] = { "10.0.0.5", "10.0.0.6", "10.0.0.7" };
        lat_orch_t oc;
        lat_result_t rs[3];
        snprintf(fake, sizeof(fake), "%s/ok_ssh", dir);
        write_file(fake, "#!/bin/sh\nexit 0\n");
        chmod(fake, 0755);
        memset(&oc, 0, sizeof(oc));
        memcpy(&oc.cred, &cred, sizeof(cred));
        oc.hosts = hosts; oc.nhosts = 3;
        oc.user = "root"; oc.cmd = "id"; oc.ssh_bin = fake;
        oc.max_parallel = 2; oc.max_attempts = 1; oc.delay_ms = 0;
        oc.timeout_ms = 5000;
        CHECK(lat_orch_run(&oc, rs, 3) == 3, "编排：三个目标全部成功");
        CHECK(rs[0].ok && rs[1].ok && rs[2].ok, "编排：结果逐项正确");
        CHECK(strcmp(rs[0].host, "10.0.0.5") == 0, "编排：主机名回填正确");
    }

    /* ---- 17. 编排：重试 ---- */
    {
        char fake[512];
        char statef[512];
        const char *hosts[] = { "h1" };
        lat_orch_t oc;
        lat_result_t rs[1];
        snprintf(statef, sizeof(statef), "%s/attempt_state", dir);
        write_file(statef, "0\n");
        snprintf(fake, sizeof(fake), "%s/flaky_ssh", dir);
        {
            char body[2048];
            snprintf(body, sizeof(body),
                "#!/bin/sh\n"
                "S=$(cat %s)\n"
                "S=$((S+1))\n"
                "echo $S > %s\n"
                "if [ \"$S\" -lt 2 ]; then exit 1; fi\n"
                "exit 0\n", statef, statef);
            write_file(fake, body);
        }
        chmod(fake, 0755);
        memset(&oc, 0, sizeof(oc));
        memcpy(&oc.cred, &cred, sizeof(cred));
        oc.hosts = hosts; oc.nhosts = 1;
        oc.user = "root"; oc.cmd = "id"; oc.ssh_bin = fake;
        oc.max_parallel = 1; oc.max_attempts = 3; oc.backoff_ms = 10;
        oc.delay_ms = 0; oc.timeout_ms = 5000;
        CHECK(lat_orch_run(&oc, rs, 1) == 1, "编排：失败后重试成功");
        CHECK(rs[0].attempts == 2, "编排：实际尝试次数正确");
    }

    /* ---- 18. 编排：速率限制生效 ---- */
    {
        char fake[512];
        const char *hosts[4] = { "a", "b", "c", "d" };
        lat_orch_t oc;
        lat_result_t rs[4];
        long t0, dt;
        snprintf(fake, sizeof(fake), "%s/ok_ssh", dir);
        memset(&oc, 0, sizeof(oc));
        memcpy(&oc.cred, &cred, sizeof(cred));
        oc.hosts = hosts; oc.nhosts = 4;
        oc.user = "root"; oc.cmd = "id"; oc.ssh_bin = fake;
        oc.max_parallel = 2; oc.max_attempts = 1;
        oc.delay_ms = 300; oc.timeout_ms = 5000;
        t0 = now_ms();
        lat_orch_run(&oc, rs, 4);
        dt = now_ms() - t0;
        CHECK(dt >= 300, "编排：批间延迟生效（速率限制不是空话）");
    }

    /* ---- 19. 编排：参数非法被拒 ---- */
    {
        const char *hosts[] = { "h" };
        lat_orch_t oc;
        lat_result_t rs[1];
        memset(&oc, 0, sizeof(oc));
        oc.hosts = hosts; oc.nhosts = 1;
        CHECK(lat_orch_run(&oc, rs, 0) == -1, "结果数组容量不足被拒绝");
    }

    /* ---- 20. 真实 ssh 客户端发起真实 SSH 协议握手（端到端） ---- */
    {
        int lfd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in sa;
        socklen_t sl = sizeof(sa);
        int port = 0;
        pid_t pid;
        char gotfile[512];
        lat_ssh_opt_t o;
        char out[LAT_OUT_MAX];

        snprintf(gotfile, sizeof(gotfile), "%s/peer_bytes", dir);
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sa.sin_port = 0;

        if (lfd >= 0 && bind(lfd, (struct sockaddr *)&sa, sizeof(sa)) == 0 &&
            listen(lfd, 1) == 0 &&
            getsockname(lfd, (struct sockaddr *)&sa, &sl) == 0) {
            port = ntohs(sa.sin_port);
        }

        if (port > 0) {
            pid = fork();
            if (pid == 0) {
                /* 假 SSH 服务端：发版本串，读客户端首包，落盘后退出 */
                int cfd = accept(lfd, NULL, NULL);
                if (cfd >= 0) {
                    const char *banner = "SSH-2.0-OpenSSH_probe\r\n";
                    char rb[512];
                    ssize_t n;
                    send(cfd, banner, strlen(banner), 0);
                    n = recv(cfd, rb, sizeof(rb) - 1, 0);
                    if (n > 0) {
                        FILE *f = fopen(gotfile, "w");
                        if (f) {
                            fwrite(rb, 1, (size_t)n, f);
                            fclose(f);
                        }
                    }
                    close(cfd);
                }
                _exit(0);
            }

            memset(&o, 0, sizeof(o));
            o.host = "127.0.0.1"; o.user = "root"; o.port = port;
            o.remote_cmd = "id"; o.connect_timeout_ms = 2000;
            o.key_path = kpath;
            lat_ssh_exec(&o, "/usr/bin/ssh", out, sizeof(out), 8000);
            close(lfd);
            { int st; waitpid(pid, &st, 0); }

            {
                char got[512];
                if (read_file(gotfile, got, sizeof(got)) == 0) {
                    CHECK(strncmp(got, "SSH-2.0-", 8) == 0,
                          "真实 ssh 客户端向真实目标发起了 SSH 协议握手");
                } else {
                    CHECK(0, "真实 ssh 客户端发起握手（服务端未收到版本串）");
                }
            }
        } else {
            printf("[SKIP] 无法建立监听，跳过握手用例\n");
        }
        if (lfd >= 0) close(lfd);
    }

    printf("\n=== %d pass, %d fail ===\n", pass, fail);
    {
        char rm[1024];
        snprintf(rm, sizeof(rm), "rm -rf %s", dir);
        if (system(rm) != 0) { /* 清理失败不影响结果 */ }
    }
    return fail ? 1 : 0;
}
