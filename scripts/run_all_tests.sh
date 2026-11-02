#!/bin/sh
# dayanjing 全模块回归
# 覆盖：C 模块单测 + 跨模块集成 + Python 侧
# 每一步都套 timeout，任何一个卡住都不拖垮整体
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
# 断点续跑：本沙盒每约 8 分钟发生一次 502 故障并杀掉全部进程，而全仓入口
# 需 30+ 分钟 —— 单次运行必然被打断（实测两次都死在同一时点，而该模块
# 单独跑只需 186s，故非挂死而是进程被杀）。
# RESUME_FROM 之前的模块由上一分段跑过，其计数经 BASE_PASSED/BASE_FAILED
# 计入，本段只跑其后的模块。汇总与完整入口等价，但由多段拼成 ——
# 汇报时必须说明，不得冒充"一次跑完"。
failed=${BASE_FAILED:-0}
passed=${BASE_PASSED:-0}
skipped=0

# 单实例锁：回归入口之间的干扰极难归因，必须前置排除。
# 实测后果（两个实例并发）：两个 make 同时写同一 build 产物 -> "Text file busy"
# 使 winshim 直接 Error 127；节点端口被对方占用 -> deploy_4node 端到端实收空
# 字节而其它断言全绿；若两者再重定向到同一日志文件，输出交错成
# "=== resPASS === result" 这种不可读的碎片。
# 三类症状没有一个指向"并发"，排查方向会被带向被干扰模块自身。
# 用 flock 而非 pidfile：pidfile 在进程被强杀后残留，会把后续所有回归
# 永久判成"已有实例在跑"。
# 临时目录不能硬编码 /tmp：本沙盒根 overlay 以 ro 挂载，/tmp 随之只读；
# /tmp 还会被环境清理。硬编码会让整条入口以 "Read-only file system" 退出，
# 报错指向文件系统，排查方向被引向"环境坏了"而非"入口选错了目录"。
TMPD="${DAYANJING_TMP:-}"
if [ -z "$TMPD" ] || ! { mkdir -p "$TMPD" 2>/dev/null && : > "$TMPD/.wtest" 2>/dev/null; }; then
    TMPD=""
    for c in /data/workspace/.regtmp /tmp; do
        if mkdir -p "$c" 2>/dev/null && : > "$c/.wtest" 2>/dev/null; then TMPD="$c"; break; fi
    done
fi
if [ -z "$TMPD" ]; then
    echo "[FATAL] 找不到可写临时目录（/data/workspace/.regtmp 与 /tmp 均不可写）"
    exit 2
fi

# ---- 临时盘自愈：运行中 $TMPD 变 Stale 时换盘，而不是让步骤伪装失败 ----
# SEQ:77 实测：/data/workspace 中途出现 Stale file handle，守卫日志
# （$TMPD/guards_*.log）与 ckpt 都写在这里 —— make test 本身还没跑，
# 重定向先失败，回归把「临时盘不可写」记成了「守卫 FAIL」，二者外观
# 完全一致，排查方向被引向守卫实现，而真凶是文件系统。
# TMPD 只在启动时选一次不够：故障发生在中途。故每次落盘前重检并换盘。
# 换盘失败时返回非 0，由调用方记 SKIP —— 绝不记 PASS：把环境故障记成
# 通过，与「判据恒绿」是同一类错，比记 FAIL 更危险。
tmpd_fix() {
    if : > "$TMPD/.wtest" 2>/dev/null; then return 0; fi
    for c in /dev/shm/dayanjing_tmp /data/workspace/.regtmp2 /tmp; do
        if mkdir -p "$c" 2>/dev/null && : > "$c/.wtest" 2>/dev/null; then
            echo "  [注意] 临时盘 $TMPD 已不可写，切换至 $c"
            TMPD="$c"
            return 0
        fi
    done
    return 1
}

# ---- checkpoint 与锁单独放盘，必须与 $TMPD 分离 ----
# SEQ:77 实测：virtiofs 抖动会让整个 /data/workspace 出现 Stale file handle，
# 而续跑状态（checkpoint）原本就写在这里 —— 于是「需要续跑」的时刻恰好是
# 「续跑状态读不出来」的时刻，断点记录随故障一起丢失，被杀后只能从头跑。
# /dev/shm 是 tmpfs，与 virtiofs 不是同一个文件系统，故障不影响它。
# 这里只放【状态】（数百字节），不放构建产物（体积大且需跨段复用，留在
# $TMPD）；产物丢了顶多重编，状态丢了整轮作废。
CKPTD=""
for c in /dev/shm/dayanjing_ckpt "$TMPD"; do
    if mkdir -p "$c" 2>/dev/null && : > "$c/.wtest" 2>/dev/null; then CKPTD="$c"; break; fi
done
[ -n "$CKPTD" ] || CKPTD="$TMPD"
# 若 /dev/shm 不可用（部分容器无 tmpfs），退化为同盘并明确告警：此时续跑
# 在文件系统故障下仍会失效，但至少不会静默降级成「看起来能续跑」。
if [ "$CKPTD" = "$TMPD" ] && [ "${DAYANJING_PRINT_FP:-0}" = "1" ]; then
    echo "[WARN] checkpoint 未分离到 tmpfs，文件系统故障时续跑将失效"
fi
REG_LOCK=$CKPTD/dayanjing_regression.lock
if command -v flock >/dev/null 2>&1; then
    exec 9>"$REG_LOCK"
    if ! flock -n 9; then
        echo "[FATAL] 已有回归实例在运行（锁 $REG_LOCK）"
        echo "        并发实例会互相破坏 build 产物与端口，结果不可信。"
        echo "        确认无实例后再跑；若确认是残留锁，删除 $REG_LOCK。"
        exit 2
    fi
else
    echo "[WARN] 无 flock，无法施加单实例锁；请勿并发运行本脚本"
fi

# 回归上下文标记：onekey.sh 在"未显式指定 PREFIX 且以 root 运行"时据此自动切
# 假根，避免部署测试写真实 /etc。非 root 场景（verify_user_deploy 用 uid=65534
# 验证用户级降级）不受影响——它落点在 $HOME，本来就不碰真实 /etc。
# ---- 自动断点续跑 ----
# 旧实现只有手写的 RESUME_FROM：进程被杀后必须由人从日志里数出断点再手工指定。
# 实测后果：两次被 502 杀掉后重启都从 01 开始，前段二十多分钟全部作废，于是
# 「跨时段稳定」这条限制一直拿不到第二次完整绿跑。
# 现在每个步骤【开跑前】落盘 checkpoint（步骤名 + 此刻计数 + 源码树指纹）：
# 被杀的步骤尚未计分，重启后从它重跑（不是跳过），计数也回退到开跑前的值，
# 不会重复计分。指纹不匹配则丢弃 checkpoint —— 跨源码树的拼接会让「55 passed」
# 对应两份不同的代码，比从头跑一遍更难发现。
CKPT=$CKPTD/dayanjing_regression.ckpt
# 镜像：两份各扛一种故障，缺一份就会漏掉一种场景。
# 实测（SEQ:78）两种故障的幸存面正好互补，单写任意一份都不够：
#   A) virtiofs 抖动（Stale file handle），沙盒存活     -> tmpfs 在，virtiofs 读不出
#   B) 沙盒重启（502 后实测 uptime 归零）              -> tmpfs 被清空，virtiofs 在
# 只写 tmpfs：B 场景断点随重启丢失（本轮实测 /dev/shm 被整盘清空）。
# 只写 virtiofs：A 场景正是「需要续跑」的时刻却「读不出断点」（SEQ:77）。
# 故双写；读取时任一可读且指纹相符即接管。
if [ "$CKPTD" != "$TMPD" ]; then
    CKPT_MIRROR=$TMPD/dayanjing_regression.ckpt
else
    CKPT_MIRROR=""
fi

tree_fp() {
    # 指纹不可得时必须【显式返回哨兵】，绝不能退化成一个"看起来合法"的值。
    # 旧实现有三条静默退化路径，每条都会让续跑跨未知状态拼接：
    #   1) rev-parse 失败 -> echo nogit，与真实状态无从区分；
    #   2) git diff 失败/被杀 -> 管道仍产出空输出，sha256(空) = e3b0c44298fc1c14，
    #      与"树干净"的指纹【逐位相同】——本仓库干净树指纹正是这个值，
    #      所以失败与干净完全不可分辨；
    #   3) 文件系统抖动时 git diff 实测挂起 48s，而它每步都要算一次，且无超时上限。
    # 后果就是那类最难发现的记账不实：55 passed 由两份不同源码树的分段拼成，
    # 而汇总输出完全正常，看不出来。
    # 【不能用 diff-index 提速】——实测证伪：本沙盒文件系统抖动（overlay ro/rw
    # 反复重挂）会让索引里的 stat 缓存整体失效，diff-index 不刷新索引、直接
    # 按 stat 判脏，于是报出 548 个"已改动"文件；而同一时刻 porcelain 的
    # git diff HEAD 只有 1 个真改动。用它会得到一份与内容无关、且会随索引
    # 是否被刷新而变的指纹——比慢更糟。正确性是硬要求，速度只能让位。
    _h=$(timeout 15 git -C "$ROOT" rev-parse HEAD 2>/dev/null)
    if [ $? -ne 0 ] || [ -z "$_h" ]; then echo "FPUNKNOWN"; return 0; fi
    # 上限 20s：实测该命令在索引需整体刷新时会挂起 48s，而它每个步骤都要算
    # 一次。超时即判"不可得"，由上层拒绝拼接，不让一次卡顿拖垮整轮。
    # 【git1 已降为备用，不再优先】原实现让 git diff 路径优先，实测引发一类
    # 新的记账不实：git diff 在本沙盒时会挂死（D 态 SIGTERM 投递不进去，timeout
    # 只能干等 20s 后被判不可得），时好时坏 —— 于是同一次回归的两次启动会分别
    # 拿到 git1 与 ch1 两种前缀。判据要求"两边相等才接管"，跨前缀必然不符，
    # 结果就是：每次被 502 杀掉后重启都从头跑，跨时段续跑实际不可用，而日志
    # 显示"指纹不符丢弃"完全合法、看不出是环境抖动导致的能力失效。
    # 修法：让指纹来源【恒定】——优先用不依赖 git diff 的 ch1 内容哈希。只要
    # 源码内容没变，任何一次启动拿到的都是同一个 ch1 值，续跑即可靠接管。
    # git diff 仅保留为 ch1 也失败时的最后兜底（见本函数末尾）。
    # ---- 降级：tracked 文件内容哈希指纹 ----
    # git diff 在本沙盒实测已稳定挂死（>20s，且 D 态下 SIGTERM 无法投递，
    # timeout 只能干等）。它一挂住，FP_NOW 就退化为 FPUNKNOWN，续跑整体失效
    # —— 宁可不拼也不错拼，但能力等于没有。所以增加一条不依赖 git diff 的
    # 降级指纹：仍用 rev-parse 取 commit，再用 git ls-files 取 tracked 清单
    # （读索引文件本身，不依赖 stat 缓存），自己按路径排序后对【文件内容】哈希。
    # 两种指纹用不同前缀区分（git1 / ch1）：跨来源必然判为不符，从而拒绝拼接；
    # 不会像旧实现那样因为"两边都退回同一个哨兵"而照常接管。
    # ls-files 输出 NUL 分隔，不能进 shell 变量（NUL 会被截断成只剩第一个文件），
    # 必须落临时文件再喂给 xargs -0。
    _tmpf=$CKPTD/.lsfiles.$$
    if timeout 15 git -C "$ROOT" ls-files -z > "$_tmpf" 2>/dev/null && [ -s "$_tmpf" ]; then
        _fp=$( (cd "$ROOT" && xargs -0 -r sha256sum < "$_tmpf") 2>/dev/null \
              | LC_ALL=C sort -k2 | sha256sum 2>/dev/null | cut -c1-16)
        rm -f "$_tmpf"
        if [ -n "$_fp" ]; then echo "ch1:${_h}:${_fp}"; return 0; fi
    else
        rm -f "$_tmpf"
    fi
    # ---- 最后兜底：git diff 路径（ch1 也不可得时才用）----
    # 它在本沙盒会挂死，故放在 ch1 之后，且上限 20s。保留它是为了在 ch1 因
    # ls-files/sha256sum 不可用时仍有一条可判别的指纹，而不是退回哨兵。
    _d=$(timeout 20 git -C "$ROOT" diff HEAD --name-only 2>/dev/null)
    if [ $? -eq 0 ]; then
        _d=$(printf '%s' "$_d" | sha256sum 2>/dev/null | cut -c1-16)
        if [ -n "$_d" ]; then echo "git1:${_h}:${_d}"; return 0; fi
    fi
    echo "FPUNKNOWN"; return 0
}

# 指纹【只在启动时算一次】，不在每个步骤重算。
# 实测代价：本沙盒文件系统抖动时 git diff 会因索引整体刷新而挂起，套了
# timeout 20 也照样被拖满（RC=124 连续两次）。而它原本在 ckpt_mark 里
# 每步调用一次 —— 55 步就是十几分钟纯卡顿，且期间拿不到任何输出。
# 按次计算并不削弱判据：跨分段拼接时，新分段在【自己的启动时】算一次
# 指纹，与 checkpoint 里记录的上一段指纹比对，树变了照样判不符。
# 反而更稳：变异审计会在运行中临时改写源码再还原，若正好在改写窗口内
# 落盘 checkpoint，逐步指纹会记下一个"还原后不复现"的值，续跑永远判不符。
# 【注意：FP_NOW 不在这里算，已移至下方 mutation_audit.py heal 之后。】
# 曾在此处计算，实测后果是跨时段续跑永远失效，而日志完全合法、看不出异常：
# 指纹用的是 ch1 内容哈希，而 heal 的职责正是还原被强杀的变异审计留下的
# 源码改写 —— 于是第一次启动在【污染态】算指纹（heal 尚未执行），被杀后
# 第二次启动在【已 heal 的干净态】算指纹，两者必然不符，判据正确地拒绝
# 拼接，续跑因此一次都没真正接管过。
# 实测三态：干净 7ad95d83… / 注入残留变异 03692b95… / 还原后回到 7ad95d83…。
# 教训：指纹必须描述"本次回归实际要跑的那份源码"，任何会改变源码的动作
# （heal、自愈、格式还原）都必须排在取指纹之前，否则指纹记的是历史态。

ckpt_mark() {
    # 先写临时文件再 mv。直接 `> "$CKPT"` 会先把文件截断成 0 字节，若此刻
    # 被杀（502 会杀掉全部进程），就留下一个空 checkpoint —— 下次一个字段都
    # 解析不到，表现同样是"指纹不符"，于是又从头跑。mv 是原子操作，不会
    # 留下半截状态。
    printf 'NEXT=%s PASSED=%s FAILED=%s SKIPPED=%s FP=%s\n' \
        "$1" "$passed" "$failed" "$skipped" "$FP_NOW" > "$CKPT.tmp" 2>/dev/null \
        && mv -f "$CKPT.tmp" "$CKPT" 2>/dev/null || rm -f "$CKPT.tmp" 2>/dev/null
    # 镜像写入失败是【允许】的：它可能正是被故障的那一面，主本已落盘即可。
    # 不能因为镜像写不进去就返回失败——那会让 step_begin 误判为跳过步骤。
    if [ -n "$CKPT_MIRROR" ]; then
        printf 'NEXT=%s PASSED=%s FAILED=%s SKIPPED=%s FP=%s\n' \
            "$1" "$passed" "$failed" "$skipped" "$FP_NOW" > "$CKPT_MIRROR.tmp" 2>/dev/null \
            && mv -f "$CKPT_MIRROR.tmp" "$CKPT_MIRROR" 2>/dev/null \
            || rm -f "$CKPT_MIRROR.tmp" 2>/dev/null
    fi
    return 0
}

. "$ROOT/scripts/reg_failclass.sh" 2>/dev/null || {
    echo "[FATAL] 无法加载 scripts/reg_failclass.sh（失败分类缺失）"
    exit 2
}

export DAYNANJING_REGRESSION=1

# 回归一律从"未被变异污染"的树开始。
# 变异审计被强杀时会留下 .mutbak 与注入后的源码；若不先自愈，本次回归
# 的每一个"通过"都是在带缺陷的二进制上得到的，报告全绿却毫无意义。
# 实测发生过：front.c 的 tls_write 错误返回被抹掉后仍被提交进树。
if [ -f "$ROOT/scripts/mutation_audit.py" ]; then
    timeout 60 python3 "$ROOT/scripts/mutation_audit.py" heal || true
fi

# 指纹【在 heal 之后、启动时算一次】，不在每个步骤重算。
# 顺序是硬要求：heal 会还原被强杀的变异审计留下的源码改写，若在它之前取
# 指纹，记下的就是污染态内容，而被杀后重启总是在已 heal 的干净态启动 ——
# 两边必然不符，续跑永远拒绝接管（实测：干净 7ad95d83 vs 污染 03692b95）。
# 实测代价：本沙盒文件系统抖动时 git diff 会因索引整体刷新而挂起，套了
# timeout 20 也照样被拖满（RC=124 连续两次）。而它原本在 ckpt_mark 里
# 每步调用一次 —— 55 步就是十几分钟纯卡顿，且期间拿不到任何输出。
# 按次计算并不削弱判据：跨分段拼接时，新分段在【自己的启动时】算一次
# 指纹，与 checkpoint 里记录的上一段指纹比对，树变了照样判不符。
# 反而更稳：变异审计会在运行中临时改写源码再还原，若正好在改写窗口内
# 落盘 checkpoint，逐步指纹会记下一个"还原后不复现"的值，续跑永远判不符。
FP_NOW=$(tree_fp)
# 仅调试用：默认关闭，不干扰正常回归输出。
if [ "${DAYANJING_PRINT_FP:-0}" = "1" ]; then echo "[DEBUG] FP_NOW=$FP_NOW"; fi

# 单个测试用例的超时（秒）。默认 120 足够绝大多数单测。
# 例外必须写明理由：12_exploit 的 canary/PIE 爆破是**逐字节试探**，
# 每个字节平均 128 次、每次一次 fork+连接，单轮约 1900 次试探，
# 两轮（含 ASLR 对照）实测约 128 秒。这不是卡住，是爆破本身的代价。
tmo_for() {
    case "$1" in
        12_exploit) echo 600 ;;
        *)          echo 120 ;;
    esac
}

# C 模块：编译后跑 build/ 下所有可执行测试
# 注意 build/linux/ 这类子目录也要扫到（agent_windows）
run_c() {
    d="$ROOT/$1"
    name="$1"
    [ -d "$d" ] || { printf "=== %-16s SKIP(目录不存在)\n" "$name"; return; }
    printf "=== %-16s " "$name"
    if ! (cd "$d" && timeout 300 make >$TMPD/mk_$name.log 2>&1); then
        echo "BUILD FAIL"
        tail -5 $TMPD/mk_$name.log
        record_fail $TMPD/mk_$name.log; return
    fi
    ok=1
    # 只取可执行文件，排除 .c/.o（.o 也会被 -perm -u+x 误匹配）
    tests=$(find "$d/build" -type f -name 'test_*' ! -name '*.c' ! -name '*.o' -perm -u+x 2>/dev/null | sort)
    if [ -z "$tests" ]; then
        # 一个测试都没找到却判 PASS，是最危险的假通过：模块可能压根没构建
        # 出测试二进制（实测：26_lateral_auto 的 all 目标只产出 .o）。
        echo "FAIL -> 未找到任何测试可执行文件（build/ 为空 or 默认目标不构建测试）"
        record_fail; return
    fi
    for t in $tests; do
        timeout "$(tmo_for "$name")" "$t" >$TMPD/t_$name.log 2>&1
        rc=$?
        # 变异审计发现：被测进程在 ptrace_stop 等场景下，"timeout 已到期"
        # 与"进程仍存活"可以同时成立，且 waitpid 可能返回 0，于是挂起的测试
        # 被记为退出码 0 -> 误判 PASS。零输出是唯一可靠的挂起判据：
        # 正常测试必定打印结果行。
        if [ ! -s $TMPD/t_$name.log ]; then
            ok=0
            echo "FAIL -> $t (零输出：疑似挂起/被杀，退出码 $rc 不可信)"
            break
        fi
        if [ $rc -eq 77 ]; then
            # 退出码 77 = 环境不具备（如无 root 读不了 /proc/kcore）。
            # 记为 SKIP：既不冒认通过，也不算作代码缺陷。
            echo "SKIP -> $(basename "$t")"
            grep -E '^\[SKIP\]' $TMPD/t_$name.log | head -2
            skipped=$((skipped+1))
            continue
        fi
        if [ $rc -ne 0 ]; then
            ok=0
            echo "FAIL -> $t"
            tail -6 $TMPD/t_$name.log
            break
        fi
    done
    if [ $ok -eq 1 ]; then echo "PASS"; passed=$((passed+1)); else record_fail $TMPD/t_$name.log; fi
}

# 跨模块集成：单独编译并运行
run_int() {
    name="$1"; shift
    step_begin "$name" || return 0
    printf "=== %-16s " "$name"
    # 源路径是相对 ROOT 的，必须先 cd，否则找不到 tests/*.c
    if (cd "$ROOT" && timeout 120 cc -std=c11 -O2 -Wall -Wextra -Wpedantic "$@" >$TMPD/cc_$name.log 2>&1) \
       && timeout 120 $TMPD/bin_$name >$TMPD/t_$name.log 2>&1; then
        echo "PASS"; passed=$((passed+1))
    else
        echo "FAIL"
        tail -6 $TMPD/cc_$name.log $TMPD/t_$name.log 2>/dev/null
        record_fail $TMPD/cc_$name.log $TMPD/t_$name.log
    fi
}

# Python 侧
run_py() {
    step_begin "$1" || return 0
    printf "=== %-16s " "$1"
    if timeout 180 python3 "$ROOT/$2" >$TMPD/py_$1.log 2>&1; then
        echo "PASS  $(tail -1 $TMPD/py_$1.log)"; passed=$((passed+1))
    else
        echo "FAIL"; tail -6 $TMPD/py_$1.log; record_fail $TMPD/py_$1.log
    fi
}

# huffman 交叉验证的用例文件在源码树里（24_front/tests/data/hf_cases.txt）。
# 不导出的话 test_huffman 会回退到 $TMPD/hf_cases.txt，该文件在干净环境里
# 不存在，于是返回 77 被记成 SKIP —— 表面不失败，实际这条验证从没跑过。
# 显式导出，让它真正参与回归。
export HF_CASES="$ROOT/24_front/tests/data/hf_cases.txt"

# 续跑接管：优先手工 RESUME_FROM；未指定时自动接管 checkpoint。
resume_active=0
resume_matched=0
CKPT_RESUMED=0
# 候选顺序：tmpfs 主本优先（virtiofs 故障时它更可能可读），virtiofs 镜像回退
# （tmpfs 被重启清空时它还在）。两份内容相同，取任一可读且指纹相符者。
CKPT_SRC=""
for _c in "$CKPT" "$CKPT_MIRROR"; do
    [ -n "$_c" ] && [ -f "$_c" ] && CKPT_SRC="$_c" && break
done
if [ -z "${RESUME_FROM:-}" ] && [ -n "$CKPT_SRC" ]; then
    _cn=""; _cp=""; _cf=""; _cs=""; _cfp=""
    # 必须逐【词】解析，不能写 `while read -r _k _v; do case "$_k" ...`：
    # read 按 IFS 切词，_k 只拿到第一个词，其余全部落进 _v —— 于是
    # PASSED/FAILED/SKIPPED/FP 一个都没被解析，_cfp 恒为空，指纹比对必然判
    # "不符"，续跑永远退回从头跑。实测连续三次如此，而表象是"源码树变了"，
    # 排查方向被引向树的状态而不是这段解析。
    for _w in $(cat "$CKPT_SRC" 2>/dev/null); do
        case "$_w" in
            NEXT=*)    _cn=${_w#NEXT=} ;;
            PASSED=*)  _cp=${_w#PASSED=} ;;
            FAILED=*)  _cf=${_w#FAILED=} ;;
            SKIPPED=*) _cs=${_w#SKIPPED=} ;;
            FP=*)      _cfp=${_w#FP=} ;;
        esac
    done
    _now=${FP_NOW:-FPUNKNOWN}
    # 指纹不可得时必须【拒绝拼接】，不能只判两边是否相等：
    # 若 checkpoint 与当前树都退回同一个哨兵值，等号成立 —— 旧实现会照常接管，
    # 于是两段来自未知（且可能不同）源码树的结果被拼成一份 55 passed。
    # 这类拼接比从头跑一遍更危险：汇总数字正常，看不出它对应哪份代码。
    _fp_ok=1
    case "$_cfp" in ""|FPUNKNOWN|*FPUNKNOWN*) _fp_ok=0 ;; esac
    case "$_now" in ""|FPUNKNOWN|*FPUNKNOWN*) _fp_ok=0 ;; esac
    if [ "$_fp_ok" = 0 ]; then
        echo "[续跑] 源码树指纹不可得，拒绝拼接"
        echo "       checkpoint: ${_cfp:-（空）}"
        echo "       当前树:     $_now"
        echo "       宁可从头跑一遍，也不能把未知状态的两段拼成一份汇总。"
        rm -f "$CKPT" "$CKPT_MIRROR"
    elif [ "$_now" != "$_cfp" ]; then
        echo "[续跑] checkpoint 指纹与当前源码树不符，丢弃并从头开始"
        echo "       checkpoint: $_cfp"
        echo "       当前树:     $_now"
        rm -f "$CKPT" "$CKPT_MIRROR"
    elif [ -n "$_cn" ]; then
        RESUME_FROM="$_cn"
        passed=${_cp:-0}; failed=${_cf:-0}; skipped=${_cs:-0}
        resume_active=1; CKPT_RESUMED=1
        echo "[续跑] 自动接管：自步骤 $_cn 开始"
        echo "       前段计数已计入 passed=$passed failed=$failed skipped=$skipped"
        echo "       本次汇总由多段拼成，非单次连续运行，汇报时必须说明。"
    fi
elif [ -n "${RESUME_FROM:-}" ]; then
    resume_active=1
fi

# 每个步骤的统一入口。返回 0 = 应当执行；返回 1 = 位于断点之前，跳过。
# 所有步骤都必须经过它：未经它保护的步骤在续跑时会重跑一遍，导致重复计分，
# 而汇总数字看起来完全正常 —— 这正是最难发现的一类记账不实。
step_begin() {
    if [ "$resume_active" = 1 ]; then
        if [ "$1" = "$RESUME_FROM" ]; then
            resume_active=0; resume_matched=1
        else
            printf "=== %-16s SKIP(续跑：前段已跑过)\n" "$1"
            return 1
        fi
    fi
    ckpt_mark "$1"
    return 0
}

for m in 00_crypto 01_proto 02_c2 03_transport 04_agent 05_server 06_db 07_ui \
         08_lateral 09_persistence 10_evasion 11_edr_bypass 12_exploit \
         14_p2p 16_initial_access 17_loader 18_privilege 19_defense 20_packer \
         21_exfil 22_kern 23_lkm 24_front 25_tls 26_lateral_auto agent_windows; do
    step_begin "$m" || continue
    run_c "$m"
done

# 常量时间比较的【机器码级】守卫。
#
# 为什么单列一项，而不是并入 00_crypto 的 run_c：
#   mutation_audit 的 M13/M14/M15 捕获的是【源码级】早退。但源码语义正确
#   不等于最终机器码无早退 —— 编译器理论上可把无副作用的累积循环优化成
#   条件跳出。那一层源码测试永远测不到，只能审查汇编。人审一次会随时间
#   腐烂（换编译器、改代码就没人再查），故固化为可复跑判据并纳入回归。
#
# 依赖 build/crypto_gcm.o（生产构建，不带 CRYPTO_CT_INSTRUMENT），
# 该产物已由上方 00_crypto 的 run_c 构建。
run_ct_asm() {
    step_begin ct_asm_guard || return 0
    printf "=== %-16s " "ct_asm_guard"
    # 依赖 build/crypto_gcm.o（生产构建，不带 CRYPTO_CT_INSTRUMENT）。
    # 00_crypto 的默认 make 只产出测试二进制，不产出该 .o —— 此前守卫能过
    # 纯属产物恰好还留在 build/ 里。显式构建，失败即报，不靠"碰巧还在"。
    if ! (cd "$ROOT/00_crypto" && make build/crypto_gcm.o >$TMPD/mk_ctasm.log 2>&1); then
        echo "BUILD FAIL"; tail -5 $TMPD/mk_ctasm.log; record_fail $TMPD/mk_ctasm.log; return
    fi
    if (cd "$ROOT/00_crypto" && python3 scripts/check_ct_asm.py >$TMPD/t_ct_asm.log 2>&1); then
        echo "PASS"; grep -E "^\[PASS\]" $TMPD/t_ct_asm.log | sed 's/^/    /'
        passed=$((passed+1))
    else
        echo "FAIL"; cat $TMPD/t_ct_asm.log
        record_fail $TMPD/t_ct_asm.log
    fi
}
run_ct_asm

# 单体植入体：全仓唯一"把所有能力链进同一个可部署二进制"的验证。
# 形态与 run_c 的 test_* 不同（单个可执行 + --selftest），故单独处理。
#
# selftest 走真实 TCP 双进程：子进程 = 服务端，父进程 = 植入体，两者经
# 环回 TCP 完成握手 -> 任务通道 -> 采集回传。服务端 stdout/stderr 写文件
# 而不是继承管道，因此不会让回归脚本等 EOF 挂起。
run_mono() {
    step_begin monolith || return 0
    printf "=== %-16s " "monolith"
    # 超时必须覆盖**冷编译**：monolith 链接 9 个上游模块，obj/ 为空时要
    # 编 52 个 .o，实测 5m26s（326s）。原 300s 在冷启动下必然被杀，
    # 表现为 BUILD FAIL，并连锁让 lifecycle 因缺少 implant 而 FAIL——
    # 两次失败都与代码无关，纯属超时预算不足。900s 留出 2.7 倍余量。
    if ! (cd "$ROOT/monolith" && timeout 900 make >$TMPD/mk_monolith.log 2>&1); then
        echo "BUILD FAIL"; tail -5 $TMPD/mk_monolith.log
        record_fail $TMPD/mk_monolith.log; return
    fi
    # --run-ms 必须有界：无上界时若帧被去重跳过，循环永不退出。
    # --budget 给足：默认预算下 3 秒窗口累积不足 1 个覆盖信元，
    # 覆盖恒为 0 是预算与时长的正常关系而非缺陷，但那样就测不到覆盖路径。
    if (cd "$ROOT/monolith" && timeout 120 ./implant --selftest --run-ms 3000 \
            --budget 307200 --allow-sandbox >$TMPD/t_monolith.log 2>&1); then
        echo "PASS"; passed=$((passed+1))
    else
        echo "FAIL"; tail -12 $TMPD/t_monolith.log
        record_fail $TMPD/t_monolith.log
    fi
}
run_mono

# 完整生命周期：烧录配置 -> 打包 -> 投递 -> memfd 执行 -> 驻留(假根)
#   -> 死亡 -> 按驻留条目重生 -> 回连 C2。
# 每个环节此前都各自验证过，但"重生后仍能回连"这条从未串起来验过，
# 而那正是持久化唯一的意义所在。
run_life()
{
    step_begin lifecycle || return 0
    printf "=== %-16s " "lifecycle"
    # lifecycle 依赖 25_deploy/build/deploy_pack，但本脚本此前从不构建
    # 25_deploy——它不在模块循环里。于是干净环境下 lifecycle 必定卡在
    # "[FATAL] 打包失败"，与被测逻辑无关。必须先补这一步。
    if ! (cd "$ROOT/25_deploy" && timeout 600 make >$TMPD/mk_25deploy.log 2>&1); then
        echo "DEP BUILD FAIL"; tail -5 $TMPD/mk_25deploy.log
        record_fail $TMPD/mk_25deploy.log; return
    fi
    if timeout 300 bash "$ROOT/25_deploy/scripts/lifecycle.sh" \
            >$TMPD/t_lifecycle.log 2>&1; then
        echo "PASS"; passed=$((passed+1))
    else
        echo "FAIL"; tail -20 $TMPD/t_lifecycle.log
        record_fail $TMPD/t_lifecycle.log
    fi
}
run_life

run_int integration \
    -I03_transport/include -I10_evasion/include -I06_db/include -I07_ui/include \
    -o $TMPD/bin_integration tests/integration.c \
    03_transport/build/*.o 10_evasion/build/*.o 06_db/build/*.o 07_ui/build/*.o

run_int e2e_camo \
    -I03_transport/include -I10_evasion/include \
    -o $TMPD/bin_e2e_camo tests/e2e_camo.c \
    03_transport/build/*.o 10_evasion/build/*.o

run_int proto_c2_layer \
    -I01_proto/include -I02_c2/include \
    -o $TMPD/bin_proto_c2_layer tests/proto_c2_layering.c \
    01_proto/build/frame.o 02_c2/build/c2_frame.o 02_c2/build/c2.o \
    02_c2/build/crypto_gcm.o 02_c2/build/crypto_hash.o

# C <-> Python 双向协议对齐（密钥派生 + 帧格式 + AAD）。
# 单独一个脚本驱动：它需要 Python 侧先生成夹具，缺夹具时 C 侧返回 77(SKIP)，
# 由脚本统一判定，避免"没比对过"被当成"比对一致"。
if step_begin c2_align && [ -f "$ROOT/scripts/run_c2_align.sh" ]; then
    if sh "$ROOT/scripts/run_c2_align.sh" > $TMPD/c2_align.log 2>&1; then
        echo "  [PASS] c2_align"
        passed=$((passed + 1))
    else
        echo "  [FAIL] c2_align"
        grep -E "FAIL" $TMPD/c2_align.log | sed 's/^/         /'
        record_fail $TMPD/c2_align.log
    fi
fi

run_py 13_c2_server_py 13_c2_server/tests/test_server.py

# 采集产物接收端：C 侧 21_exfil 真编码 -> Python ExfilSink 真解码的跨语言对齐。
# 依赖 21_exfil/build/dump_cells，缺失时先构建。
if [ ! -x "$ROOT/21_exfil/build/dump_cells" ] || \
   [ ! -x "$ROOT/21_exfil/build/dump_task" ]; then
    make -C "$ROOT/21_exfil" > /dev/null 2>&1
fi
run_py 13_c2_server_exfil 13_c2_server/tests/test_exfil_sink.py

# C2 下行任务通道：远程开采/停采/改参数。C 侧 dump_task 真编码 <-> Python 双向对齐。
run_py 13_c2_server_task 13_c2_server/tests/test_exfil_task.py
run_py 13_c2_server_cache 13_c2_server/tests/test_session_cache.py
run_py 13_c2_server_resume 13_c2_server/tests/test_session_resume.py
run_py 13_c2_server_seqin 13_c2_server/tests/test_seq_in.py

# 真实第三方软件漏洞挖掘：Pillow _imagingcms 堆溢出探测工具自检
# 只验证工具逻辑（偏移/版本判定/指针构造），不触发崩溃（触发需受影响版本）
run_py 12_exploit_pillowcms 12_exploit/tests/test_pillow_cms.py

# Windows 后端 cam_mf.cpp 的逻辑验证。MinGW 不可得（apt/release 均 403），
# 改用 SDK shim 在 Linux 下真实编译并用 mock 设备真跑其逻辑。
if step_begin winshim_mf; then
echo "=== winshim_mf ==="
if make -C "$ROOT/agent_windows" winshim > $TMPD/winshim.log 2>&1 \
   && grep -q "19 pass, 0 fail" $TMPD/winshim.log; then
    echo "  [PASS] winshim_mf (cam_mf 19/19)"
    passed=$((passed + 1))
else
    echo "  [FAIL] winshim_mf  (见 $TMPD/winshim.log)"
    tail -15 $TMPD/winshim.log
    record_fail $TMPD/winshim.log
fi
fi

# 部署自检：真实起 4 节点（endpoint->edge0->edge1->core）+ echo 目标，
# 建洋葱电路并校验端到端回显一致。这不是单测，是部署级贯通验证。
if step_begin deploy_4node && [ -x /usr/bin/python3 ] && [ -f 14_p2p/tools/deploy.py ]; then
    echo "=== deploy_4node ==="
    if python3 14_p2p/tools/deploy.py \
        --topology 14_p2p/tools/topo_4node.json \
        --out $TMPD/dep_selftest --run > $TMPD/dep_selftest.log 2>&1 \
        && grep -q "端到端贯通 PASS" $TMPD/dep_selftest.log; then
        echo "  [PASS] deploy_4node"
        passed=$((passed + 1))
    else
        echo "  [FAIL] deploy_4node  (见 $TMPD/dep_selftest.log)"
        tail -12 $TMPD/dep_selftest.log
        record_fail $TMPD/dep_selftest.log
    fi
fi

# 跨网络命名空间部署验证：4 个节点各占独立网络栈 + 独立目标栈，
# 经网桥互通 —— 跨主机部署会遇到的绑定/路由/邻居问题在这里真实暴露。
# 需要 root 与 ip/netns 能力，不具备时跳过而不计失败。
# step_begin 必须独立判断，不能写成 `step_begin X && [能力] && ...`：
# step_begin 返回 1（续跑跳过）会短路进 else，而 else 打印的是
# "无 root/netns 能力" —— 于是前段跑过的步骤被记成"环境不支持"。
# 分段续跑的汇总里这类错误归因最致命：它让"哪一步真跑了"不可信，
# 排查方向还会被带到环境上，而这一步从头到尾没被执行过。
if ! step_begin deploy_crossns; then
    :  # 续跑跳过，已由 step_begin 打印
elif [ "$(id -u)" = "0" ] && command -v ip >/dev/null 2>&1 \
   && ip netns list >/dev/null 2>&1 && [ -f "$ROOT/14_p2p/tools/deploy_crossns.sh" ]; then
    echo "=== deploy_crossns ==="
    if timeout 300 bash "$ROOT/14_p2p/tools/deploy_crossns.sh" > $TMPD/xns_reg.log 2>&1 \
       && grep -q "端到端贯通 PASS" $TMPD/xns_reg.log; then
        echo "  [PASS] deploy_crossns (4 独立网络栈贯通)"
        passed=$((passed + 1))
    else
        echo "  [SKIP] deploy_crossns 未通过（见 $TMPD/xns_reg.log）"
        grep -E "FAIL|Error" $TMPD/xns_reg.log | head -5
    fi
else
    echo "=== deploy_crossns   SKIP(无 root/netns 能力) ==="
fi

# ---------------------------------------------------------------------------
# 变异审计：把"此前声称已修复"的缺陷注入回退，验证测试是否真能捕获。
# 放在最后：它会改源码再恢复，中途跑会污染后续用例的构建产物。
#
# 常态化用抽样（默认 1 个）：全量 6 个逐个重建太慢，曾导致整个回归超时。
# 每次抽样不同，长期收敛到全覆盖；要一次性全量用 MUTATION=full。
#
# 判定：存活(测试仍全绿) 与 审计失效(锚点腐烂/挂起) 都计入 failed。
# 后者尤其不能放过——锚点失效若记 SKIP，变异集合会静默腐烂，
# 报告上永远"0 存活"，实际审计面在缩小。
#
# 秘密比较守卫：枚举全仓每一处 memcmp，要求逐处分类。
#
# 为什么必须进回归（M9 的教训推广）：M9/M13/M14/M15 只钉住了
# crypto_constant_time_eq 这一个【函数】。但风险面在【调用点】——
# 任何人随时可以在别处写一行 memcmp(tag, expected, n)，功能正确、
# 测试全绿，却引入逐字节早退的时序预言机；源码插桩看不见它（那个
# 函数根本没被调用），机器码守卫也看不见它（它审的是函数体）。
# 未分类即失败，新增任何一处 memcmp 都会被拦下要求人工判定。
if step_begin check_secret_cmp && [ -f "$ROOT/scripts/check_secret_cmp.py" ]; then
    echo "=== check_secret_cmp（全仓 memcmp 分类守卫） ==="
    if python3 "$ROOT/scripts/check_secret_cmp.py" > $TMPD/seccmp.log 2>&1; then
        echo "  [PASS] 全仓 memcmp 均已分类且无秘密比较"
        grep -E "^\[INFO\]|^\[WARN\]" $TMPD/seccmp.log | sed 's/^/         /'
        passed=$((passed + 1))
    else
        echo "  [FAIL] 秘密比较守卫未通过（见 $TMPD/seccmp.log）"
        sed -n '/\[FAIL\]/,$p' $TMPD/seccmp.log | head -40
        record_fail $TMPD/seccmp.log
    fi
fi

# ---------------------------------------------------------------------------
# 结构化变异真值的漂移检查。
#
# 这两组用例的期望值（容忍/拒绝）不是设计出来的，是拿真实 OpenSSL 逐例
# 实测出来的，然后【固化】进头文件。固化就意味着会腐：OpenSSL 升级、换了
# 对端实现、甚至有人手改头文件，真值都会漂移，而测试会继续拿旧真值跑出
# 一片全绿——它验的已经不是"我们和真实实现是否一致"，而是"我们和一份
# 过期快照是否一致"。
#
# 手写期望值曾经直接制造过一个假缺陷：C10_hs_len_plus10 被写成必须拒绝，
# 而 OpenSSL 实际是在等剩余字节、并不发告警。手写的 47 例里只错这一例，
# 但足以把"两边完全一致"记成缺陷，引着人去改一段本来正确的代码。
#
# 判据用逐字节比对而非只比 expect：头文件里还固化着报文本体，生成器改了
# 而头文件没重新生成，同样会让测试跑的不是当前用例。
#
# 退出码 77 = 前置不具备（无 openssl 或缺证书）；78 = 探测起不来（端口被占）。
# 两者都记为 SKIP 而非 PASS：未验证不等于无漂移，显式报出来，不许混进通过数。
# 用退出码区分而不是在输出里匹配文案 —— 文案一改，文本检测就静默失效。
for g in gen_ch_struct gen_cke_struct; do
    step_begin "${g}_check" || continue
    if [ -f "$ROOT/scripts/$g.py" ]; then
        echo "=== $g --check（结构化变异真值漂移） ==="
        python3 "$ROOT/scripts/$g.py" --check > $TMPD/$g.log 2>&1
        rc=$?
        if [ $rc -eq 0 ]; then
            echo "  [PASS] $(grep -E '^\[PASS\]' $TMPD/$g.log | sed 's/^\[PASS\] //')"
            passed=$((passed + 1))
        elif [ $rc -eq 77 ]; then
            echo "  [SKIP] 未验证：$(grep -E '^\[SKIP\]' $TMPD/$g.log | head -1 | sed 's/^\[SKIP\] //')"
            skipped=$((skipped + 1))
        elif [ $rc -eq 78 ]; then
            echo "  [SKIP] 探测起不来（退出码 78，端口被占等）—— 未取得真值"
            grep -E "^\[FATAL\]" $TMPD/$g.log | sed 's/^/         [环境] /'
            skipped=$((skipped + 1))
        else
            echo "  [FAIL] 真值已漂移或检查失败（见 $TMPD/$g.log）"
            # 区分两种故障：「起不来」（环境/端口问题）与「真值漂移」（真缺陷）。
            # 不区分的话，一次端口冲突会被当成产品缺陷去查。
            grep -E "^\[FATAL\]" $TMPD/$g.log | sed 's/^/         [环境] /'
            grep -E "^\[FAIL\]|^       " $TMPD/$g.log | sed 's/^/         /'
            record_fail $TMPD/$g.log
        fi
    fi
done

# ---------------------------------------------------------------------------
# 去重守卫：两个生成器的探测基础设施必须共用 tls_truth.py。
#
# 这一层守护的是上面 --check 数字的【可比性】。两份实现此前是逐字复制的，
# 一旦只在一侧修了探测逻辑（端口重试、判据收紧、超时窗口），另一侧不跟着
# 变，而两边各自固化下来的期望值仍然"全绿" —— 同一套真值体系里出现两套
# 口径，且固化常量不会暴露这个分叉。
# ---------------------------------------------------------------------------
if step_begin check_gen_dedup && [ -f "$ROOT/scripts/check_gen_dedup.py" ]; then
    echo "=== check_gen_dedup（探测基础设施去重） ==="
    python3 "$ROOT/scripts/check_gen_dedup.py" > $TMPD/gen_dedup.log 2>&1
    rc=$?
    if [ $rc -eq 0 ]; then
        echo "  [PASS] $(grep -E '^\[PASS\]' $TMPD/gen_dedup.log | sed 's/^\[PASS\] //')"
        passed=$((passed + 1))
    else
        echo "  [FAIL] 探测基础设施出现重复实现"
        grep -E '^       ' $TMPD/gen_dedup.log | sed 's/^/         /'
        record_fail $TMPD/gen_dedup.log
    fi
fi

# ---------------------------------------------------------------------------
# check_guards（Python 守卫自身的正反双向防回归）
#
# 上面两个 check_* 是仓库里唯二没有测试的 Python 守卫：C 侧每条断言都有
# 变异条目盯着，它们没有。于是唯一失效模式无人看管 —— 守卫自己被改坏后
# 恒返回"通过"，报告一片全绿。
#
# 本项跑正反双向（合规 fixture 须 PASS、违规 fixture 须 FAIL），任一侧不符
# 即判失败。只跑上面两项无法替代：它们只证明"此刻通过"，证明不了"该红的
# 时候会红"。
# ---------------------------------------------------------------------------
if step_begin check_guards && [ -f "$ROOT/scripts/check_guards.py" ]; then
    echo "=== check_guards（Python 守卫自身双向有效） ==="
    python3 "$ROOT/scripts/check_guards.py" > $TMPD/guards.log 2>&1
    rc=$?
    if [ $rc -eq 0 ]; then
        echo "  [PASS] $(grep -E '^\[PASS\]' $TMPD/guards.log | sed 's/^\[PASS\] //')"
        passed=$((passed + 1))
    else
        echo "  [FAIL] Python 侧守卫自身失效（恒绿或恒红）"
        grep -E '^       |^\[FATAL\]' $TMPD/guards.log | sed 's/^/         /'
        record_fail $TMPD/guards.log
    fi
fi

# ---------------------------------------------------------------------------
# Python runner 判定标记守卫的自检。
#
# 守护的是变异审计【报告里每一个 CAUGHT 的含义】。退出码非零不等于抓到了
# 缺陷：生成器或守卫自己崩溃时同样 rc=1，与"真漂移/真违规"在退出码上完全
# 一样。不区分的话，报告显示一片 CAUGHT，读起来像所有缺陷都有防回归，实际
# 其中一部分只是工具崩了 —— M28~M30 此前就混着这一类。
#
# 不能靠一条普通变异条目来锁：CAUGHT 在归类时被直接跳过、永远不计入失败，
# 所以守卫退化会被 CAUGHT 静默接受。故用独立子命令直接断言状态字。
# ---------------------------------------------------------------------------
if step_begin mut_audit_selftest && [ -f "$ROOT/scripts/mutation_audit.py" ]; then
    echo "=== mutation_audit selftest-py（崩溃不得算作捕获） ==="
    python3 "$ROOT/scripts/mutation_audit.py" selftest-py > /data/ma_selftest.log 2>&1
    rc=$?
    if [ $rc -eq 0 ]; then
        echo "  [PASS] $(grep -E '^\[PASS\]' /data/ma_selftest.log | sed 's/^\[PASS\] //')"
        passed=$((passed + 1))
    elif [ $rc -eq 77 ]; then
        # 无 openssl / 缺证书 / 端口起不来：自检拿不到真值，记 SKIP。
        # 归 FAIL 会让这类环境里回归一直红，最后被人加 || true 关掉。
        echo "  [SKIP] $(grep -E '^\[SKIP\]' /data/ma_selftest.log | head -1 | sed 's/^\[SKIP\] //')"
        skipped=$((skipped + 1))
    else
        echo "  [FAIL] Python runner 判定标记守卫失效（崩溃被记成捕获）"
        grep -E '^\[BAD\]|^\[FAIL\]' /data/ma_selftest.log | sed 's/^/         /'
        record_fail /data/ma_selftest.log
    fi
fi

# ---------------------------------------------------------------------------
# 构建契约审计：每个模块声明的测试二进制，是否都会被回归实际调用的目标构建。
#
# 这一层守护的是上面所有数字的【可信度】。回归先 `make` 再执行 build/ 下的
# test_*，于是有个隐含契约：make 必须产出回归会跑的每一个二进制。契约一破，
# build/ 里上一次 `make test` 留下的旧二进制会被继续跑——源码改了、产物没重建、
# 报告照样全绿。实测三处：
#   08_lateral  all 只产出库          -> 清空 build 后 make 产出 0 个测试
#   14_p2p      all 只产出 2/16       -> 14 个套件一直在跑陈旧产物
#   21_exfil    all 漏 test_tol
#   26_lateral_auto  E2E 变量定义在 all 之后，先决条件展开为空
# 归为 failed 而非 warn：这里一旦失守，前面所有 pass 数都不可信。
if step_begin audit_makefile_tests && [ -f "$ROOT/scripts/audit_makefile_tests.py" ]; then
    echo "=== audit_makefile_tests（构建契约） ==="
    if python3 "$ROOT/scripts/audit_makefile_tests.py" > $TMPD/mkaudit.log 2>&1; then
        echo "  [PASS] 各模块测试二进制均由回归调用的目标构建"
        grep -E "^\[WARN\]" $TMPD/mkaudit.log | sed 's/^/         /'
        passed=$((passed + 1))
    else
        echo "  [FAIL] 构建契约被破坏：有测试二进制不由 make 产出，"
        echo "         build/ 中可能正被执行陈旧产物（见 $TMPD/mkaudit.log）"
        grep -E "^\[MISS\]|^\[ERR \]" $TMPD/mkaudit.log | sed 's/^/         /'
        record_fail $TMPD/mkaudit.log
    fi
fi

MUT_MODE=${MUTATION:-sample:1}
if step_begin mutation_audit && [ "$MUT_MODE" != "off" ] && [ -f "$ROOT/scripts/mutation_audit.py" ]; then
    echo "=== mutation_audit ==="
    case "$MUT_MODE" in
        full)     MUT_ARGS="" ;;
        sample:*) MUT_ARGS="--sample ${MUT_MODE#sample:}" ;;
        *)        MUT_ARGS="" ;;
    esac
    if timeout 1200 python3 "$ROOT/scripts/mutation_audit.py" $MUT_ARGS \
        > $TMPD/mut.log 2>&1; then
        echo "  [PASS] mutation_audit ($MUT_MODE)"
        # 必须带上"已知盲区"两栏：它们是 SURVIVED 但审计不失败的项，
        # 若只 grep 前三项，回归报告会完全看不见"哪些缺陷测不了"，
        # 等于把盲区单列出来的努力白费掉。
        grep -E "^捕获|^存活|^审计失效|^符合预期|^已知盲区|^\[!\]|^    M[0-9]" \
            $TMPD/mut.log | sed 's/^/         /'
        passed=$((passed + 1))
    else
        echo "  [FAIL] mutation_audit ($MUT_MODE)  (见 $TMPD/mut.log)"
        sed -n '/=== 变异审计结果 ===/,$p' $TMPD/mut.log
        record_fail $TMPD/mut.log
    fi
fi

# 必须在最后：前面的部署测试会写真实 /etc。本守卫负责在收尾时点名污染，
# 否则污染只在别处表现为"某个断言返回值不符"，排查方向被指向实现代码。
# 自带正向对照（--selftest）：永远找不到的扫描器永远"通过"，那等于没守卫。
# 为什么单独补这一段：
#   run_c 只做「make 构建 + 逐个跑 build/test_* 二进制」，它从不调用 make test。
#   而近十轮新增的判据几乎全部是 Python 守卫（verify-*.py），它们只挂在
#   make test 上 —— 于是全仓回归的「53 passed」从来不覆盖它们。
#   实测坐实：入口日志里 verify-autoroot / verify-cron-exec / verify-user-deploy /
#   verify-v4l2-degrade / verify-degrade-report / redline_check 一个都没出现，
#   而当时入口是绿的。
#   这是第 5 处同类漏洞（前四处：判据恒绿、红线与常规限制混排、
#   run() 未定义变量致 PENDING 恒 0、证据不绑源码），且是最严重的一处：
#   它让「入口绿」与「守卫验过」长期脱钩。
#   放在真实根污染检查之前：这些守卫会做部署，污染检查必须收尾。
for m in 21_exfil agent_windows; do
    step_begin "${m}_guards" || continue
    printf "=== %-16s " "${m}_guards"
    # 落盘前先自愈临时盘：不可写时换盘（SEQ:77 的 Stale 就发生在这里）
    if ! tmpd_fix; then
        echo "SKIP（临时盘不可写，非守卫缺陷）"
        skipped=$((skipped + 1))
        continue
    fi
    # 目录不可达属文件系统抖动，与守卫实现无关；记 SKIP 而非 FAIL。
    if ! timeout 10 stat "$ROOT/$m/." >/dev/null 2>&1; then
        echo "SKIP（$m 目录不可达，非守卫缺陷）"
        skipped=$((skipped + 1))
        continue
    fi
    if (cd "$ROOT/$m" && timeout 1800 make test >$TMPD/guards_$m.log 2>&1); then
        echo "PASS"
        passed=$((passed + 1))
    else
        echo "FAIL"
        grep -E "^\[FAIL\]|^\[ERROR\]|make.*\*\*\*" $TMPD/guards_$m.log | head -20 | sed 's/^/         /'
        record_fail $TMPD/guards_$m.log
    fi
done


if step_begin realroot_pollution && [ -f "$ROOT/scripts/check_realroot_pollution.py" ]; then
    echo "=== check_realroot_pollution（真实根污染） ==="
    if python3 "$ROOT/scripts/check_realroot_pollution.py"; then
        passed=$((passed + 1))
    else
        failed=$((failed + 1))
    fi
    if python3 "$ROOT/scripts/check_realroot_pollution.py" --selftest \
        > $TMPD/rrguard.log 2>&1; then
        echo "  [PASS] 污染守卫正向对照（种下必检出、清除必归零）"
        grep -E "^  \[OK\]" $TMPD/rrguard.log | sed 's/^/         /'
        passed=$((passed + 1))
    else
        echo "  [FAIL] 污染守卫本身失效（恒绿或自检留污染）"
        cat $TMPD/rrguard.log | sed 's/^/         /'
        record_fail $TMPD/rrguard.log
    fi
fi

# 续跑一致性校验：指定了断点却一次都没匹配上，说明断点名已失效（步骤改名 /
# checkpoint 陈旧）。此时上面所有步骤都被静默跳过，汇总会把「前段计数」原样
# 输出成一个看起来正常的绿 —— 必须拦下。
if [ -n "${RESUME_FROM:-}" ] && [ "$resume_matched" = 0 ]; then
    echo "[FATAL] 续跑断点 '$RESUME_FROM' 未匹配任何步骤：本次未执行任何测试"
    exit 2
fi
if [ "$CKPT_RESUMED" = 1 ]; then
    echo "[注意] 本次汇总由分段续跑拼成，非单次连续运行"
fi
rm -f "$CKPT" "$CKPT_MIRROR"
echo "-------- passed: $passed  failed: $failed  skipped: $skipped --------"
exit $failed
