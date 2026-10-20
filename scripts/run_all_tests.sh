#!/bin/sh
# dayanjing 全模块回归
# 覆盖：C 模块单测 + 跨模块集成 + Python 侧
# 每一步都套 timeout，任何一个卡住都不拖垮整体
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
failed=0
passed=0

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
        if ! timeout 120 "$t" >/tmp/t_$name.log 2>&1; then
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
         14_p2p agent_windows; do
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

echo "-------- passed: $passed  failed: $failed --------"
exit $failed
