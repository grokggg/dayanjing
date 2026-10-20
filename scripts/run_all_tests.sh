#!/bin/sh
# dayanjing 全模块回归
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
failed=0
run() {
    d="$ROOT/$1"; shift
    [ -d "$d" ] || { echo "=== $1 === SKIP(目录不存在)"; return; }
    printf "=== %-16s " "$1"
    if (cd "$d" && timeout 300 make clean >/dev/null 2>&1; timeout 600 make >/tmp/mk_$1.log 2>&1); then
        :
    else
        echo "BUILD FAIL"; failed=$((failed+1)); return
    fi
    ok=1
    for t in "$d"/build/test_*; do
        case "$t" in *.c|*.o) continue;; esac
        [ -x "$t" ] || continue
        timeout 120 "$t" >/tmp/t_$1.log 2>&1 || { ok=0; echo "FAIL"; echo "--- $t ---"; tail -5 /tmp/t_$1.log; }
    done
    [ $ok -eq 1 ] && echo "PASS"
    [ $ok -eq 1 ] || failed=$((failed+1))
}
for m in 00_crypto 01_proto 02_c2 03_transport 04_agent 05_server 06_db 07_ui \
         08_lateral 09_persistence 10_evasion 11_edr_bypass 12_exploit agent_windows; do
    run "$m" "$m"
done
# 跨模块集成
printf "=== %-16s " "integration"
if cc -std=c11 -O2 -Wall -Wextra -Wpedantic -I03_transport/include -I10_evasion/include \
      -I06_db/include -I07_ui/include tests/integration.c -o /tmp/integration \
      03_transport/build/*.o 10_evasion/build/*.o 06_db/build/*.o 07_ui/build/*.o 2>/dev/null \
   && timeout 60 /tmp/integration >/tmp/t_int.log 2>&1; then echo "PASS"; else echo "FAIL"; tail -5 /tmp/t_int.log; failed=$((failed+1)); fi
printf "=== %-16s " "e2e_camo"
if cc -std=c11 -O2 -Wall -Wextra -Wpedantic -I03_transport/include -I10_evasion/include \
      tests/e2e_camo.c -o /tmp/e2e 03_transport/build/*.o 10_evasion/build/*.o 2>/dev/null \
   && timeout 60 /tmp/e2e >/tmp/t_e2e.log 2>&1; then echo "PASS"; else echo "FAIL"; tail -5 /tmp/t_e2e.log; failed=$((failed+1)); fi
printf "=== %-16s " "proto_c2_layer"
if cc -std=c11 -O2 -Wall -Wextra -Wpedantic -I01_proto/include -I02_c2/include \
      tests/proto_c2_layering.c -o /tmp/layering \
      01_proto/build/frame.o 02_c2/build/c2_frame.o 02_c2/build/c2.o \
      02_c2/build/crypto_gcm.o 02_c2/build/crypto_hash.o 2>/dev/null \
   && timeout 60 /tmp/layering >/tmp/t_lay.log 2>&1; then echo "PASS"; else echo "FAIL"; tail -5 /tmp/t_lay.log; failed=$((failed+1)); fi
echo "-------- failed: $failed --------"
exit $failed
