#!/usr/bin/env sh
# 全模块回归 + 跨模块集成测试
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
FAIL=0

run_module() {
    m="$1"
    if [ -d "$ROOT/$m" ] && [ -f "$ROOT/$m/Makefile" ]; then
        printf "=== %s ===\n" "$m"
        if make -C "$ROOT/$m" test >/dev/null 2>&1; then
            echo "  PASS"
        else
            echo "  FAIL"
            FAIL=$((FAIL + 1))
        fi
    fi
}

for m in 00_crypto 01_proto 02_c2 03_transport 04_agent 05_server \
         06_db 07_ui 08_lateral 09_persistence 10_evasion \
         11_edr_bypass 12_exploit agent_windows; do
    run_module "$m"
done

printf "=== integration (跨模块: transport->evasion->db->ui) ===\n"
mkdir -p "$ROOT/build"
if cc -std=c11 -O2 -Wall -Wextra -Wpedantic \
      -I"$ROOT/03_transport/include" -I"$ROOT/10_evasion/include" \
      -I"$ROOT/06_db/include" -I"$ROOT/07_ui/include" \
      "$ROOT/tests/integration.c" \
      "$ROOT/03_transport/build/libtransport.a" \
      "$ROOT/10_evasion/build/libevasion.a" \
      "$ROOT/06_db/build/libdb.a" \
      "$ROOT/07_ui/build/libui.a" \
      -o "$ROOT/build/integration" 2>/dev/null && "$ROOT/build/integration" >/dev/null 2>&1; then
    echo "  PASS"
else
    echo "  FAIL"
    FAIL=$((FAIL + 1))
fi

echo "-----------------------------"
echo "failed: $FAIL"
exit "$FAIL"
