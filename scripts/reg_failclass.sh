#!/bin/sh
# 回归失败分类：区分「代码缺陷」与「环境故障」。
#
# 为什么必须单独成文件：
#   判据要能被独立测试，就不能埋在 run_all_tests.sh 里（source 那个脚本会
#   直接把整轮回归跑起来）。独立成文件后，verify_regression_envfail.py 可以
#   source 它并对单个函数做正反向断言。
#
# 背景（SEQ:77 实测）：
#   全仓回归跑到最后两个守卫步骤时，virtiofs 出现 Stale file handle，
#   表现为 `grep: ...: Stale file handle` 与 `can't cd to .../agent_windows`。
#   这两步被记成 failed，汇总输出 49 passed / 4 failed。
#   四项失败事后逐一定性，全部是环境所致（单独重跑即绿），但汇总数字就是
#   failed=4 —— 不能包装成通过，也不该让「环境抖动」冒充「代码缺陷」。
#
# 更严重的后果不是数字难看，而是【核心链路没验完就交卷】：
#   被吃掉的两步恰恰是 21_exfil_guards（摄像头链路守卫）与
#   agent_windows_guards（Windows 侧守卫）。它们没跑到，等于是「回归绿」
#   掩盖了「核心守卫根本没执行」——这正是本项目反复出现的最难发现的一类
#   记账不实。
#
# 修法：环境故障【立即中止并保留断点】，而不是记一个 failed 继续往下跑。
#   继续往下跑的每一步都会因同一环境故障再失败一次，白耗时间，且最终汇总
#   里混着一堆环境噪声，无法据此判断代码状态。
#   中止后 checkpoint 仍指向该步骤（ckpt_mark 在 step_begin 里、步骤开跑前
#   落盘），重启即自动从它续跑，环境恢复后就能拿到真实结果。
#
# 退出码约定（与 run_all_tests.sh 的 `exit $failed` 区分）：
#   0  全绿
#   N  有 N 个【代码缺陷】导致的失败
#   3  环境故障中止（不计入 failed；断点保留，可续跑）

# 环境故障签名。
# 【为什么只收这几条】：必须保守。判据一旦过宽，真正的代码缺陷也会被归成
# 环境故障而中止，回归就永远跑不完，而且表现为「能力失效」而不是「有缺陷」，
# 排查方向会被彻底带偏。
# 实测排除误判：tests/ 与 scripts/ 下没有任何测试会【正常输出】这些字符串
# （唯一命中是 run_all_tests.sh 自身的注释），因此命中即真环境故障。
# 不收 "Device or resource busy"：端口冲突既可能是环境残留，也可能是被测
# 代码的真实缺陷，无法由文本判别。
# 不收 "Too many open files"：可能是真实的 fd 泄漏缺陷。
ENV_FAIL_RE='Stale file handle|Read-only file system|Input/output error|Transport endpoint is not connected|No space left on device|can(not|'"'"'t) cd to'

# 命中任意一个日志文件即返回 0（是环境故障）。
# 只接受文件参数；不存在的文件被静默跳过，因此「无日志的真失败」不会被误判。
env_sig_hit() {
    [ $# -gt 0 ] || return 1
    grep -q -E "$ENV_FAIL_RE" "$@" 2>/dev/null
}

# 记一次失败：先分类，环境故障则中止。
# 调用点必须位于 run_all_tests.sh 的【顶层 shell】（不能是子 shell），
# 否则 exit 3 只会退出子 shell，回归会带着残留状态继续跑下去。
record_fail() {
    if env_sig_hit "$@"; then
        echo "  [ENV_ABORT] 检测到环境故障（非代码缺陷）：本步骤结果不可信"
        echo "  [ENV_ABORT] 断点已保留，环境恢复后重跑本脚本即从该步骤续跑"
        echo "  [ENV_ABORT] 退出码 3（区别于代码缺陷的 failed 计数）"
        # 必须保留 checkpoint：ckpt_mark 在步骤【开跑前】落盘，此刻它正指向
        # 本步骤，计数也回退到开跑前的值，重启续跑不会重复计分。
        exit 3
    fi
    failed=$((failed + 1))
    return 0
}
