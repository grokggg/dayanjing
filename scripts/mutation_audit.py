#!/usr/bin/env python3
"""
变异审计（常态化）：把"此前声称已修复"的缺陷逐个变异回退，验证测试是否真能捕获。

  CAUGHT   = 测试失败/挂起 -> 修复真的被防回归保护住了
  SURVIVED = 测试仍全绿    -> 该用例证明不了任何事，是真实缺口
  ERROR    = 变异没生效/构建失败/锚点失效 -> 审计本身失效，必须修脚本

设计要点（都是此前用代价换来的）：

1. 锚点失效不再是 SKIP，而是 ERROR。
   变异锚点会随代码演进失效。若像旧版那样记 SKIP，这个变异就永久腐烂，
   而报告上永远"0 存活"——表面一切正常，实际审计面在缩小。这是静默降级。

2. 变异必须校验"真的改了"。
   只判断 old 在不在源码里不够：replace 可能命中注释、可能命中另一处。
   改为校验文件哈希确实变化，并对锚点做唯一性检查。

3. 恢复必须用 git 校验。
   旧版用 .mutbak 覆盖回去，若中途被杀会留下变异代码，下一次构建就带着缺陷。
   改为 finally 中恢复后比对 git hash-object，不一致即报错。

4. 挂起不能被当成 CAUGHT。
   subprocess 超时返回 -999，旧版判 CAUGHT —— 碰巧对了，但报告里看不出是挂起
   还是真失败，会掩盖"测试挂起且无人知晓"。单独记 HANG。

5. 工作区必须干净。
   变异会改源码再恢复。若有未提交改动，恢复会把它一起弄丢。

用法：
  python3 scripts/mutation_audit.py            # 全量
  python3 scripts/mutation_audit.py --sample 2 # 抽样（常态化用，控制耗时）
  python3 scripts/mutation_audit.py --only M1,M4
"""
import os, sys, shutil, subprocess, hashlib, random, time, signal, atexit, re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ---------------------------------------------------------------- 变异集合
# old 必须是**实现中的真实代码行**，不能是注释里的文字。
# unique=False 时表示源码中有多处，全部替换（all_occurrences）。
MUTATIONS = [
    {
        "id": "M1",
        "desc": "25_deploy: 关闭组装摘要校验（篡改的制品也能 seal）",
        "file": "25_deploy/src/drop.c",
        "old": "if (crypto_constant_time_eq(d, a->digest, DP_DIGEST_LEN) == 0)",
        "new": "if (0)",
        "mod": "25_deploy",
        "bin": "build/test_drop",
    },
    {
        "id": "M2",
        "desc": "19_defense: ptrace 回退为在调用进程自身执行（植入体自伤挂死）",
        "file": "19_defense/src/debug.c",
        "old": "pid = fork();",
        "new": "pid = 0;",
        "mod": "19_defense",
        "bin": "build/test_defense",
        # 该缺陷的症状本身就是进程挂死在 ptrace_stop，因此"测试挂起"是
        # 正确观测，不是审计失效。真正防止它被误记成通过的是回归脚本的
        # 零输出守卫（run_all_tests.sh），审计这里只负责不把 HANG 当 PASS。
        # 不给它声明 expect 的话，抽样抽到 M2 就恒 exit 1 —— 一个随机失败
        # 的检查会被习惯性忽略，等于没有。
        "expect": "HANG",
    },
    {
        "id": "M16",
        "desc": "24_front: front_send 忽略 tls_write 失败（写失败被当成成功）",
        "file": "24_front/src/front.c",
        "old": "    if (tls_write(c->tls, req, rlen) != TLS_OK) return FRONT_ERR_TLS;",
        "new": "    (void)tls_write(c->tls, req, rlen);",
        "mod": "24_front",
        "bin": "build/test_front_real",
    },
    {
        "id": "M17",
        "desc": "24_front: front_recv 忽略 tls_read 失败（读失败被当成 IO）",
        "file": "24_front/src/front.c",
        # 锚点必须带上后继行：front_recv(h1) 与 recv_h2 里有一模一样的这一行，
        # 只写单行会同时命中两处，替换目标不明确 —— 脚本拒绝模糊替换是对的。
        "old": "        if (tls_read(c->tls, tmp, sizeof(tmp), &got) != TLS_OK) return FRONT_ERR_TLS;\n        if (got == 0) return FRONT_ERR_IO;\n        if (c->resp_len + got > sizeof(c->resp)) return FRONT_ERR_RANGE;",
        "new": "        (void)tls_read(c->tls, tmp, sizeof(tmp), &got);\n        if (got == 0) return FRONT_ERR_IO;\n        if (c->resp_len + got > sizeof(c->resp)) return FRONT_ERR_RANGE;",
        "mod": "24_front",
        "bin": "build/test_front_real",
    },
    {
        "id": "M18",
        "desc": "24_front: SNI 写成真实主机（域前置失效，真实目标暴露在 SNI 上）",
        "file": "24_front/src/front.c",
        "old": "    tc.sni         = c->cfg.front_domain;     /* 观察者可见的是前置域 */",
        "new": "    tc.sni         = c->cfg.real_host;",
        "mod": "24_front",
        "bin": "build/test_front_real",
    },
    {
        # 这四条是"结构化变异"防回归：它们的危害不是崩溃，而是"该拒绝的
        # 没拒绝"。实测 OpenSSL s_server 对这些报文发 decode_error 告警，
        # 我们若照单收下并握成，探测者只需发一个畸形 ClientHello 就能把
        # 我们与真实服务端区分开 —— 这类指纹比功能出错更致命。
        "id": "M23",
        "desc": "25_tls: 套件列表长度不再校验奇数（畸形容忍度与 OpenSSL 分歧）",
        "file": "25_tls/src/tls_server.c",
        "old": "    if (cslen == 0 || (cslen & 1u)) return TLS_ERR_HANDSHAKE;",
        "new": "    if (0) return TLS_ERR_HANDSHAKE;",
        "mod": "25_tls",
        "bin": "build/test_tls_ch_struct",
    },
    {
        "id": "M24",
        "desc": "25_tls: 不再拒绝重复扩展（RFC 5246/8446 禁止，OpenSSL 发 decode_error）",
        "file": "25_tls/src/tls_server.c",
        "old": "            if (seen_ext[et >> 3] & (uint8_t)(1u << (et & 7u)))\n                return TLS_ERR_HANDSHAKE;            /* 重复扩展 */",
        "new": "            /* MUT */",
        "mod": "25_tls",
        "bin": "build/test_tls_ch_struct",
    },
    {
        # 锚点必须带上后继的 uint16_t g：signature_algorithms 下有一模一样的
        # 这一行，只写单行会同时命中两处，脚本的模糊替换拒绝是对的。
        "id": "M25",
        "desc": "25_tls: supported_groups 内层列表长度不再校验（声明与实际不符被接受）",
        "file": "25_tls/src/tls_server.c",
        "old": "                if (2u + nl != el) return TLS_ERR_HANDSHAKE;\n                for (size_t i = 2; i + 1 < el; i += 2) {\n                    uint16_t g = (uint16_t)((ev[i] << 8) | ev[i + 1]);",
        "new": "                if (0) return TLS_ERR_HANDSHAKE;\n                for (size_t i = 2; i + 1 < el; i += 2) {\n                    uint16_t g = (uint16_t)((ev[i] << 8) | ev[i + 1]);",
        "mod": "25_tls",
        "bin": "build/test_tls_ch_struct",
    },
    {
        "id": "M26",
        "desc": "25_tls: supported_versions 结构不再校验（我们不实现 1.3 但结构须同步严格）",
        "file": "25_tls/src/tls_server.c",
        "old": "                if (el < 1 || 1u + ev[0] != el) return TLS_ERR_HANDSHAKE;",
        "new": "                if (0) return TLS_ERR_HANDSHAKE;",
        "mod": "25_tls",
        "bin": "build/test_tls_ch_struct",
    },
    {
        "id": "M27",
        "desc": "25_tls: 握手消息未收齐时对端关闭 -> 发告警（真实实现选择沉默等待，"
                "发告警即产生可被探测的分歧）",
        "file": "25_tls/src/tls_server.c",
        "old": "        tls_err e = rec_read(c, &rt, &rb, &rl);\n        if (e != TLS_OK) return e;\n        if (rt == CT_ALERT) return TLS_ERR_ALERT;",
        "new": "        tls_err e = rec_read(c, &rt, &rb, &rl);\n        if (e != TLS_OK) { rec_write(c, CT_ALERT, (const uint8_t *)\"\\x02\\x32\", 2); return e; }\n        if (rt == CT_ALERT) return TLS_ERR_ALERT;",
        "mod": "25_tls",
        "bin": "build/test_tls_ch_struct",
    },
    {
        # 这三个变异针对真值探测本身（scripts/tls_truth.py）。
        #
        # 为什么必须登记：47+17 例的期望值是**固化进头文件**的快照，而快照
        # 由 tls_truth.py 实测取得。这个文件一旦改坏，两侧（CH/CKE）仍然
        # 各自全绿 —— 固化下来的常量不会暴露分叉，它只会表现为"某个用例的
        # 期望值与另一组不一致"，那时没人知道该信哪个。
        #
        # 形态上它们与 C 侧变异不同：没有构建步骤、没有二进制，判定靠
        # 生成器 --check 的退出码与输出，故用 lang="py" 走独立 runner。
        "id": "M28",
        "desc": "scripts: 端口探测恒失败（s_server 起不来，真值无从取得）",
        "file": "scripts/tls_truth.py",
        "old": "    s = socket.socket()\n    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n    try:\n        s.bind((\"127.0.0.1\", port))\n        return True\n    except OSError:\n        return False\n    finally:\n        s.close()",
        "new": "    return False",
        "lang": "py",
        "cmds": ["python3 scripts/gen_ch_struct.py --check",
                 "python3 scripts/gen_cke_struct.py --check"],
    },
    {
        "id": "M29",
        "desc": "scripts: 记录层判定恒为 REJECT（把'静默等待'误判成'对端告警'）",
        "file": "scripts/tls_truth.py",
        "old": "    off = 0\n    saw_hs = False\n    while off + 5 <= len(buf):",
        "new": "    if True:\n        return \"REJECT\"\n    off = 0\n    saw_hs = False\n    while off + 5 <= len(buf):",
        "lang": "py",
        "cmds": ["python3 scripts/gen_ch_struct.py --check",
                 "python3 scripts/gen_cke_struct.py --check"],
    },
    {
        # 与 M29 方向相反：M29 是"把沉默误判成拒绝"，M30 是"漏识别告警"。
        # 后者更接近真实编码错误 —— 改坏判据的人不会写明"恒为 REJECT"，
        # 只会让某个条件不再成立。危害也更隐蔽：本该 REJECT 的用例被降级
        # 成 ANY（不做断言），测试从"验一条真实分歧"退化成"只验不崩"。
        "id": "M30",
        "desc": "scripts: 告警识别失效，ct==21 不再判为 REJECT（真分歧被降级成不断言）",
        "file": "scripts/tls_truth.py",
        "old": "        if ct == 21 and ln >= 2:\n            return \"REJECT\"",
        "new": "        if False:\n            return \"REJECT\"",
        "lang": "py",
        "cmds": ["python3 scripts/gen_ch_struct.py --check",
                 "python3 scripts/gen_cke_struct.py --check"],
    },
    {
        # 这两个变异针对【Python 守卫自身】。
        #
        # 为什么必须登记：check_gen_dedup.py 与 check_secret_cmp.py 是仓库里
        # 唯二没有测试的 Python 守卫 —— C 侧每条断言都有变异盯着，它们没有。
        # 于是唯一的失效模式无人看管：
        #
        #     守卫自己被改坏 -> 恒返回"通过" -> 报告一片全绿 -> 无人察觉。
        #
        # 这和 C 侧"测试假设掩盖缺陷"同类，只是更隐蔽：守卫的价值恰恰在于
        # "在正确的时候变红"，而恒绿守卫看起来和健康守卫一模一样。
        #
        # 检测者是 scripts/check_guards.py（元守卫），它跑正反双向：
        # 合规 fixture 必须 PASS、违规 fixture 必须 FAIL。只验一侧的话，
        # "恒绿"或"恒红"其中一个仍能溜过去。
        "id": "M31",
        "desc": "scripts: 去重守卫恒绿（重复实现被复制回去也不再报错）",
        "file": "scripts/check_gen_dedup.py",
        "old": "    if bad:\n        print(\"[FAIL] 探测基础设施出现重复实现\")",
        "new": "    if False:\n        print(\"[FAIL] 探测基础设施出现重复实现\")",
        "lang": "py",
        "cmds": ["python3 scripts/check_guards.py"],
    },
    {
        "id": "M32",
        "desc": "scripts: 秘密比较守卫恒绿（未分类/SECRET 调用点都不再报错）",
        "file": "scripts/check_secret_cmp.py",
        "old": "    if banned or unknown or annot_bad or annot_miss or orph:",
        "new": "    if False:",
        "lang": "py",
        "cmds": ["python3 scripts/check_guards.py"],
    },
    {
        # 与 M32 方向不同：M32 是"整个判定被短路"，M33 是"SECRET 这一类不再
        # 被认出来"。后者更接近真实编码错误 —— 改坏的人不会写 if False，
        # 只会让某个条件不再成立。危害也更隐蔽：判为 SECRET 的调用点会退化
        # 成"已分类但不是秘密"，守卫从"拦下秘密比较"退化成"什么都不拦"。
        "id": "M33",
        "desc": "scripts: SECRET 分类不再被识别（秘密比较点被当成普通已分类放过）",
        "file": "scripts/check_secret_cmp.py",
        "old": "        elif cls(allow[key]) == BANNED:",
        "new": "        elif False:",
        "lang": "py",
        "cmds": ["python3 scripts/check_guards.py"],
    },
    {
        "id": "M3",
        "desc": "20_packer: 入口 nop 垫恒为 0（首字节变回跨构建恒定签名）",
        "file": "20_packer/src/poly.c",
        "old": "int npad = (int)rnd(p, 3);",
        "new": "int npad = 0;",
        "mod": "20_packer",
        "bin": "build/test_poly",
        "all_occurrences": True,
    },
    {
        "id": "M4",
        "desc": "25_deploy: 未 seal 也允许组装（投送不全就执行）",
        "file": "25_deploy/src/drop.c",
        "old": "if (!a->sealed) return DP_ERR_INCOMPLETE;",
        "new": "if (0)",
        "mod": "25_deploy",
        "bin": "build/test_drop",
    },
    {
        "id": "M5",
        "desc": "agent_windows: 去掉对抗闸门（不安全环境也会采集/回传/驻留）",
        "file": "agent_windows/src/implant_main.c",
        "old": "if (h->defend(h->defend_ud) != 0) return IMW_ERR_UNSAFE;",
        "new": "if (0)",
        "mod": "agent_windows",
        "bin": "build/winshim/test_implant_main",
        # 必须显式指定：agent_windows 的默认目标 all 只建 $(TEST_BINS)，
        # 不含 winshim。不指定的话审计跑的是陈旧二进制，结果毫无意义
        # （曾据此得出 M5 SURVIVED 的假结论）。
        #
        # 用 winshim-build 而不是 winshim：后者在 recipe 里直接跑测试，
        # 变异生效时 make 非零退出，会被记成"构建失败"而非 CAUGHT ——
        # 把"测试抓到了"掩盖成"构建坏了"。这里要的是测试结果由 run_one
        # 独立判定，所以只建不跑。
        "target": "winshim-build",
    },
    {
        "id": "M6",
        "desc": "17_loader: PE32+ TLS 回调偏移改回 +20（TLS 回调静默丢失）",
        "file": "17_loader/src/reflect.c",
        "old": "cb_va = ld_rd64(img->buf + off + 24u);",
        "new": "cb_va = ld_rd64(img->buf + off + 20u);",
        "mod": "17_loader",
        "bin": "build/test_loader",
    },
    {
        "id": "M7",
        "desc": "14_p2p: 带宽探测失败(bw=0)不再返回 UNKNOWN（覆盖被静默禁用）",
        "file": "14_p2p/src/cover_budget.c",
        "old": "if (bw_kbps == 0) return B_UNKNOWN;",
        "new": "if (0) return B_UNKNOWN;",
        "mod": "14_p2p",
        "bin": "build/test_cover_budget",
        # 14_p2p 的 all 目标不含 test_cover_budget（它只在 test 目标里）。
        "target": "build/test_cover_budget",
        # 这类缺陷最危险的地方：它不报错。探测失败被当成"带宽真的是 0"，
        # 预算算出 0，覆盖流量静默消失，链路退化成无覆盖的静默链路，
        # 而调用方读到的仍是 OK。所以必须有一条变异钉住它。
    },
    {
        "id": "M8",
        "desc": "agent_windows: 节区 W+X 不再拒绝（内存中留下 RWX 页）",
        "file": "agent_windows/src/reflect_run.c",
        "old": "if ((p & RR_P_X) && (p & RR_P_W)) return RR_ERR_WX;",
        "new": "if (0) return RR_ERR_WX;",
        "mod": "agent_windows",
        "bin": "build/linux/test_reflect_run",
        # 注意：test_reflect_run 在默认目标 all 的 TESTS 里（与 M5 的
        # test_implant_main 不同），所以这里不需要显式 target。
    },
    {
        "id": "M9",
        "desc": "00_crypto: GCM tag 改用 memcmp（引入时序侧信道，功能仍完全正确）",
        "file": "00_crypto/src/crypto_gcm.c",
        "old": "if (!crypto_constant_time_eq(tag, expected_tag, GCM_TAG_LEN))",
        "new": "if (memcmp(tag, expected_tag, GCM_TAG_LEN) != 0)",
        "mod": "00_crypto",
        "bin": "build/test_gcm",
        # 这一类才是变异审计最该盯的：改完之后加解密、验签、所有功能
        # 全部照常工作，测试几乎必然全绿。它不产生错误结果，只泄露
        # "tag 在第几个字节开始不同"这一位信息。
        #
        # 若它 SURVIVED，那本身就是结论：我们没有时序侧信道的回归保护。
        # 与 M1/M4 那种"功能错、必然被抓"的变异相比，SURVIVED 不代表
        # 审计失败，而是暴露了一块此前从未被验证过的测试盲区。
        #
        # 【历史实测：曾穷举三条路，全部失败】
        #   1) 时钟测量：3e6 次调用/配置，memcmp 各失配位耗时比 1.0000~1.0050，
        #      ct_eq 是 1.0000~1.0057 —— 两者差异同量级，都在噪声内。
        #      现代 glibc 对 16 字节 memcmp 走无分支路径，测不出差异。
        #   2) 符号引用：变异后 objdump 查 memcmp 调用数 = 0 —— 被内联展开。
        #   3) 指令序列：可做但随编译器版本漂移，属脆弱判据。
        #
        # 【重要】"本环境测不出" 不等于 "该缺陷无害"。memcmp 不保证常量时间，
        # 换平台（无 SIMD 的 CPU、老 libc）可能逐字节早退。正确做法是保持
        # constant_time_eq —— 它的正确性来自语义契约，不来自本环境的实测。
        #
        # 三条都失败，所以一度声明 known_blind（在报告中单列"测不了"）。
        # 2026-10 找到第四条路后转 expect=CAUGHT，见下方。保留这段记录：
        # 它说明"本环境测不出"和"该缺陷无害"是两件事，也提醒别再把
        # "本地测不出时序差异"当成"可以改用 memcmp"的理由。
        #
        # 【2026-10 破盲：第四条路 —— 语义契约可观测化】
        # 测不了时序，就不测时序。改为把"是否走了常量时间原语"变成
        # 可断言的事实：crypto_constant_time_eq 在 CRYPTO_CT_INSTRUMENT
        # 下记录循环体执行次数（插桩在循环体最前面，任何早退都会被抓），
        # test_gcm 断言 gcm_open 一次 -> 步数恒 == GCM_TAG_LEN。
        #
        # 换成 memcmp 后该函数根本不被调用，计数器保持 0 -> 3 项失败。
        #
        # 剩余边界（如实声明）：这测的是【源码级执行步数】，不是机器码
        # 级常量时间。编译器理论上仍可把无副作用循环优化成早退，那一层
        # 需人工审查汇编。但源码级早退是最常见的破坏方式，已可捕获。
    },
    {
        "id": "M13",
        "desc": "00_crypto: 常量时间比较改为发现不同即 break（早退，引入侧信道）",
        "file": "00_crypto/src/crypto_gcm.c",
        "old": "        diff |= (uint8_t)(a[i] ^ b[i]);\n    }\n    return diff == 0;",
        "new": "        diff |= (uint8_t)(a[i] ^ b[i]);\n        if (diff) break;\n    }\n    return diff == 0;",
        "mod": "00_crypto",
        "bin": "build/test_gcm",
        # 与 M9 同源的另一类破坏：功能完全正确（返回值一样），只是
        # 提前退出。插桩点在循环体最前面才能捕获它 —— 放在循环体
        # 末尾的话，写在末尾的 break 就逃过去了。
    },
    {
        "id": "M14",
        "desc": "00_crypto: 常量时间比较改为发现不同即 return 0（早退，功能等价）",
        "file": "00_crypto/src/crypto_gcm.c",
        "old": "        diff |= (uint8_t)(a[i] ^ b[i]);\n    }\n    return diff == 0;",
        "new": "        diff |= (uint8_t)(a[i] ^ b[i]);\n        if (diff) return 0;\n    }\n    return diff == 0;",
        "mod": "00_crypto",
        "bin": "build/test_gcm",
        # M13 是 break，M14 是 return。两者功能返回值都与原实现一致
        # （全同 -> 1，任一不同 -> 0），差别只在退出方式。只做 M13 就
        # 断言"早退已覆盖"是过度声称：改代码的人用 return 是同样自然
        # 的写法，必须各自有变异钉住。
    },
    {
        "id": "M15",
        "desc": "00_crypto: 常量时间比较改为循环条件带 !diff（早退，最隐蔽的一种）",
        "file": "00_crypto/src/crypto_gcm.c",
        "old": "    uint8_t diff = 0;\n    for (size_t i = 0; i < len; i++) {",
        "new": "    uint8_t diff = 0;\n    for (size_t i = 0; i < len && !diff; i++) {",
        "mod": "00_crypto",
        "bin": "build/test_gcm",
        # 第三种早退写法：不动循环体，只改循环条件。比 break/return 更
        # 隐蔽 —— 读循环体看不出问题。若只测了 M13/M14 就宣称"早退全覆盖"，
        # 这一条会漏。
    },
    {
        "id": "M21",
        "desc": "00_crypto: crypto_ct_cmp 用带分支的写法（步数不变，源码层漏过）",
        "file": "00_crypto/src/crypto_gcm.c",
        "old": "        unsigned undecided = (gt | lt) ^ 1u;\n        gt |= undecided & gt_b;\n        lt |= undecided & lt_b;",
        "new": "        if (gt | lt) continue;\n        if (x > y) gt = 1;\n        else if (x < y) lt = 1;",
        "mod": "00_crypto",
        "bin": "build/test_gcm",
        "mc_symbol": "crypto_ct_cmp",
        "mc_max": 4,
        #
        # 这一条是"源码层守卫够不够"的分水岭。
        #
        # 变异用 continue 而非 break：循环仍走满 len 次，插桩步数不变，
        # 所以 test_gcm 的步数断言【全绿】—— 实测 344/344 通过。
        # 但循环体内多了 3 条数据相关的条件跳转（4 -> 7），常量时间性质
        # 已被破坏，只是源码层看不见。
        #
        # 这正是 M9 破盲时声明的"剩余边界"：源码级步数不等于机器码级
        # 常量时间。M16 把那层边界变成可断言的事实。
        #
        # mc_max=4 的构成：3 条 NULL 检查 + 1 条循环条件（数据无关）。
        # 循环体内应为 0。该数字随编译器/优化级别变化 —— 若升级工具链后
        # 误报，应重新标定而不是放宽判据。
    },
    {
        "id": "M22",
        "desc": "00_crypto: crypto_ct_cmp 改回比较运算符 x>y / x<y",
        "file": "00_crypto/src/crypto_gcm.c",
        "old": "        unsigned lt_b = ((x - y) >> CT_SIGN_BIT) & 1u;   /* x < y */\n        unsigned gt_b = ((y - x) >> CT_SIGN_BIT) & 1u;   /* x > y */",
        "new": "        unsigned lt_b = (x < y);\n        unsigned gt_b = (x > y);",
        "mod": "00_crypto",
        "bin": "build/test_gcm",
        "known_blind": True,
        "expect": "SURVIVED",
        #
        # 【实测：本环境测不出，如实记为盲区】
        # 两种写法的条件跳转数**都是 4**（编译器把 x<y 优化成 sub+shr，
        # 与手写算术版生成的机器码等价）。反汇编确认循环体内零条件跳转。
        #
        # 所以"改回比较运算符"在本工具链下是无害的 —— 但这是【编译器
        # 的善意】，不是【语言的保证】。换编译器或降优化级别即可能生成
        # 分支。保留无运算符写法的理由是消除对编译器行为的依赖，
        # 而不是因为测出来它更快或更安全。
        #
        # 不把它伪装成 CAUGHT：机器码数一样，写 expect 就是自欺。
    },
    {
        "id": "M10",
        "desc": "23_lkm: 去掉链表互指校验（结构不一致也照写，写坏内核链表）",
        "file": "23_lkm/src/lkm.c",
        "old": "    if (back != node)\n        return LKM_ERR_CORRUPT;",
        "new": "    if (0)\n        return LKM_ERR_CORRUPT;",
        "mod": "23_lkm",
        "bin": "build/test_lkm",
        "all_occurrences": True,
        # 两处（nxt->prev 与 prv->next）都要改，只改一处会被另一处挡住，
        # 得出"测试抓到了"的假结论。
    },
    {
        "id": "M11",
        "desc": "26_lateral_auto: base64 非法字符静默跳过（放行命令注入）",
        "file": "26_lateral_auto/src/cred.c",
        "old": "            return -1;               /* 非法字符：宁可失败，不可静默跳过 */",
        "new": "            continue;",
        "mod": "26_lateral_auto",
        "bin": "build/test_lateral_auto",
        # all 只建 $(OBJ)，不含测试二进制 —— 不显式指定 target 就会跑
        # 陈旧二进制，得到毫无意义的"CAUGHT"。
        "target": "build/test_lateral_auto",
    },
    {
        "id": "M12",
        "desc": "21_exfil: 信元 AUTH 失败不再上报（篡改信元被当正常处理）",
        "file": "21_exfil/src/exfil.c",
        "old": "if (rc == P2P_CELL_ERR_AUTH) return EXF_ERR_AUTH;",
        "new": "if (0) return EXF_ERR_AUTH;",
        "mod": "21_exfil",
        "bin": "build/test_exfil",
        "all_occurrences": True,
    },
    {
        "id": "M19",
        "desc": "25_tls: 服务端 hs_read 静默忽略非握手记录（握手前夹带应用数据被接受）",
        "file": "25_tls/src/tls_server.c",
        "old": "             * rec_read 循环，不经过 hs_read。 */\n            return TLS_ERR_HANDSHAKE;",
        "new": "             * rec_read 循环，不经过 hs_read。 */\n            continue;",
        "mod": "25_tls",
        "bin": "build/test_tls_seq",
        #
        # 【真实缺陷，不是假想变异】2026-10 由 test_tls_seq 的语义断言抓到：
        # 在 ClientHello 之前注入一条格式正确的应用数据记录，服务端原样
        # 跳过并继续等握手消息，最终 stage=7 完整握手成功、回显正确。
        # 字节级变异（test_tls_hs）永远碰不到它 —— 那条记录一个字节都没改。
        #
        # 危害不是"崩了"，而是"该拒绝的没拒绝"：对端获得一条静默通道，
        # 可在握手期间夹带任意记录类型而不触发任何告警。握手完成前不得有
        # 应用数据，这条不变式原先只靠"恰好没去处理它"维持着。
        #
        # 反向已验：改回 continue 后该断言变红（cli_rc=0 srv_rc=0 stage=7）。
    },
    {
        "id": "M20",
        "desc": "25_tls: 客户端 hs_read 静默忽略非握手记录（恶意服务端可夹带数据）",
        "file": "25_tls/src/tls.c",
        "old": "             * 察觉，客户端照样完成握手 —— 等于把\"是否安全\"交给对方决定。 */\n            return TLS_ERR_HANDSHAKE;",
        "new": "             * 察觉，客户端照样完成握手 —— 等于把\"是否安全\"交给对方决定。 */\n            continue;",
        "mod": "25_tls",
        "bin": "build/test_tls_seq",
        # 客户端侧同源缺陷。若只修服务端就宣称"意外消息已覆盖"，客户端
        # 仍会把"是否安全"交给恶意服务端决定 —— 它可以在 ServerHello 与
        # Finished 之间插入数据，客户端照样报握手成功。
        # 反向已验：改回 continue 后该断言变红（cli_rc=0 srv_rc=0 stage=7）。
    },
]

# 变异 -> 应当出现的症状。多数变异期望被测试以失败捕获（CAUGHT），
# 只有少数缺陷的症状是"跑不完"（见 M2 注释）。命中的不计入失败，
# 否则常态化审计会出现随机失败项，进而被整体忽略。
EXPECT = {m["id"]: m["expect"] for m in MUTATIONS if "expect" in m}
BLIND = {m["id"]: True for m in MUTATIONS if m.get("known_blind")}


def _check_ids():
    """ID 必须唯一。EXPECT / BLIND 都以 id 为键，撞号时后定义的覆盖前者，
    结果是某个变异错享另一个的 expect（把 FAIL 判成"符合预期症状"）——
    那是假通过，比漏掉一个变异危险得多。历史上 M16/M17 就被 24_front
    与 00_crypto 各用了一次，靠人工核对才发现。"""
    seen = {}
    for m in MUTATIONS:
        i = m["id"]
        if i in seen:
            raise SystemExit(
                "[FATAL] 变异 ID 重复：%s 同时用于 %s 与 %s"
                % (i, seen[i], m.get("file")))
        seen[i] = m.get("file")
    return seen


_check_ids()


def sh(cmd, cwd, timeout=900):
    try:
        p = subprocess.run(cmd, shell=True, cwd=cwd, timeout=timeout,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return p.returncode, p.stdout.decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        return -999, ""


def heal():
    """启动时自愈：恢复上一次被强杀留下的变异。

    finally 在 SIGKILL 下不执行——实测中进程被杀后 .mutbak 与变异代码同时
    留在工作区，下一次构建就带着人为注入的缺陷跑，且无人知晓。
    所以每次启动先扫一遍残留备份并还原。
    """
    healed = []
    for dirpath, _dirs, files in os.walk(ROOT):
        if "/.git" in dirpath or "/build" in dirpath:
            continue
        for fn in files:
            if fn.endswith(".mutbak"):
                bak = os.path.join(dirpath, fn)
                orig = bak[: -len(".mutbak")]
                shutil.move(bak, orig)
                # 同 run_one 的 finally：推高 mtime，否则 make 认为 .o 更新
                # 而跳过重编译，残留的变异目标码会继续参与后续构建。
                os.utime(orig, None)
                healed.append(os.path.relpath(orig, ROOT))
    return healed


def files_clean(files):
    """只校验将被变异的文件本身干净。

    早期版本要求整个工作区干净，结果审计脚本自己没提交就跑不起来——
    守卫反而挡住了正常使用。真正需要保护的是变异目标文件：它有未提交
    改动时，审计产生的构建产物会被误认为对应那份改动。
    """
    dirty = []
    for f in files:
        rc, out = sh("git status --porcelain -- '%s'" % f, ROOT, 60)
        if rc != 0 or out.strip():
            dirty.append(f)
    return dirty


def blob_hash(path):
    """用 git 的对象哈希，与仓库判定一致，避免自己算错。"""
    rc, out = sh("git hash-object '%s'" % path, ROOT, 60)
    return out.strip() if rc == 0 else None


def build(mod, target=None):
    d = os.path.join(ROOT, mod)
    # 不 clean：变异只改一个 .c，增量重建即可。
    # 旧版每次 make clean 是全量重编，是上一轮审计超时的直接原因。
    cmd = "make -s %s 2>&1 | tail -8" % target if target else "make -s 2>&1 | tail -8"
    rc, out = sh(cmd, d, 900)
    return rc, out


def count_cond_jumps(binpath, symbol):
    """统计指定函数内的条件跳转条数（不含 call/jmp/ret）。

    源码层步数守卫抓不到的一类变异：不减步数、不早退，但在循环体内
    引入数据相关分支（例：if (gt|lt) continue; if (x>y) gt=1; ...）。
    步数仍是 len，测试全绿，只有看机器码才现形。
    """
    rc, out = sh("objdump -d %s --no-show-raw-insn" % binpath, ROOT, 120)
    if rc != 0:
        return None
    lines = out.splitlines()
    start = None
    for i, l in enumerate(lines):
        if "<%s>:" % symbol in l:
            start = i
            break
    if start is None:
        return None
    pat = re.compile(r"\b(je|jne|jg|jge|jl|jle|ja|jae|jb|jbe|js|jns|jo|jno|jc|jnc)\s")
    n = 0
    for l in lines[start + 1:]:
        if not l.strip():
            break                      # 下一个函数
        if pat.search(l):
            n += 1
    return n


def run_one(m):
    path = os.path.join(ROOT, m["file"])
    if not os.path.exists(path):
        return (m["id"], "ERROR", "文件不存在（变异集合已腐烂）")

    if m.get("lang") == "py":
        return run_one_py(m)

    with open(path, "r", encoding="utf-8") as f:
        src = f.read()

    n = src.count(m["old"])
    if n == 0:
        return (m["id"], "ERROR", "锚点失效：未找到 %r —— 变异已不再测任何东西" % m["old"][:50])
    if n > 1 and not m.get("all_occurrences"):
        return (m["id"], "ERROR", "锚点出现 %d 次但未声明 all_occurrences，替换目标不明确" % n)

    before_hash = blob_hash(path)
    bak = path + ".mutbak"
    shutil.copy2(path, bak)
    try:
        mutated = src.replace(m["old"], m["new"]) if m.get("all_occurrences") \
            else src.replace(m["old"], m["new"], 1)
        with open(path, "w", encoding="utf-8") as f:
            f.write(mutated)

        # 校验变异真的生效（哈希必须变）。不校验的话，old==new 之类会让
        # 审计静默变成"什么都没测但报告 CAUGHT"。
        if blob_hash(path) == before_hash:
            return (m["id"], "ERROR", "变异未改变文件内容（old/new 相同？）")

        binpath = os.path.join(ROOT, m["mod"], m["bin"])

        t_build = time.time()
        rc, out = build(m["mod"], m.get("target"))
        if rc != 0:
            return (m["id"], "ERROR", "构建失败: %s" % out.strip()[:160])

        if not os.path.exists(binpath):
            return (m["id"], "ERROR", "测试二进制不存在: %s" % m["bin"])

        # 通用守卫：二进制必须**真的被这次构建更新过**。
        #
        # 否则跑的是陈旧产物，SURVIVED 就成了假结论 —— 测试全绿只因为它
        # 压根没包含变异代码。这类失效已三次出现（M5 的 winshim、M7 的
        # test_cover_budget 都只在非默认目标里），每次都表现为"测试仍全绿"。
        #
        # 与其逐个手工指定 target，不如让脚本自己判定：构建没产出新的二进制
        # 就直接判 ERROR。留 2 秒余量给文件系统时间戳粒度。
        if os.path.getmtime(binpath) < t_build - 2:
            return (m["id"], "ERROR",
                    "构建未更新 %s（跑的是陈旧产物，判定无意义）—— 需显式 target"
                    % m["bin"])

        # 120s：正常测试几秒内结束。挂起型变异（如 M2 的 ptrace 自伤）值得
        # 等，但 600s 会让整轮审计超过回归脚本的总时限，反而被上层杀掉，
        # 留下变异代码无人恢复。
        trc, tout = sh("./" + m["bin"], os.path.join(ROOT, m["mod"]), 120)
        if trc == -999:
            return (m["id"], "HANG", "测试超时无输出 —— 挂起，不是被捕获")
        if not tout.strip():
            return (m["id"], "HANG", "测试零输出 —— 疑似挂起/被杀，退出码 %d 不可信" % trc)
        if trc == 0:
            # 源码层漏过 -> 机器码层补刀。
            # 只对声明了 mc_symbol/mc_max 的变异生效（目前 M16）。
            if m.get("mc_symbol") and m.get("mc_max") is not None:
                n = count_cond_jumps(binpath, m["mc_symbol"])
                if n is None:
                    return (m["id"], "ERROR", "机器码守卫失效：未能解析 %s" % m["mc_symbol"])
                if n > m["mc_max"]:
                    return (m["id"], "CAUGHT",
                            "机器码层：%s 条件跳转 %d > %d（源码层全绿，仅机器码可见）"
                            % (m["mc_symbol"], n, m["mc_max"]))
            return (m["id"], "SURVIVED", "测试仍全绿 —— 该缺陷无法被捕获")
        fails = [l for l in tout.splitlines() if "FAIL" in l]
        return (m["id"], "CAUGHT", "失败 %d 项, 例: %s" %
                (len(fails), fails[0][:80].strip() if fails else "rc=%d" % trc))
    finally:
        shutil.move(bak, path)
        after = blob_hash(path)
        if after != before_hash:
            # 恢复失败必须显式报错：否则下一次构建就带着变异代码。
            print("[FATAL] %s 恢复失败: %s -> %s，请检查工作区" % (m["id"], before_hash, after))
            sys.exit(2)
        # 还原后必须把 mtime 推到当前。
        #
        # copy2 保留了原始 mtime，move 回去后源码时间戳回到过去，make 会
        # 认为 .o 比源码新从而**跳过重编译** —— 于是变异产生的目标码留在
        # 构建产物里，源码看起来是干净的。后果是审计跑完之后，后续任何构建
        # 和测试都在跑被注入的缺陷代码，而没人知道。
        #
        # 实测触发：M7 之后 14_p2p 的测试出现 3 项失败（其中一项是原本通过的
        # 既有断言），而 git status 显示源码干净、无 .mutbak 残留。
        os.utime(path, None)

        # 仅推 mtime 仍不够：变异期间编译出的 .o / 测试二进制本身是"缺陷产物"。
        # 实测（全量回归）中 14_p2p 报 3 项失败、26_lateral_auto 报 2 项失败，
        # 而 git status 干净、强制重建后均为 0 失败 —— 即回归跑的是残留的
        # 变异二进制。同一机制也能反向造成"假通过"，那更危险。
        # 故还原后清除该模块构建产物，使下次构建必然从当前源码重新编译。
        _purge_build(path)


def run_one_py(m):
    """Python 侧变异：无构建步骤、无二进制，判定靠命令的退出码与输出。

    为什么不能复用 C 侧那套 build/bin 流程：Python 改完即生效，没有
    "构建是否更新了被测产物"这回事。C 侧那条 mtime 守卫（构建没产出新
    二进制就判 ERROR）在这里既不适用，也不能省 —— 它防的是"跑陈旧产物"，
    而 Python 侧对应的风险是"命令没真的执行"，用退出码 77 与零输出来防。

    退出码口径必须与回归脚本一致：
        0   -> 命令认为一切正常（对 --check 而言即无漂移）
        77  -> 环境缺失未验证。既不是"没抓到"也不是"抓到了"，判 ERROR：
               把它算成 CAUGHT 会让无 openssl 的机器一直"全绿通过"，
               算成 SURVIVED 又会让真缺口被环境噪音掩盖。
        其它 -> 抓到（漂移或 FATAL）
    """
    path = os.path.join(ROOT, m["file"])
    with open(path, "r", encoding="utf-8") as f:
        src = f.read()

    n = src.count(m["old"])
    if n == 0:
        return (m["id"], "ERROR", "锚点失效：未找到 %r —— 变异已不再测任何东西"
                % m["old"][:50])
    if n > 1:
        return (m["id"], "ERROR", "锚点出现 %d 次，替换目标不明确" % n)

    before_hash = blob_hash(path)
    bak = path + ".mutbak"
    shutil.copy2(path, bak)
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(src.replace(m["old"], m["new"], 1))

        if blob_hash(path) == before_hash:
            return (m["id"], "ERROR", "变异未改变文件内容（old/new 相同？）")

        # 每条命令都必须被抓到：只跑一条的话，另一侧生成器仍会拿被改坏的
        # 公共模块产出错误真值，而审计报告却是绿的。
        for cmd in m["cmds"]:
            trc, tout = sh(cmd, ROOT, m.get("timeout", 300))
            if trc == -999:
                return (m["id"], "HANG", "命令超时：%s" % cmd)
            # 77 必须排在零输出判定之前。
            # 实测：一个静默 exit(77) 的命令没有输出，若先判零输出就会
            # 被记成 HANG（"疑似挂起"），把"环境缺失没验证"误导成"进程
            # 卡死" —— 排查方向完全不同。SKIP 是明确的语义，优先识别。
            if trc == 77:
                return (m["id"], "ERROR",
                        "环境缺失未验证（SKIP）：%s" % cmd)
            if not tout.strip():
                return (m["id"], "HANG", "命令零输出：%s" % cmd)
            if trc != 0:
                bad = [l for l in tout.splitlines()
                       if "FAIL" in l or "FATAL" in l]
                return (m["id"], "CAUGHT", "%s -> rc=%d, 例: %s"
                        % (cmd.split()[-1], trc,
                           bad[0][:80].strip() if bad else "rc=%d" % trc))
        return (m["id"], "SURVIVED", "%d 条命令仍全部通过 —— 该缺陷无法被捕获"
                % len(m["cmds"]))
    finally:
        shutil.move(bak, path)
        after = blob_hash(path)
        if after != before_hash:
            print("[FATAL] %s 恢复失败: %s -> %s，请检查工作区"
                  % (m["id"], before_hash, after))
            sys.exit(2)
        # Python 无构建产物，但 .pyc 缓存同样会留着变异后的字节码。
        # 实测风险与 C 侧 .o 残留同源：源码看着干净，跑的却是缺陷代码。
        os.utime(path, None)
        _purge_pycache(path)


def _purge_pycache(path):
    """清除被变异文件所在目录的 __pycache__，杜绝陈旧字节码被复用。"""
    import shutil as _sh
    d = os.path.dirname(os.path.abspath(path))
    pc = os.path.join(d, "__pycache__")
    if os.path.isdir(pc):
        _sh.rmtree(pc, ignore_errors=True)


def _purge_build(path):
    """清除被变异文件所属模块的 build/ 目录，杜绝陈旧产物被复用。"""
    import shutil as _sh
    rel = os.path.relpath(os.path.abspath(path), ROOT)
    parts = rel.split(os.sep)
    if len(parts) < 2:
        return
    bdir = os.path.join(ROOT, parts[0], "build")
    if os.path.isdir(bdir):
        try:
            _sh.rmtree(bdir)
            print("[INFO] 已清除陈旧构建产物: %s" % os.path.relpath(bdir, ROOT))
        except OSError as e:
            print("[WARN] 清除 %s 失败: %s（需手工确认）" % (bdir, e))


LOCK = "/tmp/mutation_audit.lock"
_OWN_LOCK = False


def _lock_owner_alive():
    """判断现存锁的持有者是否还活着。

    不仅看 /proc/<pid> 是否存在，还要确认它确实是本脚本：
    pid 会被复用，一个无关进程恰好占用该 pid 时，只看存在性会误判为
    "还活着"，于是审计被一个根本不存在的实例挡住。
    """
    try:
        txt = open(LOCK).read().strip()
    except Exception:
        return True, "?"   # 读不出来就保守认为活着，不擅自删
    m = re.search(r"pid=(\d+)", txt)
    if not m:
        return True, (txt or "?")   # 格式不明，保守
    pid = int(m.group(1))
    if pid == os.getpid():
        return True, txt
    if not os.path.exists("/proc/%d" % pid):
        return False, txt
    try:
        cmd = open("/proc/%d/cmdline" % pid, "rb").read().decode("utf-8", "replace")
    except Exception:
        cmd = ""
    if "mutation_audit" not in cmd:
        return False, txt          # pid 被别的进程复用，非本脚本实例
    return True, txt


def acquire_lock():
    """单实例锁。

    两个审计并发时，A 还原文件的瞬间 B 正要移回 .mutbak —— 实测出现过
    FileNotFoundError: .mutbak 不存在，且源码随后被永久留在变异状态。
    并发不是理论风险：上层超时杀掉进程后，孤儿进程仍在跑。

    【陈旧锁必须自动清除】
    持有者若被 SIGKILL（atexit 来不及跑），锁文件会永久残留，此后
    每一次审计都被这一行挡住 —— 常态化下表现为"变异审计从某天起再也
    没跑过"，而报告上不会有任何提示。本轮实测就被它阻塞了两次。
    故：持有者已死或 pid 已被复用时自动清锁继续，并留 WARN 可见。
    """
    global _OWN_LOCK
    try:
        fd = os.open(LOCK, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        alive, owner = _lock_owner_alive()
        if alive:
            print("[FATAL] 另一个审计实例正在运行（%s）。"
                  "若确认已死，手动删除 %s" % (owner, LOCK))
            sys.exit(2)
        print("[WARN] 检测到陈旧锁（%s，持有者已不在），自动清除后继续" % owner)
        try:
            os.unlink(LOCK)
        except OSError:
            pass
        try:
            fd = os.open(LOCK, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            print("[FATAL] 清锁后仍无法获取 %s，可能真有并发实例" % LOCK)
            sys.exit(2)
    os.write(fd, ("pid=%d" % os.getpid()).encode())
    os.close(fd)
    _OWN_LOCK = True
    # 异常退出（含 install_signals 抛出的 SystemExit）也要放锁，
    # 否则下一次审计会被自己的陈旧锁挡住。
    atexit.register(release_lock)


def release_lock():
    """只删除自己创建的锁。

    无条件 unlink 会删掉别人的锁：install_signals() 先于 acquire_lock()
    生效，那段时间窗内收到信号会走到这里，而此时锁属于另一个实例 ——
    把它删掉等于放行第二次并发，正是本锁要防的事故。
    """
    global _OWN_LOCK
    if not _OWN_LOCK:
        return
    _OWN_LOCK = False
    try:
        os.unlink(LOCK)
    except OSError:
        pass


def install_signals():
    """被上层超时/中断时，先让 finally 还原源码再退出。

    实测：进程被杀后 .mutbak 与变异代码同时留在工作区，下一次构建就带着
    人为注入的缺陷跑。SIGKILL 拦不住（靠下次启动的 heal 兜底），
    SIGTERM/SIGINT 必须拦住 —— 这正是上层超时用的信号。
    """
    def _h(signum, _frame):
        print("[SIGNAL] 收到信号 %d，正在还原变异..." % signum, flush=True)
        raise SystemExit(3)
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        try:
            signal.signal(sig, _h)
        except (ValueError, OSError):
            pass


class Usage(Exception):
    pass


def parse_args(args):
    """解析参数。未知参数与空选择集都必须报错退出，不能静默跑全套/跑零个。

    实测教训：曾敲 `--help` 想看用法，结果参数被静默忽略，脚本跑了 1 分半
    的全套审计还占住锁。同样地，`--only M99`（不存在的变异）会让选择集变
    空，脚本跑 0 个变异然后 exit 0 —— "什么都没验"被记成"全部通过"。
    两者都属于静默失效，宁可报错也不可含糊。
    """
    sel = None
    sample = None
    known = {"--only", "--sample"}
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--only":
            if i + 1 >= len(args):
                raise Usage("--only 需要一个参数")
            sel = set(args[i + 1].split(","))
            i += 2
        elif a == "--sample":
            if i + 1 >= len(args):
                raise Usage("--sample 需要一个参数")
            try:
                sample = int(args[i + 1])
            except ValueError:
                raise Usage("--sample 需要一个整数，收到 %r" % args[i + 1])
            i += 2
        elif a in ("-h", "--help"):
            print(__doc__ or "用法: mutation_audit.py [--only M1,M2] [--sample N]")
            raise SystemExit(0)
        elif a.startswith("-"):
            raise Usage("未知参数 %r（已知: %s）" % (a, ", ".join(sorted(known))))
        else:
            raise Usage("多余的位置参数 %r" % a)
        # 取过值的那个参数不再当选项解析（避免 --only --sample 被吃掉）
    return sel, sample


class Usage(Exception):
    pass


def main():
    install_signals()
    # heal 必须能独立调用。
    #
    # 实测事故：一次审计被强杀后，.mutbak 与变异代码同时留在工作区，而
    # heal() 只在脚本启动时被动执行 —— 从被杀到下一次运行之间，这棵树上
    # 一直带着人为注入的缺陷，任何人 make 都会用到它，且无人知晓。本次
    # 会话正是在这种状态下开始的（front.c 的 tls_write 错误返回被抹掉）。
    #
    # 所以 heal 做成子命令：回归脚本开头无条件跑一次，不必等到审计启动。
    if len(sys.argv) > 1 and sys.argv[1] == "heal":
        if len(sys.argv) > 2:
            print("[FATAL] heal 不接受额外参数")
            sys.exit(2)
        h = heal()
        if h:
            print("[HEAL] 恢复了上一次被强杀留下的变异:")
            for f in h:
                print("       %s" % f)
        else:
            print("[HEAL] 无残留变异备份")
        sys.exit(0)
    try:
        sel, sample = parse_args(sys.argv[1:])
    except Usage as e:
        print("[FATAL] 参数错误: %s" % e)
        sys.exit(2)
    acquire_lock()
    h = heal()
    if h:
        print("[HEAL] 恢复了上次被强杀残留的变异: %s" % ", ".join(h))

    pool = MUTATIONS
    if sel is not None:
        # 不能用 `if sel:` —— 空集合非空字符串都会走到 else，把"选了不存在
        # 的变异"当成"没指定、跑全部"。
        unknown = sorted(sel - {m["id"] for m in MUTATIONS})
        if unknown:
            print("[FATAL] 不存在的变异: %s（已有: %s）"
                  % (", ".join(unknown),
                     ", ".join(m["id"] for m in MUTATIONS)))
            release_lock()
            sys.exit(2)
        pool = [m for m in pool if m["id"] in sel]
        if not pool:
            print("[FATAL] 选择集为空 —— 跑 0 个变异毫无意义，拒绝含糊通过")
            release_lock()
            sys.exit(2)
    if sample and sample < len(pool):
        random.seed()  # 每次抽样不同，长期看覆盖全部
        pool = random.sample(pool, sample)

    dirty = files_clean([m["file"] for m in pool])
    if dirty:
        print("[FATAL] 以下文件有未提交改动，变异会造成混淆：%s" % ", ".join(dirty))
        sys.exit(2)

    results = []
    print("=== 变异审计（逐条，超时也能保留已完成部分）===", flush=True)
    for m in pool:
        r = run_one(m)
        results.append(r)
        print("[%-8s] %s : %s" % (r[0], r[1], r[2]), flush=True)

    print("\n=== 变异审计结果 ===")

    release_lock()

    survived, errors, expected, blind = [], [], [], []
    for r in results:
        if r[1] == "CAUGHT":
            # 捕获就是捕获，优先归类。此前若变异声明了 expect="CAUGHT"，
            # 它会被同时计入"捕获"和"符合预期症状"两栏 —— 后者语义是
            # "没抓到，但有理由"，被抓到的变异不属于它。这会让明明已
            # 覆盖的缺陷看起来仍是例外，等于自己骗自己。
            continue
        exp = EXPECT.get(r[0])
        if exp and r[1] == exp:
            # 同样"不计入失败"，性质却完全不同：
            #   M2 类 —— 症状本身就是挂起，跑不完是正确观测；
            #   M9 类 —— 我们根本没有分辨力，是未被覆盖的风险面。
            # 混在一栏里报告，等于把"测不了"记成"没问题"。
            if BLIND.get(r[0]):
                blind.append(r)
            else:
                expected.append(r)
        elif r[1] == "SURVIVED":
            survived.append(r)
        elif r[1] in ("ERROR", "HANG"):
            errors.append(r)

    print("\n存活(用例证明不了任何事) = %d" % len(survived))
    print("审计失效/挂起           = %d" % len(errors))
    print("捕获                    = %d" % len([r for r in results if r[1] == "CAUGHT"]))
    print("符合预期症状(如M2挂起)  = %d" % len(expected))
    print("已知盲区(测不了,未覆盖) = %d" % len(blind))
    if blind:
        print("\n[!] 以下缺陷无法被自动化捕获，风险面未覆盖（非'已验证安全'）：")
        for r in blind:
            print("    %-4s %s" % (r[0], r[2]))

    # SURVIVED 是真缺口；ERROR/HANG 是审计或测试基建的问题，同样不能放过。
    # 声明了 expect 且症状吻合的不算失败 —— 见 M2 注释。
    sys.exit(1 if (survived or errors) else 0)


if __name__ == "__main__":
    main()
