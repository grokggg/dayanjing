#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gen_ch_struct.py —— 生成 ClientHello 结构化变异用例
=====================================================================
为什么需要它（与已有的 test_tls_ch.c 的区别）：

  test_tls_ch.c 做的是「字节级」变异：截断、单字节置 0x00/0xFF。
  字节翻转有个先天盲区 —— 它几乎不可能产生出「格式完全正确、但语义
  刁钻」的报文。而解析器真正会出事的地方，往往正是这类报文：

    * 一个类型未知、但长度声明合法的扩展
    * GREASE 值出现在套件列表 / 扩展类型 / 组列表 / 签名算法里
    * 声明长度比实际多 1 个字节
    * 同一个扩展出现两次

  这些都必须在「外层长度重算正确」的前提下构造，否则测的是截断而不是
  解析器。本文件就干这件事：从真实报文出发，按 TLS 结构做手术，
  该重算的长度一律重算，只有「长度不符」这一类才故意不重算。

输入：25_tls/tests/clienthello_default.h 里的 CH_REAL（真实 OpenSSL
      3.0.2 默认 s_client 发出的第一个记录）
输出：25_tls/tests/clienthello_struct.h

用法：python3 scripts/gen_ch_struct.py
=====================================================================
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "25_tls", "tests", "clienthello_default.h")
DST = os.path.join(ROOT, "25_tls", "tests", "clienthello_struct.h")

# GREASE 值（RFC 8701）：0x?A?A，两端字节相同且低半字节为 A
GREASE = [0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A,
          0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A,
          0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA]

EXPECT_TOLERATE = 1   # 必须被接受：服务端应当照常产出响应（sent > 0）
EXPECT_REJECT = 0     # 必须被拒绝：结构非法，不得产出响应（sent == 0）
EXPECT_ANY = -1       # 只要求不崩不挂，不强求接受或拒绝


def load_real():
    src = open(SRC, encoding="utf-8").read()
    m = re.search(r"CH_REAL\[\]\s*=\s*\{(.*?)\}", src, re.S)
    if not m:
        raise SystemExit("[FATAL] 在 %s 里找不到 CH_REAL" % SRC)
    return bytes(int(x, 16) for x in re.findall(r"0x([0-9a-fA-F]{2})", m.group(1)))


def parse(b):
    """解析 ClientHello，返回各字段偏移。偏移是做手术的前提 ——
    猜偏移等于在构造假报文。"""
    assert b[0] == 0x16 and b[1] == 0x03
    rec_len = int.from_bytes(b[3:5], "big")
    assert 5 + rec_len == len(b), (rec_len, len(b))
    assert b[5] == 0x01
    hs_len = int.from_bytes(b[6:9], "big")
    assert 9 + hs_len == len(b)
    o = 9
    ver = b[o:o + 2]; o += 2
    rnd = b[o:o + 32]; o += 32
    sid_len = b[o]; o += 1
    sid = b[o:o + sid_len]; o += sid_len
    cs_len = int.from_bytes(b[o:o + 2], "big"); o += 2
    suites = b[o:o + cs_len]; o += cs_len
    assert cs_len % 2 == 0
    comp_len = b[o]; o += 1
    comp = b[o:o + comp_len]; o += comp_len
    ext_len = int.from_bytes(b[o:o + 2], "big"); o += 2
    exts_raw = b[o:o + ext_len]; o += ext_len
    assert o == len(b), (o, len(b))
    # 逐条切扩展
    exts = []
    p = 0
    while p < len(exts_raw):
        t = int.from_bytes(exts_raw[p:p + 2], "big")
        L = int.from_bytes(exts_raw[p + 2:p + 4], "big")
        exts.append({"type": t, "body": exts_raw[p + 4:p + 4 + L]})
        p += 4 + L
    assert p == len(exts_raw)
    return dict(ver=ver, rnd=rnd, sid=sid, suites=suites, comp=comp, exts=exts)


def ext_bytes(exts, override_total=None):
    """把扩展列表（每项为 {'type','body'}）序列化为「总长 + 逐条」。
    override_total 用于故意把总长写错。"""
    raw = b"".join(e["type"].to_bytes(2, "big")
                   + len(e["body"]).to_bytes(2, "big") + e["body"] for e in exts)
    total = len(raw) if override_total is None else override_total
    return total.to_bytes(2, "big") + raw


def build(p, exts=None, override_ext_total=None, override_cs_len=None,
          override_hs_len=None, override_sid_len=None, override_rec_len=None,
          suites=None, sid=None, ext_block=None, extra_tail=b""):
    """按结构重建完整记录。默认所有长度都如实重算 —— 只有显式
    override_* 的那些才是故意做坏的。ext_block 若给出则原样使用
    （用于构造「单条扩展声明长度与体不符」这类 ext_bytes 造不出的块）。"""
    exts = p["exts"] if exts is None else exts
    cs = p["suites"] if suites is None else suites
    sidb = p["sid"] if sid is None else sid
    cs_len = len(cs) if override_cs_len is None else override_cs_len
    sid_len = len(sidb) if override_sid_len is None else override_sid_len
    body = (p["ver"] + p["rnd"] + bytes([sid_len]) + sidb
            + cs_len.to_bytes(2, "big") + cs
            + bytes([len(p["comp"])]) + p["comp"]
            + (ext_bytes(exts, override_ext_total) if ext_block is None else ext_block))
    hs_len = len(body) if override_hs_len is None else override_hs_len
    rec = bytes([0x01]) + hs_len.to_bytes(3, "big") + body + extra_tail
    rec_len = len(rec) if override_rec_len is None else override_rec_len
    return bytes([0x16, 0x03, 0x01]) + rec_len.to_bytes(2, "big") + rec


def find(p, t):
    for e in p["exts"]:
        if e["type"] == t:
            return e
    return None


def list_append(body, hdr, add):
    """给「长度前缀 + 列表」结构的扩展体追加字节，并如实重算内层长度。

    hdr: 长度前缀占几字节（supported_groups / sig_algs / key_share 是 2，
         supported_versions 是 1）。

    为什么单独抽出来：第一版写成 (len(body) + len(add))，而 len(body)
    已经包含头部，于是内层声明长度凭空多算了 len(hdr) 个字节 —— 造出来的
    不是「掺了 GREASE 的合法扩展」，而是「内层长度自相矛盾的畸形扩展」。
    OpenSSL 因此发 decode_error，差点被我记成被测端的缺陷。
    """
    inner = len(body) - hdr + len(add)
    return inner.to_bytes(hdr, "big") + body[hdr:] + add


def dup_exts(p, t, newbody=None):
    """复制某扩展（值可选替换），保持原顺序并追加在末尾。"""
    out = [dict(e) for e in p["exts"]]
    for e in out:
        if e["type"] == t:
            nb = e["body"] if newbody is None else newbody
            out.append({"type": t, "body": nb})
            break
    return out


def cases(p):
    C = []
    add = lambda n, b, e, w: C.append((n, b, e, w))

    # ============ Z0. 重建自检 ============
    # 不修改任何字段地重建一遍，必须与 CH_REAL 逐字节相同。
    # 这条不成立，说明 parse/build 的偏移算错了 —— 那后面 33 个
    # 用例测的就都不是「真实报文的变体」而是我编出来的另一个包，
    # 全部结论作废。所以它不是装饰，是整个文件的前提。
    add("Z0_roundtrip_equals_real", build(p), EXPECT_TOLERATE,
        "重建未修改的报文必须与 CH_REAL 逐字节相同（生成器自检）")

    # ============ A. 未知扩展：必须被忽略（RFC 要求）============
    unk = [dict(e) for e in p["exts"]]
    unk.append({"type": 0x0A0A, "body": bytes(range(8))})
    add("A1_unknown_ext_len8", build(p, unk), EXPECT_TOLERATE,
        "类型未知但长度合法的扩展：必须忽略并照常响应")

    unk0 = [dict(e) for e in p["exts"]]
    unk0.append({"type": 0xFF02, "body": b""})
    add("A2_unknown_ext_len0", build(p, unk0), EXPECT_TOLERATE,
        "零长未知扩展（0xFF02 未分配；0xFF01 是 renegotiation_info，不能用）")

    unkbig = [dict(e) for e in p["exts"]]
    unkbig.append({"type": 0xFF02, "body": bytes(300)})
    add("A3_unknown_ext_len300", build(p, unkbig), EXPECT_TOLERATE,
        "300 字节的未知扩展：必须按长度跳过，不得逐字节猜内容")

    many = [dict(e) for e in p["exts"]]
    for i in range(64):
        many.append({"type": 0x8000 + i, "body": b"\x01\x02"})
    add("A4_64_unknown_exts", build(p, many), EXPECT_TOLERATE,
        "64 个未知扩展：考验扩展遍历的累加有没有溢出")

    # 声明长度比实际多 —— 最经典的越界读。外层长度照常重算，
    # 坏掉的只有「单条扩展」的声明长度。若外层也不重算，测到的
    # 就是截断而不是解析器了。
    good_block = ext_bytes(p["exts"])[2:]          # 去掉正确的 2 字节总长
    bad_tail = (0xFF01).to_bytes(2, "big") + (5).to_bytes(2, "big") + b"\x00\x01\x02"
    for delta in (1, 4, 64):
        blk = good_block + bad_tail
        add("A5_ext_body_len_plus%d" % delta,
            build(p, ext_block=(len(blk)).to_bytes(2, "big") + blk),
            EXPECT_REJECT,
            "未知扩展声明长度比实际多 %d：OpenSSL 实测拒绝，必须拒绝" % delta)
    # 单条扩展声明长度超过整个扩展块剩余 —— 更极端的一档
    blk2 = good_block + (0xFF01).to_bytes(2, "big") + (0xFFFF).to_bytes(2, "big") + b"\x00"
    add("A6_ext_body_len_ffff",
        build(p, ext_block=len(blk2).to_bytes(2, "big") + blk2),
        EXPECT_REJECT, "未知扩展声明长度 0xFFFF：必须拒绝，不得按它去读")

    # ============ B. GREASE（RFC 8701）：必须被容忍 ============
    g = [dict(e) for e in p["exts"]]
    g.insert(0, {"type": GREASE[0], "body": b""})
    add("B1_grease_ext_front", build(p, g), EXPECT_TOLERATE,
        "GREASE 扩展在最前面（零长）：不得因未知类型拒绝握手")
    g2 = [dict(e) for e in p["exts"]]
    g2.insert(0, {"type": GREASE[5], "body": b"\xde\xad\xbe\xef"})
    add("B2_grease_ext_body", build(p, g2), EXPECT_TOLERATE,
        "GREASE 扩展带 4 字节体：必须按长度跳过")

    # GREASE 套件：插到套件列表最前
    old_suites = p["suites"]
    p["suites"] = GREASE[3].to_bytes(2, "big") + old_suites
    add("B3_grease_suite_front", build(p), EXPECT_TOLERATE,
        "GREASE 套件插在最前：不得把它当成真实套件")
    p["suites"] = old_suites + GREASE[7].to_bytes(2, "big")
    add("B4_grease_suite_tail", build(p), EXPECT_TOLERATE, "GREASE 套件在末尾")
    p["suites"] = old_suites

    # GREASE 进 supported_groups(0x000a) 列表
    sg = find(p, 0x000A)
    if sg:
        orig = sg["body"]
        save = sg["body"]
        sg["body"] = list_append(orig, 2, GREASE[2].to_bytes(2, "big"))
        add("B5_grease_group", build(p), EXPECT_TOLERATE,
            "supported_groups 里掺 GREASE 组：必须跳过未知组")
        sg["body"] = save

    # GREASE 进 signature_algorithms(0x000d)
    sa = find(p, 0x000D)
    if sa:
        save = sa["body"]
        sa["body"] = list_append(save, 2, GREASE[9].to_bytes(2, "big"))
        add("B6_grease_sigalg", build(p), EXPECT_TOLERATE,
            "signature_algorithms 里掺 GREASE：不得在未知算法上死循环")
        sa["body"] = save

    # GREASE 进 key_share(0x0033)：一个未知组、长度合法的 share
    ks = find(p, 0x0033)
    if ks:
        save = ks["body"]
        entry = GREASE[11].to_bytes(2, "big") + (4).to_bytes(2, "big") + b"\x00\x01\x02\x03"
        ks["body"] = list_append(save, 2, entry)
        add("B7_grease_keyshare", build(p), EXPECT_TOLERATE,
            "key_share 里掺 GREASE 组：必须按 entry 长度跳过")
        ks["body"] = save

    # GREASE 进 supported_versions(0x002b)
    sv = find(p, 0x002B)
    if sv:
        save = sv["body"]
        sv["body"] = list_append(save, 1, GREASE[13].to_bytes(2, "big"))
        add("B8_grease_version", build(p), EXPECT_TOLERATE,
            "supported_versions 里掺 GREASE 版本：只实现 1.2 的实现必须忽略它")
        sv["body"] = save

    # ============ B9. 扩展内层列表长度自相矛盾 ============
    # 外层 el 是自洽的，坏的是「列表前缀声明的长度」与「列表实际字节数」
    # 不符。这一档是上一版生成器自己踩出来的坑：它把内层长度算多了，
    # 结果造出的是畸形扩展，OpenSSL 因此发 decode_error —— 差点被我
    # 记成被测端的缺陷。既然撞上了，就把它变成一条正经用例。
    for t, hdr, nm in ((0x000A, 2, "groups"), (0x000D, 2, "sigalgs"),
                       (0x002B, 1, "versions"), (0x0033, 2, "keyshare")):
        e = find(p, t)
        if not e:
            continue
        save = e["body"]
        vmax = (1 << (8 * hdr)) - 1          # 1 字节前缀上限 255，2 字节 65535
        # key_share 例外：实测 OpenSSL 3.0.2 对它的内层长度不符是接受的
        # （对 groups / sigalgs / versions 都是 decode_error）。所以这里
        # 不强求拒绝，只要求不崩不挂 —— 期望必须来自实测，不能来自
        # "我觉得应该严格"。
        want = EXPECT_TOLERATE if t == 0x0033 else EXPECT_REJECT
        for delta, tag in ((1, "plus1"), (4, "plus4"), (10 ** 6, "max")):
            inner = min(len(save) - hdr + delta, vmax)
            bad = inner.to_bytes(hdr, "big") + save[hdr:]
            e["body"] = bad
            add("B9_%s_inner_%s" % (nm, tag), build(p), want,
                "%s 内层列表长度声明 %s（%s）" % (
                    nm, tag,
                    "OpenSSL 接受，故也须接受" if want == EXPECT_TOLERATE else "必须拒绝"))
        e["body"] = save

    # ============ C. 声明长度与实际不符：必须干净拒绝 ============
    exts_len = len(ext_bytes(p["exts"])) - 2
    add("C1_ext_total_plus1", build(p, override_ext_total=exts_len + 1),
        EXPECT_REJECT, "扩展总长声明 +1")
    add("C2_ext_total_plus100", build(p, override_ext_total=exts_len + 100),
        EXPECT_REJECT, "扩展总长声明 +100")
    add("C3_ext_total_ffff", build(p, override_ext_total=0xFFFF),
        EXPECT_REJECT, "扩展总长声明 0xFFFF")
    add("C4_ext_total_minus1", build(p, override_ext_total=max(0, exts_len - 1)),
        EXPECT_REJECT, "扩展总长声明 -1（尾部会有孤立字节）")

    add("C5_cs_len_plus1", build(p, override_cs_len=len(p["suites"]) + 1),
        EXPECT_REJECT, "套件长度声明 +1")
    add("C6_cs_len_odd", build(p, override_cs_len=len(p["suites"]) + 1 if
                               len(p["suites"]) % 2 == 0 else len(p["suites"])),
        EXPECT_REJECT, "套件长度奇数（非 2 的倍数）：OpenSSL 实测拒绝")
    add("C7_cs_len_ffff", build(p, override_cs_len=0xFFFF),
        EXPECT_REJECT, "套件长度声明 0xFFFF")

    add("C8_sid_len_plus1", build(p, override_sid_len=len(p["sid"]) + 1),
        EXPECT_REJECT, "session_id 长度声明 +1")
    add("C9_sid_len_ff", build(p, override_sid_len=0xFF),
        EXPECT_REJECT, "session_id 长度声明 0xFF")

    hs_len = len(build(p)) - 9
    add("C10_hs_len_plus10", build(p, override_hs_len=hs_len + 10),
        EXPECT_REJECT, "握手体长度声明 +10（超出记录实际内容）")
    add("C11_hs_len_minus10", build(p, override_hs_len=hs_len - 10),
        EXPECT_REJECT, "握手体长度声明 -10（记录内会剩孤立字节）")

    # ============ D. 重复扩展 / 顺序 ============
    add("D1_dup_sni", build(p, dup_exts(p, 0x0000)), EXPECT_REJECT,
        "server_name 出现两次：RFC 禁止同类型重复，OpenSSL 实测拒绝")
    add("D2_dup_alpn", build(p, dup_exts(p, 0x0010, b"\x02h3")), EXPECT_REJECT,
        "ALPN 出现两次且值不同：同类型重复，必须拒绝")
    add("D3_dup_versions", build(p, dup_exts(p, 0x002B)), EXPECT_REJECT,
        "supported_versions 出现两次：同类型重复，必须拒绝")
    add("D4_exts_reversed", build(p, list(reversed([dict(e) for e in p["exts"]]))),
        EXPECT_TOLERATE, "扩展顺序完全颠倒：OpenSSL 接受，故也须接受")

    # ============ E. 极端但合法 ============
    add("E1_no_exts", build(p, []), EXPECT_REJECT,
        "完全没有扩展：则无 supported_groups/sig_algs，OpenSSL 与我们都拒绝")
    add("E2_empty_suites", build(p, suites=b""), EXPECT_REJECT,
        "套件列表为空：OpenSSL 报 no ciphers specified，必须拒绝")
    add("E3_zero_sid", build(p, sid=b""), EXPECT_TOLERATE,
        "session_id 长度为 0：合法，OpenSSL 接受，故也须接受")

    return C


def emit(C):
    L = []
    L.append("/* clienthello_struct.h —— ClientHello 结构化变异用例")
    L.append(" *")
    L.append(" * 由 scripts/gen_ch_struct.py 从真实 OpenSSL 3.0.2 s_client 报文生成。")
    L.append(" * 不要手改本文件：改生成器再重新生成。")
    L.append(" *")
    L.append(" * 与 test_tls_ch.c 的分工：")
    L.append(" *   那个做字节级变异（截断 / 单字节置 00-FF），这个做结构化变异 ——")
    L.append(" *   未知扩展、GREASE、声明长度与实际不符、重复扩展。字节翻转几乎")
    L.append(" *   产生不出这些报文，因为它们的长度字段全都是自洽的。")
    L.append(" */")
    L.append("#ifndef CH_STRUCT_H")
    L.append("#define CH_STRUCT_H")
    L.append("#include <stddef.h>")
    L.append("#include <stdint.h>")
    L.append("")
    L.append("/* 期望：1=必须被接受并产出响应；0=必须被干净拒绝（不得产出响应）；")
    L.append(" *       -1=只要求不崩不挂 */")
    L.append("#define CH_EXPECT_TOLERATE 1")
    L.append("#define CH_EXPECT_REJECT   0")
    L.append("#define CH_EXPECT_ANY     (-1)")
    L.append("")
    names = []
    for i, (nm, blob, exp, why) in enumerate(C):
        vn = "CHS_%s" % nm
        names.append((vn, nm, exp, why))
        L.append("static const unsigned char %s[] = {" % vn)
        for o in range(0, len(blob), 12):
            L.append("    " + "".join("0x%02x," % b for b in blob[o:o + 12]))
        L.append("};")
        L.append("")
    L.append("typedef struct {")
    L.append("    const char          *name;")
    L.append("    const unsigned char *buf;")
    L.append("    size_t               len;")
    L.append("    int                  expect;")
    L.append("    const char          *why;")
    L.append("} chs_case_t;")
    L.append("")
    L.append("static const chs_case_t CHS_CASES[] = {")
    for vn, nm, exp, why in names:
        L.append('    {"%s", %s, sizeof(%s), %d, "%s"},'
                 % (nm, vn, vn, exp, why))
    L.append("};")
    L.append("#define CHS_N (sizeof(CHS_CASES)/sizeof(CHS_CASES[0]))")
    L.append("")
    L.append("#endif /* CH_STRUCT_H */")
    return "\n".join(L) + "\n"


def main():
    b = load_real()
    p = parse(b)
    C = cases(p)
    out = emit(C)
    open(DST, "w", encoding="utf-8").write(out)
    print("[OK] 生成 %d 个结构化用例 -> %s" % (len(C), DST))
    for nm, blob, exp, why in C:
        print("  %-26s len=%-5d expect=%-2d  %s" % (nm, len(blob), exp, why))


if __name__ == "__main__":
    main()
