#!/usr/bin/env python3
"""把 camd 二进制 base64 内嵌进 onekey.sh，产出目标机可直接跑的一键安装脚本。

设计要点（每一条都对应真实事故）：

1. 内嵌而非外链。"一键部署"若依赖目标机能访问某个下载源，在隔离网/断网
   目标上就不成立。内嵌让脚本自身即完整投递物。

2. 多架构分节。一份包可同时内嵌 amd64/arm64/386/arm 四份产物，目标机按
   `uname -m` 选节。单架构包在错架构机器上会造成最坏的一类事故：
   实测把 e_machine=183 的产物装到 x86_64 上，ELF 魔数校验照样通过、
   安装全绿、退出码 0，而 camd 执行报 "Exec format error"——
   systemd 下配合 Restart=always 是无限重启循环，部署者看到的是"成功"。

3. 判据是 e_machine，不是 file(1) 的字符串。
   file 的输出随版本变化（"x86-64" / "x86_64" / "ARM aarch64"），
   字符串匹配在版本变化时会静默失效；e_machine 是 ELF 头里的事实。
   两侧都查：构建期拦"打包了错东西"，目标机侧拦"产物被换过 / 架构不符"。

用法：
    # 单架构（旧格式，仍受支持）
    python3 make_onekey.py <camd二进制路径> <架构名> [-o 输出路径]

    # 多架构（推荐：一份包覆盖所有目标机）
    python3 make_onekey.py amd64=<路径> arm64=<路径> [-o 输出路径]
"""
import base64
import os
import struct
import sys

BEGIN = "# PAYLOAD_BEGIN\n"
END = "# PAYLOAD_END\n"

# ELF e_machine 值。与 onekey.sh 的 arch_machine() 必须一一对应，
# 两边不一致会让构建期通过而目标机侧拒绝（或反之）。
EM = {"amd64": 62, "arm64": 183, "386": 3, "arm": 40}


def die(msg):
    print("[FATAL] %s" % msg)
    sys.exit(1)


def elf_machine(path):
    """读 ELF 头的 e_machine。读不到返回 -1。"""
    try:
        with open(path, "rb") as f:
            head = f.read(20)
        if len(head) < 20 or head[:4] != b"\x7fELF":
            return -1
        endian = "<" if head[5] == 1 else ">"
        return struct.unpack_from(endian + "H", head, 18)[0]
    except Exception:
        return -1


def check_payload(path, arch):
    """构建期校验：必须是 ELF，且 e_machine 与声称的架构一致。"""
    if not os.path.isfile(path):
        die("产物不存在: %s" % path)
    mach = elf_machine(path)
    if mach < 0:
        die("不是 ELF: %s —— 拒绝内嵌 stub（会导致部署全绿而采集零产出）" % path)
    if arch not in EM:
        die("未知架构名: %s（可选: %s）" % (arch, "/".join(sorted(EM))))
    want = EM[arch]
    if mach != want:
        die("架构不符：声称 %s(e_machine=%d)，产物 e_machine=%d —— %s"
            % (arch, want, mach, path))
    return mach


def main():
    args = sys.argv[1:]
    if not args:
        die("用法: make_onekey.py <路径> <架构> | amd64=<路径> arm64=<路径> [-o 输出]")

    pairs = []
    out = None
    if "-o" in args:
        i = args.index("-o")
        out = args[i + 1]
        del args[i:i + 2]

    # 多架构形态：arch=path
    kv = [a for a in args if "=" in a]
    if kv:
        for a in kv:
            k, _, v = a.partition("=")
            if k not in EM:
                die("未知架构名: %s（可选: %s）" % (k, "/".join(sorted(EM))))
            pairs.append((k, v))
    else:
        if len(args) < 2:
            die("用法: make_onekey.py <路径> <架构> [-o 输出]")
        pairs.append((args[1], args[0]))

    if not pairs:
        die("没有指定任何产物")

    tpl = os.path.join(os.path.dirname(os.path.abspath(__file__)), "onekey.sh")
    if not os.path.isfile(tpl):
        die("找不到模板 onekey.sh")
    with open(tpl, "r", encoding="utf-8") as f:
        text = f.read()
    if BEGIN not in text or END not in text:
        die("模板缺少 PAYLOAD_BEGIN/END 标记")

    segs = []
    for arch, path in pairs:
        mach = check_payload(path, arch)
        with open(path, "rb") as f:
            blob = f.read()
        b64 = base64.b64encode(blob).decode("ascii")
        # 每行 76 字符：超长行在部分 base64 实现（busybox）下会解码失败。
        lines = [b64[i:i + 76] for i in range(0, len(b64), 76)]
        segs.append("# PAYLOAD_BEGIN %s\n%s\n# PAYLOAD_END %s\n"
                    % (arch, "\n".join(lines), arch))
        print("[OK] 内嵌 %-6s %s (%d 字节, e_machine=%d)" % (arch, path, len(blob), mach))

    # 连裸标记一起替换掉。只替换"标记之间"会留下 BEGIN/END 嵌套，
    # 虽然 awk 仍能选对节，但人工读包时会误以为还有一个未标注的节。
    i = text.index(BEGIN)
    j = text.index(END) + len(END)
    text = text[:i] + "".join(segs) + text[j:]

    if out is None:
        if len(pairs) == 1:
            out = os.path.join(os.path.dirname(tpl), "onekey-%s.sh" % pairs[0][0])
        else:
            out = os.path.join(os.path.dirname(tpl), "onekey-multi.sh")
    with open(out, "w", encoding="utf-8") as f:
        f.write(text)
    os.chmod(out, 0o755)

    print("[OK] 产物: %s" % out)
    print("[OK] 架构: %s" % " ".join(a for a, _ in pairs))


if __name__ == "__main__":
    main()
