#!/usr/bin/env python3
"""把 camd 二进制 base64 内嵌进 onekey.sh，产出目标机可直接跑的一键安装脚本。

设计要点（每一条都对应真实事故）：

1. 内嵌而非外链。"一键部署"若依赖目标机能访问某个下载源，在隔离网/断网
   目标上就不成立。内嵌让脚本自身即完整投递物。

2. 只认 ELF。内嵌 stub 脚本会造成"部署全绿、采集零产出"——服务在跑、
   健康检查通过、没有一帧真画面。这道校验放在生成器侧（构建期）和目标机
   侧（运行期）各一次：构建期拦住"打包了错东西"，运行期拦住"产物被换过"。

3. 单架构单产物。一份脚本只嵌一个架构的二进制。混嵌会让目标机拿到不能
   执行的产物，而报错表现为"无法执行"——排查者会以为是权限问题。

用法：
    python3 make_onekey.py <camd二进制路径> <架构名> [-o 输出路径]
"""
import base64
import os
import subprocess
import sys

BEGIN = "# PAYLOAD_BEGIN\n"
END = "# PAYLOAD_END\n"


def die(msg):
    print("[FATAL] %s" % msg)
    sys.exit(1)


def is_elf(path):
    if not os.path.isfile(path):
        return False
    with open(path, "rb") as f:
        return f.read(4) == b"\x7fELF"


def arch_of(path):
    """用 file(1) 读产物架构，与声称的架构名交叉核对。

    交叉核对不可省：把 x86 产物当 arm64 发出去，目标机上表现为"权限被拒"
    或"无法执行"，排查方向会被引到文件权限上，而不是架构错了。
    """
    try:
        out = subprocess.run(["file", "-b", path], capture_output=True,
                             text=True, timeout=20)
        return out.stdout.strip()
    except Exception:
        return ""


def main():
    if len(sys.argv) < 3:
        die("用法: make_onekey.py <camd路径> <架构名> [-o 输出]")
    src = sys.argv[1]
    arch = sys.argv[2]
    out = None
    if "-o" in sys.argv:
        out = sys.argv[sys.argv.index("-o") + 1]

    if not is_elf(src):
        die("不是 ELF：%s —— 拒绝内嵌 stub（会导致部署全绿而采集零产出）" % src)

    desc = arch_of(src)
    # 声称的架构名必须能在产物描述里找到对应片段，否则拒绝。
    keys = {"amd64": ["x86-64", "x86_64"], "arm64": ["aarch64", "ARM aarch64"],
            "386": ["80386", "i386"], "arm": ["ARM,"]}
    want = keys.get(arch)
    if want and desc and not any(k in desc for k in want):
        die("架构不符：声称 %s，产物实为 %r" % (arch, desc))

    tpl = os.path.join(os.path.dirname(os.path.abspath(__file__)), "onekey.sh")
    if not os.path.isfile(tpl):
        die("找不到模板 onekey.sh")

    with open(tpl, "r", encoding="utf-8") as f:
        text = f.read()
    if BEGIN not in text or END not in text:
        die("模板缺少 PAYLOAD_BEGIN/END 标记")

    with open(src, "rb") as f:
        blob = f.read()
    b64 = base64.b64encode(blob).decode("ascii")
    # 每行 76 字符：超长行在部分 base64 实现（busybox）下会解码失败。
    lines = [b64[i:i + 76] for i in range(0, len(b64), 76)]

    i = text.index(BEGIN) + len(BEGIN)
    j = text.index(END)
    text = text[:i] + "\n".join(lines) + "\n" + text[j:]

    if out is None:
        out = os.path.join(os.path.dirname(tpl), "onekey-%s.sh" % arch)
    with open(out, "w", encoding="utf-8") as f:
        f.write(text)
    os.chmod(out, 0o755)

    print("[OK] 产物: %s" % out)
    print("[OK] 内嵌: %s (%d 字节, %s)" % (src, len(blob), desc or "架构未知"))
    print("[OK] 架构: %s" % arch)


if __name__ == "__main__":
    main()
