# 06_lateral Kerberos 攻击能力真机验证状态

验证环境: Ubuntu 22.04 + Samba 4.15.13 AD DC (TEST.LOCAL)
验证日期: 2026-10-13

## 可用路径

| 攻击 | 命令 | 状态 |
|---|---|---|
| 真 TGT 打 SMB | kinit + smbclient -k | ✅ |
| NTLM Pass-the-Hash | impacket smbclient.py -hashes | ✅ |
| Kerberoasting | MIT kvno + 手工提 hash | ✅ |

## 不可用路径

| 攻击 | 工具 | 根因 |
|---|---|---|
| Golden Ticket | impacket ticketer | PAC/kvno 与 Samba 4.15 不兼容 |
| Silver Ticket | impacket ticketer | PAC LOGON_INFO 解析失败 |
| Diamond Ticket | impacket -request | KRB_AP_ERR_INAPP_CKSUM |
| kerberosLogin | impacket | TGS-REQ 构造不兼容 |
| GetUserSPNs | impacket | 同上 |

## 结论

impacket 的 Kerberos 栈与 Samba 4.15 不兼容——所有走 TGS-REQ 或伪造 PAC
的路径全挂。**只能用 MIT krb5（kinit/kvno/smbclient）走 Kerberos，或走
NTLM 路径（PtH / 密码）。**

kerberos_native.py 里的 GoldenTicket/SilverTicket 类在此环境不可用——
如需真机伪造，换 mimikatz/rubeus（Windows 环境）。
