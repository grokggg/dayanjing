#!/usr/bin/env python3
"""
统一构建系统

功能：
1. 交叉编译 Windows payload (mingw-w64)
2. 编译 Linux payload (gcc/clang)
3. 打包所有模块为分发包
4. 生成构建报告
"""

import os
import sys
import subprocess
import json
import shutil
import platform
import argparse
from pathlib import Path
from datetime import datetime


class BuildSystem:
    def __init__(self, root_dir, output_dir="dist", build_type="release"):
        self.root = Path(root_dir).resolve()
        self.output = Path(output_dir).resolve()
        self.build_type = build_type
        self.report = {
            "timestamp": datetime.utcnow().isoformat(),
            "build_type": build_type,
            "platform": platform.system(),
            "modules": [],
            "artifacts": [],
            "errors": []
        }

    def _has_mingw(self):
        """检查 mingw-w64 是否可用"""
        try:
            result = subprocess.run(["x86_64-w64-mingw32-gcc", "--version"],
                                  capture_output=True, text=True)
            return result.returncode == 0
        except FileNotFoundError:
            return False

    def _has_gcc(self):
        """检查 gcc 是否可用"""
        try:
            result = subprocess.run(["gcc", "--version"],
                                  capture_output=True, text=True)
            return result.returncode == 0
        except FileNotFoundError:
            return False

    def _has_clang(self):
        """检查 clang 是否可用"""
        try:
            result = subprocess.run(["clang", "--version"],
                                  capture_output=True, text=True)
            return result.returncode == 0
        except FileNotFoundError:
            return False

    def compile_windows(self, source_files, output_name, extra_flags=""):
        """
        使用 mingw-w64 交叉编译 Windows PE
        """
        if not self._has_mingw():
            self.report["errors"].append("mingw-w64 not found")
            return None

        self.output.mkdir(parents=True, exist_ok=True)
        output_path = self.output / output_name

        flags = [
            "-O2" if self.build_type == "release" else "-O0",
            "-Wall",
            "-s",  # Strip symbols
            "-static",
            "-Wl,--subsystem,windows",  # GUI subsystem (no console)
        ]

        if extra_flags:
            flags.extend(extra_flags.split())

        cmd = ["x86_64-w64-mingw32-gcc"] + flags + list(source_files) + ["-o", str(output_path)]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if result.returncode == 0:
                self.report["artifacts"].append({
                    "name": output_name,
                    "platform": "windows",
                    "path": str(output_path),
                    "size": output_path.stat().st_size
                })
                return output_path
            else:
                self.report["errors"].append({
                    "module": output_name,
                    "stdout": result.stdout,
                    "stderr": result.stderr
                })
                return None
        except subprocess.TimeoutExpired:
            self.report["errors"].append({"module": output_name, "error": "timeout"})
            return None

    def compile_linux(self, source_files, output_name, extra_flags=""):
        """
        编译 Linux ELF
        """
        compiler = "gcc"
        if not self._has_gcc() and self._has_clang():
            compiler = "clang"
        elif not self._has_gcc():
            self.report["errors"].append("No C compiler found")
            return None

        self.output.mkdir(parents=True, exist_ok=True)
        output_path = self.output / output_name

        flags = [
            "-O2" if self.build_type == "release" else "-O0",
            "-Wall",
            "-s",  # Strip symbols
        ]

        if extra_flags:
            flags.extend(extra_flags.split())

        cmd = [compiler] + flags + list(source_files) + ["-o", str(output_path)]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if result.returncode == 0:
                self.report["artifacts"].append({
                    "name": output_name,
                    "platform": "linux",
                    "path": str(output_path),
                    "size": output_path.stat().st_size
                })
                return output_path
            else:
                self.report["errors"].append({
                    "module": output_name,
                    "stdout": result.stdout,
                    "stderr": result.stderr
                })
                return None
        except subprocess.TimeoutExpired:
            self.report["errors"].append({"module": output_name, "error": "timeout"})
            return None

    def compile_python_modules(self, modules_dir):
        """
        编译 Python 模块为字节码
        """
        pyc_dir = self.output / "pyc"
        pyc_dir.mkdir(parents=True, exist_ok=True)

        module_files = list(Path(modules_dir).rglob("*.py"))
        compiled = []

        for py_file in module_files:
            try:
                # 使用 py_compile 编译
                pyc_path = pyc_dir / py_file.relative_to(modules_dir).with_suffix(".pyc")
                pyc_path.parent.mkdir(parents=True, exist_ok=True)
                subprocess.run([
                    sys.executable, "-m", "py_compile",
                    str(py_file), "-o", str(pyc_path)
                ], capture_output=True, check=True)
                compiled.append(str(pyc_path))
            except subprocess.CalledProcessError as e:
                self.report["errors"].append({
                    "module": str(py_file),
                    "error": str(e)
                })

        self.report["modules"].extend(compiled)
        return compiled

    def build_all(self):
        """
        构建所有模块
        """
        print(f"[*] Build type: {self.build_type}")
        print(f"[*] Output directory: {self.output}")

        # 1. 编译 C/C++ 模块
        print("\n[*] Compiling C/C++ modules...")

        # Windows 模块
        win_modules = {
            "camera_capture.exe": str(self.root / "05_persistence" / "windows_camera.c"),
            "persistence.exe": str(self.root / "05_persistence" / "windows_persist.c"),
            "stealth.exe": str(self.root / "11_stealth" / "api_hash.c"),
        }

        for name, source in win_modules.items():
            if Path(source).exists():
                print(f"  [+] Compiling {name}...")
                self.compile_windows([source], name)

        # Linux 模块
        linux_modules = {
            "camera_capture": str(self.root / "05_persistence" / "linux_camera.c"),
            "persistence": str(self.root / "05_persistence" / "linux_persist.c"),
            "rootkit.ko": str(self.root / "05_persistence" / "rootkit.c"),
        }

        for name, source in linux_modules.items():
            if Path(source).exists():
                print(f"  [+] Compiling {name}...")
                extra = "-D__KERNEL__ -DMODULE" if name.endswith(".ko") else ""
                self.compile_linux([source], name, extra_flags=extra)

        # 2. 编译 Python 模块
        print("\n[*] Compiling Python modules...")
        py_modules = self.compile_python_modules(self.root)
        print(f"  [+] Compiled {len(py_modules)} Python modules")

        # 3. 生成构建报告
        report_path = self.output / "build_report.json"
        with open(report_path, 'w') as f:
            json.dump(self.report, f, indent=2, default=str)

        print(f"\n[*] Build complete. Report: {report_path}")
        print(f"  Artifacts: {len(self.report['artifacts'])}")
        print(f"  Errors:    {len(self.report['errors'])}")

        return self.report

    def package(self, archive_name="payload_bundle"):
        """
        打包所有产物为 zip
        """
        import zipfile

        zip_path = self.output / f"{archive_name}.zip"
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            for artifact in self.report["artifacts"]:
                zf.write(artifact["path"], arcname=Path(artifact["path"]).name)

        print(f"[*] Package created: {zip_path}")
        return zip_path


def main():
    parser = argparse.ArgumentParser(description="Unified Build System")
    parser.add_argument("--root", default=str(Path(__file__).parent.parent),
                       help="Project root directory")
    parser.add_argument("--output", default="dist", help="Output directory")
    parser.add_argument("--type", choices=["debug", "release"], default="release",
                       help="Build type")
    parser.add_argument("--package", action="store_true", help="Create zip package")

    args = parser.parse_args()

    builder = BuildSystem(args.root, args.output, args.type)
    report = builder.build_all()

    if args.package:
        builder.package()

    if report["errors"]:
        print("\n[!] Build errors:")
        for err in report["errors"][:5]:
            print(f"  - {err}")
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
