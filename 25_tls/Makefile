# 25_tls — 自研 TLS 1.2 客户端
# 测试二进制统一落在 build/，与仓库其它模块一致（全仓回归脚本按此约定查找）。
CC      = gcc
CFLAGS  = -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow \
          -Iinclude -I../00_crypto/include \
          -DTLS_TESTDATA="\"$(CURDIR)/tests/data\""
LDFLAGS =

BUILD   = build
CRYPTO  = ../00_crypto/src/crypto_gcm.c \
          ../00_crypto/src/crypto_hash.c \
          ../00_crypto/src/crypto_x25519.c

SRCS    = src/bn.c src/asn1.c src/rsa.c src/x509.c src/tls.c src/tls_server.c
OBJS    = $(SRCS:.c=.o) $(CRYPTO:.c=.o)

TESTS   = $(BUILD)/test_bn $(BUILD)/test_asn1 $(BUILD)/test_x509 $(BUILD)/test_tls \
          $(BUILD)/test_tls_srv $(BUILD)/test_tls_ch $(BUILD)/test_tls_hs \
          $(BUILD)/test_tls_seq $(BUILD)/test_tls_ch_struct \
          $(BUILD)/test_tls_cke_struct

# 跨实现互操作工具：把服务端/客户端挂到真实 TCP 端口，与 OpenSSL 的
# s_client / s_server 对连。它们不是单元测试，由 scripts/interop_openssl.sh 驱动。
TOOLS   = $(BUILD)/tls_srv_tcp $(BUILD)/tls_cli_tcp

.PHONY: all clean test inspect testdata verify-fixtures

# ---------------------------------------------------------------------------
# 测试夹具：tests/data/ 被 .gitignore 忽略（夹具不入库），所以"缺夹具"是
# 环境重建后的常态，不是异常。此前 testdata 是独立 phony 目标、需人工记得跑，
# 而测试二进制的构建规则并不依赖它 —— 于是缺夹具时 make 照样成功，
# 失败发生在运行期，且症状是"证书校验失败"，排查被引向产品代码。
#
# 改为：夹具成为构建依赖，缺失即自动生成。
# 用 grouped target(&:) 让一次执行产出全部文件；若写成多条独立规则，
# make 会为每个缺失文件各跑一次生成器。
# ---------------------------------------------------------------------------
FIXTURES := tests/data/ca.pem tests/data/ca.key \
            tests/data/leaf.pem tests/data/leaf.key tests/data/leaf.csr \
            tests/data/leaf_ext.cnf tests/data/selfsigned.pem \
            tests/data/rsa.pem tests/data/rsa_n.bin tests/data/rsa_n.hex \
            tests/data/rsa_e.bin tests/data/rsa_msg.bin tests/data/rsa_sig.bin \
            tests/data/real_chain.pem

$(FIXTURES) &: scripts/gen_testdata.sh
	sh scripts/gen_testdata.sh

all: $(TESTS) $(TOOLS)

$(BUILD):
	mkdir -p $(BUILD)

# 所有测试/工具都确保夹具存在。只影响"缺夹具时先生成"，夹具齐全时零开销。
$(TESTS) $(TOOLS): $(FIXTURES)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/test_bn: tests/test_bn.c $(OBJS) | $(BUILD)
	$(CC) $(CFLAGS) $< $(OBJS) -o $@ $(LDFLAGS)

$(BUILD)/test_asn1: tests/test_asn1.c $(OBJS) | $(BUILD)
	$(CC) $(CFLAGS) $< $(OBJS) -o $@ $(LDFLAGS)

$(BUILD)/test_x509: tests/test_x509.c $(OBJS) | $(BUILD)
	$(CC) $(CFLAGS) $< $(OBJS) -o $@ $(LDFLAGS)

$(BUILD)/test_tls: tests/test_tls.c $(OBJS) | $(BUILD)
	$(CC) $(CFLAGS) $< $(OBJS) -o $@ $(LDFLAGS)

$(BUILD)/test_tls_srv: tests/test_tls_srv.c $(OBJS) | $(BUILD)
	$(CC) $(CFLAGS) $< $(OBJS) -o $@ $(LDFLAGS)

# 真实 ClientHello 解析器健壮性：必须进默认目标，否则又是一个"写了没接"的测试
$(BUILD)/test_tls_ch: tests/test_tls_ch.c tests/clienthello_default.h $(OBJS) | $(BUILD)
	$(CC) $(CFLAGS) $< $(OBJS) -o $@ $(LDFLAGS)

# ClientHello 结构化变异（未知扩展 / GREASE / 声明长度不符 / 重复扩展）。
# 用例头文件由 scripts/gen_ch_struct.py 生成，声明为依赖以便重新生成后重编。
# 必须进默认目标，否则又是一个"写了没接"的测试。
$(BUILD)/test_tls_ch_struct: tests/test_tls_ch_struct.c tests/clienthello_struct.h \
                             tests/clienthello_default.h $(OBJS) | $(BUILD)
	$(CC) $(CFLAGS) $< $(OBJS) -o $@ $(LDFLAGS)

# 完整握手序列上的变异健壮性（MITM 代理）。必须进默认目标，
# 否则又是一个"写了没接"的测试。
$(BUILD)/test_tls_hs: tests/test_tls_hs.c $(OBJS) | $(BUILD)
	$(CC) $(CFLAGS) $< $(OBJS) -o $@ $(LDFLAGS)

# 协议时序攻击（丢弃/重放/重排/注入）+ 语义断言：该拒绝的必须拒绝。
# 必须进默认目标。
# 原先这里重复定义了 -DTLS_TESTDATA 且用的是 $(PWD)：
#   $(PWD) 是 make **启动时**的工作目录，$(CURDIR) 是 make -C 切换**之后**的目录。
#   全仓回归脚本按 make -C <mod> 调用，两者不等 —— 于是该测试去找
#   <仓库根>/tests/data 而非 <模块>/tests/data，报 "[FATAL] 缺 leaf.key"。
#   症状是"夹具缺失"，而夹具其实齐备，排查会被带偏。
#   改为不再重复定义，统一沿用 CFLAGS 里的 $(CURDIR) 版本（单一产地）。
$(BUILD)/test_tls_cke_struct: tests/test_tls_cke_struct.c tests/cke_struct.h \
                              tests/hs_msgs_real.h $(OBJS) | $(BUILD)
	$(CC) $(CFLAGS) -Iinclude -Isrc -Itests $< $(OBJS) -o $@

$(BUILD)/test_tls_seq: tests/test_tls_seq.c $(OBJS) | $(BUILD)
	$(CC) $(CFLAGS) $< $(OBJS) -o $@ $(LDFLAGS)

$(BUILD)/tls_srv_tcp: tools/tls_srv_tcp.c $(OBJS) | $(BUILD)
	$(CC) $(CFLAGS) $< $(OBJS) -o $@ $(LDFLAGS)

$(BUILD)/tls_cli_tcp: tools/tls_cli_tcp.c $(OBJS) | $(BUILD)
	$(CC) $(CFLAGS) $< $(OBJS) -o $@ $(LDFLAGS)

# 素材由 OpenSSL 生成，用于跨实现交叉验证。现在已是构建依赖，
# 保留此目标以便显式重建（例如怀疑夹具过期时 make testdata）。
testdata: $(FIXTURES)

# 夹具语义校验：存在不等于正确。
# 上一轮真实教训 —— 手工重签的 leaf.pem 文件齐备、openssl verify 也通过，
# 但 SAN 只有 IP 型而无 DNS 名，消费方 SNI=front.test 匹配不上，
# 症状是 "hostname mismatch"，排查方向被引向 TLS 实现。
# 只判"文件在"抓不到这类缺陷，故必须判语义。
verify-fixtures: $(FIXTURES)
	@sh scripts/verify_fixtures.sh

# interop 必须与单元测试走同一条入口：它是唯一能证明"符合协议"的检查，
# 只放在文档里的话迟早没人跑。缺 openssl 时跳过而不是失败——
# 不能让环境差异把"没验证"伪装成"验证通过"，所以跳过要显式打印出来。
test: $(TESTS) $(TOOLS) verify-fixtures
	@fail=0; \
	for t in $(TESTS); do \
		echo "=== $$t ==="; \
		timeout 300 $$t || fail=1; \
	done; \
	if command -v openssl >/dev/null 2>&1; then \
		echo "=== interop A (自研服务端 <- OpenSSL) ==="; \
		sh scripts/interop_openssl.sh A || fail=1; \
		echo "=== interop B (自研客户端 -> OpenSSL) ==="; \
		sh scripts/interop_openssl.sh B || fail=1; \
	else \
		echo "=== interop SKIPPED: 未找到 openssl（未验证，不是通过）==="; \
	fi; \
	exit $$fail

inspect: $(TESTS)
	@echo "--- dynamic deps ---"; ldd $(BUILD)/test_tls | grep -Ei "ssl|crypto" || echo "none"
	@echo "--- third-party symbols ---"; nm -u $(BUILD)/test_tls | grep -Ei "EVP_|SSL_|dlopen|dlsym" || echo "none"
	@echo "--- sensitive strings ---"; strings $(BUILD)/test_tls | grep -Ei "openssl|/home/|/Users/|/etc/passwd" || echo "none"

interop: $(TOOLS)
	sh scripts/interop_openssl.sh

clean:
	rm -rf $(BUILD) $(OBJS)
