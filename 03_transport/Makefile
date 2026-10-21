CC ?= cc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow -Iinclude -I../14_p2p/include
BUILD := build

all: $(BUILD)/libtransport.a $(BUILD)/test_transport $(BUILD)/test_net $(BUILD)/test_dnstun $(BUILD)/test_dnspub $(BUILD)/test_swin $(BUILD)/test_icmtun $(BUILD)/test_icmppub $(BUILD)/test_dnsdown $(BUILD)/test_cover_cost

$(BUILD)/libtransport.a: $(BUILD)/transport.o $(BUILD)/net.o $(BUILD)/dnstun.o $(BUILD)/swin.o $(BUILD)/icmtun.o
	ar rcs $@ $^

$(BUILD)/transport.o: src/transport.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/net.o: src/net.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/dnstun.o: src/dnstun.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/test_transport: tests/test_transport.c $(BUILD)/libtransport.a | $(BUILD)
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libtransport.a

$(BUILD)/test_net: tests/test_net.c $(BUILD)/libtransport.a | $(BUILD)
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libtransport.a

$(BUILD)/test_dnstun: tests/test_dnstun.c $(BUILD)/libtransport.a | $(BUILD)
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libtransport.a

$(BUILD)/test_dnspub: tests/test_dnspub.c $(BUILD)/libtransport.a | $(BUILD)
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libtransport.a

$(BUILD)/swin.o: src/swin.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/icmtun.o: src/icmtun.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/test_swin: tests/test_swin.c $(BUILD)/libtransport.a | $(BUILD)
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libtransport.a

$(BUILD)/test_icmtun: tests/test_icmtun.c $(BUILD)/libtransport.a | $(BUILD)
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libtransport.a

# 公网 ICMP 真实收发（依赖外网 + raw socket，不可达时 SKIP 而非 FAIL）
$(BUILD)/test_icmppub: tests/test_icmppub.c $(BUILD)/libtransport.a | $(BUILD)
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libtransport.a

# 公网 DNS 下行解码验证（需外网；不可达时 SKIP）
$(BUILD)/test_dnsdown: tests/test_dnsdown.c $(BUILD)/libtransport.a | $(BUILD)
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libtransport.a

# 实测各类信道下每个信元的线上字节成本，回填 14_p2p 自适应覆盖流量模型
$(BUILD)/test_cover_cost: tests/test_cover_cost.c $(BUILD)/libtransport.a ../14_p2p/build/cover.o | $(BUILD)
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libtransport.a ../14_p2p/build/cover.o

testpub: $(BUILD)/test_icmppub $(BUILD)/test_dnsdown
	./$(BUILD)/test_icmppub
	./$(BUILD)/test_dnsdown

$(BUILD):
	mkdir -p $(BUILD)

test: $(BUILD)/test_transport $(BUILD)/test_net $(BUILD)/test_dnstun $(BUILD)/test_swin $(BUILD)/test_icmtun
	./$(BUILD)/test_transport
	./$(BUILD)/test_net
	./$(BUILD)/test_dnstun
	./$(BUILD)/test_swin
	./$(BUILD)/test_icmtun

clean:
	rm -rf $(BUILD)

.PHONY: all test clean testpub
