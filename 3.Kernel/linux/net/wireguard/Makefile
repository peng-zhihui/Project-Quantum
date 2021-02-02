ccflags-y := -O3 -fvisibility=hidden
ccflags-$(CONFIG_WIREGUARD_DEBUG) += -DDEBUG -g
ccflags-y += -Wframe-larger-than=8192
ccflags-y += -D'pr_fmt(fmt)=KBUILD_MODNAME ": " fmt'
wireguard-y := main.o noise.o device.o peer.o timers.o queueing.o send.o receive.o socket.o hashtables.o allowedips.o ratelimiter.o cookie.o netlink.o
wireguard-y += crypto/curve25519.o crypto/chacha20poly1305.o crypto/blake2s.o

ifeq ($(CONFIG_X86_64),y)
	wireguard-y += crypto/chacha20-ssse3-x86_64.o crypto/poly1305-sse2-x86_64.o
	avx_supported := $(call as-instr,vpxor %xmm0$(comma)%xmm0$(comma)%xmm0,yes,no)
	ifeq ($(avx_supported),yes)
		wireguard-y += crypto/blake2s-avx-x86_64.o crypto/curve25519-avx-x86_64.o
	endif
	avx2_supported := $(call as-instr,vpgatherdd %ymm0$(comma)(%eax$(comma)%ymm1$(comma)4)$(comma)%ymm2,yes,no)
	ifeq ($(avx2_supported),yes)
		wireguard-y += crypto/chacha20-avx2-x86_64.o crypto/poly1305-avx2-x86_64.o
	endif
endif

ifeq ($(CONFIG_ARM64),y)
	wireguard-$(CONFIG_KERNEL_MODE_NEON) += crypto/chacha20-neon-arm64.o
endif
ifeq ($(CONFIG_ARM),y)
	wireguard-$(CONFIG_KERNEL_MODE_NEON) += crypto/chacha20-neon-arm.o
	ifneq ($(CONFIG_CPU_THUMBONLY),y)
		wireguard-$(CONFIG_KERNEL_MODE_NEON) += crypto/curve25519-neon-arm.o
	endif
endif

ifneq ($(KBUILD_EXTMOD),)
CONFIG_WIREGUARD := m
endif

include $(src)/compat/Makefile.include

obj-$(CONFIG_WIREGUARD) := wireguard.o
