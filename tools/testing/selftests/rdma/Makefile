# SPDX-License-Identifier: GPL-2.0
TEST_PROGS := rxe_rping_between_netns.sh \
		rxe_ipv6.sh \
		rxe_socket_with_netns.sh \
		rxe_test_NETDEV_UNREGISTER.sh \
		rxe_sent_rcvd_bytes.sh

TEST_GEN_PROGS := rxe_netkit_dump
include ../lib.mk

CLANG	?= clang
LLC	?= llc
BPFTOOL	?= bpftool

INCLUDES	:= -I../../../../usr/include -I../../../../include/uapi -I../bpf
CFLAGS		+= -g -Wall $(INCLUDES)
LDFLAGS		+= -lbpf -lelf -lz

$(OUTPUT)/rxe_netkit_dump: rxe_pkg_user_dump.c $(OUTPUT)/rxe_pkg_kernel.skel.h
	$(CC) $(CFLAGS) $< $(LDFLAGS) -o $@

$(OUTPUT)/rxe_pkg_kernel_dump.o: rxe_pkg_kernel_dump.c
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_x86 $(INCLUDES) -c $< -o $@

$(OUTPUT)/rxe_pkg_kernel.skel.h: $(OUTPUT)/rxe_pkg_kernel_dump.o
	$(BPFTOOL) gen skeleton $< > $@

EXTRA_CLEAN := $(OUTPUT)/rxe_pkg_kernel_dump.o $(OUTPUT)/rxe_pkg_kernel.skel.h
