# SPDX-License-Identifier: GPL-2.0
TEST_PROGS := rxe_rping_between_netns.sh \
		rxe_ipv6.sh \
		rxe_socket_with_netns.sh \
		rxe_test_NETDEV_UNREGISTER.sh \
		rxe_ebpf

RXE_TESTS := rxe_ebpf

all: $(RXE_TESTS)

$(RXE_TESTS): %: %.c
	$(CC) $(CFLAGS) $< -o $@

include ../lib.mk
