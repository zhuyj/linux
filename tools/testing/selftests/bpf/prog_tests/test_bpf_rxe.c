#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
/* To invoke test__force_log, need to include this header */
#include <test_progs.h>

/* Include the generated skeleton header */
#include "bpf_rxe.skel.h"

void test_bpf_rxe(void) {
	struct bpf_rxe *skel;
	int err;

	test__force_log();

	system("modprobe -v rdma_rxe");

	/* Clear the logs in trace */
	system("echo > /sys/kernel/debug/tracing/trace");

	/* Open the BPF application */
	skel = bpf_rxe__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return;
	}

	/* Load & verify the BPF program */
	err = bpf_rxe__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton: %d\n", err);
		goto cleanup;
	}

	/* Attach the BPF program (e.g., attach kprobe) */
	err = bpf_rxe__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
		goto cleanup;
	}

	printf("BPF program loaded and attached successfully.\n");

	system("ip tuntap add mode tun tun0");
	system("ip addr add 1.1.1.1/24 dev tun0");
	system("ip link set tun0 up");
	system("rdma link add rxe0 type rxe netdev tun0");
	system("rping -s -a 1.1.1.1&");
	system("rping -c -a 1.1.1.1 -d -v -C 3");
	system("rdma link del rxe0");
	system("ip addr del 1.1.1.1/24 dev tun0");
	system("ip tuntap del mode tun tun0");
	system("modprobe -v -r tun");

	/* output the bpf_rxe logs */
	system("cat /sys/kernel/debug/tracing/trace");
cleanup:
	/* Clean up and destroy the BPF program */
	bpf_rxe__destroy(skel);
}
