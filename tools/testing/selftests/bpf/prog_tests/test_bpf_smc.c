// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "bpf_smc.skel.h"

static void load(void)
{
	struct bpf_smc *skel;

	fprintf(stdout, "test, file: %s +%d func: %s, caller: %ps\n", __FILE__, __LINE__, __func__, __builtin_return_address(0));
	skel = bpf_smc__open_and_load();
	if (!ASSERT_OK_PTR(skel, "bpf_smc__open_and_load"))
		return;

	bpf_smc__destroy(skel);
}

void test_bpf_smc(void)
{
	test__force_log();
	fprintf(stdout, "test, file: %s +%d func: %s, caller: %ps\n", __FILE__, __LINE__, __func__, __builtin_return_address(0));
	if (test__start_subtest("load"))
		load();
}
