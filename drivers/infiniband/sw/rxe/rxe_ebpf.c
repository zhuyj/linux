#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include "rxe_ebpf.h"

__bpf_kfunc int bpf_strstr(const char *str, u32 str__sz, const char *substr, u32 substr__sz);

__bpf_kfunc_start_defs();

__bpf_kfunc int bpf_strstr(const char *str, u32 str__sz, const char *substr, u32 substr__sz) {

	if (substr__sz == 0) {
		return 0;
	}

	if (substr__sz > str__sz) {
		return -1;
	}

	for (size_t i = 0; i <= str__sz - substr__sz; i++) {
		size_t j = 0;

		while (j < substr__sz && str[i + j] == substr[j]) {
			j++;
		}

		if (j == substr__sz) {
			return i;
		}
	}
	return -1;
}

__bpf_kfunc int bpf_set_cqe(int cqe) {
	pr_info("%s +%d func: %s, cqe: %d\n", __FILE__, __LINE__, __func__, cqe);

	return 0;
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(bpf_kfunc_rxe_ids_set)
BTF_ID_FLAGS(func, bpf_strstr)
BTF_ID_FLAGS(func, bpf_set_cqe)
BTF_KFUNCS_END(bpf_kfunc_rxe_ids_set)

static const struct btf_kfunc_id_set bpf_kfunc_rxe_set = {
	.owner = THIS_MODULE,
	.set = &bpf_kfunc_rxe_ids_set,
};

int rxe_register_ebpf(void) {
	int ret;

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_KPROBE, &bpf_kfunc_rxe_set);
	if (ret) {
		pr_err("fail to register BTF kfunc ID set\n");
		return ret;
	}
	pr_info("eBPF succeed registering\n");
	return 0; /* success 0 */
}
