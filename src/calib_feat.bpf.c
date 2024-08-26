// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Facebook */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "retsnoop.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_ATTEMPTS 50

struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __type(key, __u32);
        __type(value, struct user_args);
        __uint(max_entries, 1);
} calib_args_map SEC(".maps");

SEC("ksyscall/nanosleep")
int calib_entry(struct pt_regs *ctx)
{
	pid_t tid;
	struct user_args *argsp;
	__u32 zero = 0;

	argsp = bpf_map_lookup_elem(&calib_args_map, &zero);
	if (!argsp)
		return 0;

	tid = (__u32)bpf_get_current_pid_tgid();
	if (tid != argsp->my_tid)
		return 0;

	/* Used for kretprobe function entry IP discovery, before
	 * bpf_get_func_ip() helper was added.
	 */

#ifdef bpf_target_x86
	/* for x86 the IP is off by one at hardware level,
	 * see https://github.com/anakryiko/retsnoop/issues/32
	 */
	argsp->entry_ip = PT_REGS_IP(ctx) - 1;
#else
	argsp->entry_ip = PT_REGS_IP(ctx);
#endif

	/* Detect if bpf_get_func_ip() helper is supported by the kernel.
	 * Added in: 9b99edcae5c8 ("bpf: Add bpf_get_func_ip helper for tracing programs")
	 * Added in: 9ffd9f3ff719 ("bpf: Add bpf_get_func_ip helper for kprobe programs")
	 */

	/* Detect if fentry/fexit re-entry protection is implemented.
	 * Added in: ca06f55b9002 ("bpf: Add per-program recursion prevention mechanism")
	 */

	/* Detect if fexit is safe to use for long-running and sleepable
	 * kernel functions.
	 * Added in: e21aa341785c ("bpf: Fix fexit trampoline")
	 */

	/* Detect if bpf_get_branch_snapshot() helper is supported.
	 * Added in: 856c02dbce4f ("bpf: Introduce helper bpf_get_branch_snapshot")
	 */

	/* Detect if BPF_MAP_TYPE_RINGBUF map is supported.
	 * Added in: 457f44363a88 ("bpf: Implement BPF ring buffer and verifier support for it")
	 */

	/* Detect if BPF cookie is supported for kprobes.
	 * Added in: 7adfc6c9b315 ("bpf: Add bpf_get_attach_cookie() BPF helper to access bpf_cookie value")
	 */

	/* Detect if multi-attach kprobes are supported.
	 * Added in: 0dcac2725406 ("bpf: Add multi kprobe link")
	 */

	return 0;
}

SEC("kretsyscall/nanosleep")
int calib_exit(struct pt_regs *ctx)
{
	struct trace_kprobe *tk;
	__u64 fp, ip, i;
	int tid, off;
	struct user_args *argsp;
	__u32 zero = 0;
	argsp = bpf_map_lookup_elem(&calib_args_map, &zero);
	if (!argsp)
		return 0;

	tid = (__u32)bpf_get_current_pid_tgid();
	if (tid != argsp->my_tid)
		return 0;

	/* get frame pointer */
	asm volatile ("%[fp] = r10" : [fp] "+r"(fp) :);

	for (i = 1; i <= MAX_ATTEMPTS; i++) {
		bpf_probe_read_kernel(&tk, sizeof(tk), (void *)(fp + i * sizeof(__u64)));
		ip = (__u64)BPF_CORE_READ(tk, rp.kp.addr);

		if (ip == argsp->entry_ip) {
			argsp->kret_ip_off = i;
			return 0;
		}
	}

	return 0;
}

