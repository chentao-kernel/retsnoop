// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2021 Facebook */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "retsnoop.h"

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

/* these two are defined by custom BPF code outside of mass_attacher */
extern int handle_func_entry(void *ctx, u32 func_id, u64 func_ip);
extern int handle_func_exit(void *ctx, u32 func_id, u64 func_ip, u64 ret);

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, unsigned);
} ip_to_id SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct user_args);
        __uint(max_entries, 1);
} args_map SEC(".maps");

#define MAX_LBR_ENTRIES 32

/* feature detection/calibration inputs */
// const volatile int kret_ip_off = 0;

/* Kernel protects from the same BPF program from refiring on the same CPU.
 * Unfortunately, it's not very useful for us right now, because each attached
 * fentry/fexit is a separate BPF, so we need to still protected ourselves.
 */

//const volatile __u32 max_cpu_mask;

/* dynamically sized arrays */
//static int running[1] SEC(".data.running");

/* has to be called from entry-point BPF program if not using
 * bpf_get_func_ip()
 */
static __always_inline u64 get_kret_func_ip(void *ctx, int kret_ip_off)
{
	struct trace_kprobe *tk;
	u64 fp, ip;

	/* get frame pointer */
	asm volatile ("%[fp] = r10" : [fp] "+r"(fp) :);

	bpf_probe_read_kernel(&tk, sizeof(tk), (void *)(fp + kret_ip_off * sizeof(__u64)));
	ip = (__u64)BPF_CORE_READ(tk, rp.kp.addr);
	return ip;
}

SEC("kprobe")
int kentry(struct pt_regs *ctx)
{
	const char *name;
	long ip;
	u32 id, zero = 0;
	struct user_args *args = NULL;

	args = bpf_map_lookup_elem(&args_map, &zero);
	if (!args || !args->ready)
		return 0;

#ifdef bpf_target_x86
	/* for x86 the IP is off by one at hardware level,
		* see https://github.com/anakryiko/retsnoop/issues/32
		*/
	ip = PT_REGS_IP(ctx) - 1;
#else
	ip = PT_REGS_IP(ctx);
#endif

	
	u32 *id_ptr;

	id_ptr = bpf_map_lookup_elem(&ip_to_id, &ip);
	if (!id_ptr) {
		bpf_printk("KENTRY UNRECOGNIZED IP %lx", ip);
		return 0;
	}

	id = *id_ptr;

	handle_func_entry(ctx, id, ip);
	return 0;
}

SEC("kretprobe")
int kexit(struct pt_regs *ctx)
{
	const char *name;
	u32 id, cpu, zero = 0;
	long ip;
	struct user_args *argsp = NULL;

	argsp = bpf_map_lookup_elem(&args_map, &zero);
	if (unlikely(!argsp) || unlikely(!argsp->ready))
		return 0;

	cpu = bpf_get_smp_processor_id();
#if 0
	capture_lbrs(cpu);
#endif

	ip = get_kret_func_ip(ctx, argsp->kret_ip_off);

	u32 *id_ptr;

	id_ptr = bpf_map_lookup_elem(&ip_to_id, &ip);
	if (!id_ptr) {
		bpf_printk("KEXIT UNRECOGNIZED IP %lx", ip);
		return 0;
	}

	id = *id_ptr;

	handle_func_exit(ctx, id, ip, PT_REGS_RC(ctx));

	return 0;
}

#if 0
static __always_inline bool recur_enter(u32 cpu)
{
	if (running[cpu & max_cpu_mask])
		return false;

	running[cpu & max_cpu_mask] += 1;

	return true;
}

static __always_inline void recur_exit(u32 cpu)
{
	running[cpu & max_cpu_mask] -= 1;
}
#endif

static __always_inline u64 get_ftrace_func_ip(void *ctx, int arg_cnt)
{
	u64 off = 1 /* skip orig rbp */
		+ 1 /* skip reserved space for ret value */;
	u64 ip;

	if (arg_cnt <= 6)
		off += arg_cnt;
	else
		off += 6;
	off = (u64)ctx + off * 8;

	if (bpf_probe_read_kernel(&ip, sizeof(ip), (void *)off))
		return 0;

	ip -= 5; /* compensate for 5-byte fentry stub */
	return ip;
}
