// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2021 Facebook */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "retsnoop.h"
#include "compat.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define printk_is_sane (bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_snprintf))

#define printk_needs_endline (!bpf_core_type_exists(struct trace_event_raw_bpf_trace_printk))

#define APPEND_ENDLINE(fmt) fmt[sizeof(fmt) - 2] = '\n'

#undef bpf_printk
#define bpf_printk(fmt, ...)						\
	({									\
	 static char ___fmt[] = fmt " ";					\
	 if (printk_needs_endline)					\
	 APPEND_ENDLINE(___fmt);					\
	 bpf_trace_printk(___fmt, sizeof(___fmt), ##__VA_ARGS__);	\
	 })

#define log(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)

#define __memcpy(dst, src, sz) bpf_probe_read_kernel(dst, sz, src)

static inline void atomic_inc(long *value)
{
	(void)__atomic_add_fetch(value, 1, __ATOMIC_RELAXED);
}

static inline void atomic_add(long *value, long n)
{
	(void)__atomic_add_fetch(value, n, __ATOMIC_RELAXED);
}

struct session {
	int pid, tgid;
	long start_ts;
	char task_comm[16], proc_comm[16];

	long scratch; /* for obfuscating pointers to be read as integers */

	bool defunct;
	bool start_emitted;

	int next_seq_id;

	int dropped_records;

	struct perf_branch_entry lbrs[MAX_LBR_ENTRIES];
	long lbrs_sz;

	struct call_stack stack;
};

struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __type(key, __u32);
        __type(value, struct user_args);
        __uint(max_entries, 1);
} ret_args_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct session);
} sessions SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct func_info_elem);
	__uint(max_entries, 1); /* could be overriden from user-space */
} func_infos_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, bool);
	__uint(max_entries, 1); /* could be overriden from user-space */
} tgids_filter SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, char[TASK_COMM_LEN]);
	__uint(max_entries, 1); /* could be overriden from user-space */
} comms_filter SEC(".maps");

// const volatile char spaces[512] = {};

// struct stats stats = {};

# if 0
static void stat_dropped_record(struct session *sess)
{
	if (sess->dropped_records == 0)
		/* only count each incomplete session once */
		atomic_inc(&stats.incomplete_sessions);
	sess->dropped_records++;
}

#endif
/* dynamically sized from the user space */
//struct func_info func_infos[1] SEC(".data.func_infos");
//const volatile __u32 func_info_mask;

static __always_inline const struct func_info *func_info(u32 id)
{
        struct func_info_elem *elem;
        u32 zero = 0;

        elem = bpf_map_lookup_elem(&func_infos_map, &zero);
        if (!elem)
                return NULL;

	return &elem->func_infos[id & elem->func_info_mask];
}

#ifdef __TARGET_ARCH_x86
static u64 get_arg_reg_value(void *ctx, u32 arg_idx)
{
	struct user_args *argsp;
	u32 zero = 0;
	argsp = bpf_map_lookup_elem(&ret_args_map, &zero);
	if (!argsp)
		return 0;

	if (argsp->use_kprobes) {
		struct pt_regs *regs = ctx;

		switch (arg_idx) {
			case 0: return PT_REGS_PARM1(regs);
			case 1: return PT_REGS_PARM2(regs);
			case 2: return PT_REGS_PARM3(regs);
			case 3: return PT_REGS_PARM4(regs);
			case 4: return PT_REGS_PARM5(regs);
			case 5: return PT_REGS_PARM6(regs);
			default: return 0;
		}
	} else {
		u64 *args = ctx, val;

		bpf_probe_read_kernel(&val, sizeof(val), &args[arg_idx]);
		return val;
	}
}

static __always_inline u64 get_stack_pointer(void *ctx)
{
	u64 sp;
	struct user_args *argsp;
	u32 zero = 0;

	argsp = bpf_map_lookup_elem(&ret_args_map, &zero);
	if (!argsp)
		return 0;


	if (argsp->use_kprobes) {
		sp = PT_REGS_SP((struct pt_regs *)ctx);
		barrier_var(sp);
	} else {
		/* current FENTRY doesn't support attaching to functions that
		 * pass arguments on the stack, so we don't really need to
		 * implement this
		 */
		sp = 0;
		barrier_var(sp);
	}

	return sp;
}
#else /* !__TARGET_ARCH_x86 */
static u64 get_arg_reg_value(void *ctx, u32 arg_idx) { return 0; }
static u64 get_stack_pointer(void *ctx) { return 0; }
#endif

static __always_inline u64 coerce_size(u64 val, int sz)
{
	int shift = (8 - sz) * 8;
	return (val << shift) >> shift;
}

static __always_inline bool is_kernel_addr(void *addr)
{
	return (long)addr <= 0;
}

static void capture_vararg(struct func_args_capture *r, u32 arg_idx, void *data)
{
	size_t data_off;
	void *dst;
	int err, kind, len;
	u32 zero = 0;
	struct user_args *argsp;

	data_off = r->data_len;
	barrier_var(data_off); /* prevent compiler from re-reading it */

	argsp = bpf_map_lookup_elem(&ret_args_map, &zero);
	if (!argsp)
		return;

	if (data_off >= argsp->args_max_total_args_sz) {
		r->arg_lens[arg_idx] = -ENOSPC;
		return;
	}

	dst = r->arg_data + data_off;

	/* at least capture raw 8 byte value */
	*(long *)dst = (long)data;
	len = 8;
	dst += 8;
	r->data_len += 8;

	/* if this looks like a kernel addrs, also try to read kernel string */
	if (is_kernel_addr(data)) {
		/* in this case we mark that we have a raw pointer value */
		r->arg_ptrs |= (1 << arg_idx);

		err = bpf_probe_read_kernel_str(dst, argsp->args_max_str_arg_sz, data);
		if (err < 0) {
			r->arg_lens[arg_idx] = err;
			return;
		}

		len = err;
		r->data_len += (len + 7) / 8 * 8;
	}

	r->arg_lens[arg_idx] = len;
}

static void capture_arg(struct func_args_capture *r, u32 arg_idx, void *data, u32 len, u32 arg_spec)
{
	size_t data_off;
	void *dst;
	int err, kind;
	u32 zero = 0;
	struct user_args *argsp;

	if (data == NULL) {
		r->arg_lens[arg_idx] = -ENODATA;
		return;
	}

	argsp = bpf_map_lookup_elem(&ret_args_map, &zero);
	if (!argsp)
		return;

	data_off = r->data_len;
	barrier_var(data_off); /* prevent compiler from re-reading it */

	if (data_off >= argsp->args_max_total_args_sz) {
		r->arg_lens[arg_idx] = -ENOSPC;
		return;
	}

	dst = r->arg_data + data_off;

	kind = (arg_spec & FNARGS_KIND_MASK) >> FNARGS_KIND_SHIFT;
	if (argsp->capture_raw_ptrs && (kind == FNARGS_KIND_PTR || kind == FNARGS_KIND_STR)) {
		*(long *)dst = (long)data;
		dst += 8;
		r->arg_ptrs |= (1 << arg_idx);
		r->data_len += 8;
	}

	if (kind == FNARGS_KIND_STR) {
		if (len > argsp->args_max_str_arg_sz) /* truncate, if necessary */
			len = argsp->args_max_str_arg_sz;
		if (is_kernel_addr(data))
			err = bpf_probe_read_kernel_str(dst, len, data);
		else
			err = bpf_probe_read_user_str(dst, len, data);
		len = err; /* len is meaningful only if successful */
	} else {
		if (len > argsp->args_max_sized_arg_sz) /* truncate, if necessary */
			len = argsp->args_max_sized_arg_sz;
		if (is_kernel_addr(data))
			err = bpf_probe_read_kernel(dst, len, data);
		else
			err = bpf_probe_read_user(dst, len, data);
	}

	if (err < 0) {
		r->arg_lens[arg_idx] = err;
		return;
	}

	r->data_len += (len + 7) / 8 * 8;
	r->arg_lens[arg_idx] = len;
}

static __noinline void record_args(void *ctx, struct session *sess, u32 func_id, u32 seq_id)
{
	struct func_args_capture *r;
	const struct func_info *fi;
	u64 i, rec_sz;
	u32 zero = 0;
	struct user_args *argsp;

	argsp = bpf_map_lookup_elem(&ret_args_map, &zero);
	if (!argsp)
		return;

	/* we waste *args_max_any_arg_sz* + 12 * 8 (for raw ptrs value) to simplify verification */
	rec_sz = sizeof(*r) + argsp->args_max_total_args_sz + argsp->args_max_any_arg_sz + 8 * MAX_FNARGS_ARG_SPEC_CNT;
	r = (struct func_args_capture *)reserve_buf(rec_sz);
	if (!r)
		return;

	r->type = REC_FUNC_ARGS_CAPTURE;
	r->pid = sess->pid;
	r->seq_id = seq_id;
	r->func_id = func_id;
	r->arg_ptrs = 0;
	r->data_len = 0;

	fi = func_info(func_id);
	for (i = 0; i < MAX_FNARGS_ARG_SPEC_CNT; i++) {
		u32 spec = fi->arg_specs[i], reg_idx, off, kind, loc;
		u16 len = spec & FNARGS_LEN_MASK;
		void *data_ptr = NULL;
		u64 vals[2];
		int err;

		if (spec == 0)
			break;

		if (len == 0) {
			r->arg_lens[i] = 0;
			continue;
		}

		loc = (spec & FNARGS_LOC_MASK) >> FNARGS_LOC_SHIFT;
		kind = (spec & FNARGS_KIND_MASK) >> FNARGS_KIND_SHIFT;

		switch (loc) {
			case FNARGS_REG:
				reg_idx = (spec & FNARGS_REGIDX_MASK) >> FNARGS_REGIDX_SHIFT;
				vals[0] = get_arg_reg_value(ctx, reg_idx);
				if (kind != FNARGS_KIND_RAW) {
					data_ptr = (void *)vals[0];
				} else {
					vals[0] = coerce_size(vals[0], len);
					data_ptr = vals;
				}
				break;
			case FNARGS_STACK:
				/* stack offset is specified in 8 byte chunks */
				off = 8 * ((spec & FNARGS_STACKOFF_MASK) >> FNARGS_STACKOFF_SHIFT);
				vals[0] = get_stack_pointer(ctx) + off;
				if (kind != FNARGS_KIND_RAW) {
					/* the pointer value itself is on the stack */
					err = bpf_probe_read_kernel(&vals[0], 8, (void *)vals[0]);
					if (err) {
						r->arg_lens[i] = err;
						continue;
					}
				}
				data_ptr = (void *)vals[0];
				break;
			case FNARGS_REG_PAIR:
				/* there is no special kind besides FNARGS_KIND_RAW for REG_PAIR */
				reg_idx = (spec & FNARGS_REGIDX_MASK) >> FNARGS_REGIDX_SHIFT;
				vals[0] = get_arg_reg_value(ctx, reg_idx);
				vals[1] = get_arg_reg_value(ctx, reg_idx + 1);
				vals[1] = coerce_size(vals[1], len - 8);
				data_ptr = (void *)vals;
				break;
			default:
				r->arg_lens[i] = -EDOM;
				continue;
		}

		if (kind == FNARGS_KIND_VARARG)
			capture_vararg(r, i, data_ptr);
		else
			capture_arg(r, i, data_ptr, len, spec);
	}
	submit_buf(ctx, r, rec_sz);
}

static __noinline void save_stitch_stack(void *ctx, struct call_stack *stack)
{
	u64 d = stack->depth;
	u64 len = stack->max_depth - d;
	u32 zero = 0;
	struct user_args *argsp;

	if (d >= MAX_FSTACK_DEPTH || len >= MAX_FSTACK_DEPTH) {
		log("SHOULDN'T HAPPEN DEPTH %ld LEN %ld\n", d, len);
		return;
	}
	argsp = bpf_map_lookup_elem(&ret_args_map, &zero);
	if (!argsp)
		return;
	if (argsp->extra_verbose) {
		log("CURRENT DEPTH %d..%d", stack->depth + 1, stack->max_depth);
		log("SAVED DEPTH %d..%d", stack->saved_depth, stack->saved_max_depth);
	}

	/* we can stitch together stack subsections */
	if (stack->saved_depth && stack->max_depth + 1 == stack->saved_depth) {
		__memcpy(stack->saved_ids + d, stack->func_ids + d, len * sizeof(stack->saved_ids[0]));
		__memcpy(stack->saved_res + d, stack->func_res + d, len * sizeof(stack->saved_res[0]));
		__memcpy(stack->saved_lat + d, stack->func_lat + d, len * sizeof(stack->saved_lat[0]));
		if (argsp->capture_args)
			__memcpy(stack->saved_seq_ids + d, stack->seq_ids + d, len * sizeof(stack->saved_seq_ids[0]));
		stack->saved_depth = stack->depth + 1;
		if (argsp->extra_verbose)
			log("STITCHED STACK %d..%d to ..%d\n",
					stack->depth + 1, stack->max_depth, stack->saved_max_depth);
		return;
	}
	if (argsp->extra_verbose)
		log("RESETTING SAVED ERR STACK %d..%d to %d..\n",
				stack->saved_depth, stack->saved_max_depth, stack->depth + 1);

	__memcpy(stack->saved_ids + d, stack->func_ids + d, len * sizeof(stack->saved_ids[0]));
	__memcpy(stack->saved_res + d, stack->func_res + d, len * sizeof(stack->saved_res[0]));
	__memcpy(stack->saved_lat + d, stack->func_lat + d, len * sizeof(stack->saved_lat[0]));
	if (argsp->capture_args)
		__memcpy(stack->saved_seq_ids + d, stack->seq_ids + d, len * sizeof(stack->saved_seq_ids[0]));

	stack->saved_depth = stack->depth + 1;
	stack->saved_max_depth = stack->max_depth;
}

static const struct session empty_session;

static bool emit_session_start(void *ctx, struct session *sess)
{
	struct session_start *r;

	r = (struct session_start *)reserve_buf(sizeof(*r));
	if (!r)
		return false;

	r->type = REC_SESSION_START;
	r->pid = sess->pid;
	r->tgid = sess->tgid;
	r->start_ts = sess->start_ts;
	__builtin_memcpy(r->task_comm, sess->task_comm, sizeof(sess->task_comm));
	__builtin_memcpy(r->proc_comm, sess->proc_comm, sizeof(sess->proc_comm));

	submit_buf(ctx, r, sizeof(*r));

	return true;
}

static __noinline bool push_call_stack(void *ctx, u32 id, u64 ip)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = (u32)pid_tgid, zero = 0;
	struct session *sess;
	int seq_id;
	u64 d;
	struct user_args *argsp;

	argsp = bpf_map_lookup_elem(&ret_args_map, &zero);
	if (!argsp)
		return false;

	sess = bpf_map_lookup_elem(&sessions, &pid);
	if (!sess) {
		struct task_struct *tsk;

		if (!(func_info(id)->flags & FUNC_IS_ENTRY))
			return false;

		bpf_map_update_elem(&sessions, &pid, &empty_session, BPF_ANY);
		sess = bpf_map_lookup_elem(&sessions, &pid);
		if (!sess) {
			return false;
		}

		sess->pid = pid;
		sess->tgid = (u32)(pid_tgid >> 32);
		sess->start_ts = bpf_ktime_get_ns();
		bpf_get_current_comm(&sess->task_comm, sizeof(sess->task_comm));
		tsk = (void *)bpf_get_current_task();
		BPF_CORE_READ_INTO(&sess->proc_comm, tsk, group_leader, comm);

		if (argsp->emit_func_trace || argsp->capture_args) {
			if (!emit_session_start(ctx, sess)) {
				log("DEFUNCT SESSION TID/PID %d/%d: failed to send SESSION_START record!\n",
						sess->pid, sess->tgid);
				sess->defunct = true;
				goto out_defunct;
			} else {
				sess->start_emitted = true;
			}
		}
	}

out_defunct:
	/* if we failed to send out REC_SESSION_START, update depth and bail */
	if (sess->defunct) {
		sess->stack.depth++;
		return false;
	}

	d = sess->stack.depth;
	barrier_var(d);
	if (d >= MAX_FSTACK_DEPTH)
		return false;

	if (sess->stack.depth != sess->stack.max_depth && sess->stack.is_err)
		save_stitch_stack(ctx, &sess->stack);

	seq_id = sess->next_seq_id;
	sess->next_seq_id++;

	sess->stack.func_ids[d] = id;
	sess->stack.seq_ids[d] = seq_id;
	sess->stack.is_err = false;
	sess->stack.depth = d + 1;
	sess->stack.max_depth = d + 1;
	sess->stack.func_lat[d] = bpf_ktime_get_ns();

	if (argsp->emit_func_trace) {
		struct func_trace_entry *fe;

		fe = (struct func_trace_entry *)reserve_buf(sizeof(*fe));
		if (!fe)
			goto skip_ft_entry;

		fe->type = REC_FUNC_TRACE_ENTRY;
		fe->ts = bpf_ktime_get_ns();
		fe->pid = pid;
		fe->seq_id = seq_id;
		fe->depth = d + 1;
		fe->func_id = id;
		fe->func_lat = 0;
		fe->func_res = 0;
		submit_buf(ctx, fe, sizeof(*fe));
skip_ft_entry:;
	}

	if (argsp->capture_args)
		record_args(ctx, sess, id, seq_id);

	if (argsp->verbose) {
		const char *func_name = func_info(id)->name;

		if (printk_is_sane) {
			if (d == 0)
				log("=== STARTING TRACING %s [COMM %s PID %d] ===",
						func_name, sess->task_comm, pid);
			//log("    ENTER %s%s [...]", spaces + 2 * ((255 - d) & 0xFF), func_name);
		} else {
			if (d == 0) {
				log("=== STARTING TRACING %s [PID %d] ===", func_name, pid);
				log("=== ...      TRACING [PID %d COMM %s] ===", pid, sess->task_comm);
			}
			//log("    ENTER [%d] %s [...]", d + 1, func_name);
		}
	}

	return true;
}

#define MAX_ERRNO 4095

static __always_inline bool IS_ERR_VALUE(long x)
{
	return (unsigned long)(void *)(x) >= (unsigned long)-MAX_ERRNO;
}

static __always_inline bool IS_ERR_VALUE32(u64 x)
{
	/* Due to BPF verifier limitations, it's really hard to do int to long
	 * sign extension generically, because some return types might be
	 * pointers and BPF verifier really hates us for treating pointer as
	 * integer and doing arbitrary (bit shifts) arithmetics on it.  So
	 * instead we just assume we have a 32-bit signed integer and check
	 * manually that it's value unsigned value lies in [-4095, 1] range.
	 * -1 is 0xffffffff, -4095 is 0xfffff001. Easy.
	 */
	if (x < 0xfffff001)
		return false;
	/* prevent clever Clang optimizaations involving math */
	barrier_var(x);
	if (x > 0xffffffff)
		return false;
	return true;
}

/* all length should be the same */
char FMT_SUCC_VOID[]         = "    EXIT  %s%s [VOID]     ";
char FMT_SUCC_TRUE[]         = "    EXIT  %s%s [true]     ";
char FMT_SUCC_FALSE[]        = "    EXIT  %s%s [false]    ";
char FMT_FAIL_NULL[]         = "[!] EXIT  %s%s [NULL]     ";
char FMT_FAIL_PTR[]          = "[!] EXIT  %s%s [%d]       ";
char FMT_SUCC_PTR[]          = "    EXIT  %s%s [0x%lx]    ";
char FMT_FAIL_LONG[]         = "[!] EXIT  %s%s [%ld]      ";
char FMT_SUCC_LONG[]         = "    EXIT  %s%s [%ld]      ";
char FMT_FAIL_INT[]          = "[!] EXIT  %s%s [%d]       ";
char FMT_SUCC_INT[]          = "    EXIT  %s%s [%d]       ";

char FMT_SUCC_VOID_COMPAT[]  = "    EXIT  [%d] %s [VOID]  ";
char FMT_SUCC_TRUE_COMPAT[]  = "    EXIT  [%d] %s [true]  ";
char FMT_SUCC_FALSE_COMPAT[] = "    EXIT  [%d] %s [false] ";
char FMT_FAIL_NULL_COMPAT[]  = "[!] EXIT  [%d] %s [NULL]  ";
char FMT_FAIL_PTR_COMPAT[]   = "[!] EXIT  [%d] %s [%d]    ";
char FMT_SUCC_PTR_COMPAT[]   = "    EXIT  [%d] %s [0x%lx] ";
char FMT_FAIL_LONG_COMPAT[]  = "[!] EXIT  [%d] %s [%ld]   ";
char FMT_SUCC_LONG_COMPAT[]  = "    EXIT  [%d] %s [%ld]   ";
char FMT_FAIL_INT_COMPAT[]   = "[!] EXIT  [%d] %s [%d]    ";
char FMT_SUCC_INT_COMPAT[]   = "    EXIT  [%d] %s [%d]    ";

static __noinline void print_exit(void *ctx, __u32 d, __u32 id, long res)
{
	const struct func_info *fi;
	const char *func_name = fi->name;
	const size_t FMT_MAX_SZ = sizeof(FMT_SUCC_PTR_COMPAT); /* UPDATE IF NECESSARY */
	u32 flags, fmt_sz;
	const char *fmt;
	bool failed;

	fi = func_info(id);
	func_name = fi->name;
	flags = fi->flags;

	if (printk_needs_endline) {
		/* before bpf_trace_printk() started using underlying
		 * tracepoint mechanism for logging to trace_pipe it didn't
		 * automatically append endline, so we need to adjust our
		 * format strings to have \n, otherwise we'll have a dump of
		 * unseparate log lines
		 */
		APPEND_ENDLINE(FMT_SUCC_VOID);
		APPEND_ENDLINE(FMT_SUCC_TRUE);
		APPEND_ENDLINE(FMT_SUCC_FALSE);
		APPEND_ENDLINE(FMT_FAIL_NULL);
		APPEND_ENDLINE(FMT_FAIL_PTR);
		APPEND_ENDLINE(FMT_SUCC_PTR);
		APPEND_ENDLINE(FMT_FAIL_LONG);
		APPEND_ENDLINE(FMT_SUCC_LONG);
		APPEND_ENDLINE(FMT_FAIL_INT);
		APPEND_ENDLINE(FMT_SUCC_INT);

		APPEND_ENDLINE(FMT_SUCC_VOID_COMPAT);
		APPEND_ENDLINE(FMT_SUCC_TRUE_COMPAT);
		APPEND_ENDLINE(FMT_SUCC_FALSE_COMPAT);
		APPEND_ENDLINE(FMT_FAIL_NULL_COMPAT);
		APPEND_ENDLINE(FMT_FAIL_PTR_COMPAT);
		APPEND_ENDLINE(FMT_SUCC_PTR_COMPAT);
		APPEND_ENDLINE(FMT_FAIL_LONG_COMPAT);
		APPEND_ENDLINE(FMT_SUCC_LONG_COMPAT);
		APPEND_ENDLINE(FMT_FAIL_INT_COMPAT);
		APPEND_ENDLINE(FMT_SUCC_INT_COMPAT);
	}

	if (flags & FUNC_RET_VOID) {
		fmt = printk_is_sane ? FMT_SUCC_VOID : FMT_SUCC_VOID_COMPAT;
		failed = false;
	} else if (flags & FUNC_RET_PTR) {
		/* consider NULL pointer an error */
		failed = (res == 0) || IS_ERR_VALUE(res);
		if (printk_is_sane)
			fmt = failed ? (res ? FMT_FAIL_PTR : FMT_FAIL_NULL) : FMT_SUCC_PTR;
		else
			fmt = failed ? (res ? FMT_FAIL_PTR_COMPAT : FMT_FAIL_NULL_COMPAT) : FMT_SUCC_PTR_COMPAT;
	} else if (flags & FUNC_RET_BOOL) {
		if (printk_is_sane)
			fmt = res ? FMT_SUCC_TRUE : FMT_SUCC_FALSE;
		else
			fmt = res ? FMT_SUCC_TRUE_COMPAT : FMT_SUCC_FALSE_COMPAT;
		failed = false;
	} else if (flags & FUNC_NEEDS_SIGN_EXT) {
		failed = IS_ERR_VALUE32((u32)res);
		if (failed)
			fmt = printk_is_sane ? FMT_FAIL_INT : FMT_FAIL_INT_COMPAT;
		else
			fmt = printk_is_sane ? FMT_SUCC_INT : FMT_SUCC_INT_COMPAT;
	} else {
		failed = IS_ERR_VALUE(res);
		if (failed)
			fmt = printk_is_sane ? FMT_FAIL_LONG : FMT_FAIL_LONG_COMPAT;
		else
			fmt = printk_is_sane ? FMT_SUCC_LONG : FMT_SUCC_LONG_COMPAT;
	}

	if (printk_is_sane) {
		//bpf_trace_printk(fmt, FMT_MAX_SZ, spaces + 2 * ((255 - d) & 0xff), func_name, res);
	} else {
		bpf_trace_printk(fmt, FMT_MAX_SZ, d + 1, func_name, res);
	}
}

static void reset_session(struct session *sess)
{
	sess->defunct = false;
	sess->start_emitted = false;

	sess->stack.is_err = false;
	sess->stack.saved_depth = 0;
	sess->stack.saved_max_depth = 0;
	sess->stack.depth = 0;
	sess->stack.max_depth = 0;
	sess->stack.kstack_sz = 0;
	sess->next_seq_id = 0;

	sess->lbrs_sz = 0;
}

static int submit_session(void *ctx, struct session *sess)
{
	bool emit_session;
	u64 emit_ts = bpf_ktime_get_ns();
	u32 zero = 0;
	struct user_args *argsp;

	argsp = bpf_map_lookup_elem(&ret_args_map, &zero);
	if (!argsp)
		return 0;

	emit_session = sess->stack.is_err || argsp->emit_success_stacks;
	if (argsp->duration_ns && emit_ts - sess->stack.func_lat[0] < argsp->duration_ns)
		emit_session = false;
#if 0
	if (emit_session) {
		dlog("EMIT %s STACK DEPTH %d (SAVED ..%d)\n",
				sess->stack.is_err ? "ERROR" : "SUCCESS",
				sess->stack.max_depth, sess->stack.saved_max_depth);
	}
#endif

	if (emit_session && !sess->start_emitted) {
		if (!emit_session_start(ctx, sess)) {
			log("DEFUNCT SESSION TID/PID %d/%d: failed to send SESSION data!\n",
					sess->pid, sess->tgid);
			sess->defunct = true;
			return -EINVAL;
		}
		sess->start_emitted = true;
	}

	if (emit_session) {
		struct lbr_stack *r;

		if (sess->lbrs_sz <= 0)
			goto skip_lbrs;
		r = (struct lbr_stack *)reserve_buf(sizeof(*r));
		if (!r) {
			sess->lbrs_sz = -ENOSPC;
			goto skip_lbrs;
		}

		r->type = REC_LBR_STACK;
		r->pid = sess->pid;
		r->lbrs_sz = sess->lbrs_sz;
		__memcpy(r->lbrs, sess->lbrs, sizeof(sess->lbrs));

		submit_buf(ctx, r, sizeof(*r));
skip_lbrs:;
	}

	if (emit_session || sess->start_emitted) {
		struct session_end *r;

		r = (struct session_end *)reserve_buf(sizeof(*r));
		if (!r)
			return -EINVAL;

		r->type = REC_SESSION_END;
		r->pid = sess->pid;
		r->emit_ts = emit_ts;
		r->ignored = !emit_session;
		r->is_err = sess->stack.is_err;
		r->last_seq_id = sess->next_seq_id - 1;
		r->lbrs_sz = sess->lbrs_sz;
		r->dropped_records = sess->dropped_records;

		/* copy over STACK_TRACE "record", if required */
		if (emit_session)
			__memcpy(&r->stack, &sess->stack, sizeof(sess->stack));

		submit_buf(ctx, r, sizeof(*r));
	}

	return 0;
}

static __noinline bool pop_call_stack(void *ctx, u32 id, u64 ip, long res)
{
	const struct func_info *fi;
	const char *func_name;
	struct session *sess;
	u32 pid, exp_id, flags, fmt_sz, zero = 0;
	const char *fmt;
	bool failed;
	u64 d, lat;
	int seq_id;
	struct user_args *argsp;

	argsp = bpf_map_lookup_elem(&ret_args_map, &zero);
	if (!argsp)
		return false;

	pid = (u32)bpf_get_current_pid_tgid();
	sess = bpf_map_lookup_elem(&sessions, &pid);
	if (!sess)
		return false;

	/* if we failed to send out REC_SESSION_START, clean up and send nothing else */
	if (sess->defunct) {
		sess->stack.depth--;
		if (sess->stack.depth == 0) {
			reset_session(sess);
			bpf_map_delete_elem(&sessions, &pid);
			log("DEFUNCT SESSION TID/PID %d/%d: SESSION_END, no data was collected!\n",
					pid, sess->tgid);
		}
		return false;
	}

	seq_id = sess->next_seq_id;
	sess->next_seq_id++;

	d = sess->stack.depth;
	if (d == 0)
		return false;

	d -= 1;
	barrier_var(d);
	if (d >= MAX_FSTACK_DEPTH)
		return false;

	fi = func_info(id);
	func_name = fi->name;
	flags = fi->flags;

	/* obfuscate pointers (tracked in fentry/fexit mode by BPF verifier
	 * for pointer-returning functions) to be interpreted as opaque
	 * integers
	 */
	sess->scratch = res;
	barrier_var(res);
	res = sess->scratch;

	if (flags & FUNC_CANT_FAIL)
		failed = false;
	else if ((flags & FUNC_RET_PTR) && res == 0)
		/* consider NULL pointer an error as well */
		failed = true;
	else if (flags & FUNC_NEEDS_SIGN_EXT)
		failed = IS_ERR_VALUE32((u32)res);
	else
		failed = IS_ERR_VALUE(res);

	lat = bpf_ktime_get_ns() - sess->stack.func_lat[d];

	if (argsp->emit_func_trace) {
		struct func_trace_entry *fe;
                fe = (struct func_trace_entry *)reserve_buf(sizeof(*fe));
	        if (!fe)
			goto skip_ft_exit;

		fe->type = REC_FUNC_TRACE_EXIT;
		fe->ts = bpf_ktime_get_ns();
		fe->pid = pid;
		fe->seq_id = seq_id;
		fe->depth = d + 1;
		fe->func_id = id;
		fe->func_lat = lat;
		fe->func_res = res;
                submit_buf(ctx, fe, sizeof(*fe));
skip_ft_exit:;
	}
	if (argsp->verbose)
		print_exit(ctx, d, id, res);

	exp_id = sess->stack.func_ids[d];
	if (exp_id != id) {
		const struct func_info *exp_fi = func_info(exp_id);

		log("POP(0) UNEXPECTED PID %d DEPTH %d MAX DEPTH %d",
				pid, sess->stack.depth, sess->stack.max_depth);
		log("POP(1) UNEXPECTED GOT  ID %d ADDR %lx NAME %s",
				id, ip, func_name);
		log("POP(2) UNEXPECTED WANT ID %u ADDR %lx NAME %s",
				exp_id, exp_fi->ip, exp_fi->name);

		reset_session(sess);
		bpf_map_delete_elem(&sessions, &pid);

		return false;
	}

	sess->stack.func_res[d] = res;
	sess->stack.func_lat[d] = lat;

	if (failed && !sess->stack.is_err) {
		sess->stack.is_err = true;
		sess->stack.max_depth = d + 1;
		sess->stack.kstack_sz = bpf_get_stack(ctx, &sess->stack.kstack, sizeof(sess->stack.kstack), 0);
	} else if (argsp->emit_success_stacks && d + 1 == sess->stack.max_depth) {
		sess->stack.kstack_sz = bpf_get_stack(ctx, &sess->stack.kstack, sizeof(sess->stack.kstack), 0);
	}
	sess->stack.depth = d;

	/* emit last complete stack trace */
	if (d == 0) {
		/* can fail or do nothing for current session */
		submit_session(ctx, sess);

		reset_session(sess);
		bpf_map_delete_elem(&sessions, &pid);
	}

	return true;
}

static __always_inline bool tgid_allowed(void)
{
	bool *verdict_ptr;
	u32 tgid, zero = 0;
	struct user_args *argsp;

	argsp = bpf_map_lookup_elem(&ret_args_map, &zero);
	if (!argsp)
		return true;

	/* if no PID filters -- allow everything */
	if (argsp->tgid_allow_cnt + argsp->tgid_deny_cnt == 0)
		return true;

	tgid = bpf_get_current_pid_tgid() >> 32;

	verdict_ptr = bpf_map_lookup_elem(&tgids_filter, &tgid);
	if (!verdict_ptr)
		/* if allowlist is non-empty, then PID didn't pass the check */
		return argsp->tgid_allow_cnt == 0;

	return *verdict_ptr;
}

static __always_inline bool comm_allowed(void)
{
	char comm[TASK_COMM_LEN] = {};
	bool *verdict_ptr;
	u32 zero = 0;
	struct user_args *argsp;

	argsp = bpf_map_lookup_elem(&ret_args_map, &zero);
	if (!argsp)
		return true;

	/* if no COMM filters -- allow everything */
	if (argsp->comm_allow_cnt + argsp->comm_deny_cnt == 0)
		return true;

	bpf_get_current_comm(comm, TASK_COMM_LEN);

	verdict_ptr = bpf_map_lookup_elem(&comms_filter, comm);
	if (!verdict_ptr)
		/* if allowlist is non-empty, then COMM didn't pass the check */
		return argsp->comm_allow_cnt == 0;

	return *verdict_ptr;
}

/* mass-attacher BPF library is calling this function, so it should be global */
int handle_func_entry(void *ctx, u32 func_id, u64 func_ip)
{
	if (!tgid_allowed() || !comm_allowed())
		return 0;

	push_call_stack(ctx, func_id, func_ip);
	return 0;
}

/* mass-attacher BPF library is calling this function, so it should be global */
int handle_func_exit(void *ctx, u32 func_id, u64 func_ip, u64 ret)
{
	if (!tgid_allowed() || !comm_allowed())
		return 0;

	pop_call_stack(ctx, func_id, func_ip, ret);
	return 0;
}


/*=========================================================================*/
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, unsigned);
} ip_to_id SEC(".maps");

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

	args = bpf_map_lookup_elem(&ret_args_map, &zero);
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

	argsp = bpf_map_lookup_elem(&ret_args_map, &zero);
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
