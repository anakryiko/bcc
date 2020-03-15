// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019 Facebook
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "runqslower.h"

#define TASK_RUNNING 0

const volatile __u64 min_us = 0;
const volatile pid_t targ_pid = 0;
const volatile pid_t targ_tgid = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, u64);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

/* record enqueue timestamp */
static __always_inline
int trace_enqueue(u32 tgid, u32 pid)
{
	u64 ts;

	if (!pid)
		return 0;
	if (targ_tgid && targ_tgid != tgid)
		return 0;
	if (targ_pid && targ_pid != pid)
		return 0;

	ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start, &pid, &ts, 0);
	return 0;
}

SEC("tp_btf/sched_wakeup")
int handle__sched_wakeup(u64 *ctx)
{
	/* TP_PROTO(struct task_struct *p) */
	struct task_struct *p = (void *)ctx[0];

	return trace_enqueue(p->tgid, p->pid);
}

SEC("tp_btf/sched_wakeup_new")
int handle__sched_wakeup_new(u64 *ctx)
{
	/* TP_PROTO(struct task_struct *p) */
	struct task_struct *p = (void *)ctx[0];

	return trace_enqueue(p->tgid, p->pid);
}

SEC("tp_btf/sched_switch")
int handle__sched_switch(u64 *ctx)
{
	/* TP_PROTO(bool preempt, struct task_struct *prev,
	 *	    struct task_struct *next)
	 */
	struct task_struct *prev = (struct task_struct *)ctx[1];
	struct task_struct *next = (struct task_struct *)ctx[2];
	struct event event = {};
	u64 *tsp, delta_us;
	long state;
	u32 pid;

	/* ivcsw: treat like an enqueue event and store timestamp */
	if (prev->state == TASK_RUNNING)
		trace_enqueue(prev->tgid, prev->pid);

	pid = next->pid;

	/* fetch timestamp and calculate delta */
	tsp = bpf_map_lookup_elem(&start, &pid);
	if (!tsp)
		return 0;   /* missed enqueue */

	delta_us = (bpf_ktime_get_ns() - *tsp) / 1000;
	if (min_us && delta_us <= min_us)
		return 0;

	event.pid = pid;
	event.delta_us = delta_us;
	bpf_probe_read_str(&event.task, sizeof(event.task), next->comm);

	/* output */
	//bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
	//		      &event, sizeof(event));

	bpf_map_delete_elem(&start, &pid);
	return 0;
}

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128); /* size should be >= number of CPUs */
	__type(key, u32);
	__type(value, struct exec_event);
} execs SEC(".maps");

static const struct exec_event empty_event = {};
const volatile size_t max_args = 20;

SEC("tp/syscalls/sys_enter_execve")
int handle__execve_enter(struct trace_event_raw_sys_enter *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = (u32)id, tgid = id >> 32;
	size_t i, len;
	void **argv, *arg, *strs;
	struct exec_event *e;

	if (bpf_map_update_elem(&execs, &pid, &empty_event, BPF_NOEXIST))
		return 0; /* should never happen */

	e = bpf_map_lookup_elem(&execs, &pid);
	if (!e)
		return 0; /* shouldn't happen */

	len = bpf_probe_read_str(e->strs, MAX_ARG_LEN, (void *)ctx->args[0]);
	if (len > MAX_ARG_LEN) /* failed to read filename, pretend it's empty */
		len = 0;

	e->pid = pid;
	e->tgid = tgid;
	e->fname_len = len;
	bpf_get_current_comm(e->comm, sizeof(e->comm));

	argv = (void **)ctx->args[1];
	strs = e->strs + len;

	#pragma unroll
	for (i = 0; i < MAX_ARG_CNT && i < max_args; i++) {
		bpf_probe_read(&arg, sizeof(arg), &argv[i]);
		if (!arg) /* no more arguments */
			break;

		len = bpf_probe_read_str(strs, MAX_ARG_LEN, arg);
		if (len > MAX_ARG_LEN) /* failed to read argument, leave it empty */
			len = 0;

		strs += len;
		e->arg_cnt++;
		e->arg_lens[i] = len;
	}
	if (i == MAX_ARG_CNT) /* there might be more arguments */
		e->arg_cnt = -e->arg_cnt;
	/* ret is reused as temporary total event size field */
	e->ret = strs - (void *)e;
	return 0;

cleanup:
	bpf_map_delete_elem(&execs, &pid);
	return 0;
}

SEC("tp/syscalls/sys_exit_execve")
int handle__execve_exit(struct trace_event_raw_sys_exit* ctx)
{
	u32 pid = (u32)bpf_get_current_pid_tgid();
	struct exec_event *e;
	size_t len;

	e = bpf_map_lookup_elem(&execs, &pid);
	if (!e) /* missed sys_enter */
		return 0;

	len = e->ret; /* restore total actual event size */
	e->ret = ctx->ret; /* now store real return result */

	if (len < sizeof(*e)) /* should always be the case */
		bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e, len);

	bpf_map_delete_elem(&execs, &pid);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
