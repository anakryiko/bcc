/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __RUNQSLOWER_H
#define __RUNQSLOWER_H

#define TASK_COMM_LEN 16

struct event {
	char task[TASK_COMM_LEN];
	__u64 delta_us;
	pid_t pid;
};

#define MAX_ARG_CNT 50
#define MAX_ARG_LEN 128
#define MAX_STRS_LEN ((MAX_ARG_CNT + 1) * MAX_ARG_LEN)

struct exec_event {
	int pid;
	int tgid;
	int ret;
	int fname_len;
	int arg_cnt;
	int arg_lens[MAX_ARG_CNT];
	char comm[TASK_COMM_LEN];
	char strs[MAX_STRS_LEN];
	char strs_end[];
};

#endif /* __RUNQSLOWER_H */
