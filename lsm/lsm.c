// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2020 Google LLC.
 */

//#include <test_progs.h>
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <sys/syscall.h> 
#include <bpf/libbpf.h>

#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include <malloc.h>
#include <stdlib.h>
#include <unistd.h>

#include "lsm.skel.h"

static struct env {
	bool verbose;
	long min_duration_ms;
} env;

#define _CHECK(condition, tag, duration, format...) ({			\
	int __ret = !!(condition);					\
	int __save_errno = errno;					\
	if (__ret) {							\
		fprintf(stdout, "%s:FAIL:%s ", __func__, tag);		\
		fprintf(stdout, ##format);				\
	} else {							\
		fprintf(stdout, "%s:PASS:%s %d nsec\n",			\
		       __func__, tag, duration);			\
	}								\
	errno = __save_errno;						\
	__ret;								\
})

#define CHECK(condition, tag, format...) \
	_CHECK(condition, tag, duration, format)


char *CMD_ARGS[] = {"true", NULL};

#define GET_PAGE_ADDR(ADDR, PAGE_SIZE)					\
	(char *)(((unsigned long) (ADDR + PAGE_SIZE)) & ~(PAGE_SIZE-1))

int stack_mprotect(void)
{
	void *buf;
	long sz;
	int ret;

	sz = sysconf(_SC_PAGESIZE);
	if (sz < 0)
		return sz;

	buf = alloca(sz * 3);
	ret = mprotect(GET_PAGE_ADDR(buf, sz), sz,
		       PROT_READ | PROT_WRITE | PROT_EXEC);
	return ret;
}

int exec_cmd(int *monitored_pid)
{
	int child_pid, child_status;

	child_pid = fork();
	if (child_pid == 0) {
		*monitored_pid = getpid();
		execvp(CMD_ARGS[0], CMD_ARGS);
		return -EINVAL;
	} else if (child_pid > 0) {
		waitpid(child_pid, &child_status, 0);
		return child_status;
	}

	return -EINVAL;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct lsm_bpf *skel;
	int err;


	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Bump RLIMIT_MEMLOCK to create BPF maps */
	bump_memlock_rlimit();

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = lsm_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	fprintf(stdout, "Opened bpf application\n");

	/* Parameterize BPF code with minimum duration parameter */
//	skel->rodata->min_duration_ns = env.min_duration_ms * 1000000ULL;

	/* Load & verify BPF programs */
	err = lsm_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	fprintf(stdout, "Loaded bpf application\n");

	/* Attach tracepoints */
	err = lsm_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	fprintf(stdout, "Attached bpf application\n");

cleanup:
	/* Clean up */
	ring_buffer__free(rb);
	lsm_bpf__destroy(skel);

	return err < 0 ? -err : 0;


//	struct lsm_bpf *skel = NULL;
//	int err, duration = 0;
//	int buf = 1234;
//
//	/* Load and verify BPF application */
//	skel = lsm_bpf__open();
//	if (CHECK(!skel, "skel_load", "lsm skeleton failed\n"))
//		goto close_prog;
//
//
//	/* Attach tracepoints */
//	err = lsm_bpf__attach(skel);
//	if (CHECK(err, "attach", "lsm attach failed: %d\n", err))
//		goto close_prog;
//
//	if (CHECK(err < 0, "exec_cmd", "err %d errno %d\n", err, errno))
//		goto close_prog;
//
//	CHECK(skel->bss->bprm_count != 1, "bprm_count", "bprm_count = %d\n",
//	      skel->bss->bprm_count);
//
//	skel->bss->monitored_pid = getpid();
//
//	err = stack_mprotect();
//	if (CHECK(errno != EPERM, "stack_mprotect", "want err=EPERM, got %d\n",
//		  errno))
//		goto close_prog;
//
//	CHECK(skel->bss->mprotect_count != 1, "mprotect_count",
//	      "mprotect_count = %d\n", skel->bss->mprotect_count);
//
//	syscall(__NR_setdomainname, &buf, -2L);
//	syscall(__NR_setdomainname, 0, -3L);
//	syscall(__NR_setdomainname, ~0L, -4L);
//
//	CHECK(skel->bss->copy_test != 3, "copy_test",
//	      "copy_test = %d\n", skel->bss->copy_test);
//
//close_prog:
//	lsm_bpf__destroy(skel);
}
