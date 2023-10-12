/* lcfs
   Copyright (C) 2021 Giuseppe Scrivano <giuseppe@scrivano.org>

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#define _GNU_SOURCE

#include "config.h"

#include "sandbox.h"

#include <err.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#ifdef HAVE_SYS_CAPABILITY_H
#include <sys/capability.h>
#endif
#ifdef HAVE_LIBSECCOMP
#include <linux/seccomp.h>
#include <seccomp.h>
#endif

static void do_seccomp_sandbox(void)
{
#ifdef HAVE_LIBSECCOMP
	scmp_filter_ctx ctx;
	int ret;
	size_t i;
	int syscalls[] = {
		SCMP_SYS(brk),	      SCMP_SYS(close),	SCMP_SYS(exit),
		SCMP_SYS(exit_group), SCMP_SYS(fstat),	SCMP_SYS(lseek),
		SCMP_SYS(mmap),	      SCMP_SYS(mremap), SCMP_SYS(munmap),
		SCMP_SYS(newfstatat), SCMP_SYS(read),	SCMP_SYS(readv),
		SCMP_SYS(sysinfo),    SCMP_SYS(write),	SCMP_SYS(writev),
	};

	ctx = seccomp_init(SCMP_ACT_ERRNO(ENOSYS));
	if (ctx == NULL)
		err(EXIT_FAILURE, "seccomp_init");

	for (i = 0; i < sizeof(syscalls) / sizeof(syscalls[0]); i++) {
		ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, syscalls[i], 0);
		if (ret < 0) {
			errno = -ret;
			err(EXIT_FAILURE, "seccomp_rule_add");
		}
	}

	ret = seccomp_load(ctx);
	if (ret < 0) {
		errno = -ret;
		err(EXIT_FAILURE, "seccomp_load");
	}
#endif
}

#ifdef __NR_pivot_root
static int pivot_root(const char *new_root, const char *put_old)
{
	return syscall(__NR_pivot_root, new_root, put_old);
}
#endif

static void do_namespace_sandbox(void)
{
	uid_t uid = geteuid();
	gid_t gid = getegid();
	int ret, fd;
#ifdef __NR_pivot_root
	int old_root;
	char *cwd;
#endif

	ret = unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWUTS |
		      CLONE_NEWIPC | CLONE_NEWNET);
	if (ret < 0)
		return;

	fd = open("/proc/self/setgroups", O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		err(EXIT_FAILURE, "open /proc/self/setgroups");
	ret = write(fd, "deny", 4);
	if (ret < 0)
		err(EXIT_FAILURE, "write to /proc/self/gid_map");
	close(fd);

	fd = open("/proc/self/gid_map", O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		err(EXIT_FAILURE, "open /proc/self/gid_map");
	ret = dprintf(fd, "0 %d 1\n", gid);
	if (ret < 0)
		err(EXIT_FAILURE, "write to /proc/self/gid_map");
	close(fd);

	fd = open("/proc/self/uid_map", O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		err(EXIT_FAILURE, "open /proc/self/uid_map");
	ret = dprintf(fd, "0 %d 1\n", uid);
	if (ret < 0)
		err(EXIT_FAILURE, "write to /proc/self/uid_map");
	close(fd);

#ifdef __NR_pivot_root
	ret = mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL);
	if (ret < 0)
		err(EXIT_FAILURE, "mount /");

	cwd = get_current_dir_name();
	if (!cwd)
		err(EXIT_FAILURE, "get_current_dir_name");

	ret = mount(NULL, cwd, "tmpfs", 0, NULL);
	if (ret < 0)
		err(EXIT_FAILURE, "mount tmpfs");

	old_root = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC);
	if (old_root < 0)
		err(EXIT_FAILURE, "open /");

	ret = chdir(cwd);
	if (ret < 0)
		err(EXIT_FAILURE, "chdir cwd");

	free(cwd);
	cwd = NULL;

	ret = pivot_root(".", ".");
	if (ret < 0)
		err(EXIT_FAILURE, "pivot_root");

	ret = fchdir(old_root);
	if (ret < 0)
		err(EXIT_FAILURE, "fchdir");
	close(old_root);

	ret = umount2(".", MNT_DETACH);
	if (ret < 0)
		err(EXIT_FAILURE, "umount2");

	ret = chdir("/");
	if (ret < 0)
		err(EXIT_FAILURE, "fchdir");
#endif
}

static void drop_caps(void)
{
#ifdef HAVE_SYS_CAPABILITY_H
	struct __user_cap_header_struct hdr = { _LINUX_CAPABILITY_VERSION_3, 0 };
	struct __user_cap_data_struct data[2] = { { 0 } };
#endif
	int ret, cap;
	ret = prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0);
	if (ret < 0)
		err(EXIT_FAILURE, "prctl(PR_SET_KEEPCAPS)");

	for (cap = 0;; cap++) {
		ret = prctl(PR_CAPBSET_DROP, cap, 0, 0, 0);
		if (ret < 0 && errno != EINVAL)
			err(EXIT_FAILURE, "prctl(PR_CAPBSET_DROP)");
		if (ret < 0)
			break;
	}

#ifdef PR_CAP_AMBIENT
	ret = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);
	if (ret < 0 && errno != EINVAL)
		err(EXIT_FAILURE, "prctl(PR_CAP_AMBIENT)");
#endif

#ifdef HAVE_SYS_CAPABILITY_H
	ret = capset(&hdr, data);
	if (ret < 0 && errno != EINVAL)
		err(EXIT_FAILURE, "capset");
#endif
}

static void do_set_oom_score_adj(void)
{
	int fd, ret;

	fd = open("/proc/self/oom_score_adj", O_WRONLY);
	if (fd < 0)
		err(EXIT_FAILURE, "open /proc/self/oom_score_adj");

	ret = write(fd, "1000", 4);
	if (ret < 0)
		err(EXIT_FAILURE, "write to /proc/self/oom_score_adj");

	close(fd);
}

void sandbox(void)
{
	do_set_oom_score_adj();
	do_namespace_sandbox();
	drop_caps();

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
		err(EXIT_FAILURE, "prctl(PR_SET_NO_NEW_PRIVS)");

	do_seccomp_sandbox();
}
