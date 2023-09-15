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

#include "libcomposefs/lcfs-writer.h"
#include "libcomposefs/lcfs-utils.h"
#include "read-file.h"

#include <stdio.h>
#include <linux/limits.h>
#include <string.h>
#include <error.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <yajl/yajl_tree.h>
#include <getopt.h>
#include <sys/prctl.h>
#include <sched.h>
#include <sys/mount.h>
#ifdef HAVE_SYS_CAPABILITY_H
#include <sys/capability.h>
#endif
#ifdef HAVE_LIBSECCOMP
#include <linux/seccomp.h>
#include <seccomp.h>
#endif
#include <time.h>

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
		SCMP_SYS(newfstatat), SCMP_SYS(read),	SCMP_SYS(sysinfo),
		SCMP_SYS(write),
	};

	ctx = seccomp_init(SCMP_ACT_ERRNO(ENOSYS));
	if (ctx == NULL)
		error(EXIT_FAILURE, errno, "seccomp_init");

	for (i = 0; i < sizeof(syscalls) / sizeof(syscalls[0]); i++) {
		ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, syscalls[i], 0);
		if (ret < 0)
			error(EXIT_FAILURE, -ret, "seccomp_rule_add");
	}

	ret = seccomp_load(ctx);
	if (ret < 0)
		error(EXIT_FAILURE, -ret, "seccomp_load");
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
		error(EXIT_FAILURE, errno, "open /proc/self/setgroups");
	ret = write(fd, "deny", 4);
	if (ret < 0)
		error(EXIT_FAILURE, errno, "write to /proc/self/gid_map");
	close(fd);

	fd = open("/proc/self/gid_map", O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		error(EXIT_FAILURE, errno, "open /proc/self/gid_map");
	ret = dprintf(fd, "0 %d 1\n", gid);
	if (ret < 0)
		error(EXIT_FAILURE, errno, "write to /proc/self/gid_map");
	close(fd);

	fd = open("/proc/self/uid_map", O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		error(EXIT_FAILURE, errno, "open /proc/self/uid_map");
	ret = dprintf(fd, "0 %d 1\n", uid);
	if (ret < 0)
		error(EXIT_FAILURE, errno, "write to /proc/self/uid_map");
	close(fd);

#ifdef __NR_pivot_root
	ret = mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL);
	if (ret < 0)
		error(EXIT_FAILURE, errno, "mount /");

	cwd = get_current_dir_name();
	if (!cwd)
		error(EXIT_FAILURE, errno, "get_current_dir_name");

	ret = mount(NULL, cwd, "tmpfs", 0, NULL);
	if (ret < 0)
		error(EXIT_FAILURE, errno, "mount tmpfs");

	old_root = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC);
	if (old_root < 0)
		error(EXIT_FAILURE, errno, "open /");

	ret = chdir(cwd);
	if (ret < 0)
		error(EXIT_FAILURE, errno, "chdir cwd");

	free(cwd);
	cwd = NULL;

	ret = pivot_root(".", ".");
	if (ret < 0)
		error(EXIT_FAILURE, errno, "pivot_root");

	ret = fchdir(old_root);
	if (ret < 0)
		error(EXIT_FAILURE, errno, "fchdir");
	close(old_root);

	ret = umount2(".", MNT_DETACH);
	if (ret < 0)
		error(EXIT_FAILURE, errno, "umount2");

	ret = chdir("/");
	if (ret < 0)
		error(EXIT_FAILURE, errno, "fchdir");
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
		error(EXIT_FAILURE, errno, "prctl(PR_SET_KEEPCAPS)");

	for (cap = 0;; cap++) {
		ret = prctl(PR_CAPBSET_DROP, cap, 0, 0, 0);
		if (ret < 0 && errno != EINVAL)
			error(EXIT_FAILURE, errno, "prctl(PR_CAPBSET_DROP)");
		if (ret < 0)
			break;
	}

#ifdef PR_CAP_AMBIENT
	ret = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);
	if (ret < 0 && errno != EINVAL)
		error(EXIT_FAILURE, errno, "prctl(PR_CAP_AMBIENT)");
#endif

#ifdef HAVE_SYS_CAPABILITY_H
	ret = capset(&hdr, data);
	if (ret < 0 && errno != EINVAL)
		error(EXIT_FAILURE, errno, "capset");
#endif
}

static void do_set_oom_score_adj(void)
{
	int fd, ret;

	fd = open("/proc/self/oom_score_adj", O_WRONLY);
	if (fd < 0)
		error(EXIT_FAILURE, errno, "open /proc/self/oom_score_adj");

	ret = write(fd, "1000", 4);
	if (ret < 0)
		error(EXIT_FAILURE, errno, "write to /proc/self/oom_score_adj");

	close(fd);
}

static void sandbox(void)
{
	do_set_oom_score_adj();
	do_namespace_sandbox();
	drop_caps();

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
		error(EXIT_FAILURE, errno, "prctl(PR_SET_NO_NEW_PRIVS)");

	do_seccomp_sandbox();
}

/* Adapted from mailutils 0.6.91(distributed under LGPL 2.0+)  */
static int b64_input(char c)
{
	const char table[64] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	int i;

	for (i = 0; i < 64; i++) {
		if (table[i] == c)
			return i;
	}
	return -1;
}

static int base64_decode(const char *iptr, size_t isize, char *optr,
			 size_t osize, size_t *nbytes)
{
	int i = 0, tmp = 0, pad = 0;
	size_t consumed = 0;
	unsigned char data[4];

	*nbytes = 0;
	while (consumed < isize && (*nbytes) + 3 < osize) {
		while ((i < 4) && (consumed < isize)) {
			tmp = b64_input(*iptr++);
			consumed++;
			if (tmp != -1)
				data[i++] = tmp;
			else if (*(iptr - 1) == '=') {
				data[i++] = '\0';
				pad++;
			}
		}

		/* I have a entire block of data 32 bits get the output data.  */
		if (i == 4) {
			*optr++ = (data[0] << 2) | ((data[1] & 0x30) >> 4);
			*optr++ = ((data[1] & 0xf) << 4) | ((data[2] & 0x3c) >> 2);
			*optr++ = ((data[2] & 0x3) << 6) | data[3];
			(*nbytes) += 3 - pad;
		} else {
			/* I did not get all the data.  */
			consumed -= i;
			return consumed;
		}
		i = 0;
	}
	return consumed;
}

static yajl_val parse_file(FILE *f)
{
	size_t l;
	yajl_val node;
	char *content;
	char errbuf[1024];

	content = fread_file(f, &l);
	if (content == NULL)
		return NULL;

	errbuf[0] = '\0';

	node = yajl_tree_parse(content, errbuf, sizeof(errbuf));
	free(content);
	if (node == NULL) {
		fprintf(stderr, "parse_error: %s\n", errbuf);
		return NULL;
	}

	return node;
}

static yajl_val get_child(yajl_val node, const char *name, int type)
{
	const char *path[] = { name, NULL };

	return yajl_tree_get(node, path, type);
}

static struct lcfs_node_s *append_child(struct lcfs_node_s *dir, const char *name)
{
	struct lcfs_node_s *child;
	struct lcfs_node_s *parent;

	for (parent = dir; parent != NULL; parent = lcfs_node_get_parent(parent)) {
		if (lcfs_node_get_mode(parent) == 0) {
			lcfs_node_set_mode(parent, 0755 | S_IFDIR);
		}
	}

	child = lcfs_node_new();
	if (child == NULL)
		return NULL;

	if (lcfs_node_add_child(dir, child, name) < 0) {
		lcfs_node_unref(child);
		return NULL;
	}

	return child;
}

static int fill_xattrs(struct lcfs_node_s *node, yajl_val xattrs)
{
	size_t i;
	char v_buffer[4096];

	if (!YAJL_IS_OBJECT(xattrs))
		return 0;

	for (i = 0; i < YAJL_GET_OBJECT(xattrs)->len; i++) {
		int r;
		size_t written;
		const char *v, *k = YAJL_GET_OBJECT(xattrs)->keys[i];

		if (!YAJL_IS_STRING(YAJL_GET_OBJECT(xattrs)->values[i])) {
			error(0, 0, "xattr value is not a string");
			return -1;
		}

		v = YAJL_GET_STRING(YAJL_GET_OBJECT(xattrs)->values[i]);

		r = base64_decode(v, strlen(v), v_buffer, sizeof(v_buffer), &written);
		if (r < 0) {
			error(0, 0, "xattr value is not valid b64");
			return -1;
		}

		r = lcfs_node_set_xattr(node, k, v_buffer, written);
		if (r < 0) {
			error(0, 0, "append xattr");
			return -1;
		}
	}

	return 0;
}

static struct lcfs_node_s *get_node(struct lcfs_node_s *root, const char *what)
{
	char *path, *dpath, *it;
	struct lcfs_node_s *node = root;

	path = strdup(what);
	if (path == NULL)
		return NULL;

	dpath = path;
	while ((it = strsep(&dpath, "/"))) {
		if (node == root && strcmp(it, "..") == 0)
			continue;
		node = lcfs_node_lookup_child(node, it);
		if (!node)
			break;
	}

	free(path);
	return node;
}

static void parse_time(const char *time, struct timespec *ts)
{
	struct tm tm;
	time_t t;
	long gmtoff;

	memset(&tm, 0, sizeof(tm));
	strptime(time, "%Y-%m-%dT%H:%M:%S%z", &tm);
	gmtoff = tm.tm_gmtoff;

	tm.tm_isdst = -1;
	t = timegm(&tm);
	ts->tv_sec = t - gmtoff;
	ts->tv_nsec = 0;
}

static int fill_file(const char *typ, struct lcfs_node_s *root,
		     struct lcfs_node_s *node, yajl_val entry)
{
	const char *payload = NULL;
	const char *content = NULL;
	char payload_buffer[128];
	uint16_t min = 0, maj = 0;
	mode_t mode = 0;
	yajl_val v;
	int res;
	bool is_regular_file = false;

	if (node == NULL) {
		error(0, 0, "node is NULL");
		return 0;
	}

	if (strcmp(typ, "reg") == 0) {
		mode |= S_IFREG;
		is_regular_file = true;
	} else if (strcmp(typ, "dir") == 0)
		mode |= S_IFDIR;
	else if (strcmp(typ, "char") == 0)
		mode |= S_IFCHR;
	else if (strcmp(typ, "block") == 0)
		mode |= S_IFBLK;
	else if (strcmp(typ, "fifo") == 0)
		mode |= S_IFIFO;
	else if (strcmp(typ, "symlink") == 0) {
		mode |= S_IFLNK;

		v = get_child(entry, "linkName", yajl_t_string);
		if (!v) {
			error(0, 0, "linkName not specified");
			return -1;
		}

		payload = YAJL_GET_STRING(v);
	} else if (strcmp(typ, "hardlink") == 0) {
		struct lcfs_node_s *target;

		mode |= S_IFREG;

		v = get_child(entry, "linkName", yajl_t_string);
		if (!v) {
			error(0, 0, "linkName not specified");
			return -1;
		}

		target = get_node(root, YAJL_GET_STRING(v));
		if (!target) {
			error(0, 0, "could not find target %s", YAJL_GET_STRING(v));
			return -1;
		}

		lcfs_node_make_hardlink(node, target);
	}

	v = get_child(entry, "mode", yajl_t_number);
	if (v)
		mode |= (YAJL_GET_INTEGER(v));

	lcfs_node_set_mode(node, mode);

	v = get_child(entry, "uid", yajl_t_number);
	if (v)
		lcfs_node_set_uid(node, YAJL_GET_INTEGER(v));

	v = get_child(entry, "gid", yajl_t_number);
	if (v)
		lcfs_node_set_gid(node, YAJL_GET_INTEGER(v));

	if ((mode & S_IFMT) != S_IFDIR) {
		v = get_child(entry, "size", yajl_t_number);
		if (v)
			lcfs_node_set_size(node, YAJL_GET_INTEGER(v));
	}

	v = get_child(entry, "modtime", yajl_t_string);
	if (v) {
		struct timespec ts;
		parse_time(YAJL_GET_STRING(v), &ts);
		lcfs_node_set_mtime(node, &ts);
	}

	v = get_child(entry, "devMinor", yajl_t_number);
	if (v)
		min = YAJL_GET_INTEGER(v);
	v = get_child(entry, "devMajor", yajl_t_number);
	if (v)
		maj = YAJL_GET_INTEGER(v);

	lcfs_node_set_rdev(node, makedev(maj, min));

	/* custom extension to the CRFS format.  */
	v = get_child(entry, "x-payload", yajl_t_string);
	if (v)
		payload = YAJL_GET_STRING(v);
	if (payload == NULL && is_regular_file) {
		char *tmp = NULL;
		v = get_child(entry, "digest", yajl_t_string);
		if (v) {
			tmp = YAJL_GET_STRING(v);
		}
		if (tmp) {
			if (strncmp(tmp, "sha256:", 7) == 0)
				tmp += 7;
			snprintf(payload_buffer, sizeof(payload_buffer) - 1,
				 "%.*s/%s", 2, tmp, tmp + 2);
			payload_buffer[sizeof(payload_buffer) - 1] = '\0';
			payload = payload_buffer;
		}
	}

	if (payload) {
		int r;

		r = lcfs_node_set_payload(node, payload);
		if (r < 0) {
			error(0, 0, "set_payload");
			return -1;
		}
	}

	/* custom extension to the CRFS format.  */
	v = get_child(entry, "x-content", yajl_t_string);
	if (v)
		content = YAJL_GET_STRING(v);
	if (content) {
		int r;
		size_t buf_size = strlen(content); /* Enough to fit base64 decoded value */
		size_t written;
		cleanup_free uint8_t *buf = malloc(buf_size);

		if (buf == NULL) {
			error(0, 0, "malloc");
			return -1;
		}

		r = base64_decode(content, strlen(content), (char *)buf,
				  buf_size, &written);
		if (r < 0) {
			error(0, 0, "x-content value is not valid b64");
			return -1;
		}

		r = lcfs_node_set_content(node, buf, written);
		if (r < 0) {
			error(0, 0, "set_content");
			return -1;
		}
	}

	v = get_child(entry, "xattrs", yajl_t_object);
	if (v) {
		res = fill_xattrs(node, v);
		if (res < 0)
			return -1;
	}

	return 0;
}

static struct lcfs_node_s *get_or_add_node(const char *typ,
					   struct lcfs_node_s *root, yajl_val entry)
{
	yajl_val tmp;
	char *path, *dpath, *it;
	struct lcfs_node_s *node = root;
	int res;

	tmp = get_child(entry, "name", yajl_t_string);
	if (tmp == NULL) {
		error(0, 0, "entry has no name");
		return NULL;
	}

	it = YAJL_GET_STRING(tmp);
	if (it == NULL) {
		error(0, 0, "name is not a string");
		return NULL;
	}

	path = strdup(it);
	if (path == NULL)
		error(EXIT_FAILURE, errno, "strdup");

	dpath = path;
	while ((it = strsep(&dpath, "/"))) {
		struct lcfs_node_s *c;

		if (it[0] == '\0' || strcmp(it, ".") == 0)
			continue;

		c = lcfs_node_lookup_child(node, it);
		if (c) {
			node = c;
			continue;
		}

		node = append_child(node, it);
		if (node == NULL) {
			error(0, errno, "append_child");
			return NULL;
		}
	}

	free(path);

	res = fill_file(typ, root, node, entry);
	if (res < 0) {
		return NULL;
	}
	return node;
}

static void do_file(struct lcfs_node_s *root, FILE *file)
{
	yajl_val entries, root_val, tmp;
	size_t i;

	root_val = parse_file(file);
	if (root_val == NULL)
		error(EXIT_FAILURE, errno, "parse_file");

	if (!YAJL_IS_OBJECT(root_val))
		error(EXIT_FAILURE, 0, "invalid type for root");

	entries = get_child(root_val, "entries", yajl_t_array);
	if (entries == NULL)
		error(EXIT_FAILURE, 0, "cannot find any entry");

	for (i = 0; i < YAJL_GET_ARRAY(entries)->len; i++) {
		static struct lcfs_node_s *n;
		const char *typ;
		yajl_val entry = YAJL_GET_ARRAY(entries)->values[i];

		tmp = get_child(entry, "type", yajl_t_string);
		if (tmp == NULL)
			error(EXIT_FAILURE, 0, "entry has no name");

		typ = YAJL_GET_STRING(tmp);

		/* Skip chunks.  */
		if (typ == NULL || (strcmp(typ, "chunk") == 0))
			continue;

		n = get_or_add_node(typ, root, entry);
		if (n == NULL)
			error(EXIT_FAILURE, 0, "get_or_add_node");
	}

	yajl_tree_free(root_val);
}

#define OPT_OUT 100
#define OPT_FORMAT 101
#define OPT_NO_SANDBOX 102

static void usage(const char *argv0)
{
	fprintf(stderr,
		"usage: %s [--out=filedname] [--format=erofs] [--no-sandbox] jsonfile...\n",
		argv0);
}

static ssize_t write_cb(void *_file, void *buf, size_t count)
{
	FILE *file = _file;

	return fwrite(buf, 1, count, file);
}

int main(int argc, char **argv)
{
	const struct option longopts[] = {
		{
			name: "out",
			has_arg: required_argument,
			flag: NULL,
			val: OPT_OUT
		},
		{
			name: "format",
			has_arg: required_argument,
			flag: NULL,
			val: OPT_FORMAT
		},
		{ name: "no-sandbox", flag: NULL, val: OPT_NO_SANDBOX },
		{},
	};
	struct lcfs_node_s *root;
	struct lcfs_write_options_s options = { 0 };
	const char *format = "erofs";
	ssize_t i;
	int opt;
	const char *out = NULL;
	FILE *out_file;
	cleanup_free FILE **input_files = NULL;
	bool no_sandbox = false;

	tzset();

	while ((opt = getopt_long(argc, argv, ":CR", longopts, NULL)) != -1) {
		switch (opt) {
		case OPT_OUT:
			out = optarg;
			break;
		case OPT_FORMAT:
			format = optarg;
			break;
		case OPT_NO_SANDBOX:
			no_sandbox = true;
			break;
		case ':':
			fprintf(stderr, "option needs a value\n");
			exit(EXIT_FAILURE);
		default:
			usage(argv[0]);
			exit(1);
		}
	}

	argv += optind;
	argc -= optind;

	if (out != NULL) {
		out_file = fopen(out, "we");
		if (out_file == NULL)
			error(EXIT_FAILURE, errno, "Failed to open output file");
	} else {
		if (isatty(1))
			error(EXIT_FAILURE, 0, "stdout is a tty.  Refusing to use it");
		out_file = stdout;
	}

	input_files = malloc(sizeof(FILE *) * argc);
	if (input_files == NULL)
		error(EXIT_FAILURE, errno, "malloc");

	for (i = 0; i < argc; i++) {
		if (strcmp(argv[i], "-") == 0) {
			input_files[i] = stdin;
		} else {
			input_files[i] = fopen(argv[i], "re");
			if (input_files[i] == NULL)
				error(EXIT_FAILURE, errno, "open `%s`", argv[i]);
		}
	}

	if (!no_sandbox)
		sandbox();

	root = lcfs_node_new();
	if (root == NULL)
		error(EXIT_FAILURE, errno, "malloc");

	for (i = 0; i < argc; i++) {
		do_file(root, input_files[i]);
		fclose(input_files[i]);
		input_files[i] = NULL;
	}

	options.format = LCFS_FORMAT_EROFS;
	options.file = out_file;
	options.file_write_cb = write_cb;

	if (strcmp(format, "erofs") == 0) {
		options.format = LCFS_FORMAT_EROFS;
	} else {
		error(EXIT_FAILURE, errno, "Unknown format %s", format);
	}

	if (lcfs_write_to(root, &options) < 0)
		error(EXIT_FAILURE, errno, "cannot write to stdout");

	if (fflush(out_file) < 0)
		error(EXIT_FAILURE, errno, "fflush");

	if (fclose(out_file) < 0)
		error(EXIT_FAILURE, errno, "fclose");

	lcfs_node_unref(root);

	return 0;
}
