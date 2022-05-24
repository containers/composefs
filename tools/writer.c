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

#include "lcfs.h"
#include "lcfs-writer.h"

#include <stdio.h>
#include <linux/limits.h>
#include <string.h>
#include <error.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <getopt.h>

static int fill_payload(struct lcfs_node_s *node,
			char *path, size_t len)
{
	size_t old_len = len;
	const char *fname;
	int ret;

        fname = lcfs_node_get_name(node);

	if (fname) {
		ret = sprintf(path + len, "/%s", fname);
		if (ret < 0)
			return ret;
		len += ret;
	}

	if (lcfs_node_dirp(node)) {
		size_t i, n_children;

		n_children = lcfs_node_get_n_children(node);
		for (i = 0; i < n_children; i++) {
			struct lcfs_node_s *child = lcfs_node_get_child(node, i);
			ret = fill_payload(child, path, len);
			if (ret < 0)
				return ret;
			path[len] = '\0';
		}
	} else if ((lcfs_node_get_mode(node) & S_IFMT) == S_IFLNK) {
		char target[PATH_MAX + 1];
		ssize_t s = readlink(path, target, sizeof(target));
		if (s < 0)
			return ret;

		target[s] = '\0';
		ret = lcfs_node_set_payload(node, target);
		if (ret < 0)
			return ret;
	} else if ((lcfs_node_get_mode(node) & S_IFMT) == S_IFREG) {
		ret = lcfs_node_set_payload(node, path);
		if (ret < 0)
			return ret;
	}
	path[old_len] = '\0';

	return 0;
}

static void usage(const char *argv0)
{
	fprintf(stderr,
		"usage: %s [--chdir=/dir] [--use-epoch] [--skip-xattrs] [--relative] [--skip-devices] [--out=filedname]\n",
		argv0);
}

#define OPT_RELATIVE 100
#define OPT_CHDIR 101
#define OPT_SKIP_XATTRS 102
#define OPT_USE_EPOCH 103
#define OPT_SKIP_DEVICES 104
#define OPT_OUT 105

int main(int argc, char **argv)
{
	const struct option longopts[] = {
		{
			name: "relative",
			has_arg: no_argument,
			flag: NULL,
			val: OPT_RELATIVE
		},
		{
			name: "skip-xattrs",
			has_arg: no_argument,
			flag: NULL,
			val: OPT_SKIP_XATTRS
		},
		{
			name: "skip-devices",
			has_arg: no_argument,
			flag: NULL,
			val: OPT_SKIP_DEVICES
		},
		{
			name: "use-epoch",
			has_arg: no_argument,
			flag: NULL,
			val: OPT_USE_EPOCH
		},
		{
			name: "chdir",
			has_arg: required_argument,
			flag: NULL,
			val: OPT_CHDIR
		},
		{
			name: "out",
			has_arg: required_argument,
			flag: NULL,
			val: OPT_OUT
		},
		{},
	};
	int buildflags = 0;
	bool relative_path = false;
	struct lcfs_node_s *root;
	const char *out = NULL;
	const char *chdir_path = NULL;
	char cwd[PATH_MAX];
	int opt;
	int fd;
	FILE *out_file;

	while ((opt = getopt_long(argc, argv, ":CR", longopts, NULL)) != -1) {
		switch (opt) {
		case OPT_USE_EPOCH:
			buildflags |= BUILD_USE_EPOCH;
			break;
		case OPT_SKIP_XATTRS:
			buildflags |= BUILD_SKIP_XATTRS;
			break;
		case OPT_SKIP_DEVICES:
			buildflags |= BUILD_SKIP_DEVICES;
			break;
		case OPT_RELATIVE:
			relative_path = true;
			break;
		case OPT_CHDIR:
			chdir_path = optarg;
			break;
		case OPT_OUT:
			out = optarg;
			break;
		case ':':
			fprintf(stderr, "option needs a value\n");
			exit(EXIT_FAILURE);
		default:
			usage(argv[0]);
			exit(1);
		}
	}

	if (out != NULL) {
		out_file = fopen(out, "w");
		if (out_file == NULL)
			error(EXIT_FAILURE, errno, "Failed to open output file");
	} else {
		if (isatty(1))
			error(EXIT_FAILURE, 0, "stdout is a tty.  Refusing to use it");
		out_file = stdout;
	}

	if (chdir_path &&
	    chdir(chdir_path) < 0)
		error(EXIT_FAILURE, errno, "chdir");

	argv += optind;
	argc -= optind;

	fd = open(".", O_RDONLY);
	if (fd < 0)
		error(EXIT_FAILURE, errno, "open current directory");

	root = lcfs_build(NULL, fd, "", "", AT_EMPTY_PATH, buildflags);
	if (root == NULL)
		error(EXIT_FAILURE, errno, "load current directory node");

	if (relative_path)
		strcpy(cwd, ".");
	else
		getcwd(cwd, sizeof(cwd));

	fill_payload(root, cwd, strlen(cwd));

	if (lcfs_write_to(root, out_file) < 0)
		error(EXIT_FAILURE, errno, "cannot write to stdout");

	return 0;
}
