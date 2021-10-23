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

static int fill_payload(struct lcfs_ctx_s *ctx, struct lcfs_node_s *node,
			char *path, size_t len)
{
	size_t old_len = len;
	size_t vdata_len;
	char *vdata;
	char *fname;
	int ret;

	ret = lcfs_get_vdata(ctx, &vdata, &vdata_len);
	if (ret < 0)
		return ret;

	if (node->data.name == 0)
		fname = "";
	else
		fname = vdata + node->data.name;

	if (fname[0]) {
		ret = sprintf(path + len, "/%s", fname);
		if (ret < 0)
			return ret;
		len += ret;
	}

	if (!lcfs_node_dirp(node)) {
		if ((node->inode_data.st_mode & S_IFMT) == S_IFLNK) {
			char target[PATH_MAX + 1];
			ssize_t s = readlink(path, target, sizeof(target));
			if (s < 0)
				return ret;

			target[s] = '\0';
			ret = lcfs_set_payload(ctx, node, target, s + 1);
			if (ret < 0)
				return ret;
		} else {
			ret = lcfs_set_payload(ctx, node, path, len + 1);
			if (ret < 0)
				return ret;
		}
	} else {
		size_t i;

		for (i = 0; i < node->children_size; i++) {
			ret = fill_payload(ctx, node->children[i], path, len);
			if (ret < 0)
				return ret;
			path[len] = '\0';
		}
	}
	path[old_len] = '\0';

	return 0;
}

static void usage(const char *argv0)
{
	fprintf(stderr, "usage: %s [--chdir=/dir] [--relative]\n", argv0);
}

#define OPT_RELATIVE 100
#define OPT_CHDIR 101

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
			name: "chdir",
			has_arg: required_argument,
			flag: NULL,
			val: OPT_CHDIR
		},
		{},
	};
	bool relative_path = false;
	struct lcfs_node_s *node;
	struct lcfs_ctx_s *ctx;
	char cwd[PATH_MAX];
	int opt;
	int fd;

	while ((opt = getopt_long(argc, argv, ":CR", longopts, NULL)) != -1) {
		switch (opt) {
		case OPT_RELATIVE:
			relative_path = true;
			break;
		case OPT_CHDIR:
			if (chdir(optarg) < 0)
				error(EXIT_FAILURE, errno, "chdir");
			break;
		case ':':
			fprintf(stderr, "option needs a value\n");
			exit(EXIT_FAILURE);
		default:
			usage(argv[0]);
			exit(1);
		}
	}

	if (isatty(1))
		error(EXIT_FAILURE, 0, "stdout is a tty.  Refusing to use it");

	argv += optind;
	argc -= optind;

	ctx = lcfs_new_ctx();
	if (ctx == NULL)
		error(EXIT_FAILURE, errno, "new_ctx");

	fd = open(".", O_RDONLY);
	if (fd < 0)
		error(EXIT_FAILURE, errno, "open current directory");

	node = lcfs_build(ctx, NULL, fd, "", "", AT_EMPTY_PATH);
	if (node == NULL)
		error(EXIT_FAILURE, errno, "load current directory node");
	close(fd);

	lcfs_set_root(ctx, node);

	if (relative_path)
		strcpy(cwd, ".");
	else
		getcwd(cwd, sizeof(cwd));

	fill_payload(ctx, node, cwd, strlen(cwd));

	if (lcfs_write_to(ctx, stdout) < 0)
		error(EXIT_FAILURE, errno, "cannot write to stdout");

	lcfs_close(ctx);
	return 0;
}
