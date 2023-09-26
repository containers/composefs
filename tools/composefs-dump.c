/* lcfs
   Copyright (C) 2023 Alexander Larsson <alexl@redhat.com>

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

#include <stdio.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>

static void usage(const char *argv0)
{
	fprintf(stderr, "usage: %s SRC DEST\n", argv0);
}

static ssize_t write_cb(void *_file, void *buf, size_t count)
{
	FILE *file = _file;

	return fwrite(buf, 1, count, file);
}

int main(int argc, char **argv)
{
	const char *bin = argv[0];
	int fd;
	struct lcfs_node_s *root;
	const char *src_path = NULL;
	const char *dst_path = NULL;
	struct lcfs_write_options_s options = { 0 };

	if (argc <= 1) {
		fprintf(stderr, "No source path specified\n");
		usage(bin);
		exit(1);
	}
	src_path = argv[1];

	if (argc <= 2) {
		fprintf(stderr, "No destination path specified\n");
		usage(bin);
		exit(1);
	}
	dst_path = argv[2];

	fd = open(src_path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		err(EXIT_FAILURE, "Failed to open '%s'", src_path);
	}

	root = lcfs_load_node_from_fd(fd);
	if (root == NULL) {
		err(EXIT_FAILURE, "Failed to load '%s'", src_path);
	}

	close(fd);

	options.format = LCFS_FORMAT_EROFS;

	FILE *out_file = fopen(dst_path, "we");
	if (out_file == NULL)
		err(EXIT_FAILURE, "failed to open '%s'", dst_path);

	options.file = out_file;
	options.file_write_cb = write_cb;

	if (lcfs_write_to(root, &options) < 0)
		err(EXIT_FAILURE, "cannot write file");

	lcfs_node_unref(root);

	return 0;
}
