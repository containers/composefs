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

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <linux/limits.h>
#include <linux/loop.h>
#include <linux/mount.h>
#include <linux/fsverity.h>

#include "libcomposefs/lcfs-mount.h"

#define MAX_OBJDIR 10

static void printexit(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);

	exit(1);
}

static void usage(const char *argv0)
{
	fprintf(stderr,
		"usage: %s [--verity] [--digest IMAGEDIGEST] [--objdir DIR] [--upperdir DIR] [--lowerdir DIR] IMAGE MOUNTPOINT\n",
		argv0);
}

#define OPT_OBJDIR 100
#define OPT_UPPERDIR 101
#define OPT_WORKDIR 102
#define OPT_DIGEST 103
#define OPT_REQUIRE_VERITY 104

int main(int argc, char **argv)
{
	const struct option longopts[] = {
		{
			name: "objdir",
			has_arg: required_argument,
			flag: NULL,
			val: OPT_OBJDIR
		},
		{
			name: "upperdirdir",
			has_arg: required_argument,
			flag: NULL,
			val: OPT_UPPERDIR
		},
		{
			name: "workdir",
			has_arg: required_argument,
			flag: NULL,
			val: OPT_WORKDIR
		},
		{
			name: "digest",
			has_arg: required_argument,
			flag: NULL,
			val: OPT_DIGEST
		},
		{
			name: "require-verity",
			has_arg: no_argument,
			flag: NULL,
			val: OPT_REQUIRE_VERITY
		},
		{},
	};
	const char *objdirs[MAX_OBJDIR] = { NULL };
	struct lcfs_mount_options_s options = { .objdirs = objdirs };
	const char *bin = argv[0];
	const char *image_path = NULL;
	const char *mount_path = NULL;
	int opt, fd, res;

	while ((opt = getopt_long(argc, argv, "", longopts, NULL)) != -1) {
		switch (opt) {
		case OPT_OBJDIR:
			if (options.n_objdirs == MAX_OBJDIR) {
				fprintf(stderr, "Too many object dirs\n");
				exit(EXIT_FAILURE);
			}
			options.objdirs[options.n_objdirs++] = optarg;
			break;
		case OPT_UPPERDIR:
			options.upperdir = optarg;
			break;
		case OPT_WORKDIR:
			options.workdir = optarg;
			break;
		case OPT_DIGEST:
			options.expected_digest = optarg;
			options.flags |= LCFS_MOUNT_FLAGS_REQUIRE_VERITY;
			break;
		case OPT_REQUIRE_VERITY:
			options.expected_digest = optarg;
			options.flags |= LCFS_MOUNT_FLAGS_REQUIRE_VERITY;
			break;
		default:
			usage(bin);
			exit(1);
		}
	}

	argv += optind;
	argc -= optind;

	if (argc < 1) {
		fprintf(stderr, "No source image path specified\n");
		usage(bin);
		exit(1);
	}
	image_path = argv[0];

	if (argc < 2) {
		fprintf(stderr, "No mount path specified\n");
		usage(bin);
		exit(1);
	}
	mount_path = argv[1];

	if (options.n_objdirs == 0) {
		fprintf(stderr, "No object dirs specified\n");
		usage(bin);
		exit(1);
	}

	if ((options.upperdir && !options.workdir) ||
	    (!options.upperdir && options.workdir)) {
		printexit("Both workdir and upperdir must be specified if used\n");
	}

	fd = open(image_path, O_RDONLY);
	if (fd < 0)
		printexit("Failed to open %s: %s\n", image_path, strerror(errno));

	res = lcfs_mount_fd(fd, mount_path, &options);
	if (res < 0) {
		int errsv = errno;

		if (errsv == ENOVERITY)
			printexit("Failed to mount composefs %s: Image has no fs-verity\n",
				  image_path);
		else if (errsv == EWRONGVERITY)
			printexit("Failed to mount composefs %s: Image has wrong fs-verity\n",
				  image_path);

		printexit("Failed to mount composefs %s: %s\n", image_path,
			  strerror(errno));
	}

	return 0;
}
