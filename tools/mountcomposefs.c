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

#include <err.h>
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

static void usage(const char *argv0)
{
	const char *bin = basename(argv0);
	fprintf(stderr,
		"usage: %s [-t type] [-o opt[,opts..]] IMAGE MOUNTPOINT\n"
		"Example:\n"
		"  %s -o basedir=/composefs/objects exampleimage.cfs /mnt/exampleimage\n"
		"or, as a mount helper:\n"
		"  mount -t composefs -o basedir=/composefs/objects exampleimage.cfs /mnt/exampleimage\n"
		"\n"
		"Supported options:\n"
		"  basedir=PATH[:PATH]    Specify location of basedir(s)\n"
		"  digest=DIGEST          Specify required image digest\n"
		"  idmap=PATH             Specify path to a user namespace whose ID mapping should be used\n"
		"  verity                 Require all files to have specified and valid fs-verity digests\n"
		"  tryverity              If supported by kernel, require fs-verity\n"
		"  ro                     Read only\n"
		"  rw                     Read/write\n"
		"  upperdir               Overlayfs upperdir\n"
		"  workdir                Overlayfs workdir\n",
		bin, bin);
}

static void unescape_option(char *s)
{
	char *d = s;

	for (;; s++, d++) {
		if (*s == '\\')
			s++;
		*d = *s;
		if (!*s)
			break;
	}
}

static char *parse_option(char *options, char **key, char **value)
{
	char *p, *equal, *next;
	;

	equal = NULL;
	for (p = options; *p; p++) {
		if (*p == '=' && equal == NULL)
			equal = p;
		else if (*p == '\\' && p[1] != 0)
			p++;
		else if (*p == ',')
			break;
	}

	if (*p)
		next = p + 1;
	else
		next = NULL;
	*p = 0;

	*key = options;
	if (equal) {
		*equal = 0;
		*value = equal + 1;
		unescape_option(*value);
	} else {
		*value = NULL;
	}

	return next;
}

int main(int argc, char **argv)
{
	struct lcfs_mount_options_s options = { 0 };
	const char *bin = argv[0];
	char *mount_options = NULL;
	const char *image_path = NULL;
	const char *mount_path = NULL;
	const char *opt_basedir = NULL;
	const char *opt_digest = NULL;
	const char *opt_idmap = NULL;
	const char *opt_upperdir = NULL;
	const char *opt_workdir = NULL;
	bool opt_verity = false;
	bool opt_tryverity = false;
	bool opt_ro = false;
	int opt, fd, res, userns_fd;

	while ((opt = getopt(argc, argv, "ht:o:")) != -1) {
		switch (opt) {
		case 't':
			if (strcmp(optarg, "composefs") != 0)
				errx(EXIT_FAILURE, "Unsupported fs type '%s'\n",
				     optarg);
			break;
		case 'o':
			mount_options = optarg;
			break;
		case 'h':
			usage(bin);
			exit(0);
		default:
			usage(bin);
			exit(1);
		}
	}

	argv += optind;
	argc -= optind;

	if (argc < 1) {
		fprintf(stderr, "No source path specified\n");
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

	while (mount_options) {
		char *key, *value;
		mount_options = parse_option(mount_options, &key, &value);

		if (strcmp("basedir", key) == 0) {
			if (value == NULL)
				errx(EXIT_FAILURE,
				     "No value specified for basedir option\n");
			opt_basedir = value;
		} else if (strcmp("digest", key) == 0) {
			if (value == NULL)
				errx(EXIT_FAILURE,
				     "No value specified for digest option\n");
			opt_digest = value;
		} else if (strcmp("verity", key) == 0) {
			opt_verity = true;
		} else if (strcmp("tryverity", key) == 0) {
			opt_tryverity = true;
		} else if (strcmp("upperdir", key) == 0) {
			if (value == NULL)
				errx(EXIT_FAILURE,
				     "No value specified for upperdir option\n");
			opt_upperdir = value;
		} else if (strcmp("workdir", key) == 0) {
			if (value == NULL)
				errx(EXIT_FAILURE,
				     "No value specified for workdir option\n");
			opt_workdir = value;
		} else if (strcmp("idmap", key) == 0) {
			if (value == NULL)
				errx(EXIT_FAILURE,
				     "No value specified for idmap option\n");
			opt_idmap = value;
		} else if (strcmp("rw", key) == 0) {
			opt_ro = false;
		} else if (strcmp("ro", key) == 0) {
			opt_ro = true;
		} else {
			errx(EXIT_FAILURE, "Unsupported option %s\n", key);
		}
	}

	if (opt_basedir != NULL) {
		int i;
		char *str, *token, *saveptr;

		options.n_objdirs = 1;
		for (str = (char *)opt_basedir; *str; str++) {
			if (*str == ':')
				options.n_objdirs++;
		}

		options.objdirs = calloc(options.n_objdirs, sizeof(char *));
		if (options.objdirs == NULL)
			errx(EXIT_FAILURE, "Out of memory\n");

		for (i = 0, str = (char *)opt_basedir;; i++, str = NULL) {
			token = strtok_r(str, ":", &saveptr);
			if (token == NULL)
				break;
			options.objdirs[i] = token;
		}
	}

	if (options.n_objdirs == 0) {
		fprintf(stderr, "No object dirs specified\n");
		usage(bin);
		exit(1);
	}

	if ((opt_upperdir && !opt_workdir) || (!opt_upperdir && opt_workdir)) {
		errx(EXIT_FAILURE,
		     "Both workdir and upperdir must be specified if used\n");
	}
	options.upperdir = opt_upperdir;
	options.workdir = opt_workdir;

	options.expected_fsverity_digest = opt_digest;

	if (opt_verity || opt_digest != NULL)
		options.flags |= LCFS_MOUNT_FLAGS_REQUIRE_VERITY;
	else if (opt_tryverity)
		options.flags |= LCFS_MOUNT_FLAGS_TRY_VERITY;
	if (opt_ro)
		options.flags |= LCFS_MOUNT_FLAGS_READONLY;

	if (opt_idmap != NULL) {
		userns_fd = open(opt_idmap, O_RDONLY | O_CLOEXEC | O_NOCTTY);
		if (userns_fd < 0)
			errx(EXIT_FAILURE, "Failed to open userns %s: %s\n",
			     opt_idmap, strerror(errno));
		options.flags |= LCFS_MOUNT_FLAGS_IDMAP;
		options.idmap_fd = userns_fd;
	}

	fd = open(image_path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		errx(EXIT_FAILURE, "Failed to open %s: %s\n", image_path,
		     strerror(errno));

	res = lcfs_mount_fd(fd, mount_path, &options);
	if (res < 0) {
		int errsv = errno;

		if (errsv == ENOVERITY)
			errx(EXIT_FAILURE,
			     "Failed to mount composefs %s: Image has no fs-verity\n",
			     image_path);
		else if (errsv == EWRONGVERITY)
			errx(EXIT_FAILURE,
			     "Failed to mount composefs %s: Image has wrong fs-verity\n",
			     image_path);
		else if (errsv == ENOSIGNATURE)
			errx(EXIT_FAILURE,
			     "Failed to mount composefs %s: Image was not signed\n",
			     image_path);

		errx(EXIT_FAILURE, "Failed to mount composefs %s: %s\n",
		     image_path, strerror(errno));
	}

	free(options.objdirs);

	return 0;
}
