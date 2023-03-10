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

#include "libcomposefs/lcfs-erofs.h"
#include "libcomposefs/lcfs.h"

#define MAX_OBJDIR 10

static void printexit(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);

	exit(1);
}

static void oom(void)
{
	printexit("Out of memory\n");
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

static char *escape_mount_option(const char *str)
{
	const char *s;
	char *res, *d;
	int n_escapes = 0;

	for (s = str; *s != 0; s++) {
		if (*s == ',')
			n_escapes++;
	}

	res = malloc(strlen(str) + n_escapes + 1);
	if (res == NULL)
		oom();

	d = res;
	for (s = str; *s != 0; s++) {
		if (*s == ',')
			*d++ = '\\';
		*d++ = *s;
	}
	*d++ = 0;

	return res;
}

static int hexdigit(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return 10 + (c - 'a');
	if (c >= 'A' && c <= 'F')
		return 10 + (c - 'A');
	return -1;
}

static int digest_to_raw(const char *digest, uint8_t *raw, int max_size)
{
	int size = 0;

	while (*digest) {
		char c1, c2;
		int n1, n2;

		if (size >= max_size)
			return -1;

		c1 = *digest++;
		n1 = hexdigit(c1);
		if (n1 < 0)
			return -1;

		c2 = *digest++;
		n2 = hexdigit(c2);
		if (n2 < 0)
			return -1;

		raw[size++] = (n1 & 0xf) << 4 | (n2 & 0xf);
	}

	return size;
}

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
	const char *bin = argv[0];
	const char *image_path = NULL;
	const char *mount_path = NULL;
	const char *upperdir = NULL;
	const char *workdir = NULL;
	const char *digest = NULL;
	char *escaped_upperdir = NULL;
	char *escaped_workdir = NULL;
	bool require_verity = false;
	const char *objdirs[MAX_OBJDIR] = { NULL };
	int n_objdirs = 0;
	int opt;
	int fd, loopctlfd, loopfd;
	long devnr;
	char imagemountbuf[] = "/tmp/composefs.XXXXXX";
	char *imagemount;
	char *escaped;
	char loopname[PATH_MAX];
	int res;
	char *overlay_options;
	char lower[PATH_MAX * (MAX_OBJDIR + 1)];
	struct loop_config loopconfig = { 0 };
	struct lcfs_erofs_header_s header;
	uint32_t image_flags;
	bool image_has_acls;

	while ((opt = getopt_long(argc, argv, "", longopts, NULL)) != -1) {
		switch (opt) {
		case OPT_OBJDIR:
			if (n_objdirs == MAX_OBJDIR) {
				fprintf(stderr, "Too many object dirs\n");
				exit(EXIT_FAILURE);
			}
			objdirs[n_objdirs++] = optarg;
			break;
		case OPT_UPPERDIR:
			upperdir = optarg;
			break;
		case OPT_WORKDIR:
			workdir = optarg;
			break;
		case OPT_DIGEST:
			digest = optarg;
			require_verity = true;
			break;
		case OPT_REQUIRE_VERITY:
			require_verity = true;
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

	if (n_objdirs == 0) {
		fprintf(stderr, "No object dirs specified\n");
		usage(bin);
		exit(1);
	}

	if ((upperdir && !workdir) || (!upperdir && workdir)) {
		printexit("Both workdir and upperdir must be specified if used\n");
	}

	fd = open(image_path, O_RDONLY);
	if (fd < 0)
		printexit("Failed to open %s: %s\n", image_path, strerror(errno));

	if (digest) {
		struct {
			struct fsverity_digest fsv;
			char buf[64];
		} buf;
		uint8_t raw_digest[64] = { 0 };
		int raw_len;

		raw_len = digest_to_raw(digest, raw_digest, sizeof(raw_digest));
		if (raw_len < 0)
			printexit("Invalid digest specified\n");

		buf.fsv.digest_size = 64;
		res = ioctl(fd, FS_IOC_MEASURE_VERITY, &buf.fsv);
		if (res == -1) {
			if (errno == ENODATA)
				printexit("Image file lacks fs-verity digest\n");
			if (errno == ENOTTY || errno == EOPNOTSUPP)
				printexit("Image file lacks fs-verity digest: Not supported\n");
			printexit("Failed to get image fs-verity digest: %s\n",
				  strerror(errno));
		}

		if (buf.fsv.digest_size != raw_len ||
		    memcmp(raw_digest, buf.fsv.digest, buf.fsv.digest_size) != 0)
			printexit("Wrong fs-verity digest on image\n");
	}

	res = pread(fd, &header, sizeof(header), 0);
	if (res < 0)
		printexit("Failed to load header from %s: %s\n", image_path,
			  strerror(errno));
	if (lcfs_u32_from_file(header.magic) != LCFS_EROFS_MAGIC)
		printexit("Invalid file header in %s\n", image_path);
	image_flags = lcfs_u32_from_file(header.flags);
	image_has_acls = (image_flags & LCFS_EROFS_FLAGS_HAS_ACL) != 0;

	loopctlfd = open("/dev/loop-control", O_RDWR);
	if (loopctlfd == -1)
		printexit("Failed to open /dev/loop-control: %s\n", strerror(errno));

	devnr = ioctl(loopctlfd, LOOP_CTL_GET_FREE);
	if (devnr == -1)
		printexit("Failed to find free loop device: %s\n", strerror(errno));
	close(loopctlfd);

	sprintf(loopname, "/dev/loop%ld", devnr);
	loopfd = open(loopname, O_RDWR);
	if (loopfd == -1)
		printexit("Failed to open %s: %s\n", loopname, strerror(errno));

	loopconfig.fd = fd;
	loopconfig.block_size =
		4096; /* This is what we use for the erofs block size, so probably good */
	loopconfig.info.lo_flags =
		LO_FLAGS_READ_ONLY | LO_FLAGS_DIRECT_IO | LO_FLAGS_AUTOCLEAR;
	strncat((char *)loopconfig.info.lo_file_name, image_path, LO_NAME_SIZE - 1);

	if (ioctl(loopfd, LOOP_CONFIGURE, &loopconfig) == -1)
		printexit("Failed to setup loop device: %s\n", strerror(errno));

	imagemount = mkdtemp(imagemountbuf);
	if (imagemount == NULL)
		printexit("Failed to create erofs mountpoint: %s\n", strerror(errno));

	res = mount(loopname, imagemount, "erofs", 0,
		    image_has_acls ? "ro" : "ro,noacl");
	if (res < 0)
		printexit("Failed to mount erofs: %s\n", strerror(errno));

	*lower = 0;
	escaped = escape_mount_option(imagemount);
	strncat(lower, escaped, sizeof(lower) - 1);
	free(escaped);
	for (int i = n_objdirs - 1; i >= 0; i--) {
		strncat(lower, ":", sizeof(lower) - strlen(lower) - 1);
		escaped = escape_mount_option(objdirs[i]);
		strncat(lower, objdirs[i], sizeof(lower) - strlen(lower) - 1);
		free(escaped);
	}

	if (upperdir)
		escaped_upperdir = escape_mount_option(upperdir);
	if (workdir)
		escaped_workdir = escape_mount_option(workdir);

	res = asprintf(&overlay_options,
		       "metacopy=on,redirect_dir=on,lowerdir=%s%s%s%s%s%s",
		       lower, upperdir ? ",upperdir=" : "",
		       upperdir ? escaped_upperdir : "",
		       workdir ? ",workdir=" : "", workdir ? escaped_workdir : "",
		       require_verity ? ",verity=require" : "");
	if (res < 0)
		oom();

	res = mount("overlay", mount_path, "overlay", 0, overlay_options);
	if (res < 0) {
		int errsv = errno;
		umount2(imagemount, MNT_DETACH);
		rmdir(imagemount);
		printexit("Failed to mount overlay: %s\n", strerror(errsv));
	}

	umount2(imagemount, MNT_DETACH);
	rmdir(imagemount);

	return 0;
}
