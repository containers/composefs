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

#include "lcfs.h"
#include "lcfs-mount.h"

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

#include "lcfs-erofs.h"

#define MAX_DIGEST_SIZE 64

struct lcfs_mount_state_s {
	const char *image_path;
	const char *mountpoint;
	struct lcfs_mount_options_s *options;
	int fd;
	uint8_t expected_digest[MAX_DIGEST_SIZE];
	int expected_digest_len;
};

static void escape_mount_option_to(const char *str, char *dest)
{
	const char *s;
	char *d;

	d = dest + strlen(dest);
	for (s = str; *s != 0; s++) {
		if (*s == ',')
			*d++ = '\\';
		*d++ = *s;
	}
	*d++ = 0;
}

static char *escape_mount_option(const char *str)
{
	const char *s;
	char *res;
	int n_escapes = 0;

	for (s = str; *s != 0; s++) {
		if (*s == ',')
			n_escapes++;
	}

	res = malloc(strlen(str) + n_escapes + 1);
	if (res == NULL)
		return NULL;

	*res = 0;

	escape_mount_option_to(str, res);

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

static int lcfs_validate_mount_options(struct lcfs_mount_state_s *state)
{
	struct lcfs_mount_options_s *options = state->options;

	if ((options->flags & ~LCFS_MOUNT_FLAGS_MASK) != 0) {
		return -EINVAL;
	}

	if (options->n_objdirs == 0)
		return -EINVAL;

	if ((options->upperdir && !options->workdir) ||
	    (!options->upperdir && options->workdir))
		return -EINVAL;

	if (options->expected_digest) {
		int raw_len = digest_to_raw(options->expected_digest,
					    state->expected_digest, MAX_DIGEST_SIZE);
		if (raw_len < 0)
			return -EINVAL;
		state->expected_digest_len = raw_len;
	}

	return 0;
}

static int lcfs_validate_verity_fd(struct lcfs_mount_state_s *state)
{
	struct {
		struct fsverity_digest fsv;
		char buf[MAX_DIGEST_SIZE];
	} buf;
	int res;

	if (state->expected_digest_len == 0)
		return 0;

	buf.fsv.digest_size = MAX_DIGEST_SIZE;
	res = ioctl(state->fd, FS_IOC_MEASURE_VERITY, &buf.fsv);
	if (res == -1) {
		if (errno == ENODATA || errno == EOPNOTSUPP || errno == ENOTTY)
			return -ENOVERITY;
		return -errno;
	}
	if (buf.fsv.digest_size != state->expected_digest_len ||
	    memcmp(state->expected_digest, buf.fsv.digest, buf.fsv.digest_size) != 0)
		return -EWRONGVERITY;

	return 0;
}

static int setup_loopback(int fd, const char *image_path, char *loopname)
{
	struct loop_config loopconfig = { 0 };
	int loopctlfd, loopfd;
	long devnr;
	int errsv;

	loopctlfd = open("/dev/loop-control", O_RDWR);
	if (loopctlfd < 0)
		return -errno;

	devnr = ioctl(loopctlfd, LOOP_CTL_GET_FREE);
	errsv = errno;
	close(loopctlfd);
	if (devnr == -1) {
		return -errsv;
	}

	sprintf(loopname, "/dev/loop%ld", devnr);
	loopfd = open(loopname, O_RDWR);
	if (loopfd < 0)
		return -errno;

	loopconfig.fd = fd;
	loopconfig.block_size =
		4096; /* This is what we use for the erofs block size, so probably good */
	loopconfig.info.lo_flags =
		LO_FLAGS_READ_ONLY | LO_FLAGS_DIRECT_IO | LO_FLAGS_AUTOCLEAR;
	if (image_path)
		strncat((char *)loopconfig.info.lo_file_name, image_path,
			LO_NAME_SIZE - 1);

	if (ioctl(loopfd, LOOP_CONFIGURE, &loopconfig) < 0) {
		errsv = errno;
		close(loopfd);
		return -errsv;
	}

	return loopfd;
}

static char *compute_lower(const char *imagemount, struct lcfs_mount_state_s *state)
{
	size_t size;
	char *lower;
	int i;

	/* Compute the total max size (including escapes) */
	size = 2 * strlen(imagemount);
	for (i = 0; i < state->options->n_objdirs; i++)
		size += 1 + 2 * strlen(state->options->objdirs[i]);

	lower = malloc(size + 1);
	if (lower == NULL)
		return NULL;
	*lower = 0;

	escape_mount_option_to(imagemount, lower);

	for (i = 0; i < state->options->n_objdirs; i++) {
		strcat(lower, ":");
		escape_mount_option_to(state->options->objdirs[i], lower);
	}

	return lower;
}

static int lcfs_mount(struct lcfs_mount_state_s *state)
{
	struct lcfs_mount_options_s *options = state->options;
	struct lcfs_erofs_header_s header;
	uint32_t image_flags;
	bool image_has_acls;
	char imagemountbuf[] = "/tmp/.composefs.XXXXXX";
	char *imagemount;
	char loopname[PATH_MAX];
	int res, errsv;
	char *lowerdir = NULL;
	char *upperdir = NULL;
	char *workdir = NULL;
	char *overlay_options = NULL;
	int loopfd;
	bool require_verity;
	bool readonly;
	int mount_flags;

	res = lcfs_validate_verity_fd(state);
	if (res < 0)
		return res;

	res = pread(state->fd, &header, sizeof(header), 0);
	if (res < 0)
		return -errno;

	if (lcfs_u32_from_file(header.magic) != LCFS_EROFS_MAGIC)
		return -EINVAL;

	image_flags = lcfs_u32_from_file(header.flags);
	image_has_acls = (image_flags & LCFS_EROFS_FLAGS_HAS_ACL) != 0;

	require_verity = (options->flags & LCFS_MOUNT_FLAGS_REQUIRE_VERITY) != 0;
	readonly = (options->flags & LCFS_MOUNT_FLAGS_READONLY) != 0;

	loopfd = setup_loopback(state->fd, state->image_path, loopname);
	if (loopfd < 0)
		return loopfd;

	imagemount = mkdtemp(imagemountbuf);
	if (imagemount == NULL) {
		errsv = errno;
		close(loopfd);
		return -errsv;
	}

	res = mount(loopname, imagemount, "erofs", MS_RDONLY,
		    image_has_acls ? "" : "noacl");
	errsv = errno;
	close(loopfd);
	if (res < 0) {
		rmdir(imagemount);
		return -errsv;
	}

	lowerdir = compute_lower(imagemount, state);
	if (lowerdir == NULL) {
		res = -ENOMEM;
		goto fail;
	}

	if (options->upperdir)
		upperdir = escape_mount_option(options->upperdir);
	if (options->workdir)
		workdir = escape_mount_option(options->workdir);

	res = asprintf(&overlay_options,
		       "metacopy=on,redirect_dir=on,lowerdir=%s%s%s%s%s%s", lowerdir,
		       upperdir ? ",upperdir=" : "", upperdir ? upperdir : "",
		       workdir ? ",workdir=" : "", workdir ? workdir : "",
		       require_verity ? ",verity=require" : "");
	if (res < 0) {
		res = -ENOMEM;
		goto fail;
	}

	mount_flags = 0;
	if (readonly)
		mount_flags |= MS_RDONLY;

	res = mount("overlay", state->mountpoint, "overlay", mount_flags,
		    overlay_options);

fail:
	free(lowerdir);
	free(workdir);
	free(upperdir);
	free(overlay_options);

	umount2(imagemount, MNT_DETACH);
	rmdir(imagemount);

	return res;
}

int lcfs_mount_fd(int fd, const char *mountpoint, struct lcfs_mount_options_s *options)
{
	struct lcfs_mount_state_s state = { .mountpoint = mountpoint,
					    .options = options,
					    .fd = fd };
	int res;

	res = lcfs_validate_mount_options(&state);
	if (res < 0) {
		errno = -res;
		return -1;
	}

	res = lcfs_mount(&state);
	if (res < 0) {
		errno = -res;
		return -1;
	}
	return 0;
}

int lcfs_mount_image(const char *path, const char *mountpoint,
		     struct lcfs_mount_options_s *options)
{
	struct lcfs_mount_state_s state = { .image_path = path,
					    .mountpoint = mountpoint,
					    .options = options,
					    .fd = -1 };
	int fd, res;

	res = lcfs_validate_mount_options(&state);
	if (res < 0) {
		errno = -res;
		return -1;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		return -1;
	}
	state.fd = fd;

	res = lcfs_mount(&state);
	close(fd);
	if (res < 0) {
		errno = -res;
		return -1;
	}

	return 0;
}
