/* lcfs
   Copyright (C) 2023 Alexander Larsson <alexl@redhat.com>

   This file is free software: you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 2.1 of the
   License, or (at your option) any later version.

   This file is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

#define _GNU_SOURCE

#include "config.h"

#include "lcfs-writer.h"
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
#include <sys/types.h>
#include <linux/limits.h>
#include <linux/loop.h>
#include <linux/fsverity.h>

#include <sys/syscall.h>
#include <sys/mount.h>
#ifdef HAVE_FSCONFIG_CMD_CREATE_LINUX_MOUNT_H
#include <linux/mount.h>
#endif
#if defined HAVE_FSCONFIG_CMD_CREATE_LINUX_MOUNT_H ||                          \
	defined HAVE_FSCONFIG_CMD_CREATE_SYS_MOUNT_H
#define HAVE_NEW_MOUNT_API
#endif

#include "lcfs-erofs.h"
#include "lcfs-utils.h"
#include "lcfs-internal.h"

static int syscall_fsopen(const char *fs_name, unsigned int flags)
{
#if defined __NR_fsopen
	return (int)syscall(__NR_fsopen, fs_name, flags);
#else
	(void)fs_name;
	(void)flags;
	errno = ENOSYS;
	return -1;
#endif
}

static int syscall_fsmount(int fsfd, unsigned int flags, unsigned int attr_flags)
{
#if defined __NR_fsmount
	return (int)syscall(__NR_fsmount, fsfd, flags, attr_flags);
#else
	(void)fsfd;
	(void)flags;
	(void)attr_flags;
	errno = ENOSYS;
	return -1;
#endif
}

static int syscall_fsconfig(int fsfd, unsigned int cmd, const char *key,
			    const void *val, int aux)
{
#if defined __NR_fsconfig
	return (int)syscall(__NR_fsconfig, fsfd, cmd, key, val, aux);
#else
	(void)fsfd;
	(void)cmd;
	(void)key;
	(void)val;
	(void)aux;
	errno = ENOSYS;
	return -1;
#endif
}

static int syscall_move_mount(int from_dfd, const char *from_pathname, int to_dfd,
			      const char *to_pathname, unsigned int flags)

{
#if defined __NR_move_mount
	return (int)syscall(__NR_move_mount, from_dfd, from_pathname, to_dfd,
			    to_pathname, flags);
#else
	(void)from_dfd;
	(void)from_pathname;
	(void)to_dfd;
	(void)to_pathname;
	(void)flags;
	errno = ENOSYS;
	return -1;
#endif
}

static int syscall_mount_setattr(int dfd, const char *path, unsigned int flags,
				 struct mount_attr *attr, size_t usize)
{
#ifdef __NR_mount_setattr
	return (int)syscall(__NR_mount_setattr, dfd, path, flags, attr, usize);
#else
	(void)dfd;
	(void)path;
	(void)flags;
	(void)attr;
	errno = ENOSYS;
	return -1;
#endif
}

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

	if ((options->flags & LCFS_MOUNT_FLAGS_REQUIRE_VERITY) &&
	    (options->flags & LCFS_MOUNT_FLAGS_DISABLE_VERITY)) {
		return -EINVAL; /* Can't have both */
	}

	if (options->n_objdirs == 0)
		return -EINVAL;

	if ((options->upperdir && !options->workdir) ||
	    (!options->upperdir && options->workdir))
		return -EINVAL;

	if (options->expected_fsverity_digest) {
		int raw_len = digest_to_raw(options->expected_fsverity_digest,
					    state->expected_digest, MAX_DIGEST_SIZE);
		if (raw_len < 0)
			return -EINVAL;
		state->expected_digest_len = raw_len;
	}

	if ((options->flags & LCFS_MOUNT_FLAGS_IDMAP) != 0 && options->idmap_fd < 0) {
		return -EINVAL;
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
	bool require_signature;
	char sig_data[1];
	struct fsverity_read_metadata_arg read_metadata = { 0 };

	require_signature = (state->options->flags &
			     LCFS_MOUNT_FLAGS_REQUIRE_FSVERITY_SIGNATURE) != 0;
	if (require_signature) {
		/* First ensure fs-verity is enabled for the image,
		 * the actual digest doesn't matter at this point. */
		buf.fsv.digest_size = MAX_DIGEST_SIZE;
		res = ioctl(state->fd, FS_IOC_MEASURE_VERITY, &buf.fsv);
		if (res == -1) {
			if (errno == ENODATA || errno == EOPNOTSUPP || errno == ENOTTY)
				return -ENOVERITY;
			return -errno;
		}

		/* If the file has verity enabled, has a signature and
		 * we were able to open it, then the kernel will have
		 * verified it against the kernel keyring, making it
		 * valid. So, we read just one byte of the signature,
		 * to validate that a signature exist in the file */

		read_metadata.metadata_type = FS_VERITY_METADATA_TYPE_SIGNATURE;
		read_metadata.offset = 0;
		read_metadata.length = sizeof(sig_data);
		read_metadata.buf_ptr = (size_t)&sig_data;

		res = ioctl(state->fd, FS_IOC_READ_VERITY_METADATA, &read_metadata);
		if (res == -1) {
			if (errno == ENODATA)
				return -ENOSIGNATURE;
			return -errno;
		}
	}

	if (state->expected_digest_len != 0) {
		buf.fsv.digest_size = MAX_DIGEST_SIZE;
		res = ioctl(state->fd, FS_IOC_MEASURE_VERITY, &buf.fsv);
		if (res == -1) {
			if (errno == ENODATA || errno == EOPNOTSUPP || errno == ENOTTY)
				return -ENOVERITY;
			return -errno;
		}
		if (buf.fsv.digest_size != state->expected_digest_len ||
		    memcmp(state->expected_digest, buf.fsv.digest,
			   buf.fsv.digest_size) != 0)
			return -EWRONGVERITY;
	}

	return 0;
}

static int setup_loopback(int fd, const char *image_path, char *loopname)
{
	struct loop_config loopconfig = { 0 };
	int loopctlfd, loopfd;
	long devnr;
	int errsv;

	loopctlfd = open("/dev/loop-control", O_RDWR | O_CLOEXEC);
	if (loopctlfd < 0)
		return -errno;

	devnr = ioctl(loopctlfd, LOOP_CTL_GET_FREE);
	errsv = errno;
	close(loopctlfd);
	if (devnr == -1) {
		return -errsv;
	}

	sprintf(loopname, "/dev/loop%ld", devnr);
	loopfd = open(loopname, O_RDWR | O_CLOEXEC);
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

static char *compute_lower(const char *imagemount,
			   struct lcfs_mount_state_s *state, bool with_datalower)
{
	size_t size;
	char *lower;
	size_t i;

	/* Compute the total max size (including escapes) */
	size = 2 * strlen(imagemount);
	for (i = 0; i < state->options->n_objdirs; i++)
		size += 2 + 2 * strlen(state->options->objdirs[i]);

	lower = malloc(size + 1);
	if (lower == NULL)
		return NULL;
	*lower = 0;

	escape_mount_option_to(imagemount, lower);

	for (i = 0; i < state->options->n_objdirs; i++) {
		if (with_datalower)
			strcat(lower, "::");
		else
			strcat(lower, ":");
		escape_mount_option_to(state->options->objdirs[i], lower);
	}

	return lower;
}

static int lcfs_mount_erofs(const char *source, const char *target,
			    uint32_t image_flags, struct lcfs_mount_state_s *state)
{
	bool image_has_acls = (image_flags & LCFS_EROFS_FLAGS_HAS_ACL) != 0;
	bool use_idmap = (state->options->flags & LCFS_MOUNT_FLAGS_IDMAP) != 0;
	int res;

#ifdef HAVE_NEW_MOUNT_API
	/* We have new mount API is in header */
	cleanup_fd int fd_fs = -1;
	cleanup_fd int fd_mnt = -1;

	fd_fs = syscall_fsopen("erofs", FSOPEN_CLOEXEC);
	if (fd_fs < 0) {
		if (errno == ENOSYS)
			goto fallback;
		return -errno;
	}

	res = syscall_fsconfig(fd_fs, FSCONFIG_SET_STRING, "source", source, 0);
	if (res < 0)
		return -errno;

	res = syscall_fsconfig(fd_fs, FSCONFIG_SET_FLAG, "ro", NULL, 0);
	if (res < 0)
		return -errno;

	if (!image_has_acls) {
		res = syscall_fsconfig(fd_fs, FSCONFIG_SET_FLAG, "noacl", NULL, 0);
		if (res < 0)
			return -errno;
	}

	res = syscall_fsconfig(fd_fs, FSCONFIG_CMD_CREATE, NULL, NULL, 0);
	if (res < 0)
		return -errno;

	fd_mnt = syscall_fsmount(fd_fs, FSMOUNT_CLOEXEC, MS_RDONLY);
	if (fd_mnt < 0)
		return -errno;

	if (use_idmap) {
		struct mount_attr attr = {
			.attr_set = MOUNT_ATTR_IDMAP,
			.userns_fd = state->options->idmap_fd,
		};

		res = syscall_mount_setattr(fd_mnt, "", AT_EMPTY_PATH, &attr,
					    sizeof(struct mount_attr));
		if (res < 0)
			return -errno;
	}

	res = syscall_move_mount(fd_mnt, "", AT_FDCWD, target,
				 MOVE_MOUNT_F_EMPTY_PATH);
	if (res < 0)
		return -errno;

	return 0;

fallback:
#endif

	/* We need new mount api for idmapped mounts */
	if (use_idmap)
		return -ENOTSUP;

	res = mount(source, target, "erofs", MS_RDONLY,
		    image_has_acls ? "ro" : "ro,noacl");
	if (res < 0)
		return -errno;

	return 0;
}

#define HEADER_SIZE sizeof(struct lcfs_erofs_header_s)

static int lcfs_mount_erofs_ovl(struct lcfs_mount_state_s *state,
				struct lcfs_erofs_header_s *header)
{
	struct lcfs_mount_options_s *options = state->options;
	uint32_t image_flags;
	char imagemountbuf[] = "/tmp/.composefs.XXXXXX";
	char *imagemount;
	bool created_tmpdir = false;
	char loopname[PATH_MAX];
	int res, errsv;
	int lowerdir_alt = 0;
	char *lowerdir[2] = { NULL, NULL };
	cleanup_free char *upperdir = NULL;
	cleanup_free char *workdir = NULL;
	cleanup_free char *overlay_options = NULL;
	int loopfd;
	bool require_verity;
	bool disable_verity;
	bool readonly;
	int mount_flags;

	image_flags = lcfs_u32_from_file(header->flags);

	require_verity = (options->flags & LCFS_MOUNT_FLAGS_REQUIRE_VERITY) != 0;
	disable_verity = (options->flags & LCFS_MOUNT_FLAGS_DISABLE_VERITY) != 0;
	readonly = (options->flags & LCFS_MOUNT_FLAGS_READONLY) != 0;

	loopfd = setup_loopback(state->fd, state->image_path, loopname);
	if (loopfd < 0)
		return loopfd;

	if (options->image_mountdir) {
		imagemount = (char *)options->image_mountdir;
	} else {
		imagemount = mkdtemp(imagemountbuf);
		if (imagemount == NULL) {
			errsv = errno;
			close(loopfd);
			return -errsv;
		}
		created_tmpdir = true;
	}

	res = lcfs_mount_erofs(loopname, imagemount, image_flags, state);
	close(loopfd);
	if (res < 0) {
		rmdir(imagemount);
		return res;
	}

	/* We use the legacy API to mount overlayfs, because the new API doesn't allow use
	 * to pass in escaped directory names
	 */

	/* First try new version with :: separating datadirs. */
	lowerdir[0] = compute_lower(imagemount, state, true);
	if (lowerdir[0] == NULL) {
		res = -ENOMEM;
		goto fail;
	}

	/* Then fall back. */
	lowerdir[1] = compute_lower(imagemount, state, false);
	if (lowerdir[1] == NULL) {
		res = -ENOMEM;
		goto fail;
	}

	if (options->upperdir)
		upperdir = escape_mount_option(options->upperdir);
	if (options->workdir)
		workdir = escape_mount_option(options->workdir);

retry:
	free(steal_pointer(&overlay_options));
	res = asprintf(&overlay_options,
		       "metacopy=on,redirect_dir=on,lowerdir=%s%s%s%s%s%s",
		       lowerdir[lowerdir_alt], upperdir ? ",upperdir=" : "",
		       upperdir ? upperdir : "", workdir ? ",workdir=" : "",
		       workdir ? workdir : "",
		       require_verity ? ",verity=require" :
					(disable_verity ? ",verity=off" : ""));
	if (res < 0) {
		res = -ENOMEM;
		goto fail;
	}

	mount_flags = 0;
	if (readonly)
		mount_flags |= MS_RDONLY;
	if (lowerdir_alt == 0)
		mount_flags |= MS_SILENT;

	res = mount("overlay", state->mountpoint, "overlay", mount_flags,
		    overlay_options);
	if (res != 0) {
		res = -errno;
	}

	if (res == -EINVAL && lowerdir_alt == 0) {
		lowerdir_alt++;
		goto retry;
	}

fail:
	free(lowerdir[0]);
	free(lowerdir[1]);

	umount2(imagemount, MNT_DETACH);
	if (created_tmpdir) {
		rmdir(imagemount);
	}

	return res;
}

static int lcfs_mount(struct lcfs_mount_state_s *state)
{
	uint8_t header_data[HEADER_SIZE];
	struct lcfs_erofs_header_s *erofs_header;
	int res;

	res = lcfs_validate_verity_fd(state);
	if (res < 0)
		return res;

	res = pread(state->fd, &header_data, HEADER_SIZE, 0);
	if (res < 0)
		return -errno;

	erofs_header = (struct lcfs_erofs_header_s *)header_data;
	if (lcfs_u32_from_file(erofs_header->magic) == LCFS_EROFS_MAGIC)
		return lcfs_mount_erofs_ovl(state, erofs_header);

	return -EINVAL;
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

	fd = open(path, O_RDONLY | O_CLOEXEC);
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
