/* lcfs
   Copyright (C) 2023 Alexander Larsson <alexl@redhat.com>

   SPDX-License-Identifier: GPL-2.0-or-later OR Apache-2.0
*/
#ifndef _LCFS_MOUNT_H
#define _LCFS_MOUNT_H

#include <stdlib.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#ifndef LCFS_EXTERN
#define LCFS_EXTERN extern
#endif

#define ENOVERITY ENOTTY
#define EWRONGVERITY EILSEQ
#define ENOSIGNATURE EBADMSG

enum lcfs_mount_flags_t {
	LCFS_MOUNT_FLAGS_NONE = 0,
	LCFS_MOUNT_FLAGS_REQUIRE_VERITY = (1 << 0),
	LCFS_MOUNT_FLAGS_READONLY = (1 << 1),
	LCFS_MOUNT_FLAGS_IDMAP = (1 << 3),
	LCFS_MOUNT_FLAGS_TRY_VERITY = (1 << 4),

	LCFS_MOUNT_FLAGS_MASK = (1 << 5) - 1,
};

struct lcfs_mount_options_s {
	const char **objdirs;
	size_t n_objdirs;
	const char *workdir;
	const char *upperdir;
	const char *expected_fsverity_digest;
	uint32_t flags;
	int idmap_fd; /* userns fd */
	const char *image_mountdir; /* Temporary location to mount images if needed */

	uint32_t reserved[4];
	void *reserved2[4];
};

LCFS_EXTERN int lcfs_mount_image(const char *path, const char *mountpoint,
				 struct lcfs_mount_options_s *options);
LCFS_EXTERN int lcfs_mount_fd(int fd, const char *mountpoint,
			      struct lcfs_mount_options_s *options);

#endif
