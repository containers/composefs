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
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#ifndef _LCFS_H
#define _LCFS_H
#include <stdlib.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#define LCFS_VERSION 1

typedef uint64_t lcfs_off_t;

typedef lcfs_off_t lcfs_c_str_t;

struct lcfs_vdata_s {
	lcfs_off_t off;
	lcfs_off_t len;
} __attribute__((packed));

struct lcfs_header_s {
	uint8_t version;
	uint8_t unused1;
	uint16_t unused2;

	uint32_t inode_len;
	uint32_t extend_len;

	uint64_t unused3[3];
} __attribute__((packed));

struct lcfs_extend_s {
	/* Total size of this extend in bytes.  */
	uint64_t st_size;

	/* Source file.  */
	struct lcfs_vdata_s payload;
} __attribute__((packed));

struct lcfs_inode_s {
	uint32_t st_mode; /* File type and mode.  */
	uint32_t st_nlink; /* Number of hard links.  */
	uint32_t st_uid; /* User ID of owner.  */
	uint32_t st_gid; /* Group ID of owner.  */
	uint32_t st_rdev; /* Device ID (if special file).  */

	struct timespec st_mtim; /* Time of last modification.  */
	struct timespec st_ctim; /* Time of last status change.  */

	/* Variable len data.  */
	struct lcfs_vdata_s xattrs;

	union {
		/* Offset and length to the content of the directory.  */
		struct lcfs_vdata_s dir;

		/* Payload used for symlinks.  */
		struct lcfs_vdata_s payload;

		/* Payload used for symlinks.  */
		struct lcfs_vdata_s extends;
	} u;
} __attribute__((packed));

struct lcfs_dentry_s {
	/* Index of struct lcfs_inode_s */
	lcfs_off_t inode_index;

	/* Variable len data.  */
	struct lcfs_vdata_s name;
} __attribute__((packed));

/* xattr representation.  */
struct lcfs_xattr_header_s {
	struct lcfs_vdata_s key;
	struct lcfs_vdata_s value;
} __attribute__((packed));

#endif
