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
	uint32_t off;
	uint32_t len;
} __attribute__((packed));

struct lcfs_header_s {
	uint8_t version;
	uint8_t unused1;
	uint16_t unused2;

	uint32_t inode_len;
	lcfs_off_t data_offset;

	uint64_t unused3[3];
} __attribute__((packed));

struct lcfs_backing_s {
	/* Total size of the backing file in bytes.  */
	uint64_t st_size;

	/* Source file.  */
	uint32_t payload_len;
	char payload[];
} __attribute__((packed));

#define lcfs_backing_size(_payload_len) (sizeof(struct lcfs_backing_s) + (_payload_len))

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

	/* This is the size of the type specific data that comes directly after
	   the inode in the file. Of this type:
	   *
	   * directory: lcfs_dir_s
	   * regular file: lcfs_backing_s
	   * symlink: the target link
	   *
	   * Canonically payload_length is 0 for empty dir/file/symlink.
	   */
	uint32_t payload_length;
} __attribute__((packed));

struct lcfs_dentry_s {
	/* Index of struct lcfs_inode_s */
	lcfs_off_t inode_index;
	uint16_t name_len;
	uint8_t d_type;
	uint8_t pad;
} __attribute__((packed));

struct lcfs_dir_s {
	/* Index of struct lcfs_inode_s */
	uint32_t n_dentries;
	struct lcfs_dentry_s dentries[];
} __attribute__((packed));

#define lcfs_dir_size(_n_dentries) (sizeof(struct lcfs_dir_s) + (_n_dentries)*sizeof(struct lcfs_dentry_s))

/* xattr representation.  */
struct lcfs_xattr_element_s {
	uint16_t key_length;
	uint16_t value_length;
} __attribute__((packed));

struct lcfs_xattr_header_s {
	uint16_t n_attr;
	struct lcfs_xattr_element_s attr[0];
} __attribute__((packed));

#define lcfs_xattr_header_size(_n_element) (sizeof(struct lcfs_xattr_header_s) + (_n_element)*sizeof(struct lcfs_xattr_element_s))

#endif
