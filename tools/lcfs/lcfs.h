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
#include <endian.h>

#define LCFS_VERSION 1

typedef uint64_t lcfs_off_t;

typedef lcfs_off_t lcfs_c_str_t;

static inline uint16_t lcfs_u16_to_file(uint16_t val) {
	return htole16(val);
}

static inline uint32_t lcfs_u32_to_file(uint32_t val) {
	return htole32(val);
}

static inline uint64_t lcfs_u64_to_file(uint64_t val) {
	return htole64(val);
}

static inline uint16_t lcfs_u16_from_file(uint16_t val) {
	return le16toh(val);
}

static inline uint32_t lcfs_u32_from_file(uint32_t val) {
	return le32toh(val);
}

static inline uint64_t lcfs_u64_from_file(uint64_t val) {
	return le64toh(val);
}

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


enum lcfs_inode_flags {
	LCFS_INODE_FLAGS_NONE            = 0,
	LCFS_INODE_FLAGS_MODE            = 1 << 0,
	LCFS_INODE_FLAGS_NLINK           = 1 << 1,
	LCFS_INODE_FLAGS_UIDGID          = 1 << 2,
	LCFS_INODE_FLAGS_RDEV            = 1 << 3,
	LCFS_INODE_FLAGS_TIMES           = 1 << 4,
	LCFS_INODE_FLAGS_TIMES_NSEC      = 1 << 5,
	LCFS_INODE_FLAGS_LOW_SIZE        = 1 << 6, /* Low 32bit of st_size */
	LCFS_INODE_FLAGS_HIGH_SIZE       = 1 << 7, /* High 32bit of st_size */

};

#define LCFS_INODE_FLAG_CHECK(_flag, _name) (((_flag) & (LCFS_INODE_FLAGS_ ## _name)) != 0)
#define LCFS_INODE_FLAG_CHECK_SIZE(_flag, _name, _size) (LCFS_INODE_FLAG_CHECK(_flag, _name) ? (_size) : 0)

#define LCFS_INODE_INDEX_SHIFT 8
#define	LCFS_INODE_FLAGS_MASK ((1 << LCFS_INODE_INDEX_SHIFT) - 1)

#define LCFS_ROOT_INODE LCFS_INODE_FLAGS_MASK

#define LCFS_INODE_DEFAULT_MODE 0100644
#define LCFS_INODE_DEFAULT_NLINK 1
#define LCFS_INODE_DEFAULT_UIDGID 0
#define LCFS_INODE_DEFAULT_RDEV 0
#define LCFS_INODE_DEFAULT_TIMES 0

struct lcfs_inode_s {
	/* This is the size of the type specific data that comes directly after
	   the inode in the file. Of this type:
	   *
	   * directory: lcfs_dir_s
	   * regular file: the backing filename
	   * symlink: the target link
	   *
	   * Canonically payload_length is 0 for empty dir/file/symlink
	   */
	uint32_t payload_length;

	/* Variable len data.  */
	struct lcfs_vdata_s xattrs;

	/* Optional data: (selected by flags) */
	uint32_t st_mode; /* File type and mode.  */
	uint32_t st_nlink; /* Number of hard links, only for regular files.  */
	uint32_t st_uid; /* User ID of owner.  */
	uint32_t st_gid; /* Group ID of owner.  */
	uint32_t st_rdev; /* Device ID (if special file).  */
	uint64_t st_size; /* Size of file, only used for regular files */

	struct timespec st_mtim; /* Time of last modification.  */
	struct timespec st_ctim; /* Time of last status change.  */
};

static inline uint32_t lcfs_inode_encoded_size(uint32_t flags)
{
	return
		sizeof(uint32_t) /* payload_length */ +
		sizeof(struct lcfs_vdata_s) /* xattrs */ +
		LCFS_INODE_FLAG_CHECK_SIZE(flags, MODE, sizeof(uint32_t)) +
		LCFS_INODE_FLAG_CHECK_SIZE(flags, NLINK, sizeof(uint32_t)) +
		LCFS_INODE_FLAG_CHECK_SIZE(flags, UIDGID, sizeof(uint32_t) + sizeof(uint32_t)) +
		LCFS_INODE_FLAG_CHECK_SIZE(flags, RDEV, sizeof(uint32_t)) +
		LCFS_INODE_FLAG_CHECK_SIZE(flags, TIMES, sizeof(uint64_t)*2) +
		LCFS_INODE_FLAG_CHECK_SIZE(flags, TIMES_NSEC, sizeof(uint32_t)*2) +
		LCFS_INODE_FLAG_CHECK_SIZE(flags, LOW_SIZE, sizeof(uint32_t)) +
		LCFS_INODE_FLAG_CHECK_SIZE(flags, HIGH_SIZE, sizeof(uint32_t))
		;
}

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
