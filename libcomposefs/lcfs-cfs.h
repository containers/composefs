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

#ifndef _LCFS_CFS_H
#define _LCFS_CFS_H
#include <stdlib.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <endian.h>
#include <errno.h>

#define LCFS_VERSION 1

#define LCFS_DIGEST_SIZE 32

#define LCFS_MAX_NAME_LENGTH 255 /* max len of file name excluding NULL */

#define LCFS_MAGIC 0xc078629aU

static inline uint16_t lcfs_u16_to_file(uint16_t val)
{
	return htole16(val);
}

static inline uint32_t lcfs_u32_to_file(uint32_t val)
{
	return htole32(val);
}

static inline uint64_t lcfs_u64_to_file(uint64_t val)
{
	return htole64(val);
}

static inline uint16_t lcfs_u16_from_file(uint16_t val)
{
	return le16toh(val);
}

static inline uint32_t lcfs_u32_from_file(uint32_t val)
{
	return le32toh(val);
}

static inline uint64_t lcfs_u64_from_file(uint64_t val)
{
	return le64toh(val);
}

struct lcfs_superblock_s {
	uint32_t version;
	uint32_t magic;
	uint64_t vdata_offset;

	/* For future use, and makes superblock 128 bytes to align
	 * inode table on cacheline boundary on most arches. */
	uint32_t unused[28];
} __attribute__((__packed__));

struct lcfs_vdata_s {
	uint64_t off;
	uint32_t len;
} __attribute__((__packed__));

struct lcfs_inode_s {
	uint32_t st_mode; /* File type and mode.  */
	uint32_t st_nlink; /* Number of hard links, only for regular files.  */
	uint32_t st_uid; /* User ID of owner.  */
	uint32_t st_gid; /* Group ID of owner.  */
	uint32_t st_rdev; /* Device ID (if special file).  */
	uint64_t st_size; /* Size of file, only used for regular files */
	int64_t st_mtim_sec;
	uint32_t st_mtim_nsec;
	int64_t st_ctim_sec;
	uint32_t st_ctim_nsec;

	/* References to variable storage area: */
	struct lcfs_vdata_s variable_data; /* dirent, backing file or symlink target */
	struct lcfs_vdata_s xattrs;
	struct lcfs_vdata_s digest;

	/* For future use, and makes inode_data 96 bytes which
	 * is semi-aligned with cacheline sizes. */
	uint32_t unused[2];
} __attribute__((__packed__));
;

struct lcfs_dirent_s {
	uint32_t inode_num;
	uint32_t name_offset; /* Offset from end of dir_header */
	uint8_t name_len;
	uint8_t d_type;
	uint16_t _padding;
} __attribute__((__packed__));
;

struct lcfs_dir_header_s {
	uint32_t n_dirents;
	struct lcfs_dirent_s dirents[0];
} __attribute__((__packed__));
;

static inline size_t lcfs_dir_header_size(size_t n_dirents)
{
	return sizeof(struct lcfs_dir_header_s) +
	       n_dirents * sizeof(struct lcfs_dirent_s);
}

/* xattr representation.  */
struct lcfs_xattr_element_s {
	uint16_t key_length;
	uint16_t value_length;
} __attribute__((__packed__));
;

struct lcfs_xattr_header_s {
	uint16_t n_attr;
	struct lcfs_xattr_element_s attr[0];
} __attribute__((__packed__));
;

static inline size_t lcfs_xattr_header_size(size_t n_element)
{
	return sizeof(struct lcfs_xattr_header_s) +
	       n_element * sizeof(struct lcfs_xattr_element_s);
}

#endif
