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

static inline int lcfs_xdigit_value(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	return -1;
}

static inline int lcfs_digest_from_payload(const char *payload, size_t payload_len,
					   uint8_t digest_out[LCFS_DIGEST_SIZE])
{
	const char *p, *end;
	uint8_t last_digit = 0;
	int digit = 0;
	size_t n_nibbles = 0;

	/* This handles payloads (i.e. path names) that are "essentially" a
	 * digest as the digest (if the DIGEST_FROM_PAYLOAD flag is set). The
	 * "essential" part means that we ignore hierarchical structure as well
	 * as any extension. So, for example "ef/deadbeef.file" would match the
	 * (too short) digest "efdeadbeef".
	 *
	 * This allows images to avoid storing both the digest and the pathname,
	 * yet work with pre-existing object store formats of various kinds.
	 */

	end = payload + payload_len;
	for (p = payload; p != end; p++) {
		/* Skip subdir structure */
		if (*p == '/')
			continue;

		/* Break at (and ignore) extension */
		if (*p == '.')
			break;

		if (n_nibbles == LCFS_DIGEST_SIZE * 2)
			return -EINVAL; /* Too long */

		digit = lcfs_xdigit_value(*p);
		if (digit == -1) {
			return -EINVAL; /* Not hex digit */
		}

		n_nibbles++;
		if ((n_nibbles % 2) == 0) {
			digest_out[n_nibbles / 2 - 1] = (last_digit << 4) | digit;
		}
		last_digit = digit;
	}

	if (n_nibbles != LCFS_DIGEST_SIZE * 2)
		return -EINVAL; /* Too short */

	return 0;
}

struct lcfs_vdata_s {
	uint64_t off;
	uint32_t len;
} __attribute__((packed));

struct lcfs_header_s {
	uint8_t version;
	uint8_t unused1;
	uint16_t unused2;

	uint32_t magic;
	uint64_t data_offset;
	uint64_t root_inode;

	uint64_t unused3[2];
} __attribute__((packed));

enum lcfs_inode_flags {
	LCFS_INODE_FLAGS_NONE = 0,
	LCFS_INODE_FLAGS_PAYLOAD = 1 << 0,
	LCFS_INODE_FLAGS_MODE = 1 << 1,
	LCFS_INODE_FLAGS_NLINK = 1 << 2,
	LCFS_INODE_FLAGS_UIDGID = 1 << 3,
	LCFS_INODE_FLAGS_RDEV = 1 << 4,
	LCFS_INODE_FLAGS_TIMES = 1 << 5,
	LCFS_INODE_FLAGS_TIMES_NSEC = 1 << 6,
	LCFS_INODE_FLAGS_LOW_SIZE = 1 << 7, /* Low 32bit of st_size */
	LCFS_INODE_FLAGS_HIGH_SIZE = 1 << 8, /* High 32bit of st_size */
	LCFS_INODE_FLAGS_XATTRS = 1 << 9,
	LCFS_INODE_FLAGS_DIGEST = 1 << 10, /* fs-verity sha256 digest */
	LCFS_INODE_FLAGS_DIGEST_FROM_PAYLOAD = 1 << 11, /* Compute digest from payload */
};

#define LCFS_INODE_FLAG_CHECK(_flag, _name)                                    \
	(((_flag) & (LCFS_INODE_FLAGS_##_name)) != 0)
#define LCFS_INODE_FLAG_CHECK_SIZE(_flag, _name, _size)                        \
	(LCFS_INODE_FLAG_CHECK(_flag, _name) ? (_size) : 0)

#define LCFS_INODE_DEFAULT_MODE 0100644
#define LCFS_INODE_DEFAULT_NLINK 1
#define LCFS_INODE_DEFAULT_NLINK_DIR 2
#define LCFS_INODE_DEFAULT_UIDGID 0
#define LCFS_INODE_DEFAULT_RDEV 0
#define LCFS_INODE_DEFAULT_TIMES 0

struct lcfs_inode_s {
	uint32_t flags;
	struct lcfs_vdata_s variable_data; /* dirent, backing file or symlink target */
	/* Optional data: (selected by flags) */

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

	uint32_t st_mode; /* File type and mode.  */
	uint32_t st_nlink; /* Number of hard links, only for regular files.  */
	uint32_t st_uid; /* User ID of owner.  */
	uint32_t st_gid; /* Group ID of owner.  */
	uint32_t st_rdev; /* Device ID (if special file).  */
	uint64_t st_size; /* Size of file, only used for regular files */

	struct lcfs_vdata_s xattrs; /* ref to variable data */

	uint8_t digest[LCFS_DIGEST_SIZE]; /* sha256 fs-verity digest */

	struct timespec st_mtim; /* Time of last modification.  */
	struct timespec st_ctim; /* Time of last status change.  */
};

static inline uint32_t lcfs_inode_encoded_size(uint32_t flags)
{
	return sizeof(uint32_t) /* flags */ +
	       sizeof(struct lcfs_vdata_s) +
	       LCFS_INODE_FLAG_CHECK_SIZE(flags, PAYLOAD, sizeof(uint32_t)) +
	       LCFS_INODE_FLAG_CHECK_SIZE(flags, MODE, sizeof(uint32_t)) +
	       LCFS_INODE_FLAG_CHECK_SIZE(flags, NLINK, sizeof(uint32_t)) +
	       LCFS_INODE_FLAG_CHECK_SIZE(flags, UIDGID,
					  sizeof(uint32_t) + sizeof(uint32_t)) +
	       LCFS_INODE_FLAG_CHECK_SIZE(flags, RDEV, sizeof(uint32_t)) +
	       LCFS_INODE_FLAG_CHECK_SIZE(flags, TIMES, sizeof(uint64_t) * 2) +
	       LCFS_INODE_FLAG_CHECK_SIZE(flags, TIMES_NSEC, sizeof(uint32_t) * 2) +
	       LCFS_INODE_FLAG_CHECK_SIZE(flags, LOW_SIZE, sizeof(uint32_t)) +
	       LCFS_INODE_FLAG_CHECK_SIZE(flags, HIGH_SIZE, sizeof(uint32_t)) +
	       LCFS_INODE_FLAG_CHECK_SIZE(flags, XATTRS,
					  sizeof(uint64_t) + sizeof(uint32_t)) +
	       LCFS_INODE_FLAG_CHECK_SIZE(flags, DIGEST, LCFS_DIGEST_SIZE);
}

struct lcfs_dirent_s {
	/* Index of struct lcfs_inode_s */
	uint64_t inode_index;
	uint32_t name_offset; /* Offset from end of dir_header */
	uint8_t name_len;
	uint8_t d_type;
	uint16_t _padding;
};

struct lcfs_dir_header_s {
	uint32_t n_dirents;
	struct lcfs_dirent_s dirents[0];
};

static inline size_t lcfs_dir_header_size(size_t n_dirents) {
	return sizeof(struct lcfs_dir_header_s) + n_dirents * sizeof(struct lcfs_dirent_s);
}

/* xattr representation.  */
struct lcfs_xattr_element_s {
	uint16_t key_length;
	uint16_t value_length;
};

struct lcfs_xattr_header_s {
	uint16_t n_attr;
	struct lcfs_xattr_element_s attr[0];
};

static inline size_t lcfs_xattr_header_size(size_t n_element) {
	return sizeof(struct lcfs_xattr_header_s) + n_element * sizeof(struct lcfs_xattr_element_s);
}

#endif
