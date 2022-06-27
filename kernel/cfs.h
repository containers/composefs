/*
 * composefs
 *
 * Copyright (C) 2021 Giuseppe Scrivano
 *
 * This file is released under the GPL.
 */

#ifndef _CFS_H
#define _CFS_H

#ifdef FUZZING
#include <stdio.h>
#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
#define timespec64 timespec
#endif

#include <linux/types.h>
#include <linux/fs.h>
#include <linux/stat.h>

#ifndef FUZZING
#include <linux/byteorder/generic.h>
#endif

#define CFS_VERSION 1

#define CFS_DIGEST_SIZE 32

#define CFS_MAGIC 0xc078629aU

#ifdef FUZZING
static inline u16 cfs_u16_to_file(u16 val)
{
	return htole16(val);
}

static inline u32 cfs_u32_to_file(u32 val)
{
	return htole32(val);
}

static inline u64 cfs_u64_to_file(u64 val)
{
	return htole64(val);
}

static inline u16 cfs_u16_from_file(u16 val)
{
	return le16toh(val);
}

static inline u32 cfs_u32_from_file(u32 val)
{
	return le32toh(val);
}

static inline u64 cfs_u64_from_file(u64 val)
{
	return le64toh(val);
}
#else
static inline u16 cfs_u16_to_file(u16 val)
{
	return cpu_to_le16(val);
}

static inline u32 cfs_u32_to_file(u32 val)
{
	return cpu_to_le32(val);
}

static inline u64 cfs_u64_to_file(u64 val)
{
	return cpu_to_le64(val);
}

static inline u16 cfs_u16_from_file(u16 val)
{
	return le16_to_cpu(val);
}

static inline u32 cfs_u32_from_file(u32 val)
{
	return le32_to_cpu(val);
}

static inline u64 cfs_u64_from_file(u64 val)
{
	return le64_to_cpu(val);
}
#endif

static inline int cfs_xdigit_value(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	return -1;
}

static inline int cfs_digest_from_payload(const char *payload,
					  size_t payload_len,
					  u8 digest_out[CFS_DIGEST_SIZE])
{
	const char *p, *end;
	u8 last_digit = 0;
	int digit = 0;
	size_t n_nibbles = 0;

	end = payload + payload_len;
	for (p = payload; p != end; p++) {
		/* Skip subdir structure */
		if (*p == '/')
			continue;

		/* Break at (and ignore) extension */
		if (*p == '.')
			break;

		if (n_nibbles == CFS_DIGEST_SIZE * 2)
			return -1; /* Too long */

		digit = cfs_xdigit_value(*p);
		if (digit == -1) {
			return -1; /* Not hex digit */
		}

		n_nibbles++;
		if ((n_nibbles % 2) == 0) {
			digest_out[n_nibbles / 2 - 1] =
				(last_digit << 4) | digit;
		}
		last_digit = digit;
	}

	if (n_nibbles != CFS_DIGEST_SIZE * 2)
		return -1; /* Too short */

	return 0;
}

struct cfs_vdata_s {
	u32 off;
	u32 len;
} __attribute__((packed));

struct cfs_header_s {
	u8 version;
	u8 unused1;
	u16 unused2;

	u32 magic;
	u64 data_offset;
	u64 root_inode;

	u64 unused3[2];
} __attribute__((packed));

enum cfs_inode_flags {
	CFS_INODE_FLAGS_NONE = 0,
	CFS_INODE_FLAGS_PAYLOAD = 1 << 0,
	CFS_INODE_FLAGS_MODE = 1 << 1,
	CFS_INODE_FLAGS_NLINK = 1 << 2,
	CFS_INODE_FLAGS_UIDGID = 1 << 3,
	CFS_INODE_FLAGS_RDEV = 1 << 4,
	CFS_INODE_FLAGS_TIMES = 1 << 5,
	CFS_INODE_FLAGS_TIMES_NSEC = 1 << 6,
	CFS_INODE_FLAGS_LOW_SIZE = 1 << 7, /* Low 32bit of st_size */
	CFS_INODE_FLAGS_HIGH_SIZE = 1 << 8, /* High 32bit of st_size */
	CFS_INODE_FLAGS_XATTRS = 1 << 9,
	CFS_INODE_FLAGS_DIGEST = 1
				 << 10, /* fs-verity sha256 digest of content */
	CFS_INODE_FLAGS_DIGEST_FROM_PAYLOAD =
		1 << 11, /* Compute digest from payload */
};

#define CFS_INODE_FLAG_CHECK(_flag, _name)                                     \
	(((_flag) & (CFS_INODE_FLAGS_##_name)) != 0)
#define CFS_INODE_FLAG_CHECK_SIZE(_flag, _name, _size)                         \
	(CFS_INODE_FLAG_CHECK(_flag, _name) ? (_size) : 0)

#define CFS_INODE_DEFAULT_MODE 0100644
#define CFS_INODE_DEFAULT_NLINK 1
#define CFS_INODE_DEFAULT_UIDGID 0
#define CFS_INODE_DEFAULT_RDEV 0
#define CFS_INODE_DEFAULT_TIMES 0

struct cfs_inode_s {
	u32 flags;

	/* Optional data: (selected by flags) */

	/* This is the size of the type specific data that comes directly after
	   the inode in the file. Of this type:
	   *
	   * directory: cfs_dir_s
	   * regular file: the backing filename
	   * symlink: the target link
	   *
	   * Canonically payload_length is 0 for empty dir/file/symlink.
	   */
	u32 payload_length;

	u32 st_mode; /* File type and mode.  */
	u32 st_nlink; /* Number of hard links, only for regular files.  */
	u32 st_uid; /* User ID of owner.  */
	u32 st_gid; /* Group ID of owner.  */
	u32 st_rdev; /* Device ID (if special file).  */
	u64 st_size; /* Size of file, only used for regular files */

	struct cfs_vdata_s xattrs; /* ref to variable data */

	u8 digest[CFS_DIGEST_SIZE]; /* sha256 fs-verity digest */

	struct timespec64 st_mtim; /* Time of last modification.  */
	struct timespec64 st_ctim; /* Time of last status change.  */
};

static inline u32 cfs_inode_encoded_size(u32 flags)
{
	return sizeof(u32) /* flags */ +
	       CFS_INODE_FLAG_CHECK_SIZE(flags, PAYLOAD, sizeof(u32)) +
	       CFS_INODE_FLAG_CHECK_SIZE(flags, MODE, sizeof(u32)) +
	       CFS_INODE_FLAG_CHECK_SIZE(flags, NLINK, sizeof(u32)) +
	       CFS_INODE_FLAG_CHECK_SIZE(flags, UIDGID,
					 sizeof(u32) + sizeof(u32)) +
	       CFS_INODE_FLAG_CHECK_SIZE(flags, RDEV, sizeof(u32)) +
	       CFS_INODE_FLAG_CHECK_SIZE(flags, TIMES, sizeof(u64) * 2) +
	       CFS_INODE_FLAG_CHECK_SIZE(flags, TIMES_NSEC, sizeof(u32) * 2) +
	       CFS_INODE_FLAG_CHECK_SIZE(flags, LOW_SIZE, sizeof(u32)) +
	       CFS_INODE_FLAG_CHECK_SIZE(flags, HIGH_SIZE, sizeof(u32)) +
	       CFS_INODE_FLAG_CHECK_SIZE(flags, XATTRS, sizeof(u32) * 2) +
	       CFS_INODE_FLAG_CHECK_SIZE(flags, DIGEST, CFS_DIGEST_SIZE);
}

struct cfs_dentry_s {
	/* Index of struct cfs_inode_s */
	u64 inode_index;
	u16 name_len;
	u8 d_type;
	u8 pad;
} __attribute__((packed));

struct cfs_dir_s {
	/* Index of struct cfs_inode_s */
	u32 n_dentries;
	struct cfs_dentry_s dentries[];
} __attribute__((packed));

#define cfs_dir_size(_n_dentries)                                              \
	(sizeof(struct cfs_dir_s) + (_n_dentries) * sizeof(struct cfs_dentry_s))

/* xattr representation.  */
struct cfs_xattr_element_s {
	u16 key_length;
	u16 value_length;
} __attribute__((packed));

struct cfs_xattr_header_s {
	u16 n_attr;
	struct cfs_xattr_element_s attr[0];
} __attribute__((packed));

#define cfs_xattr_header_size(_n_element)                                      \
	(sizeof(struct cfs_xattr_header_s) +                                   \
	 (_n_element) * sizeof(struct cfs_xattr_element_s))

#endif
