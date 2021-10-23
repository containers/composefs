/*
 * composefs
 *
 * Copyright (C) 2021 Giuseppe Scrivano
 *
 * This file is released under the GPL.
 */

#ifndef _LCFS_H
#define _LCFS_H

#include <linux/fs.h>
#include <linux/stat.h>

#define LCFS_VERSION 1

#define LCFS_USE_TIMESPEC 0

typedef u32 lcfs_off_t;

typedef lcfs_off_t lcfs_c_str_t;

struct lcfs_vdata_s {
	lcfs_off_t off;
	lcfs_off_t len;
} __attribute__((packed));

struct lcfs_header_s {
	u8 version;
	u8 unused1;
	u16 unused2;
	u32 unused3;
} __attribute__((packed));

struct lcfs_inode_data_s {
	u32 st_mode; /* File type and mode.  */
	u32 st_nlink; /* Number of hard links.  */
	u32 st_uid; /* User ID of owner.  */
	u32 st_gid; /* Group ID of owner.  */
	u32 st_rdev; /* Device ID (if special file).  */
} __attribute__((packed));

struct lcfs_inode_s {
	/* Index of struct lcfs_inode_data_s. */
	lcfs_off_t inode_data_index;

	/* stat data.  */
	union {
		/* Offset and length to the content of the directory.  */
		struct {
			lcfs_off_t off;
			lcfs_off_t len;
		} dir;

		struct {
			/* Total size, in bytes.  */
			u64 st_size;
			lcfs_c_str_t payload;
		} file;
	} u;

#if LCFS_USE_TIMESPEC
	struct timespec st_mtim; /* Time of last modification.  */
	struct timespec st_ctim; /* Time of last status change.  */
#else
	u64 st_mtim; /* Time of last modification.  */
	u64 st_ctim; /* Time of last modification.  */
#endif

	/* Variable len data.  */
	struct lcfs_vdata_s xattrs;
} __attribute__((packed));

struct lcfs_dentry_s {
	/* Index of struct lcfs_inode_s */
	lcfs_off_t inode_index;

	/* Variable len data.  */
	lcfs_c_str_t name;

} __attribute__((packed));

/* xattr representation.  */
struct lcfs_xattr_header_s {
	struct lcfs_vdata_s key;
	struct lcfs_vdata_s value;
} __attribute__((packed));

#endif
