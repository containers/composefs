/* SPDX-License-Identifier: GPL-2.0 */
/*
 * composefs
 *
 * Copyright (C) 2021 Giuseppe Scrivano
 * Copyright (C) 2022 Alexander Larsson
 *
 * This file is released under the GPL.
 */

#ifndef _CFS_H
#define _CFS_H

#include <asm/byteorder.h>
#include <crypto/sha2.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/types.h>

#define CFS_VERSION 1

#define CFS_MAGIC 0xc078629aU

struct cfs_superblock {
	__le32 version;
	__le32 magic;
	__le64 data_offset;
	__le64 root_inode;

	__le64 unused3[2];
};

struct cfs_vdata {
	__le64 off;
	__le32 len;
};

struct cfs_inode_data {
	__le32 st_mode; /* File type and mode.  */
	__le32 st_nlink; /* Number of hard links, only for regular files.  */
	__le32 st_uid; /* User ID of owner.  */
	__le32 st_gid; /* Group ID of owner.  */
	__le32 st_rdev; /* Device ID (if special file).  */
	__le64 st_size; /* Size of file, only used for regular files */
	__le64 st_mtim_sec;
	__le32 st_mtim_nsec;
	__le64 st_ctim_sec;
	__le32 st_ctim_nsec;

	/* References to variable storage area: */
	struct cfs_vdata variable_data; /* dirent, backing file or symlink target */
	struct cfs_vdata xattrs; /* ref to variable data */
	struct cfs_vdata digest;
};

struct cfs_dirent {
	/* Index of struct cfs_inode */
	__le64 inode_index;
	__le32 name_offset;  /* Offset from end of dir_header */
	u8 name_len;
	u8 d_type;
	u16 _padding;
};

struct cfs_dir_header {
	__le32 n_dirents;
	struct cfs_dirent dirents[];
};

static inline size_t cfs_dir_header_size(size_t n_dirents) {
	return sizeof(struct cfs_dir_header) + n_dirents * sizeof(struct cfs_dirent);
}

/* xattr representation.  */
struct cfs_xattr_element {
	__le16 key_length;
	__le16 value_length;
};

struct cfs_xattr_header {
	__le16 n_attr;
	struct cfs_xattr_element attr[0];
};

static inline size_t cfs_xattr_header_size(size_t n_element) {
	return sizeof(struct cfs_xattr_header) + n_element * sizeof(struct cfs_xattr_element);
}

#endif
