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

/* Descriptor file layout:
 *
 *  +-----------------------+
 *  | cfs_superblock        |
 *  |   vdata_offfset       |---|
 *  +-----------------------|   |
 *  | Inode table           |   |
 *  |  N * cfs_inode_data   |   |
 *  +-----------------------|   |
 *  | Variable data section |<--/
 *  | Used for:             |
 *  |  symlink targets      |
 *  |  backing file paths   |
 *  |  dirents              |
 *  |  xattrs               |
 *  |  digests              |
 *  +-----------------------+
 *
 * The superblock is at the start of the file, and the inode table
 * directly follows it. The variable data section found via
 * vdata_offset and all sections are 32bit aligned. All data is
 *  little endian.
 *
 * The inode table is a table of fixed size cfs_inode_data elements.
 * The filesystem inode numbers are 32bit indexes into this table.
 * Actual file content (for regular files) is referenced by a backing
 * file path which is looked up relative to a given base dir.
 *
 * All variable size data are stored in the variable data section and
 * are referenced using cfs_vdata (64bit offset from the start of the
 * vdata section and 32bit lengths).
 *
 * Directory dirent data is stored in one 32bit aligned vdata chunk,
 * staring with a table of fixed size cfs_dirents and which is
 * followed by a string table. The dirents reference the strings by
 * offsets form the string table. The dirents are sorted for efficient
 * binary search lookups.
 *
 * Xattrs data are stored in a 32bit aligned vdata chunk. This is
 * a table of cfs_xattr, followed by the key/value data. The
 * xattrs are sorted by key. Note that many inodes can reference
 * the same xattr data.
 */

/* Current (and atm only) version of the image format. */
#define CFS_VERSION 1

#define CFS_MAGIC 0xc078629aU

#define CFS_SUPERBLOCK_OFFSET 0
#define CFS_INODE_TABLE_OFFSET sizeof(struct cfs_superblock)
#define CFS_INODE_SIZE sizeof(struct cfs_inode_data)
#define CFS_DIRENT_SIZE sizeof(struct cfs_dirent)
#define CFS_XATTR_ELEM_SIZE sizeof(struct cfs_xattr_element)
#define CFS_ROOT_INO 0

/* Fits at least the root inode */
#define CFS_DESCRIPTOR_MIN_SIZE                                                \
	(sizeof(struct cfs_superblock) + sizeof(struct cfs_inode_data))

/* More that this would overflow header size computation */
#define CFS_MAX_DIRENTS (U32_MAX / CFS_DIRENT_SIZE - 1)

#define CFS_MAX_XATTRS U16_MAX

struct cfs_superblock {
	__le32 version; /* CFS_VERSION */
	__le32 magic; /* CFS_MAGIC */

	/* Offset of the variable data section from start of file */
	__le64 vdata_offset;

	/* For future use, and makes superblock 128 bytes to align
	 * inode table on cacheline boundary on most arches.
	 */
	__le32 unused[28];
} __packed;

struct cfs_vdata {
	__le64 off; /* Offset into variable data section */
	__le32 len;
} __packed;

struct cfs_inode_data {
	__le32 st_mode; /* File type and mode.  */
	__le32 st_nlink; /* Number of hard links, only for regular files.  */
	__le32 st_uid; /* User ID of owner.  */
	__le32 st_gid; /* Group ID of owner.  */
	__le32 st_rdev; /* Device ID (if special file).  */
	__le64 st_size; /* Size of file */
	__le64 st_mtim_sec;
	__le32 st_mtim_nsec;
	__le64 st_ctim_sec;
	__le32 st_ctim_nsec;

	/* References to variable storage area: */

	/* per-type variable data:
	 * S_IFDIR: dirents
	 * S_IFREG: backing file pathnem
	 * S_IFLNLK; symlink target
	 */
	struct cfs_vdata variable_data;

	struct cfs_vdata xattrs;
	struct cfs_vdata digest; /* Expected fs-verity digest of backing file */

	/* For future use, and makes inode_data 96 bytes which
	 * is semi-aligned with cacheline sizes.
	 */
	__le32 unused[2];
} __packed;

struct cfs_dirent {
	__le32 inode_num; /* Index in inode table */
	__le32 name_offset; /* Offset from end of cfs_dir_header */
	u8 name_len;
	u8 d_type;
	u16 _padding;
} __packed;

/* Directory entries, stored in variable data section, 32bit aligned,
 * followed by name string table
 */
struct cfs_dir_header {
	__le32 n_dirents;
	struct cfs_dirent dirents[];
} __packed;

static inline size_t cfs_dir_header_size(size_t n_dirents)
{
	return sizeof(struct cfs_dir_header) + n_dirents * CFS_DIRENT_SIZE;
}

struct cfs_xattr_element {
	__le16 key_length;
	__le16 value_length;
} __packed;

/* Xattrs, stored in variable data section , 32bit aligned, followed
 * by key/value table
 */
struct cfs_xattr_header {
	__le16 n_attr;
	struct cfs_xattr_element attr[0];
} __packed;

static inline size_t cfs_xattr_header_size(size_t n_element)
{
	return sizeof(struct cfs_xattr_header) + n_element * CFS_XATTR_ELEM_SIZE;
}

#endif
