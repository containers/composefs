/*
 * composefs
 *
 * Copyright (C) 2021 Giuseppe Scrivano
 *
 * This file is released under the GPL.
 */

#ifndef _LCFS_H
#define _LCFS_H

#ifdef FUZZING
# include <stdio.h>
# include <sys/types.h>
# include <stdint.h>
# include <stdbool.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
#define timespec64 timespec
#endif

#include <linux/types.h>
#include <linux/fs.h>
#include <linux/stat.h>

#define LCFS_VERSION 1

typedef u64 lcfs_off_t;

typedef lcfs_off_t lcfs_c_str_t;

struct lcfs_vdata_s {
	u32 off;
	u32 len;
} __attribute__((packed));

struct lcfs_header_s {
	u8 version;
	u8 unused1;
	u16 unused2;

	u32 inode_len;
	lcfs_off_t data_offset;

	u64 unused3[3];
} __attribute__((packed));

struct lcfs_backing_s {
	/* Total size of the backing file in bytes.  */
	u64 st_size;

	/* Source file.  */
	u32 payload_len;
	char payload[];
} __attribute__((packed));

#define lcfs_backing_size(_payload_len) (sizeof(struct lcfs_backing_s) + (_payload_len))

/* Same as lcfs_backing_s, but with PATH_MAX elements */
struct lcfs_backing_buf_s {
	/* Total size of the backing file in bytes.  */
	u64 st_size;

	/* Source file.  */
	u32 payload_len;
	char payload[PATH_MAX];
} __attribute__((packed));

struct lcfs_inode_s {
	u32 st_mode; /* File type and mode.  */
	u32 st_nlink; /* Number of hard links.  */
	u32 st_uid; /* User ID of owner.  */
	u32 st_gid; /* Group ID of owner.  */
	u32 st_rdev; /* Device ID (if special file).  */

	struct timespec64 st_mtim; /* Time of last modification.  */
	struct timespec64 st_ctim; /* Time of last status change.  */

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
	u32 payload_length;
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
	u32 n_dentries;
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
