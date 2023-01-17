/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _CFS_INTERNALS_H
#define _CFS_INTERNALS_H

#include "cfs.h"
#include "cfs-verity.h"

#define EFSCORRUPTED EUCLEAN /* Filesystem is corrupted */

#define CFS_N_PRELOAD_DIR_CHUNKS 4

struct cfs_inode_extra_data {
	char *path_payload; /* Real pathname for files, target for symlinks */

	u64 xattrs_offset;
	u32 xattrs_len;

	u64 dirents_offset;
	u32 dirents_len;

	bool has_digest;
	u8 digest[SHA256_DIGEST_SIZE]; /* fs-verity digest */
};

struct cfs_context {
	struct cfs_superblock superblock;
	struct file *descriptor;
	u64 data_offset;
	u64 root_inode;

	u64 descriptor_len;
};

int cfs_init_ctx(const char *descriptor_path, const u8 *required_digest,
		 struct cfs_context *ctx);

void cfs_ctx_put(struct cfs_context *ctx);

void cfs_inode_extra_data_put(struct cfs_inode_extra_data *inode_data);

int cfs_init_inode(struct cfs_context *ctx, u32 inode_num,
                   struct inode *inode,
                   struct cfs_inode_extra_data *data);

ssize_t cfs_list_xattrs(struct cfs_context *ctx, struct cfs_inode_extra_data *inode_data,
			char *names, size_t size);
int cfs_get_xattr(struct cfs_context *ctx, struct cfs_inode_extra_data *inode_data,
		  const char *name, void *value, size_t size);

typedef bool (*cfs_dir_iter_cb)(void *private, const char *name, int namelen,
				u64 ino, unsigned int dtype);

int cfs_dir_iterate(struct cfs_context *ctx, u64 index,
		    struct cfs_inode_extra_data *inode_data, loff_t first,
		    cfs_dir_iter_cb cb, void *private);

int cfs_dir_lookup(struct cfs_context *ctx, u64 index,
		   struct cfs_inode_extra_data *inode_data, const char *name,
		   size_t name_len, u64 *index_out);

#endif
