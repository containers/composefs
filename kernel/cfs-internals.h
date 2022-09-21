/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _CFS_INTERNALS_H
#define _CFS_INTERNALS_H

#include "cfs.h"
#include "cfs-verity.h"

#define EFSCORRUPTED EUCLEAN /* Filesystem is corrupted */

#define CFS_MAX_STACK 500
#define CFS_N_PRELOAD_DIR_CHUNKS 4

struct cfs_inode_data_s {
	u32 payload_length;
	char *path_payload; /* Real pathname for files, target for symlinks */
	u32 n_dir_chunks;
	struct cfs_dir_chunk_s preloaded_dir_chunks[CFS_N_PRELOAD_DIR_CHUNKS];

	u64 xattrs_offset;
	u32 xattrs_len;

	bool has_digest;
	u8 digest[SHA256_DIGEST_SIZE]; /* fs-verity digest */
};

struct cfs_context_s {
	struct cfs_header_s header;
	struct file *descriptor;

	u64 descriptor_len;
};

#define MIN(a, b) ((a) < (b) ? (a) : (b))

int cfs_init_ctx(const char *descriptor_path, const u8 *required_digest,
		 struct cfs_context_s *ctx);

void cfs_ctx_put(struct cfs_context_s *ctx);

void cfs_inode_data_put(struct cfs_inode_data_s *inode_data);

struct cfs_inode_s *cfs_get_root_ino(struct cfs_context_s *ctx,
				     struct cfs_inode_s *ino_buf, u64 *index);

struct cfs_inode_s *cfs_get_ino_index(struct cfs_context_s *ctx, u64 index,
				      struct cfs_inode_s *buffer);

int cfs_init_inode_data(struct cfs_context_s *ctx, struct cfs_inode_s *ino,
			u64 index, struct cfs_inode_data_s *data);

ssize_t cfs_list_xattrs(struct cfs_context_s *ctx,
			struct cfs_inode_data_s *inode_data, char *names,
			size_t size);
int cfs_get_xattr(struct cfs_context_s *ctx,
		  struct cfs_inode_data_s *inode_data, const char *name,
		  void *value, size_t size);

typedef bool (*cfs_dir_iter_cb)(void *private, const char *name, int namelen,
				u64 ino, unsigned int dtype);

int cfs_dir_iterate(struct cfs_context_s *ctx, u64 index,
		    struct cfs_inode_data_s *inode_data, loff_t first,
		    cfs_dir_iter_cb cb, void *private);

int cfs_dir_lookup(struct cfs_context_s *ctx, u64 index,
		   struct cfs_inode_data_s *inode_data, const char *name,
		   size_t name_len, u64 *index_out);

#endif
