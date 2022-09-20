#ifndef _CFS_INTERNALS_H
#define _CFS_INTERNALS_H

#include "cfs.h"
#include "cfs-verity.h"

#define EFSCORRUPTED EUCLEAN /* Filesystem is corrupted */

#define CFS_MAX_STACK 500
#define CFS_N_PRELOAD_DIR_CHUNKS 4

struct cfs_buf {
	struct page *page;
	void *base;
};
#define CFS_VDATA_BUF_INIT                                                     \
	{                                                                      \
		NULL, NULL                                                     \
	}

struct cfs_inode_data_s {
	u32 payload_length;
	u32 n_dir_chunks;
	struct cfs_dir_chunk_s preloaded_dir_chunks[CFS_N_PRELOAD_DIR_CHUNKS];
};

struct cfs_context_s {
	struct cfs_header_s header;
	struct file *descriptor;

	u64 descriptor_len;
};

#define MIN(a, b) ((a) < (b) ? (a) : (b))

int cfs_init_ctx(const char *descriptor_path, const u8 *required_digest,
		 struct cfs_context_s *ctx);

void cfs_destroy_ctx(struct cfs_context_s *ctx);

struct cfs_inode_s *cfs_get_root_ino(struct cfs_context_s *ctx,
				     struct cfs_inode_s *ino_buf, u64 *index);

struct cfs_inode_s *cfs_get_ino_index(struct cfs_context_s *ctx, u64 index,
				      struct cfs_inode_s *buffer);

const uint8_t *cfs_get_digest(struct cfs_context_s *ctx,
			      struct cfs_inode_s *ino, const char *payload,
			      u8 digest_buf[SHA256_DIGEST_SIZE]);

int cfs_init_inode_data(struct cfs_context_s *ctx, struct cfs_inode_s *ino,
			u64 index, struct cfs_inode_data_s *data);

struct cfs_xattr_header_s *cfs_get_xattrs(struct cfs_context_s *ctx,
					  struct cfs_inode_s *ino);
ssize_t cfs_list_xattrs(struct cfs_xattr_header_s *xattrs, char *names,
			size_t size);
int cfs_get_xattr(struct cfs_xattr_header_s *xattrs, const char *name,
		  void *value, size_t size);

typedef bool (*cfs_dir_iter_cb)(void *private, const char *name, int namelen,
				u64 ino, unsigned int dtype);

int cfs_dir_iterate(struct cfs_context_s *ctx, u64 index,
		    struct cfs_inode_data_s *inode_data, loff_t first,
		    cfs_dir_iter_cb cb, void *private);

int cfs_dir_lookup(struct cfs_context_s *ctx, u64 index,
		   struct cfs_inode_data_s *inode_data, const char *name,
		   size_t name_len, u64 *index_out);

char *cfs_dup_payload_path(struct cfs_context_s *ctx, struct cfs_inode_s *ino,
			   u64 index);

#endif
