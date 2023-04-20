/* lcfs
   Copyright (C) 2023 Alexander Larsson <alexl@redhat.com>

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

#ifndef _LCFS_INTERNAL_H
#define _LCFS_INTERNAL_H

#include "lcfs-writer.h"
#include "lcfs-cfs.h"
#include "lcfs-fsverity.h"
#include "hash.h"

#define ALIGN_TO(_offset, _align_size)                                         \
	(((_offset) + _align_size - 1) & ~(_align_size - 1))

#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define round_up(x, y) ((((x)-1) | __round_mask(x, y)) + 1)
#define round_down(x, y) ((x) & ~__round_mask(x, y))

#define max(a, b) ((a > b) ? (a) : (b))

/* In memory representation used to build the file.  */

struct lcfs_xattr_s {
	char *key;
	char *value;
	size_t value_len;

	/* Used during writing */
	int64_t erofs_shared_xattr_offset; /* shared offset, or -1 if not shared */
};

struct lcfs_node_s {
	int ref_count;

	struct lcfs_node_s *parent;

	struct lcfs_node_s **children; /* Owns refs */
	size_t children_size;

	/* Used to create hard links.  */
	struct lcfs_node_s *link_to; /* Owns refs */

	char *name;
	char *payload; /* backing file or symlink target */

	struct lcfs_xattr_s *xattrs;
	size_t n_xattrs;

	bool digest_set;
	uint8_t digest[LCFS_DIGEST_SIZE]; /* sha256 fs-verity digest */

	struct lcfs_inode_s inode;

	/* Used during compute_tree */
	struct lcfs_node_s *next; /* Use for the queue in compute_tree */
	bool in_tree;
	uint32_t inode_num;

	bool erofs_compact;
	uint32_t erofs_ipad; /* padding before inode data */
	uint32_t erofs_isize;
	uint32_t erofs_nid;
	uint32_t erofs_n_blocks;
	uint32_t erofs_tailsize;
};

struct lcfs_ctx_s {
	struct lcfs_write_options_s *options;
	struct lcfs_node_s *root;
	bool destroy_root;

	/* Used by compute_tree.  */
	struct lcfs_node_s *queue_end;
	uint32_t num_inodes;
	int64_t min_mtim_sec;
	uint32_t min_mtim_nsec;
	bool has_acl;

	void *file;
	lcfs_write_cb write_cb;
	off_t bytes_written;
	FsVerityContext *fsverity_ctx;

	void (*finalize)(struct lcfs_ctx_s *ctx);
};

/* lcfs-writer.c */
size_t hash_memory(const char *string, size_t len, size_t n_buckets);
int lcfs_write(struct lcfs_ctx_s *ctx, void *_data, size_t data_len);
int lcfs_write_align(struct lcfs_ctx_s *ctx, size_t align_size);
int lcfs_write_pad(struct lcfs_ctx_s *ctx, size_t data_len);
int lcfs_compute_tree(struct lcfs_ctx_s *ctx, struct lcfs_node_s *root);
int lcfs_clone_root(struct lcfs_ctx_s *ctx);
char *maybe_join_path(const char *a, const char *b);
struct lcfs_node_s *follow_links(struct lcfs_node_s *node);
int node_get_dtype(struct lcfs_node_s *node);

/* lcfs-writer-erofs.c */

int lcfs_write_erofs_to(struct lcfs_ctx_s *ctx);
struct lcfs_ctx_s *lcfs_ctx_erofs_new(void);

/* lcfs-writer-cfs.c */

int lcfs_write_cfs_to(struct lcfs_ctx_s *ctx);
struct lcfs_ctx_s *lcfs_ctx_cfs_new(void);

#endif
