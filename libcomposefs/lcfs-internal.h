/* lcfs
   Copyright (C) 2023 Alexander Larsson <alexl@redhat.com>

   This file is free software: you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 2.1 of the
   License, or (at your option) any later version.

   This file is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

#ifndef _LCFS_INTERNAL_H
#define _LCFS_INTERNAL_H

#include <endian.h>

#include "lcfs-writer.h"
#include "lcfs-fsverity.h"
#include "hash.h"

/* When using LCFS_BUILD_INLINE_SMALL in lcfs_load_node_from_file() inline files below this size
 * We pick 64 which is the size of a sha256 digest that would otherwise be used as a redirect
 * xattr, so the inlined file is smaller.
 */
#define LCFS_BUILD_INLINE_FILE_SIZE_LIMIT 64

#define OVERLAY_XATTR_USER_PREFIX "user."
#define OVERLAY_XATTR_TRUSTED_PREFIX "trusted."
#define OVERLAY_XATTR_PARTIAL_PREFIX "overlay."
#define OVERLAY_XATTR_PREFIX                                                   \
	OVERLAY_XATTR_TRUSTED_PREFIX OVERLAY_XATTR_PARTIAL_PREFIX
#define OVERLAY_XATTR_USERXATTR_PREFIX                                         \
	OVERLAY_XATTR_USER_PREFIX OVERLAY_XATTR_PARTIAL_PREFIX
#define OVERLAY_XATTR_ESCAPE_PREFIX OVERLAY_XATTR_PREFIX "overlay."
#define OVERLAY_XATTR_METACOPY OVERLAY_XATTR_PREFIX "metacopy"
#define OVERLAY_XATTR_REDIRECT OVERLAY_XATTR_PREFIX "redirect"
#define OVERLAY_XATTR_WHITEOUT OVERLAY_XATTR_PREFIX "whiteout"
#define OVERLAY_XATTR_WHITEOUTS OVERLAY_XATTR_PREFIX "whiteouts"
#define OVERLAY_XATTR_OPAQUE OVERLAY_XATTR_PREFIX "opaque"

#define OVERLAY_XATTR_ESCAPED_WHITEOUT OVERLAY_XATTR_ESCAPE_PREFIX "whiteout"
#define OVERLAY_XATTR_ESCAPED_WHITEOUTS OVERLAY_XATTR_ESCAPE_PREFIX "whiteouts"

#define OVERLAY_XATTR_USERXATTR_WHITEOUT                                       \
	OVERLAY_XATTR_USERXATTR_PREFIX "whiteout"
#define OVERLAY_XATTR_USERXATTR_WHITEOUTS                                      \
	OVERLAY_XATTR_USERXATTR_PREFIX "whiteouts"

#define ALIGN_TO(_offset, _align_size)                                         \
	(((_offset) + _align_size - 1) & ~(_align_size - 1))

#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define round_up(x, y) ((((x)-1) | __round_mask(x, y)) + 1)
#define round_down(x, y) ((x) & ~__round_mask(x, y))

#define LCFS_MAX_NAME_LENGTH 255 /* max len of file name excluding NULL */

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

/* In memory representation used to build the file.  */

struct lcfs_xattr_s {
	char *key;
	char *value;
	size_t value_len;

	/* Used during writing */
	int64_t erofs_shared_xattr_offset; /* shared offset, or -1 if not shared */
};

struct lcfs_inode_s {
	uint32_t st_mode; /* File type and mode.  */
	uint32_t st_nlink; /* Number of hard links, only for regular files.  */
	uint32_t st_uid; /* User ID of owner.  */
	uint32_t st_gid; /* Group ID of owner.  */
	uint32_t st_rdev; /* Device ID (if special file).  */
	uint64_t st_size; /* Size of file, only used for regular files */
	int64_t st_mtim_sec;
	uint32_t st_mtim_nsec;
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

	uint8_t *content;

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

static inline void lcfs_node_unrefp(struct lcfs_node_s **nodep)
{
	if (*nodep != NULL) {
		lcfs_node_unref(*nodep);
		*nodep = NULL;
	}
}
#define cleanup_node __attribute__((cleanup(lcfs_node_unrefp)))

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

int lcfs_node_rename_xattr(struct lcfs_node_s *node, size_t index,
			   const char *new_name);

/* lcfs-writer-erofs.c */

int lcfs_write_erofs_to(struct lcfs_ctx_s *ctx);
struct lcfs_ctx_s *lcfs_ctx_erofs_new(void);

/* lcfs-writer-cfs.c */

int lcfs_write_cfs_to(struct lcfs_ctx_s *ctx);
struct lcfs_ctx_s *lcfs_ctx_cfs_new(void);

#endif
