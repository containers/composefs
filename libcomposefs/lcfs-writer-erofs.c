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

#define _GNU_SOURCE

#include "config.h"

#include "lcfs-internal.h"
#include "lcfs-writer.h"
#include "lcfs-fsverity.h"
#include "lcfs-erofs.h"
#include "hash.h"

#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/xattr.h>
#include <sys/param.h>
#include <assert.h>
#include <linux/fsverity.h>

struct lcfs_ctx_erofs_s {
	struct lcfs_ctx_s base;

	uint64_t inodes_end; /* start of xattrs */
	uint64_t shared_xattr_size;
	uint64_t n_data_blocks;
	uint64_t current_end;
	struct lcfs_xattr_s **shared_xattrs;
	size_t n_shared_xattrs;
};

static void lcfs_ctx_erofs_finalize(struct lcfs_ctx_s *ctx)
{
	struct lcfs_ctx_erofs_s *ctx_erofs = (struct lcfs_ctx_erofs_s *)ctx;

	free(ctx_erofs->shared_xattrs);
}

struct lcfs_ctx_s *lcfs_ctx_erofs_new(void)
{
	struct lcfs_ctx_erofs_s *ret = calloc(1, sizeof(struct lcfs_ctx_erofs_s));
	if (ret == NULL) {
		return NULL;
	}

	ret->base.finalize = lcfs_ctx_erofs_finalize;

	return &ret->base;
}

#include "erofs_fs_wrapper.h"

static int erofs_make_file_type(int regular)
{
	switch (regular) {
	case DT_LNK:
		return EROFS_FT_SYMLINK;
	case DT_DIR:
		return EROFS_FT_DIR;
	case DT_REG:
		return EROFS_FT_REG_FILE;
	case DT_BLK:
		return EROFS_FT_BLKDEV;
	case DT_CHR:
		return EROFS_FT_CHRDEV;
	case DT_SOCK:
		return EROFS_FT_SOCK;
	case DT_FIFO:
		return EROFS_FT_FIFO;
	default:
		return EROFS_FT_UNKNOWN;
	}
}

struct hasher_xattr_s {
	struct lcfs_xattr_s *xattr;
	uint32_t count;

	bool shared;
	uint64_t shared_offset; /* offset in bytes from start of shared xattrs */
};

static size_t xattrs_ht_hasher(const void *d, size_t n)
{
	const struct hasher_xattr_s *v = d;
	return (hash_string(v->xattr->key, n) ^
		hash_memory(v->xattr->value, v->xattr->value_len, n)) %
	       n;
}

static bool xattrs_ht_comparator(const void *d1, const void *d2)
{
	const struct hasher_xattr_s *v1 = d1;
	const struct hasher_xattr_s *v2 = d2;

	if (strcmp(v1->xattr->key, v2->xattr->key) != 0)
		return false;

	if (v1->xattr->value_len != v2->xattr->value_len)
		return false;

	return memcmp(v1->xattr->value, v2->xattr->value, v1->xattr->value_len) == 0;
}

/* Sort alphabetically by key and value to get some canonical order */
static int xattrs_ht_sort(const void *d1, const void *d2)
{
	const struct hasher_xattr_s *v1 = *(const struct hasher_xattr_s **)d1;
	const struct hasher_xattr_s *v2 = *(const struct hasher_xattr_s **)d2;
	int r;

	r = strcmp(v2->xattr->key, v1->xattr->key);
	if (r != 0)
		return r;

	if (v1->xattr->value_len != v2->xattr->value_len)
		return (int)v2->xattr->value_len - (int)v1->xattr->value_len;

	return memcmp(v2->xattr->value, v1->xattr->value, v1->xattr->value_len);
}

static bool str_has_prefix(const char *str, const char *prefix)
{
	return strncmp(str, prefix, strlen(prefix)) == 0;
}

static uint8_t xattr_erofs_entry_index(struct lcfs_xattr_s *xattr, char **rest)
{
	char *key = xattr->key;
	struct {
		const char *prefix;
		uint8_t index;
	} keys[] = { { "user.", EROFS_XATTR_INDEX_USER },
		     { "system.posix_acl_access", EROFS_XATTR_INDEX_POSIX_ACL_ACCESS },
		     { "system.posix_acl_default", EROFS_XATTR_INDEX_POSIX_ACL_DEFAULT },
		     { "trusted.", EROFS_XATTR_INDEX_TRUSTED },
		     { "security.", EROFS_XATTR_INDEX_SECURITY },
		     { NULL } };
	for (size_t i = 0; keys[i].prefix != NULL; i++) {
		if (str_has_prefix(key, keys[i].prefix)) {
			*rest = key + strlen(keys[i].prefix);
			return keys[i].index;
		}
	}

	*rest = key;
	return 0;
}

static size_t xattr_erofs_entry_size(struct lcfs_xattr_s *xattr)
{
	char *key_suffix;
	xattr_erofs_entry_index(xattr, &key_suffix);

	return round_up(sizeof(struct erofs_xattr_entry) + strlen(key_suffix) +
				xattr->value_len,
			sizeof(uint32_t));
}

static size_t xattr_erofs_icount(size_t xattr_size)
{
	if (xattr_size == 0)
		return 0;
	return (xattr_size - sizeof(struct erofs_xattr_ibody_header)) /
		       sizeof(uint32_t) +
	       1;
}

static size_t xattr_erofs_inode_size(size_t n_shared_xattrs, size_t unshared_xattrs_size)
{
	if (n_shared_xattrs == 0 && unshared_xattrs_size == 0) {
		return 0;
	}

	return round_up(sizeof(struct erofs_xattr_ibody_header) +
				n_shared_xattrs * sizeof(uint32_t) +
				unshared_xattrs_size,
			sizeof(uint32_t));
}

static bool erofs_xattr_should_be_shared(struct hasher_xattr_s *ent)
{
	/* Share multi-use xattrs */
	if (ent->count > 1)
		return true;

	/* Also share verity overlay xattrs, as they are kind
	   of large to have inline, and not always accessed. */
	if (strcmp(ent->xattr->key, "trusted.overlay.verity") == 0)
		return true;

	return false;
}

static int compute_erofs_shared_xattrs(struct lcfs_ctx_s *ctx)
{
	struct lcfs_ctx_erofs_s *ctx_erofs = (struct lcfs_ctx_erofs_s *)ctx;
	struct lcfs_node_s *node;
	Hash_table *xattr_hash;
	struct hasher_xattr_s **sorted = NULL;
	size_t n_xattrs;
	uint64_t xattr_offset;

	/* Find the use count for each xattr key/value in use */

	xattr_hash = hash_initialize(0, NULL, xattrs_ht_hasher,
				     xattrs_ht_comparator, free);
	if (xattr_hash == NULL) {
		return -1;
	}

	for (node = ctx->root; node != NULL; node = node->next) {
		for (size_t i = 0; i < node->n_xattrs; i++) {
			struct hasher_xattr_s hkey = { .xattr = &node->xattrs[i] };
			struct hasher_xattr_s *ent;

			ent = hash_lookup(xattr_hash, &hkey);
			if (ent == NULL) {
				struct hasher_xattr_s *new_ent =
					calloc(1, sizeof(struct hasher_xattr_s));
				if (new_ent == NULL) {
					goto fail;
				}
				new_ent->xattr = &node->xattrs[i];
				ent = hash_insert(xattr_hash, new_ent);
				if (ent == NULL) {
					goto fail;
				}
			}
			ent->count++;
		}
	}

	/* Compute the xattr list in canonical order */

	n_xattrs = hash_get_n_entries(xattr_hash);
	sorted = calloc(n_xattrs, sizeof(struct hasher_xattr_s *));
	if (sorted == NULL)
		goto fail;
	n_xattrs = hash_get_entries(xattr_hash, (void **)sorted, n_xattrs);
	qsort(sorted, n_xattrs, sizeof(struct hasher_xattr_s *), xattrs_ht_sort);

	/* Compute the list of shared (multi-use) xattrs and their offsets */
	ctx_erofs->shared_xattrs = calloc(n_xattrs, sizeof(struct lcfs_xattr_s *));
	if (ctx_erofs->shared_xattrs == NULL)
		goto fail;
	ctx_erofs->n_shared_xattrs = 0;

	xattr_offset = 0;
	for (size_t i = 0; i < n_xattrs; i++) {
		struct hasher_xattr_s *ent = sorted[i];
		if (erofs_xattr_should_be_shared(ent)) {
			ent->shared = true;
			ent->shared_offset = xattr_offset;

			ctx_erofs->shared_xattrs[ctx_erofs->n_shared_xattrs] =
				ent->xattr;
			ctx_erofs->n_shared_xattrs++;

			xattr_offset += xattr_erofs_entry_size(ent->xattr);
		}
	}

	ctx_erofs->shared_xattr_size = xattr_offset;

	/* Assign shared xattr offsets for all inodes */

	for (node = ctx->root; node != NULL; node = node->next) {
		int n_shared = 0;
		for (size_t i = 0; i < node->n_xattrs; i++) {
			struct lcfs_xattr_s *xattr = &node->xattrs[i];
			struct hasher_xattr_s hkey = { .xattr = xattr };
			struct hasher_xattr_s *ent;

			ent = hash_lookup(xattr_hash, &hkey);
			assert(ent != NULL);
			if (ent->shared && n_shared < EROFS_MAX_SHARED_XATTRS) {
				xattr->erofs_shared_xattr_offset = ent->shared_offset;
				n_shared++;
			} else {
				xattr->erofs_shared_xattr_offset = -1;
			}
		}
	}

	free(sorted);
	hash_free(xattr_hash);
	return 0;

fail:
	errno = ENOMEM;
	free(sorted);
	hash_free(xattr_hash);
	return -1;
}

static bool lcfs_fits_in_erofs_compact(struct lcfs_ctx_s *ctx,
				       struct lcfs_node_s *node)
{
	int type = node->inode.st_mode & S_IFMT;
	uint64_t size;

	if (node->inode.st_mtim_sec != ctx->min_mtim_sec ||
	    node->inode.st_mtim_nsec != ctx->min_mtim_nsec) {
		return false;
	}

	if (node->inode.st_nlink > UINT16_MAX ||
	    node->inode.st_uid > UINT16_MAX || node->inode.st_gid > UINT16_MAX) {
		return false;
	}

	if (type == S_IFDIR) {
		size = (uint64_t)node->erofs_n_blocks * EROFS_BLKSIZ +
		       node->erofs_tailsize;
	} else {
		size = node->inode.st_size;
	}
	if (size > UINT32_MAX) {
		return false;
	}

	return true;
}

static void compute_erofs_dir_size(struct lcfs_node_s *node)
{
	uint32_t n_blocks = 0;
	size_t block_size = 0;

	for (size_t i = 0; i < node->children_size; i++) {
		struct lcfs_node_s *child = node->children[i];
		size_t len = sizeof(struct erofs_dirent) + strlen(child->name);
		if (block_size + len > EROFS_BLKSIZ) {
			n_blocks++;
			block_size = 0;
		}
		block_size += len;
	}

	/* As a heuristic, we never inline more than half a block */
	if (block_size > EROFS_BLKSIZ / 2) {
		n_blocks++;
		block_size = 0;
	}

	node->erofs_n_blocks = n_blocks;
	node->erofs_tailsize = block_size;
}

static uint32_t compute_erofs_chunk_bitsize(struct lcfs_node_s *node)
{
	uint64_t file_size = node->inode.st_size;

	// Compute the chunksize to use for the file size
	// We want as few chunks as possible, but not an
	// unnecessary large chunk.
	uint32_t chunkbits = ilog2(file_size - 1) + 1;

	// At least one logical block
	if (chunkbits < EROFS_BLKSIZ_BITS)
		chunkbits = EROFS_BLKSIZ_BITS;

	// Not larger chunks than max possible
	if (chunkbits - EROFS_BLKSIZ_BITS > EROFS_CHUNK_FORMAT_BLKBITS_MASK)
		chunkbits = EROFS_CHUNK_FORMAT_BLKBITS_MASK + EROFS_BLKSIZ_BITS;

	return chunkbits;
}

static void compute_erofs_inode_size(struct lcfs_node_s *node)
{
	int type = node->inode.st_mode & S_IFMT;
	uint64_t file_size = node->inode.st_size;

	if (type == S_IFDIR) {
		compute_erofs_dir_size(node);
	} else if (type == S_IFLNK) {
		node->erofs_n_blocks = 0;
		node->erofs_tailsize = strlen(node->payload);
	} else if (type == S_IFREG && file_size > 0) {
		uint32_t chunkbits = compute_erofs_chunk_bitsize(node);
		uint64_t chunksize = 1ULL << chunkbits;
		uint32_t chunk_count = DIV_ROUND_UP(file_size, chunksize);

		node->erofs_n_blocks = 0;
		node->erofs_tailsize = chunk_count * sizeof(uint32_t);
	} else {
		node->erofs_n_blocks = 0;
		node->erofs_tailsize = 0;
	}
}

static void compute_erofs_xattr_counts(struct lcfs_node_s *node,
				       size_t *n_shared_xattrs_out,
				       size_t *unshared_xattrs_size_out)
{
	size_t n_shared_xattrs = 0;
	size_t unshared_xattrs_size = 0;

	for (size_t i = 0; i < node->n_xattrs; i++) {
		struct lcfs_xattr_s *xattr = &node->xattrs[i];
		if (xattr->erofs_shared_xattr_offset >= 0) {
			n_shared_xattrs++;
		} else {
			unshared_xattrs_size += xattr_erofs_entry_size(xattr);
		}
	}

	*n_shared_xattrs_out = n_shared_xattrs;
	*unshared_xattrs_size_out = unshared_xattrs_size;
}

static uint64_t compute_erofs_inode_padding_for_tail(struct lcfs_node_s *node,
						     uint64_t pos, size_t inode_size,
						     size_t xattr_size)
{
	int type = node->inode.st_mode & S_IFMT;
	uint64_t block_remainder;
	size_t non_tail_size = inode_size + xattr_size;
	size_t total_size = inode_size + xattr_size + node->erofs_tailsize;

	/* This adds extra padding in front of an inode to ensure that
	 * the tail data doesn't cross a block boundary.
	 */

	if (type == S_IFLNK) {
		/* Due to how erofs_fill_symlink is implemented, we
		 * need *both* the inode data and the symlink tail
		 * data in the same block, wheras normally just the
		 * tail data itself need to be inside a block.
		 */
		if (pos / EROFS_BLKSIZ != (pos + total_size - 1) / EROFS_BLKSIZ) {
			return round_up(pos, EROFS_BLKSIZ) - pos;
		}
		return 0;
	}

	block_remainder = EROFS_BLKSIZ - ((pos + non_tail_size) % EROFS_BLKSIZ);
	if (block_remainder < node->erofs_tailsize) {
		/* Add (aligned) padding so that tail starts in new block */
		uint64_t extra_pad = round_up(block_remainder, EROFS_SLOTSIZE);

		/* Due to the extra_pad round up it is possible the tail does not fit anyway */
		block_remainder = EROFS_BLKSIZ -
				  ((pos + non_tail_size + extra_pad) % EROFS_BLKSIZ);
		if (node->erofs_tailsize <= block_remainder) {
			/* It fit! */
			return extra_pad;
		}
		/* Didn't fit, don't inline the tail. */
		node->erofs_n_blocks++;
		node->erofs_tailsize = 0;
	}

	return 0;
}

static int compute_erofs_inodes(struct lcfs_ctx_s *ctx)
{
	struct lcfs_ctx_erofs_s *ctx_erofs = (struct lcfs_ctx_erofs_s *)ctx;
	struct lcfs_node_s *node;
	uint64_t pos, ppos;
	uint64_t meta_start, extra_pad;

	// Start inode data directly after superblock
	pos = EROFS_SUPER_OFFSET + sizeof(struct erofs_super_block);

	// But inode offsets (nids) are relative to start of block
	meta_start = round_down(pos, EROFS_BLKSIZ);

	for (node = ctx->root; node != NULL; node = node->next) {
		size_t n_shared_xattrs, unshared_xattrs_size;
		size_t inode_size, xattr_size;

		compute_erofs_inode_size(node);
		node->erofs_compact = lcfs_fits_in_erofs_compact(ctx, node);
		inode_size = node->erofs_compact ?
				     sizeof(struct erofs_inode_compact) :
				     sizeof(struct erofs_inode_extended);

		compute_erofs_xattr_counts(node, &n_shared_xattrs,
					   &unshared_xattrs_size);
		xattr_size = xattr_erofs_inode_size(n_shared_xattrs,
						    unshared_xattrs_size);

		/* Align inode start to next slot */
		ppos = pos;
		pos = round_up(pos, EROFS_SLOTSIZE);
		node->erofs_ipad = pos - ppos;

		/* Ensure tail does not straddle block boundaries */
		extra_pad = compute_erofs_inode_padding_for_tail(
			node, pos, inode_size, xattr_size);
		node->erofs_ipad += extra_pad;
		pos += extra_pad;

		node->erofs_isize = inode_size + xattr_size + node->erofs_tailsize;
		ctx_erofs->n_data_blocks += node->erofs_n_blocks;
		node->erofs_nid = (pos - meta_start) / EROFS_SLOTSIZE;

		/* Assert that tails never span multiple blocks */
		assert(node->erofs_tailsize == 0 ||
		       ((pos + inode_size + xattr_size) / EROFS_BLKSIZ) ==
			       ((pos + node->erofs_isize - 1) / EROFS_BLKSIZ));

		pos += node->erofs_isize;
	}

	ctx_erofs->inodes_end = round_up(pos, EROFS_SLOTSIZE);

	return 0;
}

static int write_erofs_xattr(struct lcfs_ctx_s *ctx, struct lcfs_xattr_s *xattr)
{
	struct erofs_xattr_entry e = { 0 };
	int ret;
	char *key_suffix;
	uint8_t index = xattr_erofs_entry_index(xattr, &key_suffix);

	e.e_name_len = strlen(key_suffix);
	e.e_name_index = index;
	e.e_value_size = lcfs_u16_to_file(xattr->value_len);

	ret = lcfs_write(ctx, &e, sizeof(e));
	if (ret < 0)
		return ret;

	ret = lcfs_write(ctx, key_suffix, strlen(key_suffix));
	if (ret < 0)
		return ret;

	ret = lcfs_write(ctx, xattr->value, xattr->value_len);
	if (ret < 0)
		return ret;

	return lcfs_write_align(ctx, sizeof(uint32_t));
}

static int write_erofs_dentries_chunk(struct lcfs_ctx_s *ctx,
				      struct lcfs_node_s *node, int first_child,
				      int n_children, int alignment)
{
	uint16_t nameoff = n_children * sizeof(struct erofs_dirent);
	int ret;

	for (int i = first_child; i < first_child + n_children; i++) {
		struct lcfs_node_s *dirent_child = node->children[i];
		struct lcfs_node_s *target_child = follow_links(dirent_child);

		struct erofs_dirent dirent = { 0 };
		dirent.nid = lcfs_u64_to_file(target_child->erofs_nid);
		dirent.nameoff = lcfs_u16_to_file(nameoff);
		dirent.file_type =
			erofs_make_file_type(node_get_dtype(target_child));

		nameoff += strlen(dirent_child->name);

		ret = lcfs_write(ctx, &dirent, sizeof(dirent));
		if (ret < 0)
			return ret;
	}

	for (int i = first_child; i < first_child + n_children; i++) {
		struct lcfs_node_s *dirent_child = node->children[i];

		ret = lcfs_write(ctx, dirent_child->name, strlen(dirent_child->name));
		if (ret < 0)
			return ret;
	}

	return lcfs_write_align(ctx, alignment);
}

static int write_erofs_dentries(struct lcfs_ctx_s *ctx, struct lcfs_node_s *node,
				bool write_blocks, bool write_tail)
{
	size_t block_size = 0;
	size_t block_written = 0;
	size_t first = 0;
	int ret;

	for (size_t i = 0; i < node->children_size; i++) {
		struct lcfs_node_s *child = node->children[i];
		size_t len = sizeof(struct erofs_dirent) + strlen(child->name);
		if (block_size + len > EROFS_BLKSIZ) {
			if (write_blocks) {
				ret = write_erofs_dentries_chunk(
					ctx, node, first, i - first, EROFS_BLKSIZ);
				if (ret < 0)
					return ret;
			}

			block_written++;
			block_size = 0;
			first = i;
		}
		block_size += len;
	}

	/* Handle the remaining block which is either tailpacked or block as decided before */

	if (block_written < node->erofs_n_blocks) {
		if (write_blocks) {
			ret = write_erofs_dentries_chunk(ctx, node, first,
							 node->children_size - first,
							 EROFS_BLKSIZ);
			if (ret < 0)
				return ret;
		}

		block_written++;
		block_size = 0;
		first = node->children_size;
	}

	if (write_tail && block_size > 0) {
		ret = write_erofs_dentries_chunk(ctx, node, first,
						 node->children_size - first, 1);
		if (ret < 0)
			return ret;
	}

	return 0;
}

static int write_erofs_inode_data(struct lcfs_ctx_s *ctx, struct lcfs_node_s *node)
{
	struct lcfs_ctx_erofs_s *ctx_erofs = (struct lcfs_ctx_erofs_s *)ctx;
	int type = node->inode.st_mode & S_IFMT;
	size_t xattr_icount;
	uint64_t size;
	int ret;
	uint16_t format;
	uint16_t version;
	uint16_t datalayout;
	off_t orig_bytes_written = ctx->bytes_written;
	size_t n_shared_xattrs;
	size_t unshared_xattrs_size;
	size_t xattr_size;
	uint32_t chunk_count = 0;
	uint16_t chunk_format = 0;

	ret = lcfs_write_pad(ctx, node->erofs_ipad);
	if (ret < 0)
		return ret;

	/* All inodes start on slot boundary */
	assert(ctx->bytes_written % EROFS_SLOTSIZE == 0);

	/* compute xattr details */

	compute_erofs_xattr_counts(node, &n_shared_xattrs, &unshared_xattrs_size);
	xattr_size = xattr_erofs_inode_size(n_shared_xattrs, unshared_xattrs_size);
	xattr_icount = xattr_erofs_icount(xattr_size);

	version = node->erofs_compact ? 0 : 1;
	datalayout = (node->erofs_tailsize > 0) ? EROFS_INODE_FLAT_INLINE :
						  EROFS_INODE_FLAT_PLAIN;

	if (type == S_IFDIR || type == S_IFLNK) {
		size = (uint64_t)node->erofs_n_blocks * EROFS_BLKSIZ +
		       node->erofs_tailsize;
	} else if (type == S_IFREG) {
		size = node->inode.st_size;

		if (size > 0) {
			uint32_t chunkbits = compute_erofs_chunk_bitsize(node);
			uint64_t chunksize = 1ULL << chunkbits;

			datalayout = EROFS_INODE_CHUNK_BASED;
			chunk_count = DIV_ROUND_UP(size, chunksize);
			chunk_format = chunkbits - EROFS_BLKSIZ_BITS;
		}
	} else {
		size = 0;
	}

	format = datalayout << EROFS_I_DATALAYOUT_BIT | version << EROFS_I_VERSION_BIT;

	if (node->erofs_compact) {
		struct erofs_inode_compact i = { 0 };
		i.i_format = lcfs_u16_to_file(format);
		i.i_xattr_icount = lcfs_u16_to_file(xattr_icount);
		i.i_mode = lcfs_u16_to_file(node->inode.st_mode);
		i.i_nlink = lcfs_u16_to_file(node->inode.st_nlink);
		i.i_size = lcfs_u32_to_file(size);
		i.i_ino = lcfs_u32_to_file(node->inode_num);
		i.i_uid = lcfs_u16_to_file(node->inode.st_uid);
		i.i_gid = lcfs_u16_to_file(node->inode.st_gid);

		if (type == S_IFDIR) {
			if (node->erofs_n_blocks > 0) {
				i.i_u.raw_blkaddr = lcfs_u32_to_file(
					ctx_erofs->current_end / EROFS_BLKSIZ);
				ctx_erofs->current_end +=
					EROFS_BLKSIZ * node->erofs_n_blocks;
			}
		} else if (type == S_IFCHR || type == S_IFBLK) {
			i.i_u.rdev = lcfs_u32_to_file(node->inode.st_rdev);
		} else if (type == S_IFREG) {
			if (datalayout == EROFS_INODE_CHUNK_BASED) {
				i.i_u.c.format = lcfs_u16_to_file(chunk_format);
			}
		}

		ret = lcfs_write(ctx, &i, sizeof(i));
		if (ret < 0)
			return ret;
	} else {
		struct erofs_inode_extended i = { 0 };
		i.i_format = lcfs_u16_to_file(format);
		i.i_xattr_icount = lcfs_u16_to_file(xattr_icount);
		i.i_mode = lcfs_u16_to_file(node->inode.st_mode);
		i.i_nlink = lcfs_u32_to_file(node->inode.st_nlink);
		i.i_size = lcfs_u64_to_file(size);
		i.i_ino = lcfs_u32_to_file(node->inode_num);
		i.i_uid = lcfs_u32_to_file(node->inode.st_uid);
		i.i_gid = lcfs_u32_to_file(node->inode.st_gid);
		i.i_mtime = lcfs_u64_to_file(node->inode.st_mtim_sec);
		i.i_mtime_nsec = lcfs_u64_to_file(node->inode.st_mtim_nsec);

		if (type == S_IFDIR) {
			if (node->erofs_n_blocks > 0) {
				i.i_u.raw_blkaddr = lcfs_u32_to_file(
					ctx_erofs->current_end / EROFS_BLKSIZ);
				ctx_erofs->current_end +=
					EROFS_BLKSIZ * node->erofs_n_blocks;
			}
		} else if (type == S_IFCHR || type == S_IFBLK) {
			i.i_u.rdev = lcfs_u32_to_file(node->inode.st_rdev);
		} else if (type == S_IFREG) {
			if (datalayout == EROFS_INODE_CHUNK_BASED) {
				i.i_u.c.format = lcfs_u16_to_file(chunk_format);
			}
		}

		ret = lcfs_write(ctx, &i, sizeof(i));
		if (ret < 0)
			return ret;
	}

	/* write xattrs */
	if (xattr_size) {
		struct erofs_xattr_ibody_header xattr_header = { 0 };
		xattr_header.h_shared_count = n_shared_xattrs;

		ret = lcfs_write(ctx, &xattr_header, sizeof(xattr_header));
		if (ret < 0)
			return ret;

		/* shared */
		for (size_t i = 0; i < node->n_xattrs; i++) {
			struct lcfs_xattr_s *xattr = &node->xattrs[i];
			if (xattr->erofs_shared_xattr_offset >= 0) {
				uint64_t offset =
					ctx_erofs->inodes_end % EROFS_BLKSIZ +
					xattr->erofs_shared_xattr_offset;
				uint32_t v =
					lcfs_u32_to_file(offset / sizeof(uint32_t));
				ret = lcfs_write(ctx, &v, sizeof(v));
				if (ret < 0)
					return ret;
			}
		}
		/* unshared */
		for (size_t i = 0; i < node->n_xattrs; i++) {
			struct lcfs_xattr_s *xattr = &node->xattrs[i];
			if (xattr->erofs_shared_xattr_offset < 0) {
				ret = write_erofs_xattr(ctx, xattr);
				if (ret < 0)
					return ret;
			}
		}
	}

	if (type == S_IFDIR) {
		ret = write_erofs_dentries(ctx, node, false, true);
		if (ret < 0)
			return ret;
	} else if (type == S_IFLNK) {
		ret = lcfs_write(ctx, node->payload, strlen(node->payload));
		if (ret < 0)
			return ret;
	} else if (type == S_IFREG) {
		for (size_t i = 0; i < chunk_count; i++) {
			uint32_t empty_chunk = 0xFFFFFFFF;
			ret = lcfs_write(ctx, &empty_chunk, sizeof(empty_chunk));
			if (ret < 0)
				return ret;
		}
	}

	assert(ctx->bytes_written - orig_bytes_written ==
	       node->erofs_isize + node->erofs_ipad);

	return 0;
}

static int write_erofs_inodes(struct lcfs_ctx_s *ctx)
{
	struct lcfs_node_s *node;
	int ret;

	for (node = ctx->root; node != NULL; node = node->next) {
		ret = write_erofs_inode_data(ctx, node);
		if (ret < 0)
			return ret;
	}

	ret = lcfs_write_align(ctx, EROFS_SLOTSIZE);
	if (ret < 0)
		return ret;

	return 0;
}

static int write_erofs_dirent_blocks(struct lcfs_ctx_s *ctx)
{
	struct lcfs_node_s *node;
	int ret;

	for (node = ctx->root; node != NULL; node = node->next) {
		ret = write_erofs_dentries(ctx, node, true, false);
		if (ret < 0)
			return ret;
	}

	return 0;
}

static int write_erofs_shared_xattrs(struct lcfs_ctx_s *ctx)
{
	struct lcfs_ctx_erofs_s *ctx_erofs = (struct lcfs_ctx_erofs_s *)ctx;
	int ret;

	for (size_t i = 0; i < ctx_erofs->n_shared_xattrs; i++) {
		struct lcfs_xattr_s *xattr = ctx_erofs->shared_xattrs[i];
		ret = write_erofs_xattr(ctx, xattr);
		if (ret < 0)
			return ret;
	}

	return 0;
}

static int add_overlayfs_xattrs(struct lcfs_node_s *node)
{
	int ret;

	if ((node->inode.st_mode & S_IFMT) == S_IFREG && node->inode.st_size > 0) {
		uint8_t xattr_data[4 + LCFS_DIGEST_SIZE];
		size_t xattr_len = 0;

		if (node->digest_set) {
			xattr_len = sizeof(xattr_data);
			xattr_data[0] = 0; /* version */
			xattr_data[1] = xattr_len;
			xattr_data[2] = 0; /* flags */
			xattr_data[3] = FS_VERITY_HASH_ALG_SHA256;
			memcpy(xattr_data + 4, node->digest, LCFS_DIGEST_SIZE);
		}

		ret = lcfs_node_set_xattr(node, "trusted.overlay.metacopy",
					  (const char *)xattr_data, xattr_len);
		if (ret < 0)
			return ret;

		if (strlen(node->payload) > 0) {
			char *path = maybe_join_path("/", node->payload);
			if (path == NULL) {
				errno = ENOMEM;
				return -1;
			}
			ret = lcfs_node_set_xattr(node, "trusted.overlay.redirect",
						  path, strlen(path));
			free(path);
			if (ret < 0)
				return ret;
		}
	}

	return 0;
}

static int add_overlay_whiteouts(struct lcfs_node_s *root)
{
	static const char hexchars[] = "0123456789abcdef";
	const char *selinux;
	size_t selinux_len;
	int res;

	selinux = lcfs_node_get_xattr(root, "security.selinux", &selinux_len);

	for (int i = 0; i <= 255; i++) {
		struct lcfs_node_s *child;
		char name[3];

		name[0] = hexchars[(i >> 4) % 16];
		name[1] = hexchars[i % 16];
		name[2] = 0;

		child = lcfs_node_lookup_child(root, name);
		if (child != NULL)
			continue;

		child = lcfs_node_new();
		if (child == NULL) {
			errno = ENOMEM;
			return -1;
		}

		lcfs_node_set_mode(child, S_IFCHR | 0644);
		lcfs_node_set_rdev(child, 0);

		child->inode.st_uid = root->inode.st_uid;
		child->inode.st_gid = root->inode.st_gid;
		child->inode.st_mtim_sec = root->inode.st_mtim_sec;
		child->inode.st_mtim_nsec = root->inode.st_mtim_nsec;

		/* Inherit selinux context from root dir */
		if (selinux != NULL) {
			res = lcfs_node_set_xattr(child, "security.selinux",
						  selinux, selinux_len);
			if (res < 0)
				return res;
		}

		res = lcfs_node_add_child(root, child, name);
		if (res < 0)
			return res;
	}

	return 0;
}

static int rewrite_tree_node_for_erofs(struct lcfs_node_s *node,
				       struct lcfs_node_s *parent)
{
	int ret;

	ret = add_overlayfs_xattrs(node);
	if (ret < 0)
		return ret;

	if (lcfs_node_dirp(node)) {
		struct lcfs_node_s *existing;

		/* Ensure we have . and .. */
		existing = lcfs_node_lookup_child(node, ".");
		if (existing == NULL) {
			struct lcfs_node_s *link = lcfs_node_new();
			if (link == NULL) {
				errno = ENOMEM;
				return -1;
			}
			lcfs_node_make_hardlink(link, node);
			ret = lcfs_node_add_child(node, link, ".");
			if (ret < 0) {
				lcfs_node_unref(link);
				return -1;
			}
		}

		existing = lcfs_node_lookup_child(node, "..");
		if (existing == NULL) {
			struct lcfs_node_s *link = lcfs_node_new();
			if (link == NULL) {
				errno = ENOMEM;
				return -1;
			}
			lcfs_node_make_hardlink(link, parent);
			ret = lcfs_node_add_child(node, link, "..");
			if (ret < 0) {
				lcfs_node_unref(link);
				return -1;
			}
		}

		for (size_t i = 0; i < node->children_size; ++i) {
			struct lcfs_node_s *child = node->children[i];

			if (child->link_to != NULL) {
				continue;
			}

			ret = rewrite_tree_node_for_erofs(child, node);
			if (ret < 0) {
				return -1;
			}
		}
	}

	return 0;
}

static int set_overlay_opaque(struct lcfs_node_s *node)
{
	int ret;

	ret = lcfs_node_set_xattr(node, "trusted.overlay.opaque", "y", 1);
	if (ret < 0)
		return ret;

	return 0;
}

static int rewrite_tree_for_erofs(struct lcfs_node_s *root)
{
	int res;

	res = rewrite_tree_node_for_erofs(root, root);
	if (res < 0)
		return res;

	res = set_overlay_opaque(root);
	if (res < 0)
		return res;

	res = add_overlay_whiteouts(root);
	if (res < 0)
		return res;

	return 0;
}

int lcfs_write_erofs_to(struct lcfs_ctx_s *ctx)
{
	struct lcfs_ctx_erofs_s *ctx_erofs = (struct lcfs_ctx_erofs_s *)ctx;
	struct lcfs_node_s *root;
	struct lcfs_erofs_header_s header = {
		.magic = lcfs_u32_to_file(LCFS_EROFS_MAGIC),
		.version = lcfs_u32_to_file(LCFS_EROFS_VERSION),
	};
	uint32_t header_flags;
	struct erofs_super_block superblock = {
		.magic = lcfs_u32_to_file(EROFS_SUPER_MAGIC_V1),
		.blkszbits = EROFS_BLKSIZ_BITS,
	};
	int ret = 0;
	uint64_t data_block_start;

	if (ctx->options->version != 0) {
		errno = -EINVAL;
		return -1;
	}

	/* Clone root so we can make required modifications to it */
	ret = lcfs_clone_root(ctx);
	if (ret < 0)
		return ret;

	root = ctx->root; /* After we cloned it */

	/* Rewrite cloned tree as needed for erofs */
	ret = rewrite_tree_for_erofs(root);
	if (ret < 0)
		return ret;

	ret = lcfs_compute_tree(ctx, root);
	if (ret < 0)
		return ret;

	ret = compute_erofs_shared_xattrs(ctx);
	if (ret < 0)
		return ret;

	ret = compute_erofs_inodes(ctx);
	if (ret < 0)
		return ret;

	header_flags = 0;
	if (ctx->has_acl)
		header_flags |= LCFS_EROFS_FLAGS_HAS_ACL;
	header.flags = lcfs_u32_to_file(header_flags);

	ret = lcfs_write(ctx, &header, sizeof(header));
	if (ret < 0)
		return ret;

	ret = lcfs_write_pad(ctx, EROFS_SUPER_OFFSET - sizeof(header));
	if (ret < 0)
		return ret;

	superblock.feature_compat = lcfs_u32_to_file(EROFS_FEATURE_COMPAT_MTIME);
	superblock.inos = lcfs_u64_to_file(ctx->num_inodes);

	superblock.build_time = lcfs_u64_to_file(ctx->min_mtim_sec);
	superblock.build_time_nsec = lcfs_u32_to_file(ctx->min_mtim_nsec);

	/* metadata is stored directly after superblock */
	superblock.meta_blkaddr = lcfs_u32_to_file(
		(EROFS_SUPER_OFFSET + sizeof(superblock)) / EROFS_BLKSIZ);
	assert(root->erofs_nid < UINT16_MAX);
	superblock.root_nid = lcfs_u16_to_file(root->erofs_nid);

	/* shared xattrs is directly after metadata */
	superblock.xattr_blkaddr =
		lcfs_u32_to_file(ctx_erofs->inodes_end / EROFS_BLKSIZ);

	data_block_start =
		round_up(ctx_erofs->inodes_end + ctx_erofs->shared_xattr_size,
			 EROFS_BLKSIZ);

	superblock.blocks = lcfs_u32_to_file(data_block_start / EROFS_BLKSIZ +
					     ctx_erofs->n_data_blocks);

	/* TODO: More superblock fields:
	 *  uuid?
	 *  volume_name?
	 */

	ret = lcfs_write(ctx, &superblock, sizeof(superblock));
	if (ret < 0)
		return ret;

	ctx_erofs->current_end = data_block_start;

	ret = write_erofs_inodes(ctx);
	if (ret < 0)
		return ret;

	assert(ctx_erofs->inodes_end == (uint64_t)ctx->bytes_written);

	ret = write_erofs_shared_xattrs(ctx);
	if (ret < 0)
		return ret;

	assert(ctx_erofs->inodes_end + ctx_erofs->shared_xattr_size ==
	       (uint64_t)ctx->bytes_written);

	/* Following are full blocks and must be block-aligned */
	ret = lcfs_write_align(ctx, EROFS_BLKSIZ);
	if (ret < 0)
		return ret;

	assert(data_block_start == (uint64_t)ctx->bytes_written);

	ret = write_erofs_dirent_blocks(ctx);
	if (ret < 0)
		return ret;

	assert(ctx_erofs->current_end == (uint64_t)ctx->bytes_written);
	assert(data_block_start + ctx_erofs->n_data_blocks * EROFS_BLKSIZ ==
	       (uint64_t)ctx->bytes_written);

	return 0;
}
