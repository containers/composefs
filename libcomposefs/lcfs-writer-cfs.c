/* lcfs
   Copyright (C) 2021 Giuseppe Scrivano <giuseppe@scrivano.org>

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

#include "lcfs-utils.h"
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

struct lcfs_ctx_cfs_s {
	struct lcfs_ctx_s base;

	/* Used for dedup.  */
	Hash_table *ht;

	char *vdata;
	size_t vdata_len;
	size_t vdata_allocated;
};

static void lcfs_ctx_cfs_finalize(struct lcfs_ctx_s *ctx)
{
	struct lcfs_ctx_cfs_s *ctx_cfs = (struct lcfs_ctx_cfs_s *)ctx;
	free(ctx_cfs->vdata);
	if (ctx_cfs->ht)
		hash_free(ctx_cfs->ht);
}

struct lcfs_ctx_s *lcfs_ctx_cfs_new(void)
{
	struct lcfs_ctx_cfs_s *ret = calloc(1, sizeof(struct lcfs_ctx_cfs_s));
	if (ret == NULL) {
		return NULL;
	}

	ret->base.finalize = lcfs_ctx_cfs_finalize;

	return &ret->base;
}

#define APPEND_FLAGS_DEDUP (1 << 0)
#define APPEND_FLAGS_ALIGN (1 << 1)

struct hasher_vdata_s {
	const char *const *vdata;
	uint64_t off;
	uint64_t len;
};

static size_t vdata_ht_hasher(const void *d, size_t n)
{
	const struct hasher_vdata_s *v = d;

	return hash_memory(*v->vdata + v->off, v->len, n);
}

static bool vdata_ht_comparator(const void *d1, const void *d2)
{
	const struct hasher_vdata_s *v1 = d1;
	const struct hasher_vdata_s *v2 = d2;
	const char *c1, *c2;

	if (v1->len != v2->len)
		return false;

	c1 = *v1->vdata + v1->off;
	c2 = *v2->vdata + v2->off;

	return memcmp(c1, c2, v1->len) == 0;
}

static void vdata_ht_freer(void *data)
{
	free(data);
}

static int lcfs_append_vdata(struct lcfs_ctx_s *ctx, struct lcfs_vdata_s *out,
			     const void *data, size_t len, uint32_t flags)
{
	struct lcfs_ctx_cfs_s *ctx_cfs = (struct lcfs_ctx_cfs_s *)ctx;
	struct hasher_vdata_s *key;
	char *new_vdata;
	size_t pad_length;
	bool dedup = (flags & APPEND_FLAGS_DEDUP) != 0;
	bool align = (flags & APPEND_FLAGS_ALIGN) != 0;

	if (dedup) {
		struct hasher_vdata_s *ent;
		const char *_data = data;
		struct hasher_vdata_s hkey = {
			.vdata = (const char *const *)&_data,
			.off = 0,
			.len = len,
		};

		ent = hash_lookup(ctx_cfs->ht, &hkey);
		if (ent) {
			out->off = ent->off;
			out->len = ent->len;
			return 0;
		}
	}

	/* We ensure that all vdata are aligned to start at 4 bytes  */
	pad_length = 0;
	if (align && ctx_cfs->vdata_len % 4 != 0)
		pad_length = 4 - ctx_cfs->vdata_len % 4;

	if (ctx_cfs->vdata_len + pad_length + len > ctx_cfs->vdata_allocated) {
		size_t new_size, increment;

		increment = max(1 << 20, pad_length + len);

		new_size = ctx_cfs->vdata_allocated + increment;
		new_vdata = realloc(ctx_cfs->vdata, new_size);
		if (new_vdata == NULL)
			return -1;

		ctx_cfs->vdata_allocated = new_size;
		ctx_cfs->vdata = new_vdata;
	}

	if (pad_length > 0) {
		memset(ctx_cfs->vdata + ctx_cfs->vdata_len, 0, pad_length);
		ctx_cfs->vdata_len += pad_length;
	}

	memcpy(ctx_cfs->vdata + ctx_cfs->vdata_len, data, len);

	out->off = ctx_cfs->vdata_len;
	out->len = len;

	/* Update to the new length.  */
	ctx_cfs->vdata_len += len;

	key = malloc(sizeof(struct hasher_vdata_s));
	if (key) {
		void *ent;

		key->vdata = (const char *const *)&ctx_cfs->vdata;
		key->off = out->off;
		key->len = out->len;

		ent = hash_insert(ctx_cfs->ht, key);
		/* Should not really happen.  */
		if (ent != key)
			free(key);
	}

	return 0;
}

static ssize_t compute_dirents_size(struct lcfs_node_s *node)
{
	size_t names_size = 0;
	size_t i;

	if (node->children_size == 0)
		return 0;

	for (i = 0; i < node->children_size; i++) {
		struct lcfs_node_s *child = node->children[i];
		size_t child_name_len = strlen(child->name);

		/* Need valid names for all children */
		if (child->name == NULL || child_name_len > LCFS_MAX_NAME_LENGTH) {
			errno = EINVAL;
			return -1;
		}

		names_size += child_name_len;
	}

	return lcfs_dir_header_size(node->children_size) + names_size;
}

static int compute_dirents(struct lcfs_ctx_s *ctx, struct lcfs_node_s *node,
			   struct lcfs_vdata_s *vdata)
{
	char *names;
	char *buffer;
	ssize_t dirents_size;
	;
	struct lcfs_dir_header_s *header;
	size_t name_offset = 0;
	int r;

	dirents_size = compute_dirents_size(node);
	if (dirents_size == 0)
		return 0;

	buffer = calloc(1, dirents_size);
	if (buffer == NULL) {
		errno = ENOMEM;
		return -1;
	}

	header = (struct lcfs_dir_header_s *)buffer;
	names = (char *)buffer + lcfs_dir_header_size(node->children_size);
	header->n_dirents = lcfs_u32_to_file(node->children_size);

	/* Write dir data */
	for (size_t i = 0; i < node->children_size; i++) {
		struct lcfs_node_s *dirent_child = node->children[i];
		struct lcfs_node_s *target_child = follow_links(dirent_child);
		struct lcfs_dirent_s *dirent = &header->dirents[i];
		size_t name_len = strlen(dirent_child->name);

		dirent->inode_num = lcfs_u32_to_file(target_child->inode_num);
		dirent->d_type = node_get_dtype(target_child);
		dirent->name_len = name_len;
		dirent->name_offset = lcfs_u32_to_file(name_offset);
		dirent->_padding = 0;

		memcpy(names + name_offset, dirent_child->name, dirent->name_len);
		name_offset += dirent->name_len;
	}

	r = lcfs_append_vdata(ctx, vdata, buffer, dirents_size, APPEND_FLAGS_ALIGN);
	free(buffer);
	return r;
}

static int compute_variable_data(struct lcfs_ctx_s *ctx)
{
	struct lcfs_node_s *node;
	int r;

	for (node = ctx->root; node != NULL; node = node->next) {
		if ((node->inode.st_mode & S_IFMT) == S_IFDIR) {
			r = compute_dirents(ctx, node, &node->inode.variable_data);
			if (r < 0)
				return r;
		}
		if ((node->inode.st_mode & S_IFMT) == S_IFREG) {
			/* Ensure we never use a payload for empty files, for canonicalization purposes */
			if (node->inode.st_size != 0 && node->payload &&
			    strlen(node->payload) != 0) {
				r = lcfs_append_vdata(ctx, &node->inode.variable_data,
						      node->payload,
						      strlen(node->payload),
						      APPEND_FLAGS_DEDUP);
				if (r < 0)
					return r;
			}
		}
		if ((node->inode.st_mode & S_IFMT) == S_IFLNK) {
			if (node->payload && strlen(node->payload) != 0) {
				r = lcfs_append_vdata(ctx, &node->inode.variable_data,
						      node->payload,
						      strlen(node->payload),
						      APPEND_FLAGS_DEDUP);
				if (r < 0)
					return r;
			}
		}

		if (node->digest_set) {
			r = lcfs_append_vdata(ctx, &node->inode.digest,
					      node->digest, LCFS_DIGEST_SIZE,
					      APPEND_FLAGS_DEDUP);
			if (r < 0)
				return r;
		}
	}

	return 0;
}

/* Canonicalizes and computes xattrs, sharing equal vdatas */
static int compute_xattrs(struct lcfs_ctx_s *ctx)
{
	struct lcfs_node_s *node;
	size_t data_length;
	size_t i;
	uint8_t *buffer, *data;
	size_t header_len;
	size_t buffer_len;
	struct lcfs_xattr_header_s *header;
	struct lcfs_vdata_s out;
	int r;

	for (node = ctx->root; node != NULL; node = node->next) {
		if (node->n_xattrs == 0)
			continue;

		/* compute_tree canonicalized the xattr order already */

		data_length = 0;
		for (i = 0; i < node->n_xattrs; i++) {
			struct lcfs_xattr_s *xattr = &node->xattrs[i];
			data_length += strlen(xattr->key) + xattr->value_len;
		}
		header_len = lcfs_xattr_header_size(node->n_xattrs);
		buffer_len = header_len + data_length;

		buffer = calloc(1, buffer_len);
		if (buffer == NULL) {
			errno = ENOMEM;
			return -1;
		}
		header = (struct lcfs_xattr_header_s *)buffer;
		header->n_attr = lcfs_u16_to_file(node->n_xattrs);

		data = buffer + header_len;
		for (i = 0; i < node->n_xattrs; i++) {
			size_t key_len;
			struct lcfs_xattr_s *xattr = &node->xattrs[i];

			key_len = strlen(xattr->key);
			header->attr[i].key_length = lcfs_u16_to_file(key_len);
			memcpy(data, xattr->key, key_len);
			data += key_len;

			header->attr[i].value_length =
				lcfs_u16_to_file(xattr->value_len);
			memcpy(data, xattr->value, xattr->value_len);
			data += xattr->value_len;
		}

		r = lcfs_append_vdata(ctx, &out, buffer, buffer_len,
				      APPEND_FLAGS_DEDUP | APPEND_FLAGS_ALIGN);
		if (r < 0) {
			free(buffer);
			return r;
		}

		free(buffer);

		node->inode.xattrs = out;
	}

	return 0;
}

static int write_inode_data(struct lcfs_ctx_s *ctx, struct lcfs_inode_s *ino)
{
	struct lcfs_inode_s copy = { 0 };

	/* Convert endianness */
	copy.st_mode = lcfs_u32_to_file(ino->st_mode);
	copy.st_nlink = lcfs_u32_to_file(ino->st_nlink);
	copy.st_uid = lcfs_u32_to_file(ino->st_uid);
	copy.st_gid = lcfs_u32_to_file(ino->st_gid);
	copy.st_rdev = lcfs_u32_to_file(ino->st_rdev);
	copy.st_size = lcfs_u64_to_file(ino->st_size);

	copy.st_mtim_sec = lcfs_u64_to_file(ino->st_mtim_sec);
	copy.st_mtim_nsec = lcfs_u32_to_file(ino->st_mtim_nsec);

	copy.st_ctim_sec = lcfs_u64_to_file(ino->st_ctim_sec);
	copy.st_ctim_nsec = lcfs_u32_to_file(ino->st_ctim_nsec);

	copy.variable_data.off = lcfs_u64_to_file(ino->variable_data.off);
	copy.variable_data.len = lcfs_u32_to_file(ino->variable_data.len);

	copy.xattrs.off = lcfs_u64_to_file(ino->xattrs.off);
	copy.xattrs.len = lcfs_u32_to_file(ino->xattrs.len);

	copy.digest.off = lcfs_u64_to_file(ino->digest.off);
	copy.digest.len = lcfs_u32_to_file(ino->digest.len);

	return lcfs_write(ctx, &copy, sizeof(struct lcfs_inode_s));
}

static int write_inodes(struct lcfs_ctx_s *ctx)
{
	struct lcfs_node_s *node;
	int ret;

	for (node = ctx->root; node != NULL; node = node->next) {
		ret = write_inode_data(ctx, &(node->inode));
		if (ret < 0)
			return ret;
	}

	return 0;
}

int lcfs_write_cfs_to(struct lcfs_ctx_s *ctx)
{
	struct lcfs_ctx_cfs_s *ctx_cfs = (struct lcfs_ctx_cfs_s *)ctx;
	struct lcfs_node_s *root = ctx->root;
	struct lcfs_superblock_s superblock = {
		.version = lcfs_u32_to_file(LCFS_VERSION),
		.magic = lcfs_u32_to_file(LCFS_MAGIC),
	};
	int ret = 0;
	;
	off_t data_offset;

	ctx_cfs->ht = hash_initialize(0, NULL, vdata_ht_hasher,
				      vdata_ht_comparator, vdata_ht_freer);

	if (ctx->options->version != 0) {
		errno = -EINVAL;
		return -1;
	}

	ret = lcfs_compute_tree(ctx, root);
	if (ret < 0)
		return ret;

	data_offset = ALIGN_TO(sizeof(struct lcfs_superblock_s) +
				       ctx->num_inodes * sizeof(struct lcfs_inode_s),
			       4);

	superblock.vdata_offset = lcfs_u64_to_file(data_offset);

	ret = compute_variable_data(ctx);
	if (ret < 0)
		return ret;

	ret = compute_xattrs(ctx);
	if (ret < 0)
		return ret;

	ret = lcfs_write(ctx, &superblock, sizeof(superblock));
	if (ret < 0)
		return ret;

	ret = write_inodes(ctx);
	if (ret < 0)
		return ret;

	assert(ctx->bytes_written ==
	       sizeof(struct lcfs_superblock_s) +
		       ctx->num_inodes * sizeof(struct lcfs_inode_s));

	if (ctx_cfs->vdata) {
		/* Pad vdata to 4k alignment */
		ret = lcfs_write_pad(ctx, data_offset - ctx->bytes_written);
		if (ret < 0)
			return ret;

		ret = lcfs_write(ctx, ctx_cfs->vdata, ctx_cfs->vdata_len);
		if (ret < 0)
			return ret;
	}

	return 0;
}
