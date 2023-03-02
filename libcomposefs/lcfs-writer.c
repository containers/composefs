/* lcfs
   Copyright (C) 2021 Giuseppe Scrivano <giuseppe@scrivano.org>

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#define _GNU_SOURCE

#include "config.h"

#include "lcfs.h"
#include "lcfs-writer.h"
#include "lcfs-fsverity.h"
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

#define ALIGN_TO(_offset, _align_size)                                         \
	(((_offset) + _align_size - 1) & ~(_align_size - 1))

#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define round_up(x, y) ((((x)-1) | __round_mask(x, y)) + 1)
#define round_down(x, y) ((x) & ~__round_mask(x, y))

#include "erofs_fs_wrapper.h"

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
	char *vdata;
	size_t vdata_len;
	size_t vdata_allocated;
	size_t curr_off;
	struct lcfs_node_s *root;
	bool destroy_root;

	/* User for dedup.  */
	Hash_table *ht;

	/* Used by compute_tree.  */
	struct lcfs_node_s *queue_end;
	loff_t inode_table_size;
	uint32_t num_inodes;
	int64_t min_mtim_sec;
	uint32_t min_mtim_nsec;

	void *file;
	lcfs_write_cb write_cb;
	off_t bytes_written;
	FsVerityContext *fsverity_ctx;

	uint64_t erofs_inodes_end; /* start of xattrs */
	uint64_t erofs_shared_xattr_size;
	uint64_t erofs_n_data_blocks;
	uint64_t erofs_current_end;
	struct lcfs_xattr_s **erofs_shared_xattrs;
	size_t erofs_n_shared_xattrs;
};

#define APPEND_FLAGS_DEDUP (1 << 0)
#define APPEND_FLAGS_ALIGN (1 << 1)

static void lcfs_node_destroy(struct lcfs_node_s *node);

int lcfs_append_vdata(struct lcfs_ctx_s *ctx, struct lcfs_vdata_s *out,
		      const void *data, size_t len, uint32_t flags);

static int lcfs_close(struct lcfs_ctx_s *ctx);

static char *maybe_join_path(const char *a, const char *b)
{
	size_t a_len = strlen(a);
	size_t b_len = 0;

	if (b != NULL)
		b_len = 1 + strlen(b);

	char *res = malloc(a_len + b_len + 1);
	if (res) {
		strcpy(res, a);
		if (b != NULL) {
			if (a_len > 0 && res[a_len - 1] != '/') {
				strcat(res, "/");
			}
			strcat(res, b);
		}
	}
	return res;
}

static char *memdup(const char *s, size_t len)
{
	char *s2 = malloc(len);
	if (s2 == NULL) {
		errno = ENOMEM;
		return NULL;
	}
	memcpy(s2, s, len);
	return s2;
}

struct hasher_vdata_s {
	const char *const *vdata;
	uint64_t off;
	uint64_t len;
};

static size_t hash_memory(const char *string, size_t len, size_t n_buckets)
{
	size_t i, value = 0;

	for (i = 0; i < len; i++) {
		value = (value * 31 + string[i]) % n_buckets;
	}
	return value;
}

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

static struct lcfs_ctx_s *lcfs_new_ctx(struct lcfs_node_s *root, bool clone_root,
				       void *file, lcfs_write_cb write_cb,
				       uint8_t *digest_out)
{
	struct lcfs_ctx_s *ret;

	ret = calloc(1, sizeof *ret);
	if (ret == NULL) {
		return ret;
	}

	if (clone_root) {
		ret->destroy_root = true;
		ret->root = lcfs_node_clone_deep(root);
		if (root == NULL) {
			lcfs_close(ret);
			return NULL;
		}
	} else {
		ret->root = lcfs_node_ref(root);
	}
	ret->ht = hash_initialize(0, NULL, vdata_ht_hasher, vdata_ht_comparator,
				  vdata_ht_freer);

	ret->file = file;
	ret->write_cb = write_cb;
	if (digest_out) {
		ret->fsverity_ctx = lcfs_fsverity_context_new();
		if (ret->fsverity_ctx == NULL) {
			lcfs_close(ret);
			return NULL;
		}
	}

	return ret;
}

#define max(a, b) ((a > b) ? (a) : (b))

int lcfs_append_vdata(struct lcfs_ctx_s *ctx, struct lcfs_vdata_s *out,
		      const void *data, size_t len, uint32_t flags)
{
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

		ent = hash_lookup(ctx->ht, &hkey);
		if (ent) {
			out->off = ent->off;
			out->len = ent->len;
			return 0;
		}
	}

	/* We ensure that all vdata are aligned to start at 4 bytes  */
	pad_length = 0;
	if (align && ctx->vdata_len % 4 != 0)
		pad_length = 4 - ctx->vdata_len % 4;

	if (ctx->vdata_len + pad_length + len > ctx->vdata_allocated) {
		size_t new_size, increment;

		increment = max(1 << 20, pad_length + len);

		new_size = ctx->vdata_allocated + increment;
		new_vdata = realloc(ctx->vdata, new_size);
		if (new_vdata == NULL)
			return -1;

		ctx->vdata_allocated = new_size;
		ctx->vdata = new_vdata;
	}

	if (pad_length > 0) {
		memset(ctx->vdata + ctx->vdata_len, 0, pad_length);
		ctx->vdata_len += pad_length;
	}

	memcpy(ctx->vdata + ctx->vdata_len, data, len);

	out->off = ctx->vdata_len;
	out->len = len;

	/* Update to the new length.  */
	ctx->vdata_len += len;

	key = malloc(sizeof(struct hasher_vdata_s));
	if (key) {
		void *ent;

		key->vdata = (const char *const *)&ctx->vdata;
		key->off = out->off;
		key->len = out->len;

		ent = hash_insert(ctx->ht, key);
		/* Should not really happen.  */
		if (ent != key)
			free(key);
	}

	return 0;
}

static int node_get_dtype(struct lcfs_node_s *node)
{
	switch ((node->inode.st_mode & S_IFMT)) {
	case S_IFLNK:
		return DT_LNK;
	case S_IFDIR:
		return DT_DIR;
	case S_IFREG:
		return DT_REG;
	case S_IFBLK:
		return DT_BLK;
	case S_IFCHR:
		return DT_CHR;
	case S_IFSOCK:
		return DT_SOCK;
	case S_IFIFO:
		return DT_FIFO;
	default:
		return DT_UNKNOWN;
	}
}

static int cmp_nodes(const void *a, const void *b)
{
	const struct lcfs_node_s *na = *((const struct lcfs_node_s **)a);
	const struct lcfs_node_s *nb = *((const struct lcfs_node_s **)b);

	return strcmp(na->name, nb->name);
}

static int cmp_xattr(const void *a, const void *b)
{
	const struct lcfs_xattr_s *na = a;
	const struct lcfs_xattr_s *nb = b;

	return strcmp(na->key, nb->key);
}

/* This ensures that the tree is in a well defined order, with
   children sorted by name, and the nodes visited in breadth-first
   order.  It also updates the inode offset. */
static int compute_tree(struct lcfs_ctx_s *ctx, struct lcfs_node_s *root)
{
	uint32_t index;
	struct lcfs_node_s *node;

	/* Start with the root node. */

	ctx->queue_end = root;
	root->in_tree = true;

	ctx->min_mtim_sec = root->inode.st_mtim_sec;
	ctx->min_mtim_nsec = root->inode.st_mtim_nsec;

	node = root;

	for (node = root, index = 0; node != NULL; node = node->next, index++) {
		if ((node->inode.st_mode & S_IFMT) != S_IFDIR &&
		    node->children_size != 0) {
			/* Only dirs can have children */
			errno = EINVAL;
			return -1;
		}

		/* Fix up directory n_links counts, they are 2 + nr of subdirs */
		if ((node->inode.st_mode & S_IFMT) == S_IFDIR) {
			size_t n_link = 2;
			for (size_t i = 0; i < node->children_size; i++) {
				struct lcfs_node_s *child = node->children[i];
				if ((child->inode.st_mode & S_IFMT) == S_IFDIR) {
					n_link++;
				}
			}
			node->inode.st_nlink = n_link;
		}

		/* Canonical order */
		qsort(node->children, node->children_size,
		      sizeof(node->children[0]), cmp_nodes);
		qsort(node->xattrs, node->n_xattrs, sizeof(node->xattrs[0]),
		      cmp_xattr);

		if (node->inode.st_mtim_sec < ctx->min_mtim_sec ||
		    (node->inode.st_mtim_sec == ctx->min_mtim_sec &&
		     node->inode.st_mtim_nsec < ctx->min_mtim_nsec)) {
			ctx->min_mtim_sec = node->inode.st_mtim_sec;
			ctx->min_mtim_nsec = node->inode.st_mtim_nsec;
		}

		/* Assign inode index */
		node->inode_num = index;
		ctx->inode_table_size += sizeof(struct lcfs_inode_s);

		node->in_tree = true;
		/* Append to queue for more work */
		for (size_t i = 0; i < node->children_size; i++) {
			struct lcfs_node_s *child = node->children[i];

			/* Skip hardlinks, they will not be serialized separately */
			if (child->link_to != NULL) {
				continue;
			}

			/* Avoid recursion */
			assert(!child->in_tree);

			ctx->queue_end->next = child;
			ctx->queue_end = child;
		}
	}

	/* Ensure all hardlinks are in tree */
	for (node = ctx->root; node != NULL; node = node->next) {
		for (size_t i = 0; i < node->children_size; i++) {
			struct lcfs_node_s *child = node->children[i];
			if (child->link_to != NULL && !child->link_to->in_tree) {
				/* Link to inode outside tree */
				errno = EINVAL;
				return -1;
			}
		}
	}

	/* Reset in_tree back to false for multiple uses */
	for (node = ctx->root; node != NULL; node = node->next) {
		node->in_tree = false;
	}

	ctx->num_inodes = index;

	return 0;
}

static struct lcfs_node_s *follow_links(struct lcfs_node_s *node)
{
	if (node->link_to)
		return follow_links(node->link_to);
	return node;
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

static int lcfs_write(struct lcfs_ctx_s *ctx, void *_data, size_t data_len)
{
	uint8_t *data = _data;
	if (ctx->fsverity_ctx)
		lcfs_fsverity_context_update(ctx->fsverity_ctx, data, data_len);

	ctx->bytes_written += data_len;

	if (ctx->write_cb) {
		while (data_len > 0) {
			ssize_t r = ctx->write_cb(ctx->file, data, data_len);
			if (r <= 0) {
				errno = EIO;
				return -1;
			}
			data_len -= r;
			data += r;
		}
	}

	return 0;
}

static int lcfs_write_pad(struct lcfs_ctx_s *ctx, size_t data_len)
{
	char buf[256] = { 0 };

	for (size_t i = 0; i < data_len; i += sizeof(buf)) {
		size_t to_write = MIN(sizeof(buf), data_len - i);
		int r = lcfs_write(ctx, buf, to_write);
		if (r < 0) {
			return r;
		}
	}

	return 0;
}

static int lcfs_write_align(struct lcfs_ctx_s *ctx, size_t align_size)
{
	off_t end = round_up(ctx->bytes_written, align_size);
	if (end > ctx->bytes_written) {
		return lcfs_write_pad(ctx, end - ctx->bytes_written);
	}
	return 0;
}

static int write_inode_data(struct lcfs_ctx_s *ctx, struct lcfs_inode_s *ino)
{
	struct lcfs_inode_s copy;

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

int lcfs_write_to(struct lcfs_node_s *root, void *file, lcfs_write_cb write_cb,
		  uint8_t *digest_out)
{
	struct lcfs_superblock_s superblock = {
		.version = lcfs_u32_to_file(LCFS_VERSION),
		.magic = lcfs_u32_to_file(LCFS_MAGIC),
	};
	int ret = 0;
	struct lcfs_ctx_s *ctx;
	off_t data_offset;

	ctx = lcfs_new_ctx(root, false, file, write_cb, digest_out);
	if (ctx == NULL) {
		errno = ENOMEM;
		return -1;
	}

	ret = compute_tree(ctx, root);
	if (ret < 0) {
		lcfs_close(ctx);
		return ret;
	}

	data_offset = ALIGN_TO(
		sizeof(struct lcfs_superblock_s) + ctx->inode_table_size, 4);

	superblock.vdata_offset = lcfs_u64_to_file(data_offset);

	ret = compute_variable_data(ctx);
	if (ret < 0) {
		lcfs_close(ctx);
		return ret;
	}

	ret = compute_xattrs(ctx);
	if (ret < 0) {
		lcfs_close(ctx);
		return ret;
	}

	ret = lcfs_write(ctx, &superblock, sizeof(superblock));
	if (ret < 0) {
		lcfs_close(ctx);
		return ret;
	}

	ret = write_inodes(ctx);
	if (ret < 0) {
		lcfs_close(ctx);
		return ret;
	}

	assert(ctx->bytes_written ==
	       sizeof(struct lcfs_superblock_s) + ctx->inode_table_size);

	if (ctx->vdata) {
		/* Pad vdata to 4k alignment */
		ret = lcfs_write_pad(ctx, data_offset - ctx->bytes_written);
		if (ret < 0) {
			lcfs_close(ctx);
			return ret;
		}

		ret = lcfs_write(ctx, ctx->vdata, ctx->vdata_len);
		if (ret < 0) {
			lcfs_close(ctx);
			return ret;
		}
	}

	if (digest_out) {
		lcfs_fsverity_context_get_digest(ctx->fsverity_ctx, digest_out);
	}

	lcfs_close(ctx);
	return 0;
}

static int lcfs_close(struct lcfs_ctx_s *ctx)
{
	if (ctx == NULL)
		return 0;

	if (ctx->fsverity_ctx)
		lcfs_fsverity_context_free(ctx->fsverity_ctx);
	hash_free(ctx->ht);
	free(ctx->vdata);
	if (ctx->root) {
		if (ctx->destroy_root) {
			lcfs_node_destroy(ctx->root);
		} else {
			lcfs_node_unref(ctx->root);
		}
	}
	free(ctx->erofs_shared_xattrs);
	free(ctx);

	return 0;
}

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

static int compute_erofs_shared_xattrs(struct lcfs_ctx_s *ctx)
{
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
	ctx->erofs_shared_xattrs = calloc(n_xattrs, sizeof(struct lcfs_xattr_s *));
	if (ctx->erofs_shared_xattrs == NULL)
		goto fail;
	ctx->erofs_n_shared_xattrs = 0;

	xattr_offset = 0;
	for (size_t i = 0; i < n_xattrs; i++) {
		struct hasher_xattr_s *ent = sorted[i];
		if (ent->count > 1) {
			ent->shared = true;
			ent->shared_offset = xattr_offset;

			ctx->erofs_shared_xattrs[ctx->erofs_n_shared_xattrs] =
				ent->xattr;
			ctx->erofs_n_shared_xattrs++;

			xattr_offset += xattr_erofs_entry_size(ent->xattr);
		}
	}

	ctx->erofs_shared_xattr_size = xattr_offset;

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
		ctx->erofs_n_data_blocks += node->erofs_n_blocks;
		node->erofs_nid = (pos - meta_start) / EROFS_SLOTSIZE;

		/* Assert that tails never span multiple blocks */
		assert(node->erofs_tailsize == 0 ||
		       ((pos + inode_size + xattr_size) / EROFS_BLKSIZ) ==
			       ((pos + node->erofs_isize - 1) / EROFS_BLKSIZ));

		pos += node->erofs_isize;
	}

	ctx->erofs_inodes_end = round_up(pos, EROFS_SLOTSIZE);

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

	for (size_t i = first_child; i < first_child + n_children; i++) {
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

	for (size_t i = first_child; i < first_child + n_children; i++) {
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
		struct erofs_inode_compact i = { lcfs_u16_to_file(format) };
		i.i_xattr_icount = lcfs_u16_to_file(xattr_icount);
		i.i_mode = lcfs_u16_to_file(node->inode.st_mode);
		i.i_nlink = lcfs_u16_to_file(node->inode.st_nlink);
		i.i_size = lcfs_u32_to_file(size);
		i.i_ino = lcfs_u32_to_file(node->inode_num);
		i.i_uid = lcfs_u16_to_file(node->inode.st_uid);
		i.i_gid = lcfs_u16_to_file(node->inode.st_gid);

		if (type == S_IFDIR) {
			if (node->erofs_n_blocks > 0) {
				i.i_u.raw_blkaddr =
					ctx->erofs_current_end / EROFS_BLKSIZ;
				ctx->erofs_current_end +=
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
		struct erofs_inode_extended i = { lcfs_u16_to_file(format) };
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
				i.i_u.raw_blkaddr =
					ctx->erofs_current_end / EROFS_BLKSIZ;
				ctx->erofs_current_end +=
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
					ctx->erofs_inodes_end % EROFS_BLKSIZ +
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
	int ret;

	for (size_t i = 0; i < ctx->erofs_n_shared_xattrs; i++) {
		struct lcfs_xattr_s *xattr = ctx->erofs_shared_xattrs[i];
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
		ret = lcfs_node_set_xattr(node, "trusted.overlay.metacopy", "", 0);
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

		if (node->digest_set) {
			ret = lcfs_node_set_xattr(node, "trusted.overlay.fs-verity",
						  (char *)node->digest,
						  LCFS_DIGEST_SIZE);
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
		child->inode.st_ctim_sec = root->inode.st_ctim_sec;
		child->inode.st_ctim_nsec = root->inode.st_ctim_nsec;

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

static int rewrite_tree_for_erofs(struct lcfs_node_s *root)
{
	int res;

	res = rewrite_tree_node_for_erofs(root, root);
	if (res < 0)
		return res;

	res = add_overlay_whiteouts(root);
	if (res < 0)
		return res;

	return 0;
}

int lcfs_write_erofs_to(struct lcfs_node_s *root, void *file,
			lcfs_write_cb write_cb, uint8_t *digest_out)
{
	struct erofs_super_block superblock = {
		.magic = lcfs_u32_to_file(EROFS_SUPER_MAGIC_V1),
		.blkszbits = EROFS_BLKSIZ_BITS,
	};
	int ret = 0;
	struct lcfs_ctx_s *ctx;
	uint64_t data_block_start;

	/* Clone root so we can make required modifications to it */
	ctx = lcfs_new_ctx(root, true, file, write_cb, digest_out);
	if (ctx == NULL) {
		errno = ENOMEM;
		return -1;
	}

	root = ctx->root; /* We cloned it */

	/* Rewrite cloned tree as needed for erofs */
	ret = rewrite_tree_for_erofs(root);
	if (ret < 0)
		goto fail;

	ret = compute_tree(ctx, root);
	if (ret < 0)
		goto fail;

	ret = compute_erofs_shared_xattrs(ctx);
	if (ret < 0)
		goto fail;

	ret = compute_erofs_inodes(ctx);
	if (ret < 0)
		goto fail;

	ret = lcfs_write_pad(ctx, EROFS_SUPER_OFFSET);
	if (ret < 0)
		goto fail;

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
		lcfs_u32_to_file(ctx->erofs_inodes_end / EROFS_BLKSIZ);

	data_block_start =
		round_up(ctx->erofs_inodes_end + ctx->erofs_shared_xattr_size,
			 EROFS_BLKSIZ);

	superblock.blocks = lcfs_u32_to_file(data_block_start / EROFS_BLKSIZ +
					     ctx->erofs_n_data_blocks);

	/* TODO: More superblock fields:
	 *  uuid?
	 *  volume_name?
	 */

	ret = lcfs_write(ctx, &superblock, sizeof(superblock));
	if (ret < 0)
		goto fail;

	ctx->erofs_current_end = data_block_start;

	ret = write_erofs_inodes(ctx);
	if (ret < 0)
		goto fail;

	assert(ctx->erofs_inodes_end == ctx->bytes_written);

	ret = write_erofs_shared_xattrs(ctx);
	if (ret < 0)
		goto fail;

	assert(ctx->erofs_inodes_end + ctx->erofs_shared_xattr_size ==
	       ctx->bytes_written);

	/* Following are full blocks and must be block-aligned */
	ret = lcfs_write_align(ctx, EROFS_BLKSIZ);
	if (ret < 0)
		goto fail;

	assert(data_block_start == ctx->bytes_written);

	ret = write_erofs_dirent_blocks(ctx);
	if (ret < 0)
		goto fail;

	assert(ctx->erofs_current_end == ctx->bytes_written);
	assert(data_block_start + ctx->erofs_n_data_blocks * EROFS_BLKSIZ ==
	       ctx->bytes_written);

	if (digest_out) {
		lcfs_fsverity_context_get_digest(ctx->fsverity_ctx, digest_out);
	}

	lcfs_close(ctx);
	return 0;

fail:
	lcfs_close(ctx);
	return -1;
}

static int read_xattrs(struct lcfs_node_s *ret, int dirfd, const char *fname)
{
	char path[PATH_MAX];
	ssize_t list_size;
	char *list, *it;
	ssize_t r;
	int fd;

	fd = openat(dirfd, fname, O_PATH | O_NOFOLLOW | O_CLOEXEC, 0);
	if (fd < 0)
		return -1;

	sprintf(path, "/proc/self/fd/%d", fd);

	list_size = listxattr(path, NULL, 0);
	if (list_size < 0) {
		close(fd);
		return list_size;
	}

	list = malloc(list_size);
	if (list == NULL) {
		close(fd);
		return -1;
	}

	r = listxattr(path, list, list_size);
	if (r < 0) {
		close(fd);
		return r;
	}

	for (it = list; it < list + list_size; it += strlen(it) + 1) {
		ssize_t value_size;
		char *value;

		value_size = getxattr(path, it, NULL, 0);
		if (value_size < 0) {
			close(fd);
			free(list);
			return value_size;
		}

		value = malloc(value_size);
		if (value == NULL) {
			close(fd);
			free(list);
			return -1;
		}

		r = getxattr(path, it, value, value_size);
		if (r < 0) {
			close(fd);
			free(list);
			free(value);
			return r;
		}

		r = lcfs_node_set_xattr(ret, it, value, value_size);
		if (r < 0) {
			close(fd);
			free(list);
			free(value);
			return r;
		}

		free(value);
	}

	free(list);
	close(fd);

	return r;
}

struct lcfs_node_s *lcfs_node_new(void)
{
	struct lcfs_node_s *node = calloc(1, sizeof(struct lcfs_node_s));
	if (node == NULL)
		return NULL;

	node->ref_count = 1;
	node->inode.st_nlink = 1;
	return node;
}

int lcfs_node_set_fsverity_from_content(struct lcfs_node_s *node, void *file,
					lcfs_read_cb read_cb)
{
	uint8_t digest[32];
	uint8_t buffer[4096];
	ssize_t n_read;
	FsVerityContext *ctx;

	ctx = lcfs_fsverity_context_new();
	if (ctx == NULL) {
		errno = ENOMEM;
		return -1;
	}

	while (true) {
		n_read = read_cb(file, buffer, sizeof(buffer));
		if (n_read < 0) {
			lcfs_fsverity_context_free(ctx);
			errno = ENODATA;
			return -1;
		}
		if (n_read == 0)
			break;
		lcfs_fsverity_context_update(ctx, buffer, n_read);
	}

	lcfs_fsverity_context_get_digest(ctx, digest);
	lcfs_node_set_fsverity_digest(node, digest);

	lcfs_fsverity_context_free(ctx);

	return 0;
}

static ssize_t fsverity_read_cb(void *_fd, void *buf, size_t count)
{
	int fd = *(int *)_fd;
	ssize_t res;

	do
		res = read(fd, buf, count);
	while (res < 0 && errno == EINTR);

	return res;
}

int lcfs_node_set_fsverity_from_fd(struct lcfs_node_s *node, int fd)
{
	int _fd = fd;
	return lcfs_node_set_fsverity_from_content(node, &_fd, fsverity_read_cb);
}

struct lcfs_node_s *lcfs_load_node_from_file(int dirfd, const char *fname,
					     int buildflags)
{
	struct lcfs_node_s *ret;
	struct stat sb;
	int r;

	if (buildflags & ~(LCFS_BUILD_SKIP_XATTRS | LCFS_BUILD_USE_EPOCH |
			   LCFS_BUILD_SKIP_DEVICES | LCFS_BUILD_COMPUTE_DIGEST)) {
		errno = EINVAL;
		return NULL;
	}

	r = fstatat(dirfd, fname, &sb, AT_SYMLINK_NOFOLLOW);
	if (r < 0)
		return NULL;

	ret = lcfs_node_new();
	if (ret == NULL)
		return NULL;

	ret->inode.st_mode = sb.st_mode;
	ret->inode.st_uid = sb.st_uid;
	ret->inode.st_gid = sb.st_gid;
	ret->inode.st_rdev = sb.st_rdev;
	ret->inode.st_size = sb.st_size;

	if ((sb.st_mode & S_IFMT) == S_IFREG) {
		if (sb.st_size != 0 && (buildflags & LCFS_BUILD_COMPUTE_DIGEST) != 0) {
			int fd = openat(dirfd, fname, O_RDONLY | O_CLOEXEC);
			if (fd < 0) {
				lcfs_node_unref(ret);
				return NULL;
			}
			r = lcfs_node_set_fsverity_from_fd(ret, fd);
			close(fd);
			if (r < 0) {
				lcfs_node_unref(ret);
				return NULL;
			}
		}
	}

	if ((buildflags & LCFS_BUILD_USE_EPOCH) == 0) {
		ret->inode.st_mtim_sec = sb.st_mtim.tv_sec;
		ret->inode.st_mtim_nsec = sb.st_mtim.tv_nsec;
		ret->inode.st_ctim_sec = sb.st_ctim.tv_sec;
		ret->inode.st_ctim_nsec = sb.st_ctim.tv_nsec;
	}

	if ((buildflags & LCFS_BUILD_SKIP_XATTRS) == 0) {
		r = read_xattrs(ret, dirfd, fname);
		if (r < 0) {
			lcfs_node_unref(ret);
			return NULL;
		}
	}

	return ret;
}

int lcfs_node_set_payload(struct lcfs_node_s *node, const char *payload)
{
	node->payload = strdup(payload);
	if (node->payload == NULL) {
		errno = ENOMEM;
		return -1;
	}

	return 0;
}

const uint8_t *lcfs_node_get_fsverity_digest(struct lcfs_node_s *node)
{
	if (node->digest_set)
		return node->digest;
	return NULL;
}

/* This is the sha256 fs-verity digest of the file contents */
void lcfs_node_set_fsverity_digest(struct lcfs_node_s *node,
				   uint8_t digest[LCFS_DIGEST_SIZE])
{
	node->digest_set = true;
	memcpy(node->digest, digest, LCFS_DIGEST_SIZE);
}

const char *lcfs_node_get_name(struct lcfs_node_s *node)
{
	return node->name;
}

size_t lcfs_node_get_n_children(struct lcfs_node_s *node)
{
	return node->children_size;
}

struct lcfs_node_s *lcfs_node_get_child(struct lcfs_node_s *node, size_t i)
{
	if (i < node->children_size)
		return node->children[i];
	return NULL;
}

uint32_t lcfs_node_get_mode(struct lcfs_node_s *node)
{
	return node->inode.st_mode;
}

void lcfs_node_set_mode(struct lcfs_node_s *node, uint32_t mode)
{
	node->inode.st_mode = mode;
}

uint32_t lcfs_node_get_uid(struct lcfs_node_s *node)
{
	return node->inode.st_uid;
}

void lcfs_node_set_uid(struct lcfs_node_s *node, uint32_t uid)
{
	node->inode.st_uid = uid;
}

uint32_t lcfs_node_get_gid(struct lcfs_node_s *node)
{
	return node->inode.st_gid;
}

void lcfs_node_set_gid(struct lcfs_node_s *node, uint32_t gid)
{
	node->inode.st_gid = gid;
}

uint32_t lcfs_node_get_rdev(struct lcfs_node_s *node)
{
	return node->inode.st_rdev;
}

void lcfs_node_set_rdev(struct lcfs_node_s *node, uint32_t rdev)
{
	node->inode.st_rdev = rdev;
}

uint32_t lcfs_node_get_nlink(struct lcfs_node_s *node)
{
	return node->inode.st_nlink;
}

void lcfs_node_set_nlink(struct lcfs_node_s *node, uint32_t nlink)
{
	node->inode.st_nlink = nlink;
}

uint64_t lcfs_node_get_size(struct lcfs_node_s *node)
{
	return node->inode.st_size;
}

void lcfs_node_set_size(struct lcfs_node_s *node, uint64_t size)
{
	node->inode.st_size = size;
}

void lcfs_node_set_mtime(struct lcfs_node_s *node, struct timespec *time)
{
	node->inode.st_mtim_sec = time->tv_sec;
	node->inode.st_mtim_nsec = time->tv_nsec;
}

void lcfs_node_get_mtime(struct lcfs_node_s *node, struct timespec *time)
{
	time->tv_sec = node->inode.st_mtim_sec;
	time->tv_nsec = node->inode.st_mtim_nsec;
}

void lcfs_node_set_ctime(struct lcfs_node_s *node, struct timespec *time)
{
	node->inode.st_ctim_sec = time->tv_sec;
	node->inode.st_ctim_nsec = time->tv_nsec;
}

void lcfs_node_get_ctime(struct lcfs_node_s *node, struct timespec *time)
{
	time->tv_sec = node->inode.st_ctim_sec;
	time->tv_nsec = node->inode.st_ctim_nsec;
}

struct lcfs_node_s *lcfs_node_lookup_child(struct lcfs_node_s *node, const char *name)
{
	size_t i;

	for (i = 0; i < node->children_size; ++i) {
		struct lcfs_node_s *child = node->children[i];

		if (child->name && strcmp(child->name, name) == 0)
			return child;
	}

	return NULL;
}

struct lcfs_node_s *lcfs_node_get_parent(struct lcfs_node_s *node)
{
	return node->parent;
}

void lcfs_node_make_hardlink(struct lcfs_node_s *node, struct lcfs_node_s *target)
{
	target = follow_links(target);
	node->link_to = lcfs_node_ref(target);
	target->inode.st_nlink++;
}

static void lcfs_node_remove_child_node(struct lcfs_node_s *parent, int offset,
					struct lcfs_node_s *child)
{
	assert(child->parent == parent);
	assert(parent->children[offset] == child);

	memcpy(&parent->children[offset], &parent->children[offset + 1],
	       sizeof(struct lcfs_node_s *) * (parent->children_size - (offset + 1)));
	parent->children_size -= 1;

	/* Unlink correctly as it may live on outside the tree and be reinserted */
	free(child->name);
	child->name = NULL;
	child->parent = NULL;

	lcfs_node_unref(child);
}

int lcfs_node_remove_child(struct lcfs_node_s *parent, const char *name)
{
	size_t i;

	if ((parent->inode.st_mode & S_IFMT) != S_IFDIR) {
		errno = ENOTDIR;
		return -1;
	}

	for (i = 0; i < parent->children_size; ++i) {
		struct lcfs_node_s *child = parent->children[i];

		if (child->name && strcmp(child->name, name) == 0) {
			lcfs_node_remove_child_node(parent, i, child);
			return 0;
		}
	}

	errno = ENOENT;
	return -1;
}

int lcfs_node_add_child(struct lcfs_node_s *parent, struct lcfs_node_s *child,
			const char *name)
{
	struct lcfs_node_s **new_children;
	size_t new_size;
	char *name_copy;

	if ((parent->inode.st_mode & S_IFMT) != S_IFDIR) {
		errno = ENOTDIR;
		return -1;
	}

	if (strlen(name) > LCFS_MAX_NAME_LENGTH) {
		errno = ENAMETOOLONG;
		return -1;
	}

	/* Each node can only be added once */
	if (child->name != NULL) {
		errno = EMLINK;
		return -1;
	}

	if (lcfs_node_lookup_child(parent, name) != NULL) {
		errno = EEXIST;
		return -1;
	}

	name_copy = strdup(name);
	if (name_copy == NULL) {
		errno = ENOMEM;
		return -1;
	}

	new_size = parent->children_size + 1;

	new_children = reallocarray(parent->children, sizeof(*parent->children),
				    new_size);
	if (new_children == NULL) {
		errno = ENOMEM;
		free(name_copy);
		return -1;
	}

	parent->children = new_children;

	parent->children[parent->children_size] = child;
	parent->children_size = new_size;
	child->parent = parent;
	child->name = name_copy;

	return 0;
}

struct lcfs_node_s *lcfs_node_ref(struct lcfs_node_s *node)
{
	node->ref_count++;
	return node;
}

void lcfs_node_unref(struct lcfs_node_s *node)
{
	size_t i;

	node->ref_count--;

	if (node->ref_count > 0)
		return;

	/* finalizing */

	/* if we have a parent, that should have a real ref to us */
	assert(node->parent == NULL);

	while (node->children_size > 0) {
		struct lcfs_node_s *child = node->children[0];
		lcfs_node_remove_child_node(node, 0, child);
	}
	free(node->children);

	if (node->link_to)
		lcfs_node_unref(node->link_to);

	free(node->name);
	free(node->payload);

	for (i = 0; i < node->n_xattrs; i++) {
		free(node->xattrs[i].key);
		free(node->xattrs[i].value);
	}
	free(node->xattrs);

	free(node);
}

/* Unlink all children (recursively) and then unref. Useful to handle refcount loops like dot and dotdot. */
static void lcfs_node_destroy(struct lcfs_node_s *node)
{
	while (node->children_size > 0) {
		struct lcfs_node_s *child = lcfs_node_ref(node->children[0]);
		lcfs_node_remove_child_node(node, 0, child);
		lcfs_node_destroy(child);
	}
	lcfs_node_unref(node);
};

struct lcfs_node_s *lcfs_node_clone(struct lcfs_node_s *node)
{
	struct lcfs_node_s *new = lcfs_node_new();

	/* Note: This copies only data, not structure like name or children */

	/* We copy the link_to, but clone_deep may rewrite this */
	if (node->link_to) {
		new->link_to = lcfs_node_ref(node->link_to);
	}

	if (node->payload) {
		new->payload = strdup(node->payload);
		if (new->payload == NULL)
			goto fail;
	}

	if (node->n_xattrs > 0) {
		new->xattrs = malloc(sizeof(struct lcfs_xattr_s) * node->n_xattrs);
		if (new->xattrs == NULL)
			goto fail;
		for (size_t i = 0; i < node->n_xattrs; i++) {
			char *key = strdup(node->xattrs[i].key);
			char *value = memdup(node->xattrs[i].value,
					     node->xattrs[i].value_len);
			if (key == NULL || value == NULL) {
				free(key);
				free(value);
				goto fail;
			}
			new->xattrs[i].key = key;
			new->xattrs[i].value = value;
			new->xattrs[i].value_len = node->xattrs[i].value_len;
			new->n_xattrs++;
		}
	}

	new->digest_set = node->digest_set;
	memcpy(new->digest, node->digest, LCFS_DIGEST_SIZE);
	new->inode = node->inode;

	return new;

fail:
	lcfs_node_unref(new);
	return NULL;
}

struct lcfs_node_mapping_s {
	struct lcfs_node_s *old;
	struct lcfs_node_s *new;
};

struct lcfs_clone_data {
	struct lcfs_node_mapping_s *mapping;
	size_t n_mappings;
	size_t allocated_mappings;
};

static struct lcfs_node_s *_lcfs_node_clone_deep(struct lcfs_node_s *node,
						 struct lcfs_clone_data *data)
{
	struct lcfs_node_s *new = lcfs_node_clone(node);

	if (data->n_mappings >= data->allocated_mappings) {
		struct lcfs_node_mapping_s *new_mapping;
		data->allocated_mappings = (data->allocated_mappings == 0) ?
						   32 :
						   data->allocated_mappings * 2;
		new_mapping = reallocarray(data->mapping,
					   sizeof(struct lcfs_node_mapping_s),
					   data->allocated_mappings);
		if (new_mapping == NULL)
			goto fail;
		data->mapping = new_mapping;
	}

	data->mapping[data->n_mappings].old = node;
	data->mapping[data->n_mappings].new = new;
	data->n_mappings++;

	for (size_t i = 0; i < node->children_size; ++i) {
		struct lcfs_node_s *child = node->children[i];
		struct lcfs_node_s *new_child = _lcfs_node_clone_deep(child, data);
		if (new_child == NULL)
			goto fail;

		if (lcfs_node_add_child(new, new_child, child->name) < 0)
			goto fail;
	}

	return new;

fail:
	lcfs_node_unref(new);
	return NULL;
}

/* Rewrite all hardlinks according to mapping */
static void _lcfs_node_clone_rewrite_links(struct lcfs_node_s *new,
					   struct lcfs_clone_data *data)
{
	for (size_t i = 0; i < new->children_size; ++i) {
		struct lcfs_node_s *new_child = new->children[i];
		_lcfs_node_clone_rewrite_links(new_child, data);
	}

	if (new->link_to != NULL) {
		for (size_t i = 0; i < data->n_mappings; ++i) {
			if (data->mapping[i].old == new->link_to) {
				lcfs_node_unref(new->link_to);
				new->link_to = lcfs_node_ref(data->mapping[i].new);
				break;
			}
		}
	}
}

struct lcfs_node_s *lcfs_node_clone_deep(struct lcfs_node_s *node)
{
	struct lcfs_clone_data data = { NULL };
	struct lcfs_node_s *new;

	new = _lcfs_node_clone_deep(node, &data);
	if (new)
		_lcfs_node_clone_rewrite_links(node, &data);

	free(data.mapping);

	return new;
}

bool lcfs_node_dirp(struct lcfs_node_s *node)
{
	return (node->inode.st_mode & S_IFMT) == S_IFDIR;
}

struct lcfs_node_s *lcfs_build(int dirfd, const char *fname, const char *name,
			       int buildflags, char **failed_path_out)
{
	struct lcfs_node_s *node = NULL;
	struct dirent *de;
	DIR *dir = NULL;
	int dfd;
	char *free_failed_subpath = NULL;
	const char *failed_subpath = NULL;
	int errsv;

	node = lcfs_load_node_from_file(dirfd, fname, buildflags);
	if (node == NULL) {
		errsv = errno;
		goto fail;
	}

	if (!lcfs_node_dirp(node)) {
		return node;
	}

	dfd = openat(dirfd, fname, O_RDONLY | O_NOFOLLOW | O_CLOEXEC, 0);
	if (dfd < 0) {
		errsv = errno;
		goto fail;
	}

	dir = fdopendir(dfd);
	if (dir == NULL) {
		errsv = errno;
		close(dfd);
		goto fail;
	}

	for (;;) {
		struct lcfs_node_s *n;
		int r;

		errno = 0;
		de = readdir(dir);
		if (de == NULL) {
			if (errno) {
				errsv = errno;
				goto fail;
			}

			break;
		}

		if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
			continue;

		if (de->d_type == DT_UNKNOWN) {
			struct stat statbuf;

			if (fstatat(dfd, de->d_name, &statbuf,
				    AT_SYMLINK_NOFOLLOW) < 0) {
				errsv = errno;
				failed_subpath = de->d_name;
				goto fail;
			}

			if (S_ISDIR(statbuf.st_mode))
				de->d_type = DT_DIR;
		}

		if (de->d_type == DT_DIR) {
			n = lcfs_build(dfd, de->d_name, de->d_name, buildflags,
				       &free_failed_subpath);
			if (n == NULL) {
				failed_subpath = free_failed_subpath;
				errsv = errno;
				goto fail;
			}
		} else {
			if (buildflags & LCFS_BUILD_SKIP_DEVICES) {
				if (de->d_type == DT_BLK || de->d_type == DT_CHR)
					continue;
			}

			n = lcfs_load_node_from_file(dfd, de->d_name, buildflags);
			if (n == NULL) {
				errsv = errno;
				failed_subpath = de->d_name;
				goto fail;
			}
		}

		r = lcfs_node_add_child(node, n, de->d_name);
		if (r < 0) {
			errsv = errno;
			goto fail;
		}
	}

	closedir(dir);
	return node;

fail:
	if (failed_path_out)
		*failed_path_out = maybe_join_path(fname, failed_subpath);
	if (free_failed_subpath)
		free(free_failed_subpath);
	if (node)
		lcfs_node_unref(node);
	if (dir)
		closedir(dir);
	errno = errsv;
	return NULL;
}

size_t lcfs_node_get_n_xattr(struct lcfs_node_s *node)
{
	return node->n_xattrs;
}

const char *lcfs_node_get_xattr_name(struct lcfs_node_s *node, size_t index)
{
	if (index >= node->n_xattrs)
		return NULL;

	return node->xattrs[index].key;
}

static ssize_t find_xattr(struct lcfs_node_s *node, const char *name)
{
	ssize_t i;
	for (i = 0; i < node->n_xattrs; i++) {
		struct lcfs_xattr_s *xattr = &node->xattrs[i];
		if (strcmp(name, xattr->key) == 0)
			return i;
	}
	return -1;
}

const char *lcfs_node_get_xattr(struct lcfs_node_s *node, const char *name,
				size_t *length)
{
	ssize_t index = find_xattr(node, name);

	if (index >= 0) {
		struct lcfs_xattr_s *xattr = &node->xattrs[index];
		*length = xattr->value_len;
		return xattr->value;
	}

	return NULL;
}

int lcfs_node_unset_xattr(struct lcfs_node_s *node, const char *name)
{
	ssize_t index = find_xattr(node, name);

	if (index >= 0) {
		if (index != node->n_xattrs - 1)
			node->xattrs[index] = node->xattrs[node->n_xattrs - 1];
		node->n_xattrs--;
	}

	return -1;
}

int lcfs_node_set_xattr(struct lcfs_node_s *node, const char *name,
			const char *value, size_t value_len)
{
	struct lcfs_xattr_s *xattrs;
	char *k, *v;
	ssize_t index = find_xattr(node, name);

	if (index >= 0) {
		/* Already set, replace */
		struct lcfs_xattr_s *xattr = &node->xattrs[index];
		v = memdup(value, value_len);
		if (v == NULL) {
			errno = ENOMEM;
			return -1;
		}
		free(xattr->value);
		xattr->value = v;
		xattr->value_len = value_len;

		return 0;
	}

	xattrs = realloc(node->xattrs,
			 (node->n_xattrs + 1) * sizeof(struct lcfs_xattr_s));
	if (xattrs == NULL) {
		errno = ENOMEM;
		return -1;
	}
	node->xattrs = xattrs;

	k = strdup(name);
	v = memdup(value, value_len);
	if (k == NULL || v == NULL) {
		free(k);
		free(v);
		errno = ENOMEM;
		return -1;
	}

	xattrs[node->n_xattrs].key = k;
	xattrs[node->n_xattrs].value = v;
	xattrs[node->n_xattrs].value_len = value_len;
	node->n_xattrs++;

	return 0;
}
