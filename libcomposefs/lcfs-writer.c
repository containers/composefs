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

/* In memory representation used to build the file.  */

struct lcfs_xattr_s {
	char *key;
	char *value;
	size_t value_len;
};

struct lcfs_node_s {
	int ref_count;

	struct lcfs_node_s *parent;

	struct lcfs_node_s **children; /* Owns refs */
	size_t children_size;

	/* Used to create hard links.  */
	struct lcfs_node_s *link_to; /* Owns refs */

	char *name;
	char *payload;
	struct lcfs_dirent_s data;
	uint64_t inode_index;

	struct lcfs_xattr_s *xattrs;
	size_t n_xattrs;

	bool digest_set;

	struct lcfs_inode_s inode;

	/* Used during compute_tree */
	struct lcfs_node_s *next; /* Use for the queue in compute_tree */
	bool in_tree;
};

struct lcfs_ctx_s {
	char *vdata;
	size_t vdata_len;
	size_t vdata_allocated;
	size_t curr_off;
	struct lcfs_node_s *root;

	/* User for dedup.  */
	Hash_table *ht;

	/* Used by compute_tree.  */
	struct lcfs_node_s *queue_end;
	loff_t inode_table_size;

	void *file;
	lcfs_write_cb write_cb;
	off_t bytes_written;
	FsVerityContext *fsverity_ctx;

#ifdef LCFS_SIZE_STATS
	loff_t inode_data_size;
	loff_t payload_data_size;
	loff_t dir_data_size;
#endif
};

int lcfs_append_vdata(struct lcfs_ctx_s *ctx, struct lcfs_vdata_s *out,
		      const void *data, size_t len);

int lcfs_append_vdata_no_dedup(struct lcfs_ctx_s *ctx, struct lcfs_vdata_s *out,
			       const void *data, size_t len);

int lcfs_append_vdata_opts(struct lcfs_ctx_s *ctx, struct lcfs_vdata_s *out,
			   const void *data, size_t len, bool dedup);

static int lcfs_close(struct lcfs_ctx_s *ctx);

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

static struct lcfs_ctx_s *lcfs_new_ctx(struct lcfs_node_s *root)
{
	struct lcfs_ctx_s *ret;

	ret = calloc(1, sizeof *ret);
	if (ret == NULL)
		return ret;

	ret->root = lcfs_node_ref(root);
	ret->ht = hash_initialize(0, NULL, vdata_ht_hasher, vdata_ht_comparator,
				  vdata_ht_freer);

	return ret;
}

#define max(a, b) ((a > b) ? (a) : (b))

int lcfs_append_vdata_opts(struct lcfs_ctx_s *ctx, struct lcfs_vdata_s *out,
			   const void *data, size_t len, bool dedup)
{
	struct hasher_vdata_s *key;
	char *new_vdata;
	size_t pad_length;

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
	if (ctx->vdata_len % 4 != 0)
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


static ssize_t compute_payload_size(struct lcfs_node_s *node)
{
	ssize_t payload_size = 0;

	if ((node->inode.st_mode & S_IFMT) == S_IFLNK) {
		if (node->payload && strlen(node->payload) != 0) {
			payload_size = strlen(node->payload);
		}
	} else if ((node->inode.st_mode & S_IFMT) == S_IFREG) {
		/* Ensure we never use a payload for empty files, for canonicalization purposes */
		if (node->inode.st_size != 0 && node->payload &&
		    strlen(node->payload) != 0) {
			payload_size = strlen(node->payload);
		}
	}

	return payload_size;
}

static uint32_t compute_flags(struct lcfs_node_s *node)
{
	uint32_t flags = 0;
	if (node->inode.payload_length != 0)
		flags |= LCFS_INODE_FLAGS_PAYLOAD;
	if (node->inode.st_mode != LCFS_INODE_DEFAULT_MODE)
		flags |= LCFS_INODE_FLAGS_MODE;
	if ((node->inode.st_mode & S_IFMT) == S_IFDIR &&
	    node->inode.st_nlink != LCFS_INODE_DEFAULT_NLINK_DIR)
		flags |= LCFS_INODE_FLAGS_NLINK;
	if ((node->inode.st_mode & S_IFMT) != S_IFDIR &&
	    node->inode.st_nlink != LCFS_INODE_DEFAULT_NLINK)
		flags |= LCFS_INODE_FLAGS_NLINK;
	if (node->inode.st_uid != LCFS_INODE_DEFAULT_UIDGID ||
	    node->inode.st_uid != LCFS_INODE_DEFAULT_UIDGID)
		flags |= LCFS_INODE_FLAGS_UIDGID;
	if (node->inode.st_rdev != LCFS_INODE_DEFAULT_RDEV)
		flags |= LCFS_INODE_FLAGS_RDEV;
	if (node->inode.st_mtim.tv_sec != LCFS_INODE_DEFAULT_TIMES ||
	    node->inode.st_ctim.tv_sec != LCFS_INODE_DEFAULT_TIMES)
		flags |= LCFS_INODE_FLAGS_TIMES;
	if (node->inode.st_mtim.tv_nsec != 0 || node->inode.st_ctim.tv_nsec != 0)
		flags |= LCFS_INODE_FLAGS_TIMES_NSEC;
	if ((node->inode.st_size & UINT32_MAX) != 0)
		flags |= LCFS_INODE_FLAGS_LOW_SIZE;
	if ((node->inode.st_size >> 32) != 0)
		flags |= LCFS_INODE_FLAGS_HIGH_SIZE;
	if (node->n_xattrs > 0)
		flags |= LCFS_INODE_FLAGS_XATTRS;
	if (node->digest_set) {
		uint8_t payload_digest[LCFS_DIGEST_SIZE];
		if (lcfs_digest_from_payload(node->payload, node->inode.payload_length,
					     payload_digest) == 0 &&
		    memcmp(payload_digest, node->inode.digest, LCFS_DIGEST_SIZE) == 0)
			flags |= LCFS_INODE_FLAGS_DIGEST_FROM_PAYLOAD;
		else
			flags |= LCFS_INODE_FLAGS_DIGEST;
	}

	return flags;
}

/* This ensures that the tree is in a well defined order, with
   children sorted by name, and the nodes visited in breadth-first
   order.  It also updates the payload length of the nodes and using
   that, their inode offset. */
static int compute_tree(struct lcfs_ctx_s *ctx, struct lcfs_node_s *root)
{
	size_t i;
	ssize_t payload_length;
	struct lcfs_node_s *node;
	uint32_t inode_size;
	uint32_t flags;

	/* Start with the root node. */

	ctx->queue_end = root;
	root->in_tree = true;

	node = root;

	for (node = root; node != NULL; node = node->next) {
		if ((node->inode.st_mode & S_IFMT) != S_IFDIR &&
		    node->children_size != 0) {
			/* Only dirs can have children */
			errno = EINVAL;
			return -1;
		}

		/* Fix up directory n_links counts, they are 2 + nr of subdirs */
		if ((node->inode.st_mode & S_IFMT) == S_IFDIR) {
			size_t n_link = 2;
			for (i = 0; i < node->children_size; i++) {
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

		/* Compute payload length */
		payload_length = compute_payload_size(node);
		if (payload_length < 0)
			return payload_length;
		if (payload_length > UINT32_MAX) {
			errno = EINVAL;
			return -1;
		}
		node->inode.payload_length = payload_length;

		flags = compute_flags(node);

		node->inode.flags = flags;

		inode_size = lcfs_inode_encoded_size(flags);

		/* Assign inode index */
		ctx->inode_table_size += payload_length;
		node->inode_index = ctx->inode_table_size;
		ctx->inode_table_size += inode_size;

#ifdef LCFS_SIZE_STATS
		ctx->inode_data_size += inode_size;
		if ((node->inode.st_mode & S_IFMT) == S_IFLNK ||
		    (node->inode.st_mode & S_IFMT) == S_IFREG) {
			ctx->payload_data_size += payload_length;
		} else if ((node->inode.st_mode & S_IFMT) == S_IFDIR) {
			ctx->dir_data_size += payload_length;
		}
#endif

		node->in_tree = true;
		/* Append to queue for more work */
		for (i = 0; i < node->children_size; i++) {
			struct lcfs_node_s *child = node->children[i];

			/* Skip hardlinks, they will not be serialized separately */
			if (node->link_to != NULL) {
				continue;
			}

			/* Avoid recursion */
			assert(!child->in_tree);

			ctx->queue_end->next = child;
			ctx->queue_end = child;
		}
	}

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

static int compute_dirents(struct lcfs_ctx_s *ctx)
{
	struct lcfs_node_s *node;

	for (node = ctx->root; node != NULL; node = node->next) {
		char *names;
		char *buffer;
		ssize_t dirents_size;
		struct lcfs_vdata_s vdata;
		struct lcfs_dir_header_s *header;
		size_t name_offset = 0;
		int r;

		if ((node->inode.st_mode & S_IFMT) != S_IFDIR)
			continue;

		dirents_size = compute_dirents_size(node);
		if (dirents_size == 0)
			continue;

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
			struct lcfs_dirent_s *dirent =	&header->dirents[i];
			size_t name_len = strlen(dirent_child->name);

			dirent->inode_index = lcfs_u64_to_file(target_child->inode_index);
			dirent->d_type = node_get_dtype(target_child);
			dirent->name_len = name_len;
			dirent->name_offset = lcfs_u32_to_file(name_offset);
			dirent->_padding = 0;

			memcpy(names + name_offset, dirent_child->name,
			       dirent->name_len);
			name_offset += dirent->name_len;
		}

		r = lcfs_append_vdata(ctx, &vdata, buffer, dirents_size);
		if (r < 0) {
			return r;
		}
		node->inode.variable_data = vdata;
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

		r = lcfs_append_vdata(ctx, &out, buffer, buffer_len);
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

static int write_uint32(struct lcfs_ctx_s *ctx, uint32_t val)
{
	uint32_t _val = lcfs_u32_to_file(val);
	return lcfs_write(ctx, &_val, sizeof(uint32_t));
}

static int write_uint64(struct lcfs_ctx_s *ctx, uint64_t val)
{
	uint64_t _val = lcfs_u64_to_file(val);
	return lcfs_write(ctx, &_val, sizeof(uint64_t));
}

static int write_inode_data(struct lcfs_ctx_s *ctx, struct lcfs_inode_s *ino)
{
	int ret;
	uint32_t flags = ino->flags;
	off_t file_start = ctx->bytes_written;

	ret = write_uint32(ctx, ino->flags);
	if (ret < 0)
		return ret;

	ret = write_uint64(ctx, ino->variable_data.off);
	if (ret < 0)
		return ret;

	ret = write_uint32(ctx, ino->variable_data.len);
	if (ret < 0)
		return ret;

	if (LCFS_INODE_FLAG_CHECK(flags, PAYLOAD)) {
		ret = write_uint32(ctx, ino->payload_length);
		if (ret < 0)
			return ret;
	}

	if (LCFS_INODE_FLAG_CHECK(flags, MODE)) {
		ret = write_uint32(ctx, ino->st_mode);
		if (ret < 0)
			return ret;
	}

	if (LCFS_INODE_FLAG_CHECK(flags, NLINK)) {
		ret = write_uint32(ctx, ino->st_nlink);
		if (ret < 0)
			return ret;
	}

	if (LCFS_INODE_FLAG_CHECK(flags, UIDGID)) {
		ret = write_uint32(ctx, ino->st_uid);
		if (ret < 0)
			return ret;
		ret = write_uint32(ctx, ino->st_gid);
		if (ret < 0)
			return ret;
	}

	if (LCFS_INODE_FLAG_CHECK(flags, RDEV)) {
		ret = write_uint32(ctx, ino->st_rdev);
		if (ret < 0)
			return ret;
	}

	if (LCFS_INODE_FLAG_CHECK(flags, TIMES)) {
		ret = write_uint64(ctx, ino->st_mtim.tv_sec);
		if (ret < 0)
			return ret;
		ret = write_uint64(ctx, ino->st_ctim.tv_sec);
		if (ret < 0)
			return ret;
	}

	if (LCFS_INODE_FLAG_CHECK(flags, TIMES_NSEC)) {
		ret = write_uint32(ctx, ino->st_mtim.tv_nsec);
		if (ret < 0)
			return ret;
		ret = write_uint32(ctx, ino->st_ctim.tv_nsec);
		if (ret < 0)
			return ret;
	}

	if (LCFS_INODE_FLAG_CHECK(flags, LOW_SIZE)) {
		ret = write_uint32(ctx, ino->st_size & UINT32_MAX);
		if (ret < 0)
			return ret;
	}

	if (LCFS_INODE_FLAG_CHECK(flags, HIGH_SIZE)) {
		ret = write_uint32(ctx, ino->st_size >> 32);
		if (ret < 0)
			return ret;
	}

	if (LCFS_INODE_FLAG_CHECK(flags, XATTRS)) {
		ret = write_uint64(ctx, ino->xattrs.off);
		if (ret < 0)
			return ret;

		ret = write_uint32(ctx, ino->xattrs.len);
		if (ret < 0)
			return ret;
	}

	if (LCFS_INODE_FLAG_CHECK(flags, DIGEST)) {
		ret = lcfs_write(ctx, ino->digest, LCFS_DIGEST_SIZE);
		if (ret < 0)
			return ret;
	}

	assert(lcfs_inode_encoded_size(flags) == ctx->bytes_written - file_start);

	return 0;
}

static int write_payload_data(struct lcfs_ctx_s *ctx, struct lcfs_node_s *node)
{
	struct lcfs_inode_s *ino = &(node->inode);
	off_t file_start = ctx->bytes_written;
	int ret;

	if (ino->payload_length == 0)
		return 0;

	if ((node->inode.st_mode & S_IFMT) == S_IFLNK ||
	    (node->inode.st_mode & S_IFMT) == S_IFREG) {
		assert(ino->payload_length == strlen(node->payload));
		ret = lcfs_write(ctx, node->payload, strlen(node->payload));
		if (ret < 0)
			return ret;
	} /*else if ((node->inode.st_mode & S_IFMT) == S_IFDIR) {
		ret = write_dir_payload_data(ctx, node);
		if (ret < 0)
			return ret;
                        }*/

	assert(node->inode.payload_length == ctx->bytes_written - file_start);

	return 0;
}

static int write_inodes(struct lcfs_ctx_s *ctx)
{
	struct lcfs_node_s *node;
	int ret;

	for (node = ctx->root; node != NULL; node = node->next) {
		ret = write_payload_data(ctx, node);
		if (ret < 0)
			return ret;

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

	ctx = lcfs_new_ctx(root);
	if (ctx == NULL) {
		errno = ENOMEM;
		return -1;
	}

	ctx->file = file;
	ctx->write_cb = write_cb;
	if (digest_out) {
		ctx->fsverity_ctx = lcfs_fsverity_context_new();
		if (ctx->fsverity_ctx == NULL) {
			lcfs_close(ctx);
			errno = ENOMEM;
			return -1;
		}
	}

	ret = compute_tree(ctx, root);
	if (ret < 0) {
		lcfs_close(ctx);
		return ret;
	}

	data_offset = ALIGN_TO(sizeof(struct lcfs_superblock_s) + ctx->inode_table_size, 4);

	superblock.data_offset = lcfs_u64_to_file(data_offset);
	superblock.root_inode = lcfs_u64_to_file(root->inode_index);

	ret = compute_dirents(ctx);
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

#ifdef LCFS_SIZE_STATS
	fprintf(stderr,
		"Size - Inodes: %ld kb, payload: %ld kb, dir: %ld kb, xattrs: %ld kb\n",
		ctx->inode_data_size / 1024, ctx->payload_data_size / 1024,
		ctx->dir_data_size / 1024, ctx->vdata_len / 1024);
#endif

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
	lcfs_node_unref(ctx->root);
	free(ctx);

	return 0;
}

int lcfs_append_vdata(struct lcfs_ctx_s *ctx, struct lcfs_vdata_s *out,
		      const void *data, size_t len)
{
	return lcfs_append_vdata_opts(ctx, out, data, len, true);
}

int lcfs_append_vdata_no_dedup(struct lcfs_ctx_s *ctx, struct lcfs_vdata_s *out,
			       const void *data, size_t len)
{
	return lcfs_append_vdata_opts(ctx, out, data, len, false);
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

	if ((sb.st_mode & S_IFMT) == S_IFREG) {
		ret->inode.st_size = sb.st_size;

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
		ret->inode.st_mtim = sb.st_mtim;
		ret->inode.st_ctim = sb.st_ctim;
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
		return node->inode.digest;
	return NULL;
}

/* This is the sha256 fs-verity digest of the file contents */
void lcfs_node_set_fsverity_digest(struct lcfs_node_s *node,
				   uint8_t digest[LCFS_DIGEST_SIZE])
{
	node->digest_set = true;
	memcpy(node->inode.digest, digest, LCFS_DIGEST_SIZE);
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
	node->inode.st_mtim = *time;
}

void lcfs_node_get_mtime(struct lcfs_node_s *node, struct timespec *time)
{
	*time = node->inode.st_mtim;
}

void lcfs_node_set_ctime(struct lcfs_node_s *node, struct timespec *time)
{
	node->inode.st_ctim = *time;
}

void lcfs_node_get_ctime(struct lcfs_node_s *node, struct timespec *time)
{
	*time = node->inode.st_ctim;
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
			memcpy(&parent->children[i], &parent->children[i + 1],
			       sizeof(struct lcfs_node_s *) *
				       (parent->children_size - (i + 1)));
			parent->children_size -= 1;

			/* Unlink correctly as it may live on outside the tree and be reinserted */
			free(child->name);
			child->name = NULL;
			child->parent = NULL;

			lcfs_node_unref(child);

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

	assert(node->parent == NULL);

	for (i = 0; i < node->children_size; i++) {
		struct lcfs_node_s *child = node->children[i];
		child->parent = NULL;
		lcfs_node_unref(child);
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

bool lcfs_node_dirp(struct lcfs_node_s *node)
{
	return (node->inode.st_mode & S_IFMT) == S_IFDIR;
}

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
			strcat(res, "/");
			strcat(res, b);
		}
	}
	return res;
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
