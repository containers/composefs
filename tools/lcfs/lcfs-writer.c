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

#include "lcfs.h"
#include "lcfs-writer.h"
#include "hash.h"

#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/xattr.h>

struct lcfs_ctx_s {
	char *vdata;
	size_t vdata_len;
	size_t vdata_allocated;
	size_t curr_off;
	struct lcfs_node_s *root;

	/* User for dedup.  */
	Hash_table *ht;

	/* Used by serialize_children.  */
	struct lcfs_node_s *cur;
};

struct hasher_vdata_s {
	const char *const *vdata;
	lcfs_off_t off;
	lcfs_off_t len;
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

struct lcfs_ctx_s *lcfs_new_ctx()
{
	struct lcfs_ctx_s *ret;
	struct lcfs_vdata_s tmp;

	ret = calloc(1, sizeof *ret);
	if (ret == NULL)
		return ret;

	ret->ht = hash_initialize(0, NULL, vdata_ht_hasher, vdata_ht_comparator,
				  vdata_ht_freer);

	if (lcfs_append_vdata(ret, &tmp, "\0", 1) < 0) {
		free(ret);
		return NULL;
	}

	return ret;
}

#define max(a, b) ((a > b) ? (a) : (b))

int lcfs_append_vdata_opts(struct lcfs_ctx_s *ctx, struct lcfs_vdata_s *out,
			   const void *data, size_t len, bool dedup)
{
	struct hasher_vdata_s *key;
	char *new_vdata;

	if (dedup) {
		struct hasher_vdata_s *ent;
		struct hasher_vdata_s key = {
			.vdata = (const char *const *)&data,
			.off = 0,
			.len = len,
		};

		ent = hash_lookup(ctx->ht, &key);
		if (ent) {
			out->off = ent->off;
			out->len = ent->len;
			return 0;
		}
	}

	if (ctx->vdata_len + len > ctx->vdata_allocated) {
		size_t new_size, increment;

		increment = max(1 << 20, len);

		new_size = ctx->vdata_allocated + increment;
		new_vdata = realloc(ctx->vdata, new_size);
		if (new_vdata == NULL)
			return -1;

		ctx->vdata_allocated = new_size;
		ctx->vdata = new_vdata;
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

static int dump_inode(struct lcfs_ctx_s *ctx, struct lcfs_node_s *node)
{
	int r;
	struct lcfs_vdata_s out;

	if (node->inode_written)
		return 0;

	if (node->link_to) {
		r = dump_inode(ctx, node->link_to);
		node->data.inode_index = node->link_to->data.inode_index;
		return r;
	} else {
		struct lcfs_inode_s *ino = &(node->inode);

		r = lcfs_append_vdata(ctx, &out, &(node->inode_data),
				      sizeof(node->inode_data));
		if (r < 0)
			return r;

		ino->inode_data_index = out.off;

		r = lcfs_append_vdata_opts(ctx, &out, ino, sizeof(*ino),
					   node == ctx->root);
		if (r < 0)
			return r;

		node->data.inode_index = out.off;

		node->inode_written = true;
	}

	return 0;
}

static int dump_dentries(struct lcfs_ctx_s *ctx, struct lcfs_node_s *node)
{
	struct lcfs_vdata_s out;
	size_t i;
	size_t o;
	int r;

	if (node->children_size == 0)
		return dump_inode(ctx, node);

	for (i = 0; i < node->children_size; i++) {
		r = dump_dentries(ctx, node->children[i]);
		if (r < 0)
			return r;
	}

	for (i = 0; i < node->children_size; i++) {
		r = lcfs_append_vdata_no_dedup(ctx, &out,
					       &(node->children[i]->data),
					       sizeof(struct lcfs_dentry_s));
		if (r < 0)
			return r;

		if (i == 0)
			o = out.off;
	}

	node->inode.u.dir.off = o;
	node->inode.u.dir.len =
		node->children_size * sizeof(struct lcfs_dentry_s);

	return dump_inode(ctx, node);
}

static void append_to_next(struct lcfs_ctx_s *ctx, struct lcfs_node_s *node)
{
	ctx->cur->next = node;
	node->index = ctx->cur->index + 1;
	ctx->cur = node;

	if (node->parent) {
		if (node->parent->inode.u.dir.off == 0)
			node->parent->inode.u.dir.off = node->index;

		node->parent->inode.u.dir.len++;
	}
}

int cmp_nodes(const void *a, const void *b, void *r)
{
	struct lcfs_ctx_s *ctx = r;
	const struct lcfs_node_s *na = *((const struct lcfs_node_s **)a);
	const struct lcfs_node_s *nb = *((const struct lcfs_node_s **)b);
	const char *name_a = ctx->vdata + na->data.name.off;
	const char *name_b = ctx->vdata + nb->data.name.off;

	return strcmp(name_a, name_b);
}

static int serialize_children(struct lcfs_ctx_s *ctx, struct lcfs_node_s *node)
{
	size_t ret = 0;
	size_t i;

	if (node->children_size == 0)
		return 0;

	qsort_r(node->children, node->children_size, sizeof(node->children[0]),
		cmp_nodes, ctx);

	for (i = 0; i < node->children_size; i++)
		append_to_next(ctx, node->children[i]);

	ret = node->children_size;

	for (i = 0; i < node->children_size; i++) {
		int r;

		r = serialize_children(ctx, node->children[i]);
		if (r < 0)
			return r;
		ret += r;
	}

	return ret;
}

int lcfs_write_to(struct lcfs_ctx_s *ctx, FILE *out)
{
	struct lcfs_header_s header = {
		.version = LCFS_VERSION,
		.unused1 = 0,
		.unused2 = 0,
		.inode_len = sizeof(struct lcfs_inode_s),
		.inode_data_len = sizeof(struct lcfs_inode_data_s),
	};
	int ret = 0;

	if (ctx == NULL)
		return 0;

	/* Start with the root node. */
	ctx->cur = ctx->root;
	ctx->cur->index = 0;

	ret = serialize_children(ctx, ctx->root);
	if (ret < 0)
		return ret;

	ret = fwrite(&header, sizeof(header), 1, out);
	if (ret < 0)
		return ret;

	ret = dump_dentries(ctx, ctx->root);
	if (ret < 0)
		return ret;

	if (ctx->vdata) {
		ret = fwrite(ctx->vdata, ctx->vdata_len, 1, out);
		if (ret < 0)
			return ret;
	}

	return 0;
}

int lcfs_close(struct lcfs_ctx_s *ctx)
{
	if (ctx == NULL)
		return 0;

	hash_free(ctx->ht);
	free(ctx->vdata);
	lcfs_free_node(ctx->root);
	free(ctx);

	return 0;
}

void lcfs_set_root(struct lcfs_ctx_s *ctx, struct lcfs_node_s *root)
{
	ctx->root = root;
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

static int read_xattrs(struct lcfs_ctx_s *ctx, struct lcfs_node_s *ret,
		       int dirfd, const char *fname, int flags)
{
	size_t buffer_len = 0;
	char *buffer = NULL;
	char path[PATH_MAX];
	ssize_t list_size;
	char *list, *it;
	ssize_t r;

	if (flags & AT_EMPTY_PATH)
		sprintf(path, "/proc/self/fd/%d", dirfd);
	else
		sprintf(path, "/proc/self/fd/%d/%s", dirfd, fname);

	list_size = llistxattr(path, NULL, 0);
	if (list_size < 0)
		return list_size;

	list = malloc(list_size);
	if (list == NULL)
		return -1;

	r = llistxattr(path, list, list_size);
	if (r < 0)
		return r;

	for (it = list; *it;) {
		ssize_t value_size;
		size_t len = strlen(it);
		char *value;

		value_size = lgetxattr(path, it, NULL, 0);
		if (value_size < 0) {
			free(list);
			free(buffer);
			return value_size;
		}

		value = malloc(value_size);
		if (value == NULL) {
			free(list);
			free(buffer);
			return -1;
		}

		r = lgetxattr(path, it, value, value_size);
		if (r < 0) {
			free(list);
			free(value);
			free(buffer);
			return r;
		}

		r = lcfs_append_xattr_to_buffer(ctx, &buffer, &buffer_len, it,
						len, value, value_size);
		if (r < 0) {
			free(list);
			free(value);
			free(buffer);
			return r;
		}

		free(value);
		it += len;
	}

	free(list);

	r = lcfs_set_xattrs(ctx, ret, buffer, buffer_len);

	free(buffer);

	return r;
}

struct lcfs_node_s *lcfs_load_node_from_file(struct lcfs_ctx_s *ctx, int dirfd,
					     const char *fname,
					     const char *name, int flags,
					     int buildflags)
{
	struct lcfs_vdata_s tmp_vdata;
	struct lcfs_node_s *ret;
	struct stat sb;
	int r;

	if (buildflags & ~(BUILD_SKIP_XATTRS | BUILD_USE_EPOCH | BUILD_SKIP_DEVICES)) {
		errno = EINVAL;
		return NULL;
	}

	if (flags & ~AT_EMPTY_PATH) {
		errno = EINVAL;
		return NULL;
	}

	r = fstatat(dirfd, fname, &sb, AT_SYMLINK_NOFOLLOW | flags);
	if (r < 0)
		return NULL;

	ret = calloc(1, sizeof(*ret));
	if (ret == NULL)
		return NULL;

	ret->inode_data.st_nlink = sb.st_nlink;
	ret->inode_data.st_mode = sb.st_mode;
	ret->inode_data.st_uid = sb.st_uid;
	ret->inode_data.st_gid = sb.st_gid;
	ret->inode_data.st_rdev = sb.st_rdev;

	if ((sb.st_mode & S_IFMT) != S_IFDIR)
		ret->inode.u.file.st_size = sb.st_size;

	if ((buildflags & BUILD_USE_EPOCH) == 0) {
		ret->inode.st_mtim = sb.st_mtim;
		ret->inode.st_ctim = sb.st_ctim;
	}

	if ((buildflags & BUILD_SKIP_XATTRS) == 0) {
		r = read_xattrs(ctx, ret, dirfd, fname, flags);
		if (r < 0) {
			free(ret);
			return NULL;
		}
	}

	if (name[0]) {
		r = lcfs_append_vdata(ctx, &tmp_vdata, name, strlen(name) + 1);
		if (r < 0) {
			free(ret);
			return NULL;
		}
		ret->data.name = tmp_vdata;
	}

	return ret;
}

int lcfs_set_payload(struct lcfs_ctx_s *ctx, struct lcfs_node_s *node,
		     const char *payload, size_t len)
{
	struct lcfs_vdata_s tmp_vdata;
	int r;

	r = lcfs_append_vdata(ctx, &tmp_vdata, payload, len);
	if (r < 0)
		return r;

	node->inode.u.file.payload = tmp_vdata;
	return 0;
}

int lcfs_set_xattrs(struct lcfs_ctx_s *ctx, struct lcfs_node_s *node,
		    const char *xattrs, size_t len)
{
	struct lcfs_vdata_s tmp_vdata;
	int r;

	r = lcfs_append_vdata(ctx, &tmp_vdata, xattrs, len);
	if (r < 0)
		return r;

	node->inode.xattrs = tmp_vdata;
	return 0;
}

int lcfs_add_child(struct lcfs_ctx_s *ctx, struct lcfs_node_s *parent,
		   struct lcfs_node_s *child)
{
	struct lcfs_node_s **new_children;
	size_t new_size;
	if ((parent->inode_data.st_mode & S_IFMT) != S_IFDIR) {
		errno = ENOTDIR;
		return -1;
	}

	new_size = parent->children_size + 1;

	new_children = reallocarray(parent->children, sizeof(*parent->children),
				    new_size);
	if (new_children == NULL)
		return -1;

	parent->children = new_children;

	parent->children[parent->children_size] = child;
	parent->children_size = new_size;
	child->parent = parent;

	return 0;
}

int lcfs_free_node(struct lcfs_node_s *node)
{
	size_t i;

	for (i = 0; i < node->children_size; i++)
		lcfs_free_node(node->children[i]);
	free(node->children);
	free(node);

	return 0;
}

bool lcfs_node_dirp(struct lcfs_node_s *node)
{
	return (node->inode_data.st_mode & S_IFMT) == S_IFDIR;
}

struct lcfs_node_s *lcfs_build(struct lcfs_ctx_s *ctx,
			       struct lcfs_node_s *parent, int fd,
			       const char *fname, const char *name,
			       int flags,
			       int buildflags)
{
	struct lcfs_node_s *node;
	struct dirent *de;
	DIR *dir;
	int dfd;

	node = lcfs_load_node_from_file(ctx, fd, fname, name, flags,
					buildflags);
	if (node == NULL) {
		close(fd);
		return NULL;
	}

	if (!lcfs_node_dirp(node)) {
		close(fd);
		return node;
	}

	dir = fdopendir(fd);
	if (dir == NULL) {
		close(fd);
		lcfs_free_node(node);
		return NULL;
	}

	dfd = dirfd(dir);
	for (;;) {
		struct lcfs_node_s *n;
		int r;

		errno = 0;
		de = readdir(dir);
		if (de == NULL) {
			if (errno)
				goto fail;

			break;
		}

		if (strcmp(de->d_name, ".") == 0 ||
		    strcmp(de->d_name, "..") == 0)
			continue;

		if (de->d_type == DT_DIR) {
			int fd;

			fd = openat(dfd, de->d_name, O_RDONLY | O_NOFOLLOW);
			if (fd < 0)
				goto fail;

			n = lcfs_build(ctx, node, fd, "", de->d_name,
				       AT_EMPTY_PATH, buildflags);
			if (n == NULL)
				goto fail;
		} else {
			int fd;

			if (buildflags & BUILD_SKIP_DEVICES) {
				if (de->d_type == DT_BLK
				    || de->d_type == DT_CHR)
					continue;
			}

			fd = dup(dfd);
			if (fd < 0)
				goto fail;

			n = lcfs_build(ctx, node, fd, de->d_name, de->d_name,
				       0, buildflags);
			if (n == NULL)
				goto fail;
		}

		r = lcfs_add_child(ctx, node, n);
		if (r < 0)
			goto fail;
	}

	closedir(dir);
	return node;

fail:
	lcfs_free_node(node);
	closedir(dir);
	return NULL;
}

int lcfs_get_vdata(struct lcfs_ctx_s *ctx, char **vdata, size_t *len)
{
	*vdata = ctx->vdata;
	*len = ctx->vdata_len;
	return 0;
}

int lcfs_append_xattr_to_buffer(struct lcfs_ctx_s *ctx, char **buffer,
				size_t *len, const char *key, size_t key_len,
				const char *value, size_t value_len)
{
	struct lcfs_xattr_header_s header;
	char *tmp;
	int r;

	r = lcfs_append_vdata(ctx, &(header.key), key, key_len);
	if (r < 0)
		return r;

	r = lcfs_append_vdata(ctx, &(header.value), value, value_len);
	if (r < 0)
		return r;

	tmp = realloc(*buffer, *len + sizeof(struct lcfs_xattr_header_s));
	if (tmp == NULL)
		return -1;

	*buffer = tmp;
	memcpy(*buffer + *len, &header, sizeof(header));
	*len = *len + sizeof(struct lcfs_xattr_header_s);

	return 0;
}
