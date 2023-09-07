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

#include "lcfs-internal.h"
#include "lcfs-writer.h"
#include "lcfs-utils.h"
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
#include <sys/mman.h>

static void lcfs_node_remove_all_children(struct lcfs_node_s *node);
static void lcfs_node_destroy(struct lcfs_node_s *node);

static int lcfs_close(struct lcfs_ctx_s *ctx);

char *maybe_join_path(const char *a, const char *b)
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

size_t hash_memory(const char *string, size_t len, size_t n_buckets)
{
	size_t i, value = 0;

	for (i = 0; i < len; i++) {
		value = (value * 31 + string[i]) % n_buckets;
	}
	return value;
}

static struct lcfs_ctx_s *lcfs_new_ctx(struct lcfs_node_s *root,
				       struct lcfs_write_options_s *options)
{
	struct lcfs_ctx_s *ret;

	switch (options->format) {
	case LCFS_FORMAT_EROFS:
		ret = lcfs_ctx_erofs_new();
		break;

	default:
		ret = NULL;
	}

	if (ret == NULL) {
		return ret;
	}

	ret->options = options;
	ret->root = lcfs_node_ref(root);

	ret->file = options->file;
	ret->write_cb = options->file_write_cb;
	if (options->digest_out) {
		ret->fsverity_ctx = lcfs_fsverity_context_new();
		if (ret->fsverity_ctx == NULL) {
			lcfs_close(ret);
			return NULL;
		}
	}

	return ret;
}

int lcfs_clone_root(struct lcfs_ctx_s *ctx)
{
	struct lcfs_node_s *clone;

	clone = lcfs_node_clone_deep(ctx->root);
	if (clone == NULL) {
		errno = -EINVAL;
		return -1;
	}

	lcfs_node_unref(ctx->root);
	ctx->root = clone;
	ctx->destroy_root = true;

	return 0;
}

int node_get_dtype(struct lcfs_node_s *node)
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
int lcfs_compute_tree(struct lcfs_ctx_s *ctx, struct lcfs_node_s *root)
{
	uint32_t index;
	struct lcfs_node_s *node;

	/* Start with the root node. */

	ctx->queue_end = root;
	root->in_tree = true;

	ctx->min_mtim_sec = root->inode.st_mtim_sec;
	ctx->min_mtim_nsec = root->inode.st_mtim_nsec;
	ctx->has_acl = false;

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
		if (node->children)
			qsort(node->children, node->children_size,
			      sizeof(node->children[0]), cmp_nodes);
		if (node->xattrs)
			qsort(node->xattrs, node->n_xattrs,
			      sizeof(node->xattrs[0]), cmp_xattr);

		if (node->inode.st_mtim_sec < ctx->min_mtim_sec ||
		    (node->inode.st_mtim_sec == ctx->min_mtim_sec &&
		     node->inode.st_mtim_nsec < ctx->min_mtim_nsec)) {
			ctx->min_mtim_sec = node->inode.st_mtim_sec;
			ctx->min_mtim_nsec = node->inode.st_mtim_nsec;
		}

		/* Assign inode index */
		node->inode_num = index;

		/* Compute has_acl */
		if (lcfs_node_get_xattr(node, "system.posix_acl_access", NULL) != NULL ||
		    lcfs_node_get_xattr(node, "system.posix_acl_default", NULL) != NULL)
			ctx->has_acl = true;

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
	for (node = root; node != NULL; node = node->next) {
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

struct lcfs_node_s *follow_links(struct lcfs_node_s *node)
{
	if (node->link_to)
		return follow_links(node->link_to);
	return node;
}

int lcfs_write(struct lcfs_ctx_s *ctx, void *_data, size_t data_len)
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

int lcfs_write_pad(struct lcfs_ctx_s *ctx, size_t data_len)
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

int lcfs_write_align(struct lcfs_ctx_s *ctx, size_t align_size)
{
	off_t end = round_up(ctx->bytes_written, align_size);
	if (end > ctx->bytes_written) {
		return lcfs_write_pad(ctx, end - ctx->bytes_written);
	}
	return 0;
}

static int lcfs_close(struct lcfs_ctx_s *ctx)
{
	if (ctx == NULL)
		return 0;

	if (ctx->finalize)
		ctx->finalize(ctx);

	if (ctx->fsverity_ctx)
		lcfs_fsverity_context_free(ctx->fsverity_ctx);
	if (ctx->root) {
		if (ctx->destroy_root) {
			lcfs_node_destroy(ctx->root);
		} else {
			lcfs_node_unref(ctx->root);
		}
	}
	free(ctx);

	return 0;
}

int lcfs_write_to(struct lcfs_node_s *root, struct lcfs_write_options_s *options)
{
	enum lcfs_format_t format = options->format;
	struct lcfs_ctx_s *ctx;
	int res;

	/* Check for unknown flags */
	if ((options->flags & ~LCFS_FLAGS_MASK) != 0) {
		errno = -EINVAL;
		return -1;
	}

	ctx = lcfs_new_ctx(root, options);
	if (ctx == NULL) {
		errno = ENOMEM;
		return -1;
	}

	if (format == LCFS_FORMAT_EROFS)
		res = lcfs_write_erofs_to(ctx);
	else {
		errno = -EINVAL;
		res = -1;
	}

	if (res < 0) {
		lcfs_close(ctx);
		return res;
	}

	if (options->digest_out) {
		lcfs_fsverity_context_get_digest(ctx->fsverity_ctx,
						 options->digest_out);
	}

	lcfs_close(ctx);
	return 0;
}

static int read_xattrs(struct lcfs_node_s *ret, int dirfd, const char *fname)
{
	char path[PATH_MAX];
	ssize_t list_size;
	cleanup_free char *list = NULL;
	ssize_t r = 0;
	cleanup_fd int fd = -1;

	fd = openat(dirfd, fname, O_PATH | O_NOFOLLOW | O_CLOEXEC, 0);
	if (fd < 0)
		return -1;

	sprintf(path, "/proc/self/fd/%d", fd);

	list_size = listxattr(path, NULL, 0);
	if (list_size < 0) {
		return list_size;
	}

	list = malloc(list_size);
	if (list == NULL) {
		return -1;
	}

	list_size = listxattr(path, list, list_size);
	if (list_size < 0) {
		return list_size;
	}

	for (const char *it = list; it < list + list_size; it += strlen(it) + 1) {
		ssize_t value_size;
		cleanup_free char *value = NULL;

		value_size = getxattr(path, it, NULL, 0);
		if (value_size < 0) {
			return value_size;
		}

		value = malloc(value_size);
		if (value == NULL) {
			return -1;
		}

		r = getxattr(path, it, value, value_size);
		if (r < 0) {
			return r;
		}

		r = lcfs_node_set_xattr(ret, it, value, value_size);
		if (r < 0) {
			return r;
		}
	}
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

static ssize_t fsverity_read_cb(void *_fd, void *buf, size_t count)
{
	int fd = *(int *)_fd;
	ssize_t res;

	do
		res = read(fd, buf, count);
	while (res < 0 && errno == EINTR);

	return res;
}

int lcfs_compute_fsverity_from_content(uint8_t *digest, void *file, lcfs_read_cb read_cb)
{
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

	lcfs_fsverity_context_free(ctx);

	return 0;
}

int lcfs_compute_fsverity_from_fd(uint8_t *digest, int fd)
{
	int _fd = fd;
	return lcfs_compute_fsverity_from_content(digest, &_fd, fsverity_read_cb);
}

int lcfs_compute_fsverity_from_data(uint8_t *digest, uint8_t *data, size_t data_len)
{
	FsVerityContext *ctx;

	ctx = lcfs_fsverity_context_new();
	if (ctx == NULL) {
		errno = ENOMEM;
		return -1;
	}

	lcfs_fsverity_context_update(ctx, data, data_len);

	lcfs_fsverity_context_get_digest(ctx, digest);

	lcfs_fsverity_context_free(ctx);

	return 0;
}

int lcfs_node_set_fsverity_from_content(struct lcfs_node_s *node, void *file,
					lcfs_read_cb read_cb)
{
	uint8_t digest[LCFS_DIGEST_SIZE];

	if (lcfs_compute_fsverity_from_content(digest, file, read_cb) < 0)
		return -1;

	lcfs_node_set_fsverity_digest(node, digest);

	return 0;
}

int lcfs_node_set_fsverity_from_fd(struct lcfs_node_s *node, int fd)
{
	int _fd = fd;
	return lcfs_node_set_fsverity_from_content(node, &_fd, fsverity_read_cb);
}

static int read_content(int fd, size_t size, uint8_t *buf)
{
	int bytes_read;

	while (size > 0) {
		do
			bytes_read = read(fd, buf, size);
		while (bytes_read < 0 && errno == EINTR);

		if (bytes_read == 0)
			break;

		size -= bytes_read;
		buf += bytes_read;
	}

	if (size > 0) {
		errno = ENODATA;
		return -1;
	}

	return 0;
}

struct lcfs_node_s *lcfs_load_node_from_file(int dirfd, const char *fname,
					     int buildflags)
{
	cleanup_node struct lcfs_node_s *ret = NULL;
	struct stat sb;
	int r;

	if (buildflags & ~(LCFS_BUILD_SKIP_XATTRS | LCFS_BUILD_USE_EPOCH |
			   LCFS_BUILD_SKIP_DEVICES | LCFS_BUILD_COMPUTE_DIGEST |
			   LCFS_BUILD_NO_INLINE)) {
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
		bool compute_digest = (buildflags & LCFS_BUILD_COMPUTE_DIGEST) != 0;
		bool no_inline = (buildflags & LCFS_BUILD_NO_INLINE) != 0;
		bool is_zerosized = sb.st_size == 0;
		bool do_digest = !is_zerosized && compute_digest;
		bool do_inline = !is_zerosized && !no_inline &&
				 sb.st_size <= LCFS_BUILD_INLINE_FILE_SIZE_LIMIT;

		if (do_digest || do_inline) {
			cleanup_fd int fd =
				openat(dirfd, fname, O_RDONLY | O_CLOEXEC);
			if (fd < 0)
				return NULL;
			if (do_digest) {
				r = lcfs_node_set_fsverity_from_fd(ret, fd);
				if (r < 0)
					return NULL;
				/* In case we re-read below */
				lseek(fd, 0, SEEK_SET);
			}
			if (do_inline) {
				uint8_t buf[LCFS_BUILD_INLINE_FILE_SIZE_LIMIT];

				r = read_content(fd, sb.st_size, buf);
				if (r < 0)
					return NULL;
				r = lcfs_node_set_content(ret, buf, sb.st_size);
				if (r < 0)
					return NULL;
			}
		}
	}

	if ((buildflags & LCFS_BUILD_USE_EPOCH) == 0) {
		ret->inode.st_mtim_sec = sb.st_mtim.tv_sec;
		ret->inode.st_mtim_nsec = sb.st_mtim.tv_nsec;
	}

	if ((buildflags & LCFS_BUILD_SKIP_XATTRS) == 0) {
		r = read_xattrs(ret, dirfd, fname);
		if (r < 0)
			return NULL;
	}

	return steal_pointer(&ret);
}

struct lcfs_node_s *lcfs_load_node_from_fd(int fd)
{
	struct lcfs_node_s *node;
	uint8_t *image_data;
	size_t image_data_size;
	struct stat s;
	int errsv;
	int r;

	r = fstat(fd, &s);
	if (r < 0) {
		return NULL;
	}

	image_data_size = s.st_size;

	image_data = mmap(0, image_data_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (image_data == MAP_FAILED) {
		return NULL;
	}

	node = lcfs_load_node_from_image(image_data, image_data_size);
	if (node == NULL) {
		errsv = errno;
		munmap(image_data, image_data_size);
		errno = errsv;
		return NULL;
	}

	munmap(image_data, image_data_size);

	return node;
}

int lcfs_node_set_payload(struct lcfs_node_s *node, const char *payload)
{
	char *dup = strdup(payload);
	if (dup == NULL) {
		errno = ENOMEM;
		return -1;
	}
	free(node->payload);
	node->payload = dup;

	return 0;
}

const char *lcfs_node_get_payload(struct lcfs_node_s *node)
{
	return node->payload;
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

int lcfs_node_set_content(struct lcfs_node_s *node, const uint8_t *data,
			  size_t data_size)
{
	uint8_t *dup = NULL;

	if (data && data_size != 0) {
		dup = malloc(data_size);
		if (dup == NULL) {
			errno = ENOMEM;
			return -1;
		}
		memcpy(dup, data, data_size);
	}
	free(node->content);
	node->content = dup;
	node->inode.st_size = data_size;

	return 0;
}

const uint8_t *lcfs_node_get_content(struct lcfs_node_s *node)
{
	return node->content;
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

/* Clears content if size changes */
void lcfs_node_set_size(struct lcfs_node_s *node, uint64_t size)
{
	if (size == node->inode.st_size)
		return;

	free(node->content);
	node->content = NULL;
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

struct lcfs_node_s *lcfs_node_get_hardlink_target(struct lcfs_node_s *node)
{
	return node->link_to;
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

	lcfs_node_remove_all_children(node);
	free(node->children);

	if (node->link_to)
		lcfs_node_unref(node->link_to);

	free(node->name);
	free(node->payload);
	free(node->content);

	for (i = 0; i < node->n_xattrs; i++) {
		free(node->xattrs[i].key);
		free(node->xattrs[i].value);
	}
	free(node->xattrs);

	free(node);
}

static void lcfs_node_remove_all_children(struct lcfs_node_s *node)
{
	for (size_t i = 0; i < node->children_size; i++) {
		struct lcfs_node_s *child = node->children[i];
		assert(child->parent == node);
		/* Unlink correctly as it may live on outside the tree and be reinserted */
		free(child->name);
		child->name = NULL;
		child->parent = NULL;
		lcfs_node_destroy(child);
	}
	node->children_size = 0;
}

/* Unlink all children (recursively) and then unref. Useful to handle refcount loops like dot and dotdot. */
static void lcfs_node_destroy(struct lcfs_node_s *node)
{
	lcfs_node_remove_all_children(node);
	lcfs_node_unref(node);
};

struct lcfs_node_s *lcfs_node_clone(struct lcfs_node_s *node)
{
	cleanup_node struct lcfs_node_s *new = lcfs_node_new();
	if (new == NULL)
		return NULL;

	/* Note: This copies only data, not structure like name or children */

	/* We copy the link_to, but clone_deep may rewrite this */
	if (node->link_to) {
		new->link_to = lcfs_node_ref(node->link_to);
	}

	if (node->payload) {
		new->payload = strdup(node->payload);
		if (new->payload == NULL)
			return NULL;
		;
	}

	if (node->content) {
		new->content = malloc(node->inode.st_size);
		if (new->content == NULL)
			return NULL;
		;
		memcpy(new->content, node->content, node->inode.st_size);
	}

	if (node->n_xattrs > 0) {
		new->xattrs = malloc(sizeof(struct lcfs_xattr_s) * node->n_xattrs);
		if (new->xattrs == NULL)
			return NULL;
		for (size_t i = 0; i < node->n_xattrs; i++) {
			char *key = strdup(node->xattrs[i].key);
			char *value = memdup(node->xattrs[i].value,
					     node->xattrs[i].value_len);
			if (key == NULL || value == NULL) {
				free(key);
				free(value);
				return NULL;
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

	return steal_pointer(&new);
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
	cleanup_node struct lcfs_node_s *new = lcfs_node_clone(node);
	if (new == NULL)
		return NULL;

	if (data->n_mappings >= data->allocated_mappings) {
		struct lcfs_node_mapping_s *new_mapping;
		data->allocated_mappings = (data->allocated_mappings == 0) ?
						   32 :
						   data->allocated_mappings * 2;
		new_mapping = reallocarray(data->mapping,
					   sizeof(struct lcfs_node_mapping_s),
					   data->allocated_mappings);
		if (new_mapping == NULL)
			return NULL;
		data->mapping = new_mapping;
	}

	data->mapping[data->n_mappings].old = node;
	data->mapping[data->n_mappings].new = new;
	data->n_mappings++;

	for (size_t i = 0; i < node->children_size; ++i) {
		struct lcfs_node_s *child = node->children[i];
		struct lcfs_node_s *new_child = _lcfs_node_clone_deep(child, data);
		if (new_child == NULL)
			return NULL;

		if (lcfs_node_add_child(new, new_child, child->name) < 0)
			return NULL;
	}

	return steal_pointer(&new);
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
		_lcfs_node_clone_rewrite_links(new, &data);

	free(data.mapping);

	return new;
}

bool lcfs_node_dirp(struct lcfs_node_s *node)
{
	return (node->inode.st_mode & S_IFMT) == S_IFDIR;
}

struct lcfs_node_s *lcfs_build(int dirfd, const char *fname, int buildflags,
			       char **failed_path_out)
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
			n = lcfs_build(dfd, de->d_name, buildflags,
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
	for (i = 0; i < (ssize_t)node->n_xattrs; i++) {
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
		if (length)
			*length = xattr->value_len;
		return xattr->value;
	}

	return NULL;
}

int lcfs_node_unset_xattr(struct lcfs_node_s *node, const char *name)
{
	ssize_t index = find_xattr(node, name);

	if (index >= 0) {
		if (index != (ssize_t)node->n_xattrs - 1)
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

/* This is an internal function.
 * Be careful to not cause duplicates if new_name already exist */
int lcfs_node_rename_xattr(struct lcfs_node_s *node, size_t index, const char *new_name)
{
	struct lcfs_xattr_s *xattr;
	cleanup_free char *dup = NULL;

	dup = strdup(new_name);
	if (dup == NULL) {
		errno = ENOMEM;
		return -1;
	}

	if (index >= node->n_xattrs) {
		errno = EINVAL;
		return -1;
	}

	xattr = &node->xattrs[index];
	free(xattr->key);
	xattr->key = steal_pointer(&dup);
	return 0;
}
