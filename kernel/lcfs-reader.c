/*
 * composefs
 *
 * Copyright (C) 2021 Giuseppe Scrivano
 *
 * This file is released under the GPL.
 */

#include "lcfs.h"
#include "lcfs-reader.h"

#ifdef FUZZING
# define GFP_KERNEL 0
# include <stdio.h>
# include <errno.h>
# include <stdlib.h>
# include <string.h>
# include <fcntl.h>
# define kfree free
# define vfree free
# define min(a, b) ((a)<(b)?(a):(b))
# define check_add_overflow(a, b, d) __builtin_add_overflow(a, b, d)

enum kernel_read_file_id {
	READING_UNKNOWN,
};

void *kzalloc(size_t len, int ignored)
{
	return malloc(len);
}

int kernel_read_file_from_path(const char *path, loff_t offset, void **buf,
			       size_t buf_size, size_t *file_size,
			       enum kernel_read_file_id id)
{
	return -ENOENT;
}
#else
# include <linux/string.h>
# include <linux/kernel_read_file.h>
# include <linux/vmalloc.h>
# include <linux/slab.h>
# include <linux/bsearch.h>
# include <linux/overflow.h>
#endif

/* just an arbitrary limit.  */
#define MAX_FILE_LENGTH (20 * 1024 * 1024)

struct lcfs_context_s {
	char *descriptor;
	size_t descriptor_len;

	/* offset of vdata in DESCRIPTOR.  */
	size_t vdata_off;
};

struct lcfs_context_s *lcfs_create_ctx_from_memory(char *blob, size_t size)
{
	struct lcfs_context_s *ctx;
	struct lcfs_header_s *h;
	size_t vdata_off;
	int ret;

	if (size < sizeof(struct lcfs_header_s) + sizeof(struct lcfs_inode_s))
		goto fail_einval;

	h = (struct lcfs_header_s *)blob;

	if (h->version != LCFS_VERSION)
		goto fail_einval;

	/* vdata starts immediately after the header */
	vdata_off = sizeof(struct lcfs_header_s);

	ctx = kzalloc(sizeof(struct lcfs_context_s), GFP_KERNEL);
	ret = -ENOMEM;
	if (ctx == NULL)
		goto fail;

	ctx->descriptor = blob;
	ctx->descriptor_len = size;
	ctx->vdata_off = vdata_off;

	return ctx;
fail_einval:
	ret = -EINVAL;
fail:
	return ERR_PTR(ret);
}

struct lcfs_context_s *lcfs_create_ctx(char *descriptor_path)
{
	struct lcfs_context_s *ctx;
	void *blob = NULL;
	size_t file_size;
	int ret;

	if (descriptor_path == NULL)
		return ERR_PTR(-EINVAL);

	/* FIXME: mmap the file and do not use any limit.  */
	ret = kernel_read_file_from_path(descriptor_path, 0, &blob,
					 MAX_FILE_LENGTH, &file_size,
					 READING_UNKNOWN);
	if (ret < 0)
		return ERR_PTR(ret);

	ctx = lcfs_create_ctx_from_memory(blob, file_size);
	if (IS_ERR (ctx)) {
		vfree(blob);
		return ctx;
	}
	return ctx;
}

void lcfs_destroy_ctx(struct lcfs_context_s *ctx)
{
	if (!ctx)
		return;
	vfree(ctx->descriptor);
	kfree(ctx);
}

struct lcfs_dentry_s *lcfs_get_dentry(struct lcfs_context_s *ctx, size_t index)
{
	struct lcfs_vdata_s vdata = {
		.off = index,
		.len = sizeof(struct lcfs_dentry_s),
	};
	return lcfs_get_vdata(ctx, vdata);
}

void *lcfs_get_vdata(struct lcfs_context_s *ctx,
		     const struct lcfs_vdata_s vdata)
{
	size_t off = vdata.off;
	size_t len = vdata.len;
	size_t index_end;
	size_t index;

	/* Verify that both ends are contained inside the blob data.  */
	if (check_add_overflow(ctx->vdata_off, off, &index))
		return ERR_PTR(-EFSCORRUPTED);

	if (index >= ctx->descriptor_len)
		return ERR_PTR(-EFSCORRUPTED);

	if (check_add_overflow(index, len, &index_end))
		return ERR_PTR(-EFSCORRUPTED);

	if (index_end > ctx->descriptor_len)
		return ERR_PTR(-EFSCORRUPTED);

	return ctx->descriptor + index;
}

char *lcfs_c_string(struct lcfs_context_s *ctx, lcfs_c_str_t off, size_t *len,
		    size_t max)
{
	char *cstr, *nul;
	size_t index;

	/* Find the beginning of the string.  */
	if (check_add_overflow(ctx->vdata_off, (size_t) off, &index))
		return ERR_PTR(-EFSCORRUPTED);

	if (index >= ctx->descriptor_len)
		return ERR_PTR(-EFSCORRUPTED);

	cstr = ctx->descriptor + index;

	/* Adjust max if it falls after the end of the buffer.  */
	max = min(ctx->descriptor_len - index, max);

	nul = memchr(cstr, '\0', max);
	if (nul == NULL)
		return ERR_PTR(-EFSCORRUPTED);

	if (len)
		*len = nul - cstr;
	return cstr;
}

lcfs_off_t lcfs_get_dentry_index(struct lcfs_context_s *ctx,
				 struct lcfs_dentry_s *de)
{
	const char *payload;

	payload = ctx->descriptor + sizeof(struct lcfs_header_s);
	return (lcfs_off_t)((const char *)de - payload);
}

struct lcfs_inode_s *lcfs_get_ino_index(struct lcfs_context_s *ctx,
					lcfs_off_t index)
{
	const struct lcfs_vdata_s vdata = {
		.off = index,
		.len = sizeof(struct lcfs_inode_s),
	};
	return lcfs_get_vdata(ctx, vdata);
}

lcfs_off_t lcfs_get_root_index(struct lcfs_context_s *ctx)
{
	lcfs_off_t payload_len;

	payload_len = ctx->descriptor_len - sizeof(struct lcfs_header_s);
	return payload_len - sizeof(struct lcfs_inode_s);
}

struct lcfs_inode_s *lcfs_dentry_inode(struct lcfs_context_s *ctx,
				       struct lcfs_dentry_s *node)
{
	return lcfs_get_ino_index(ctx, node->inode_index);
}

struct lcfs_inode_data_s *lcfs_inode_data(struct lcfs_context_s *ctx,
					  struct lcfs_inode_s *ino)
{
	const struct lcfs_vdata_s vdata = {
		.off = ino->inode_data_index,
		.len = sizeof(struct lcfs_inode_data_s),
	};
	return lcfs_get_vdata(ctx, vdata);
}

u64 lcfs_ino_num(struct lcfs_context_s *ctx, struct lcfs_inode_s *ino)
{
	char *v = ctx->descriptor + ctx->vdata_off;
	return ((char *)ino) - v;
}

static const struct lcfs_xattr_header_s *
get_xattrs(struct lcfs_context_s *ctx, struct lcfs_inode_s *cfs_ino, size_t *n_xattrs)
{
	const struct lcfs_xattr_header_s *xattrs;

	if (cfs_ino->xattrs.len < sizeof(struct lcfs_xattr_header_s))
		return NULL;

	xattrs = lcfs_get_vdata(ctx, cfs_ino->xattrs);
	if (IS_ERR(xattrs))
		return ERR_CAST(xattrs);

	*n_xattrs = cfs_ino->xattrs.len / sizeof(struct lcfs_xattr_header_s);

	return xattrs;
}

ssize_t lcfs_list_xattrs(struct lcfs_context_s *ctx, struct lcfs_inode_s *ino, char *names, size_t size)
{
	const struct lcfs_xattr_header_s *xattrs;
	size_t n_xattrs = 0, i;
	ssize_t copied = 0;

	xattrs = get_xattrs(ctx, ino, &n_xattrs);
	if (IS_ERR(xattrs))
		return PTR_ERR(xattrs);

	if (xattrs == NULL)
		return 0;

	for (i = 0; i < n_xattrs; i++) {
		const void *xattr;

		xattr = lcfs_get_vdata(ctx, xattrs[i].key);
		if (IS_ERR(xattr))
			return PTR_ERR(xattr);

		if (size) {
			if (size - copied < xattrs[i].key.len + 1)
				return -E2BIG;

			memcpy(names + copied, xattr, xattrs[i].key.len);
			names[copied + xattrs[i].key.len] = '\0';
		}
		copied += xattrs[i].key.len + 1;
	}
	return copied;
}

int lcfs_get_xattr(struct lcfs_context_s *ctx, struct lcfs_inode_s *ino, const char *name, void *value, size_t size)
{
	const struct lcfs_xattr_header_s *xattrs;
	size_t name_len = strlen(name);
	size_t n_xattrs = 0, i;

	xattrs = get_xattrs(ctx, ino, &n_xattrs);
	if (IS_ERR(xattrs))
		return PTR_ERR(xattrs);

	if (xattrs == NULL)
		return -ENODATA;

	for (i = 0; i < n_xattrs; i++) {
		const void *v;

		if (xattrs[i].key.len != name_len)
			continue;

		v = lcfs_get_vdata(ctx, xattrs[i].key);
		if (IS_ERR(v))
			return PTR_ERR(v);

		if (memcmp(v, name, name_len) == 0) {
			if (size == 0)
				return xattrs[i].value.len;

			if (size < xattrs[i].value.len)
				return -E2BIG;

			v = lcfs_get_vdata(ctx, xattrs[i].value);
			if (IS_ERR(v))
				return PTR_ERR(v);

			memcpy(value, v, xattrs[i].value.len);
			return xattrs[i].value.len;
		}
	}

	return -ENODATA;
}

int lcfs_iterate_dir(struct lcfs_context_s *ctx, loff_t first, struct lcfs_inode_s *dir_ino, lcfs_dir_iter_cb cb, void *private)
{
	size_t i, entries;

	entries = dir_ino->u.dir.len / sizeof(struct lcfs_dentry_s);

	for (i = first; i < entries; i++) {
		struct lcfs_inode_data_s *ino_data;
		struct lcfs_dentry_s *dentry;
		struct lcfs_inode_s *ino;
		size_t name_len = 0;
		const char *name;
		size_t nd;

		nd = i * sizeof(struct lcfs_dentry_s);

		dentry = lcfs_get_dentry(ctx, dir_ino->u.dir.off + nd);
		if (IS_ERR(dentry))
			return PTR_ERR(dentry);

		name = lcfs_c_string(ctx, dentry->name, &name_len, NAME_MAX);
		if (IS_ERR(name))
			return PTR_ERR(name);

		ino = lcfs_dentry_inode(ctx, dentry);
		if (IS_ERR(ino))
			return PTR_ERR(ino);

		ino_data = lcfs_inode_data(ctx, ino);
		if (IS_ERR(ino_data))
			return PTR_ERR(ino_data);

		if (!cb(private, name, name_len, lcfs_dentry_ino(dentry),
			      ino_data->st_mode & S_IFMT))
			break;
	}
	return 0;
}

struct bsearch_key_s {
	const char *name;
	struct lcfs_context_s *ctx;
	int err;
};

/* The first argument is the KEY, so take advantage to pass additional data.  */
static int compare_names(const void *a, const void *b)
{
	struct bsearch_key_s *key = (struct bsearch_key_s *)a;
	const struct lcfs_dentry_s *dentry = b;
	const char *name;

	name = lcfs_c_string(key->ctx, dentry->name, NULL, NAME_MAX);
	if (IS_ERR(name)) {
		key->err = PTR_ERR(name);
		return 0;
	}
	return strcmp(key->name, name);
}

int lcfs_lookup(struct lcfs_context_s *ctx, struct lcfs_inode_s *dir, const char *name, lcfs_off_t *index)
{
	struct lcfs_dentry_s *dir_content, *end;
	struct lcfs_dentry_s *found;
	struct bsearch_key_s key = {
		.name = name,
		.ctx = ctx,
		.err = 0,
	};

	dir_content = lcfs_get_dentry(ctx, dir->u.dir.off);
	if (IS_ERR(dir_content))
		return 0;

	/* Check that the last index is valid as well.  */
	end = lcfs_get_dentry(ctx, dir->u.dir.off + dir->u.dir.len);
	if (end == NULL)
		return 0;

	found = bsearch(&key, dir_content,
			dir->u.dir.len / sizeof(struct lcfs_dentry_s),
			sizeof(struct lcfs_dentry_s), compare_names);
	if (found == NULL || key.err)
		return 0;

	*index = lcfs_get_dentry_index(ctx, found);
	return 1;
}

const char *lcfs_get_payload(struct lcfs_context_s *ctx, struct lcfs_inode_s *ino)
{
	const char *real_path;

	if (ino->u.file.payload == 0)
		return ERR_PTR(-EINVAL);

	real_path = lcfs_c_string(ctx, ino->u.file.payload, NULL, PATH_MAX);
	if (real_path == NULL)
		return ERR_PTR(-EIO);


	return real_path;
}
