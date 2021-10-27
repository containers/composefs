/*
 * composefs
 *
 * Copyright (C) 2021 Giuseppe Scrivano
 *
 * This file is released under the GPL.
 */

#include "lcfs.h"
#include "lcfs-reader.h"

#include <linux/string.h>
#include <linux/kernel_read_file.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>

/* just an arbitrary limit.  */
#define MAX_FILE_LENGTH (20 * 1024 * 1024)

struct lcfs_context_s {
	char *descriptor;
	size_t descriptor_len;

	/* offset of vdata in DESCRIPTOR.  */
	size_t vdata_off;
};

struct lcfs_context_s *lcfs_create_ctx(char *descriptor_path)
{
	struct lcfs_context_s *ctx;
	struct lcfs_header_s *h;
	void *blob = NULL;
	size_t vdata_off;
	size_t file_size;
	int ret;

	if (descriptor_path == NULL)
		return ERR_PTR(-EINVAL);

	/* FIXME: mmap the file and do not use any limit.  */
	ret = kernel_read_file_from_path(descriptor_path, 0, &blob,
					 MAX_FILE_LENGTH, &file_size,
					 READING_UNKNOWN);
	if (ret < 0)
		goto fail;

	if (ret < sizeof(struct lcfs_header_s) + sizeof(struct lcfs_inode_s))
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
	ctx->descriptor_len = file_size;
	ctx->vdata_off = vdata_off;

	return ctx;
fail_einval:
	ret = -EINVAL;
fail:
	if (blob)
		vfree(blob);
	return ERR_PTR(ret);
}

void lcfs_destroy_ctx(struct lcfs_context_s *ctx)
{
	if (!ctx)
		return;
	vfree(ctx->descriptor);
	kfree(ctx);
}

void *lcfs_get_vdata(struct lcfs_context_s *ctx,
		     const struct lcfs_vdata_s *vdata)
{
	size_t off = vdata->off;
	size_t len = vdata->len;

	if (off >= ctx->descriptor_len || len > ctx->descriptor_len)
		return ERR_PTR(-ENOMEDIUM);

	if (ctx->vdata_off + off + len > ctx->descriptor_len)
		return ERR_PTR(-ENOMEDIUM);

	return (char *)(ctx->descriptor + ctx->vdata_off + off);
}

struct lcfs_dentry_s *lcfs_get_dentry(struct lcfs_context_s *ctx, size_t index)
{
	struct lcfs_vdata_s vdata = {
		.off = index,
		.len = sizeof(struct lcfs_dentry_s),
	};
	return lcfs_get_vdata(ctx, &vdata);
}

char *lcfs_c_string(struct lcfs_context_s *ctx, lcfs_c_str_t off, size_t *len,
		    size_t max)
{
	char *data, *endl;

	if (ctx->vdata_off >= ctx->descriptor_len)
		return ERR_PTR(-ENOMEDIUM);

	if (off >= ctx->descriptor_len)
		return ERR_PTR(-ENOMEDIUM);

	data = (char *)(ctx->descriptor + ctx->vdata_off + off);

	/* Adjust max if it falls after the end of the buffer.  */
	if (ctx->descriptor + ctx->descriptor_len < data + max)
		max = ctx->descriptor + ctx->descriptor_len - data;

	endl = memchr(data, '\0', max);
	if (endl == NULL)
		return ERR_PTR(-ENOMEDIUM);

	if (len)
		*len = endl - data;
	return data;
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
	return lcfs_get_vdata(ctx, &vdata);
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
	return lcfs_get_vdata(ctx, &vdata);
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

	xattrs = lcfs_get_vdata(ctx, &(cfs_ino->xattrs));
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

		xattr = lcfs_get_vdata(ctx, &(xattrs[i].key));
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

		v = lcfs_get_vdata(ctx, &(xattrs[i].key));
		if (IS_ERR(v))
			return PTR_ERR(v);

		if (memcmp(v, name, name_len) == 0) {
			if (size == 0)
				return xattrs[i].value.len;

			if (size < xattrs[i].value.len)
				return -E2BIG;

			v = lcfs_get_vdata(ctx, &(xattrs[i].value));
			if (IS_ERR(v))
				return PTR_ERR(v);

			memcpy(value, v, xattrs[i].value.len);
			return xattrs[i].value.len;
		}
	}

	return -ENODATA;
}
