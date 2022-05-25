/*
 * composefs
 *
 * Copyright (C) 2021 Giuseppe Scrivano
 *
 * This file is released under the GPL.
 */

#include "lcfs.h"
#include "lcfs-reader.h"

#ifndef FUZZING
# include <linux/string.h>
# include <linux/kernel_read_file.h>
# include <linux/vmalloc.h>
# include <linux/slab.h>
# include <linux/bsearch.h>
# include <linux/overflow.h>
#endif

#include "lcfs-fuzzing.h"

struct lcfs_context_s
{
	struct lcfs_header_s header;
	struct file *descriptor;

	size_t descriptor_len;
};

struct lcfs_context_s *lcfs_create_ctx(char *descriptor_path)
{
	struct lcfs_context_s *ctx;
	struct file *descriptor;
	loff_t i_size;

	if (sizeof(void *) != sizeof(lcfs_off_t)) {
		return ERR_PTR(-ENOTSUPP);
	}

	descriptor = filp_open(descriptor_path, O_RDONLY, 0);
	if (IS_ERR(descriptor))
		return ERR_CAST(descriptor);

	i_size = i_size_read(file_inode(descriptor));
	if (i_size <= 0 || i_size > SIZE_MAX) {
		fput(descriptor);
		return ERR_PTR(-EINVAL);
	}

	ctx = kzalloc(sizeof(struct lcfs_context_s), GFP_KERNEL);
	if (ctx == NULL) {
		fput(descriptor);
		return ERR_PTR(-ENOMEM);
	}

	ctx->descriptor = descriptor;
	ctx->descriptor_len = (size_t) i_size;

	return ctx;
}

void lcfs_destroy_ctx(struct lcfs_context_s *ctx)
{
	if (!ctx)
		return;
	fput(ctx->descriptor);
	kfree(ctx);
}

struct lcfs_dentry_s *lcfs_get_dentry(struct lcfs_context_s *ctx, size_t index,
				      struct lcfs_dentry_s *buffer)
{
	struct lcfs_vdata_s vdata = {
		.off = index,
		.len = sizeof(struct lcfs_dentry_s),
	};
	return lcfs_get_vdata(ctx, vdata, buffer);
}

void *lcfs_get_vdata(struct lcfs_context_s *ctx,
		     const struct lcfs_vdata_s vdata,
		     void *dest)
{
	size_t copied;
	loff_t pos = vdata.off + sizeof(struct lcfs_header_s);

	if (!dest)
		return NULL;

	copied = 0;
	while (copied < vdata.len) {
		ssize_t bytes;

		bytes = kernel_read(ctx->descriptor, dest + copied,
				    vdata.len - copied, &pos);
		if (bytes < 0)
			return ERR_PTR(bytes);
		if (bytes == 0)
			return ERR_PTR(-EINVAL);

		copied += bytes;
	}

	if (copied != vdata.len)
		return ERR_PTR(-EFSCORRUPTED);
	return dest;
}

void *lcfs_alloc_vdata(struct lcfs_context_s *ctx,
		       const struct lcfs_vdata_s vdata)
{
	u8 *buf;
	void *res;

	buf = kmalloc(vdata.len, GFP_KERNEL);
	if (!buf)
		return ERR_PTR(-ENOMEM);

	res = lcfs_get_vdata(ctx, vdata, buf);
	if (IS_ERR(res))
		kfree(buf);

	return res;
}

const char *lcfs_c_string(struct lcfs_context_s *ctx, struct lcfs_vdata_s vdata,
			  char *buf, size_t max)
{
	char *cstr;

	if (vdata.len == 0)
		return "";

	if (vdata.len > max)
		return ERR_PTR(-EINVAL);

	cstr = lcfs_get_vdata(ctx, vdata, buf);
	if (IS_ERR(cstr))
		return ERR_CAST(cstr);

	/* Make sure the string is NUL terminated.  */
	if (cstr[vdata.len - 1] != '\0')
		return ERR_PTR(-EFSCORRUPTED);

	return cstr;
}

struct lcfs_inode_s *lcfs_get_ino_index(struct lcfs_context_s *ctx,
					lcfs_off_t index,
					struct lcfs_inode_s *buffer)
{
	const struct lcfs_vdata_s vdata = {
		.off = index,
		.len = sizeof(struct lcfs_inode_s),
	};
	return lcfs_get_vdata(ctx, vdata, buffer);
}

lcfs_off_t lcfs_get_root_index(struct lcfs_context_s *ctx)
{
	lcfs_off_t payload_len;

	payload_len = ctx->descriptor_len - sizeof(struct lcfs_header_s);
	return payload_len - sizeof(struct lcfs_inode_s);
}

struct lcfs_inode_s *lcfs_dentry_inode(struct lcfs_context_s *ctx,
				       struct lcfs_dentry_s *node,
				       struct lcfs_inode_s *buffer)
{
	return lcfs_get_ino_index(ctx, node->inode_index, buffer);
}

ssize_t lcfs_list_xattrs(struct lcfs_context_s *ctx, struct lcfs_inode_s *ino, char *names, size_t size)
{
	const struct lcfs_xattr_header_s *xattrs;
	u8 *data, *data_end;
	size_t n_xattrs = 0, i;
	ssize_t copied = 0;
	ssize_t ret;

	if (ino->xattrs.len == 0)
		return 0;

	/* Gotta be large enought to fit the n_attr */
	if (ino->xattrs.len < sizeof(struct lcfs_xattr_header_s))
		return -EFSCORRUPTED;

	xattrs = lcfs_alloc_vdata(ctx, ino->xattrs);
	if (IS_ERR(xattrs))
		return PTR_ERR(xattrs);

	n_xattrs = xattrs->n_attr;

	/* And the entire array */
	if (ino->xattrs.len < lcfs_xattr_header_size(n_xattrs)) {
		ret = -EFSCORRUPTED;
		goto fail;
	}

	data = ((u8 *)xattrs) + lcfs_xattr_header_size(n_xattrs);
	data_end = ((u8 *)xattrs) + ino->xattrs.len;

	for (i = 0; i < n_xattrs; i++) {
		uint16_t key_len = xattrs->attr[i].key_length;
		uint16_t value_len = xattrs->attr[i].value_length;

		if (key_len > XATTR_NAME_MAX) {
			ret = -EFSCORRUPTED;
			goto fail;
		}

		/* key needs to fit in data */
		if (data_end - data < key_len) {
			ret = -EFSCORRUPTED;
			goto fail;
		}

		if (size) {
			if (size - copied < key_len + 1) {
				ret = -E2BIG;
				goto fail;
			}

			memcpy(names + copied, data, key_len);
			names[copied + key_len] = '\0';
		}
		data += key_len;
		copied += key_len + 1;

		/* Skip value, but ensure if fits in data */
		if (data_end - data < value_len)
			return -EFSCORRUPTED;
		data += value_len;
	}

	kfree(xattrs);
	return copied;

 fail:
	kfree(xattrs);
	return ret;
}

int lcfs_get_xattr(struct lcfs_context_s *ctx, struct lcfs_inode_s *ino, const char *name, void *value, size_t size)
{
	const struct lcfs_xattr_header_s *xattrs;
	size_t name_len = strlen(name);
	size_t n_xattrs = 0, i;
	u8 *data, *data_end;
	int ret;

	if (ino->xattrs.len == 0)
		return -ENODATA;

	if (name_len > XATTR_NAME_MAX)
		return -ENODATA;

	/* Gotta be large enought to fit the n_attr */
	if (ino->xattrs.len < sizeof(struct lcfs_xattr_header_s))
		return -EFSCORRUPTED;

	xattrs = lcfs_alloc_vdata(ctx, ino->xattrs);
	if (IS_ERR(xattrs))
		return PTR_ERR(xattrs);

	n_xattrs = xattrs->n_attr;
	/* And the entire array */
	if (ino->xattrs.len < lcfs_xattr_header_size(n_xattrs)) {
		ret = -EFSCORRUPTED;
		goto fail;
	}

	data = ((u8 *)xattrs) + lcfs_xattr_header_size(n_xattrs);
	data_end = ((u8 *)xattrs) + ino->xattrs.len;

	for (i = 0; i < n_xattrs; i++) {
		char *this_key;
		u8 *this_value;
		uint16_t key_len = xattrs->attr[i].key_length;
		uint16_t value_len = xattrs->attr[i].value_length;

		if (key_len > XATTR_NAME_MAX) {
			ret = -EFSCORRUPTED;
			goto fail;
		}

		/* key needs to fit in data */
		if (data_end - data < key_len) {
			ret = -EFSCORRUPTED;
			goto fail;
		}

		this_key = data;
		data += key_len;

		if (data_end - data < value_len) {
			ret = -EFSCORRUPTED;
			goto fail;
		}
		this_value = data;
		data += value_len;

		if (key_len != name_len)
			continue;

		if (memcmp(this_key, name, name_len) != 0)
			continue;

		if (size > 0) {
			if (size < value_len) {
				ret = -E2BIG;
				goto fail;
			}
			memcpy(value, this_value, value_len);
		}

		kfree(xattrs);
		return value_len;
	}

	kfree(xattrs);
	return -ENODATA;

 fail:
	kfree(xattrs);
	return ret;
}

int lcfs_iterate_dir(struct lcfs_context_s *ctx, loff_t first, struct lcfs_inode_s *dir_ino, lcfs_dir_iter_cb cb, void *private)
{
	size_t i, entries;
	void *check;

	/* Check for overflows.  */
	check = lcfs_get_vdata(ctx, dir_ino->u.dir, NULL);
	if (IS_ERR(check))
		return PTR_ERR(check);

	entries = dir_ino->u.dir.len / sizeof(struct lcfs_dentry_s);

	for (i = first; i < entries; i++) {
		struct lcfs_dentry_s dentry_buf;
		struct lcfs_dentry_s *dentry;
		struct lcfs_inode_s ino_buf;
		struct lcfs_inode_s *ino;
		char name_buf[NAME_MAX];
		const char *name;
		size_t nd;

		nd = i * sizeof(struct lcfs_dentry_s);

		dentry = lcfs_get_dentry(ctx, dir_ino->u.dir.off + nd,
					 &dentry_buf);
		if (IS_ERR(dentry))
			return PTR_ERR(dentry);

		name = lcfs_c_string(ctx, dentry->name, name_buf, NAME_MAX);
		if (IS_ERR(name))
			return PTR_ERR(name);

		ino = lcfs_dentry_inode(ctx, dentry, &ino_buf);
		if (IS_ERR(ino))
			return PTR_ERR(ino);

		if (!cb(private, name, dentry->name.len,
			lcfs_dentry_ino(dentry),
			ino->st_mode & S_IFMT))
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
	struct bsearch_key_s *key = (struct bsearch_key_s *) a;
	const struct lcfs_dentry_s *dentry;
	struct lcfs_dentry_s dentry_buf;
	char buf[NAME_MAX];
	const char *name;

	dentry = lcfs_get_dentry(key->ctx, (size_t) b, &dentry_buf);
	if (IS_ERR(dentry)) {
		key->err = PTR_ERR(dentry);
		return 0;
	}

	name = lcfs_c_string(key->ctx, dentry->name, buf, NAME_MAX);
	if (IS_ERR(name)) {
		key->err = PTR_ERR(name);
		return 0;
	}
	return strcmp(key->name, name);
}

int lcfs_lookup(struct lcfs_context_s *ctx, struct lcfs_inode_s *dir, const char *name, lcfs_off_t *index)
{
	struct lcfs_dentry_s *found;
	struct bsearch_key_s key = {
		.name = name,
		.ctx = ctx,
		.err = 0,
	};
	size_t size, n_entries;
	void *check;

	/* Check the entire directory is in the blob.  */
	check = lcfs_get_vdata(ctx, dir->u.dir, NULL);
	if (check)
		return PTR_ERR(check);

	size = sizeof(struct lcfs_dentry_s);
	n_entries = dir->u.dir.len / size;

	found = bsearch(&key, NULL + dir->u.dir.off, n_entries,
			size, compare_names);
	if (found == NULL || key.err)
		return 0;

	*index = (lcfs_off_t) found;

	return 1;
}

const char *lcfs_get_payload(struct lcfs_context_s *ctx, struct lcfs_inode_s *ino, void *buf)
{
	if (ino->u.payload.len == 0)
		return ERR_PTR(-EINVAL);

	return lcfs_c_string(ctx, ino->u.payload, buf, PATH_MAX);
}

char *lcfs_dup_payload_path(struct lcfs_context_s *ctx, struct lcfs_inode_s *ino)
{
	const char *v;
	char *link;

	if (ino->u.payload.len == 0)
		return ERR_PTR(-EINVAL);

	if (ino->u.payload.len > PATH_MAX)
		return ERR_PTR(-EINVAL);

	link = kmalloc(ino->u.payload.len, GFP_KERNEL);
	if (!link)
		return ERR_PTR(-ENOMEM);

	v = lcfs_c_string(ctx, ino->u.payload, link,
			  ino->u.payload.len);
	if (IS_ERR(v)) {
		kfree(link);
		return ERR_CAST(v);
	}

	return link;
}

const char *lcfs_get_extend(struct lcfs_context_s *ctx, struct lcfs_inode_s *ino, size_t n_extend, void *buf)
{
	struct lcfs_extend_s extends_buf;
	struct lcfs_extend_s *extends;

	/* Only one extend support yet.  */
	if (n_extend != 0)
		return ERR_PTR(-EINVAL);

	if (ino->u.extends.len != sizeof (struct lcfs_extend_s))
		return ERR_PTR(-EFSCORRUPTED);

	extends = lcfs_get_vdata(ctx, ino->u.extends, &extends_buf);
	if (IS_ERR (extends)) {
		/* otherwise gcc complains with -Wreturn-local-addr.  */
		int r;

		r = PTR_ERR(extends);
		return ERR_PTR(r);;
	}

	return lcfs_c_string(ctx, extends[0].payload, buf, PATH_MAX);
}

int lcfs_get_file_size(struct lcfs_context_s *ctx, struct lcfs_inode_s *ino, loff_t *size)
{
	struct lcfs_extend_s extends_buf;
	struct lcfs_extend_s *extends;

	if (ino->u.extends.len == 0) {
		*size = 0;
		return 0;
	}

	/* Only one extend support yet.  */
	if (ino->u.extends.len != sizeof (struct lcfs_extend_s))
		return -EFSCORRUPTED;

	extends = lcfs_get_vdata(ctx, ino->u.extends, &extends_buf);
	if (IS_ERR (extends))
		return PTR_ERR(extends);

	*size = (loff_t) extends[0].st_size;
	return 0;
}
