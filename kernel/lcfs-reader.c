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

	u64 descriptor_len;
};

static void *lcfs_read_data(struct lcfs_context_s *ctx,
			    u64 offset,
			    u64 size,
			    u8 *dest)
{
	size_t copied;
	loff_t pos = offset;

	if (offset > ctx->descriptor_len)
		return ERR_PTR(-EFSCORRUPTED);

	if ((offset + size < offset) ||
	    (offset + size > ctx->descriptor_len))
		return ERR_PTR(-EFSCORRUPTED);

	copied = 0;
	while (copied < size) {
		ssize_t bytes;

		bytes = kernel_read(ctx->descriptor, dest + copied,
				    size - copied, &pos);
		if (bytes < 0)
			return ERR_PTR(bytes);
		if (bytes == 0)
			return ERR_PTR(-EINVAL);

		copied += bytes;
	}

	if (copied != size)
		return ERR_PTR(-EFSCORRUPTED);
	return dest;
}

struct lcfs_context_s *lcfs_create_ctx(char *descriptor_path)
{
	struct lcfs_header_s *header;
	struct lcfs_context_s *ctx;
	struct file *descriptor;
	loff_t i_size;

	descriptor = filp_open(descriptor_path, O_RDONLY, 0);
	if (IS_ERR(descriptor))
		return ERR_CAST(descriptor);

	i_size = i_size_read(file_inode(descriptor));
	if (i_size <= (sizeof(struct lcfs_header_s) + sizeof(struct lcfs_inode_s))) {
		fput(descriptor);
		return ERR_PTR(-EINVAL);
	}

	ctx = kzalloc(sizeof(struct lcfs_context_s), GFP_KERNEL);
	if (ctx == NULL) {
		fput(descriptor);
		return ERR_PTR(-ENOMEM);
	}

	ctx->descriptor = descriptor;
	ctx->descriptor_len = i_size;

	header = lcfs_read_data(ctx, 0, sizeof(struct lcfs_header_s), (u8 *)&ctx->header);
	if (IS_ERR(header)) {
		fput(descriptor);
		kfree(ctx);
		return ERR_CAST(header);
	}

	return ctx;
}

void lcfs_destroy_ctx(struct lcfs_context_s *ctx)
{
	if (!ctx)
		return;
	fput(ctx->descriptor);
	kfree(ctx);
}

static void *lcfs_get_inode_data(struct lcfs_context_s *ctx,
				 u64 offset,
				 u64 size,
				 u8 *dest)
{
	return lcfs_read_data(ctx,
			      offset + sizeof(struct lcfs_header_s),
			      size, dest);
}

static void *lcfs_alloc_inode_data(struct lcfs_context_s *ctx,
			    u64 offset,
			    u64 size)
{
	u8 *buf;
	void *res;

	buf = kmalloc(size, GFP_KERNEL);
	if (!buf)
		return ERR_PTR(-ENOMEM);

	res = lcfs_get_inode_data(ctx, offset, size, buf);
	if (IS_ERR(res))
		kfree(buf);

	return res;
}

static void *lcfs_get_inode_payload(struct lcfs_context_s *ctx,
				    struct lcfs_inode_s *ino,
				    lcfs_off_t index,
				    u8 *dest)
{
	return lcfs_get_inode_data(ctx, index + sizeof(struct lcfs_inode_s), ino->payload_length, dest);
}

static void *lcfs_alloc_inode_payload(struct lcfs_context_s *ctx,
				      struct lcfs_inode_s *ino,
				      lcfs_off_t index)
{
	return lcfs_alloc_inode_data(ctx, index + sizeof(struct lcfs_inode_s), ino->payload_length);
}


static void *lcfs_get_vdata(struct lcfs_context_s *ctx,
			    const struct lcfs_vdata_s vdata,
			    void *dest)
{
	if (!dest)
		return NULL;

	return lcfs_read_data(ctx,
			      vdata.off + ctx->header.data_offset,
			      vdata.len, dest);
}

static void *lcfs_alloc_vdata(struct lcfs_context_s *ctx,
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

struct lcfs_inode_s *lcfs_get_ino_index(struct lcfs_context_s *ctx,
					lcfs_off_t index,
					struct lcfs_inode_s *buffer)
{
	return lcfs_get_inode_data(ctx, index, sizeof(struct lcfs_inode_s), (u8 *)buffer);
}

struct lcfs_dir_s *lcfs_get_dir(struct lcfs_context_s *ctx,
				struct lcfs_inode_s *ino,
				lcfs_off_t index)
{
	struct lcfs_dir_s *dir;
	u8 *data, *data_end;
	size_t n_dentries, i;

	if ((ino->st_mode & S_IFMT) != S_IFDIR ||
	    ino->payload_length == 0) {
		return NULL;
	}

	/* Gotta be large enough to fit the n_dentries */
	if (ino->payload_length < sizeof(struct lcfs_dir_s))
		return ERR_PTR(-EFSCORRUPTED);

	dir = lcfs_alloc_inode_payload(ctx, ino, index);
	if (IS_ERR(dir))
		return ERR_CAST(dir);

	n_dentries = dir->n_dentries;

	/* Verify that array fits */
	if (ino->payload_length < lcfs_dir_size(n_dentries))
		goto corrupted;

	data = ((u8 *)dir) + lcfs_dir_size(n_dentries);
	data_end = ((u8 *)dir) + ino->payload_length;

	/* Verify all dentries upfront */
	for (i = 0; i < n_dentries; i++) {
		uint32_t name_len = dir->dentries[i].name_len;

		/* name needs to fit in data */
		if (data_end - data < name_len)
			goto corrupted;
		data += name_len;
	}

	/* No unexpected data at the end */
	if (data != data_end)
		goto corrupted;

	return dir;

 corrupted:
	kfree(dir);
	return ERR_PTR(-EFSCORRUPTED);
}


struct lcfs_xattr_header_s *lcfs_get_xattrs(struct lcfs_context_s *ctx, struct lcfs_inode_s *ino)
{
	struct lcfs_xattr_header_s *xattrs;
	u8 *data, *data_end;
	size_t n_xattrs, i;

	if (ino->xattrs.len == 0) {
		return NULL;
	}

	/* Gotta be large enought to fit the n_attr */
	if (ino->xattrs.len < sizeof(struct lcfs_xattr_header_s))
		return ERR_PTR(-EFSCORRUPTED);

	xattrs = lcfs_alloc_vdata(ctx, ino->xattrs);
	if (IS_ERR(xattrs))
		return ERR_CAST(xattrs);

	n_xattrs = xattrs->n_attr;

	/* Verify that array fits */
	if (ino->xattrs.len < lcfs_xattr_header_size(n_xattrs))
		goto corrupted;

	data = ((u8 *)xattrs) + lcfs_xattr_header_size(n_xattrs);
	data_end = ((u8 *)xattrs) + ino->xattrs.len;

	/* Verify all keys and value sizes upfront */
	for (i = 0; i < n_xattrs; i++) {
		uint16_t key_len = xattrs->attr[i].key_length;
		uint16_t value_len = xattrs->attr[i].value_length;
		if (key_len > XATTR_NAME_MAX)
			goto corrupted;

		/* key needs to fit in data */
		if (data_end - data < key_len)
			goto corrupted;
		data += key_len;

		/* value needs to fit in data */
		if (data_end - data < value_len)
			goto corrupted;
		data += value_len;
	}

	/* No unexpected data at the end */
	if (data != data_end)
		goto corrupted;

	return xattrs;

 corrupted:
	kfree(xattrs);
	return ERR_PTR(-EFSCORRUPTED);
}


ssize_t lcfs_list_xattrs(struct lcfs_xattr_header_s *xattrs, char *names, size_t size)
{
	u8 *data;
	size_t n_xattrs = 0, i;
	ssize_t copied = 0;

	if (xattrs == NULL)
		return 0;

	/* The contents was verified in lcfs_get_xattrs, so trust it here */
	n_xattrs = xattrs->n_attr;

	data = ((u8 *)xattrs) + lcfs_xattr_header_size(n_xattrs);

	for (i = 0; i < n_xattrs; i++) {
		uint16_t key_len = xattrs->attr[i].key_length;
		uint16_t value_len = xattrs->attr[i].value_length;

		if (size) {
			if (size - copied < key_len + 1)
				return -E2BIG;

			memcpy(names + copied, data, key_len);
			names[copied + key_len] = '\0';
		}
		data += key_len + value_len;
		copied += key_len + 1;
	}

	return copied;
}

int lcfs_get_xattr(struct lcfs_xattr_header_s *xattrs, const char *name, void *value, size_t size)
{
	size_t name_len = strlen(name);
	size_t n_xattrs = 0, i;
	u8 *data;

	if (xattrs == 0)
		return -ENODATA;

	if (name_len > XATTR_NAME_MAX)
		return -ENODATA;

	/* The contents was verified in lcfs_get_xattrs, so trust it here */
	n_xattrs = xattrs->n_attr;

	data = ((u8 *)xattrs) + lcfs_xattr_header_size(n_xattrs);

	for (i = 0; i < n_xattrs; i++) {
		char *this_key;
		u8 *this_value;
		uint16_t key_len = xattrs->attr[i].key_length;
		uint16_t value_len = xattrs->attr[i].value_length;

		this_key = data;
		data += key_len;

		this_value = data;
		data += value_len;

		if (key_len != name_len)
			continue;

		if (memcmp(this_key, name, name_len) != 0)
			continue;

		if (size > 0) {
			if (size < value_len)
				return -E2BIG;
			memcpy(value, this_value, value_len);
		}

		return value_len;
	}

	return -ENODATA;
}

int lcfs_iterate_dir(struct lcfs_dir_s *dir, loff_t first, lcfs_dir_iter_cb cb, void *private)
{
	size_t i, n_dentries;
	u8 *data;

	if (dir == NULL)
		return 0;

	/* dir is validated by lcfs_get_dir(), so we can trust it here. */

	n_dentries = dir->n_dentries;

	/* Early exit if guaranteed past end */
	if (first >= n_dentries)
		return 0;

	data = ((u8 *)dir) + lcfs_dir_size(n_dentries);

	for (i = 0; i < n_dentries; i++) {
		char *name = data;
		u32 name_len = dir->dentries[i].name_len;

		data += name_len;

		if (i < first)
			continue;

		if (!cb(private, name, name_len,
			dir->dentries[i].inode_index,
			dir->dentries[i].d_type))
			break;
	}
	return 0;
}

int lcfs_lookup(struct lcfs_dir_s *dir, const char *name, size_t name_len, lcfs_off_t *index)
{
	size_t i, n_dentries;
	u8 *data;

	if (dir == NULL)
		return 0;

	/* dir is validated by lcfs_get_dir(), so we can trust it here. */

	n_dentries = dir->n_dentries;

	data = ((u8 *)dir) + lcfs_dir_size(n_dentries);
	for (i = 0; i < n_dentries; i++) {
		char *entry_name = data;
		u32 entry_name_len = dir->dentries[i].name_len;

		if (name_len == entry_name_len &&
		    memcmp(entry_name, name, name_len) == 0) {
			*index = dir->dentries[i].inode_index;
			return 1;
		}

		data += entry_name_len;
	}
	return 0;
}

char *lcfs_dup_payload_path(struct lcfs_context_s *ctx,
			    struct lcfs_inode_s *ino,
			    lcfs_off_t index)
{
	const char *v;
	char *link;

	if (ino->payload_length == 0 ||
	    ino->payload_length > PATH_MAX)
		return ERR_PTR(-EFSCORRUPTED);

	link = kmalloc(ino->payload_length + 1, GFP_KERNEL);
	if (!link)
		return ERR_PTR(-ENOMEM);

	v = lcfs_get_inode_payload(ctx, ino, index, link);
	if (IS_ERR(v)) {
		kfree(link);
		return ERR_CAST(v);
	}

	/* zero terminate */
	link[ino->payload_length] = 0;

	return link;
}

int lcfs_get_backing(struct lcfs_context_s *ctx,
		     struct lcfs_inode_s *ino,
		     lcfs_off_t index,
		     loff_t *out_size,
		     char **out_path)
{
	struct lcfs_backing_s *backing;
	char *path = NULL;
	size_t size;
	u32 payload_len;

	if (ino->payload_length == 0) {
		size = 0;
		path = NULL;
	} else {
		if (ino->payload_length < sizeof(struct lcfs_backing_s) ||
		    ino->payload_length > sizeof(struct lcfs_backing_buf_s))
			return -EFSCORRUPTED;

		backing = lcfs_alloc_inode_payload(ctx, ino, index);
		if (IS_ERR(backing))
			return PTR_ERR(backing);

		size = backing->st_size;
		payload_len = backing->payload_len;

		if (lcfs_backing_size(payload_len) != ino->payload_length ||
		    /* Make sure we fit in the PATH_MAX bytes in out_buf, including zero (which is not in the file) */
		    payload_len >= PATH_MAX) {
			kfree(backing);
			return -EFSCORRUPTED;
		}

		if (out_path) {
			path = kstrndup(backing->payload, backing->payload_len, GFP_KERNEL);
			if (path == NULL) {
				kfree(backing);
				return -ENOMEM;
			}
		}

		kfree(backing);
	}

	if (out_size)
		*out_size = size;
	if (out_path)
		*out_path = path;

	return 0;
}
