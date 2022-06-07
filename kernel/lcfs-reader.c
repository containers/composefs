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
# include <linux/overflow.h>
#include <linux/unaligned/packed_struct.h>
#endif

#include "lcfs-fuzzing.h"
#include "lcfs-verity.h"

#define MIN(a,b) ((a)<(b) ? (a) : (b))

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

struct lcfs_context_s *lcfs_create_ctx(char *descriptor_path, const u8 *required_digest)
{
	struct lcfs_header_s *header;
	struct lcfs_context_s *ctx;
	struct file *descriptor;
	loff_t i_size;

	descriptor = filp_open(descriptor_path, O_RDONLY, 0);
	if (IS_ERR(descriptor))
		return ERR_CAST(descriptor);

	if (required_digest) {
		size_t digest_size;
		u8 *verity_digest;
		struct fsverity_info *verity_info = fsverity_get_info(d_inode(descriptor->f_path.dentry));
		if (verity_info == NULL) {
			pr_err("ERROR: composefs descriptor has no fs-verity digest\n");
			fput(descriptor);
			return ERR_PTR(-EINVAL);
		}
		verity_digest = lcfs_fsverity_info_get_digest(verity_info, &digest_size);
		if (digest_size != LCFS_DIGEST_SIZE ||
		    memcmp(required_digest, verity_digest, LCFS_DIGEST_SIZE) != 0) {
			pr_err("ERROR: composefs descriptor has wrong fs-verity digest\n");
			fput(descriptor);
			return ERR_PTR(-EINVAL);
		}
	}

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
	header->magic = lcfs_u32_from_file(header->magic);
	header->data_offset = lcfs_u64_from_file(header->data_offset);

        if (header->magic != LCFS_MAGIC ||
            header->data_offset > ctx->descriptor_len) {
		fput(descriptor);
		kfree(ctx);
		return ERR_PTR(-EINVAL);
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

static void *lcfs_get_inode_data_max(struct lcfs_context_s *ctx,
				     u64 offset,
				     u64 max_size,
				     u64 *read_size,
				     u8 *dest)
{
	u64 remaining = ctx->descriptor_len - sizeof(struct lcfs_header_s);
	u64 size;

	if (offset > remaining)
		return ERR_PTR(-EINVAL);
	remaining -= offset;

	/* Read at most remaining bytes, and no more than max_size */
	size = MIN(remaining, max_size);
	*read_size = size;

	return lcfs_get_inode_data(ctx, offset, size, dest);
}

static void *lcfs_get_inode_payload(struct lcfs_context_s *ctx,
				    struct lcfs_inode_s *ino,
				    lcfs_off_t index,
				    u8 *dest)
{
	u32 flags = ino->flags;
	u64 offset = index;
	u64 inode_size = lcfs_inode_encoded_size(flags);
	return lcfs_get_inode_data(ctx, offset + inode_size, ino->payload_length, dest);
}

static void *lcfs_alloc_inode_payload(struct lcfs_context_s *ctx,
				      struct lcfs_inode_s *ino,
				      lcfs_off_t index)
{
	u8 *buf;
	void *res;

	buf = kmalloc(ino->payload_length, GFP_KERNEL);
	if (!buf)
		return ERR_PTR(-ENOMEM);

	res = lcfs_get_inode_payload(ctx, ino, index, buf);
	if (IS_ERR(res))
		kfree(buf);

	return res;
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

static u32 lcfs_read_u32(u8 **data) {
	u32 v = lcfs_u32_from_file (__get_unaligned_cpu32(*data));
	*data += sizeof(u32);
	return v;
}

static u64 lcfs_read_u64(u8 **data) {
	u64 v = lcfs_u64_from_file (__get_unaligned_cpu64(*data));
	*data += sizeof(u64);
	return v;
}

struct lcfs_inode_s *lcfs_get_ino_index(struct lcfs_context_s *ctx,
					lcfs_off_t index,
					struct lcfs_inode_s *ino)
{
	u64 offset = index;
	u8 buffer[sizeof(struct lcfs_inode_s)]; /* This will fix the maximal encoded size */
	u64 read_size;
	u64 inode_size;
	u8 *data;

	data = lcfs_get_inode_data_max(ctx, offset, sizeof(buffer), &read_size, buffer);
	if (IS_ERR(data))
		return ERR_CAST(data);

	/* Need to fit at least flags to decode */
	if (read_size < sizeof(u32))
		return ERR_PTR(-EFSCORRUPTED);

	memset(ino, 0, sizeof(struct lcfs_inode_s));
	ino->flags = lcfs_read_u32(&data);

	inode_size = lcfs_inode_encoded_size(ino->flags);
	/* Shouldn't happen, but lets check */
	if (inode_size > sizeof(buffer))
		return ERR_PTR(-EFSCORRUPTED);

	if (LCFS_INODE_FLAG_CHECK(ino->flags, PAYLOAD)) {
		ino->payload_length = lcfs_read_u32(&data);
	} else {
		ino->payload_length = 0;
	}

	if (LCFS_INODE_FLAG_CHECK(ino->flags, MODE)) {
		ino->st_mode = lcfs_read_u32(&data);
	} else {
		ino->st_mode = LCFS_INODE_DEFAULT_MODE;
	}

	if (LCFS_INODE_FLAG_CHECK(ino->flags, NLINK)) {
		ino->st_nlink = lcfs_read_u32(&data);
	} else {
		ino->st_nlink = LCFS_INODE_DEFAULT_NLINK;
	}

	if (LCFS_INODE_FLAG_CHECK(ino->flags, UIDGID)) {
		ino->st_uid = lcfs_read_u32(&data);
		ino->st_gid = lcfs_read_u32(&data);
	} else {
		ino->st_uid = LCFS_INODE_DEFAULT_UIDGID;
		ino->st_gid = LCFS_INODE_DEFAULT_UIDGID;
	}

	if (LCFS_INODE_FLAG_CHECK(ino->flags, RDEV)) {
		ino->st_rdev = lcfs_read_u32(&data);
	} else {
		ino->st_rdev = LCFS_INODE_DEFAULT_RDEV;
	}

	if (LCFS_INODE_FLAG_CHECK(ino->flags, TIMES)) {
		ino->st_mtim.tv_sec = lcfs_read_u64(&data);
		ino->st_ctim.tv_sec = lcfs_read_u64(&data);
	} else {
		ino->st_mtim.tv_sec = LCFS_INODE_DEFAULT_TIMES;
		ino->st_ctim.tv_sec = LCFS_INODE_DEFAULT_TIMES;
	}

	if (LCFS_INODE_FLAG_CHECK(ino->flags, TIMES_NSEC)) {
		ino->st_mtim.tv_nsec = lcfs_read_u32(&data);
		ino->st_ctim.tv_nsec = lcfs_read_u32(&data);
	} else {
		ino->st_mtim.tv_nsec = 0;
		ino->st_ctim.tv_nsec = 0;
	}

	if (LCFS_INODE_FLAG_CHECK(ino->flags, LOW_SIZE)) {
		ino->st_size = lcfs_read_u32(&data);
	} else {
		ino->st_size = 0;
	}

	if (LCFS_INODE_FLAG_CHECK(ino->flags, HIGH_SIZE)) {
		ino->st_size += (u64)lcfs_read_u32(&data) << 32;
	}

	if (LCFS_INODE_FLAG_CHECK(ino->flags, XATTRS)) {
		ino->xattrs.off = lcfs_read_u32(&data);
		ino->xattrs.len = lcfs_read_u32(&data);
	} else {
		ino->xattrs.off = 0;
		ino->xattrs.len = 0;
	}

	if (LCFS_INODE_FLAG_CHECK(ino->flags, DIGEST)) {
		memcpy(ino->digest, data, LCFS_DIGEST_SIZE);
		data += 32;
	}

	return ino;
}

struct lcfs_inode_s *lcfs_get_root_ino(struct lcfs_context_s *ctx,
				       struct lcfs_inode_s *ino_buf,
				       lcfs_off_t *index)
{
	lcfs_off_t root_ino = 0;

	*index = root_ino;
	return lcfs_get_ino_index(ctx, root_ino, ino_buf);
}

const uint8_t *lcfs_get_digest(struct lcfs_context_s *ctx, struct lcfs_inode_s *ino, const char *payload, u8 digest_buf[LCFS_DIGEST_SIZE])
{
	if (LCFS_INODE_FLAG_CHECK(ino->flags, DIGEST)) {
		return ino->digest;
	}

	if (LCFS_INODE_FLAG_CHECK(ino->flags, DIGEST_FROM_PAYLOAD && payload != NULL)) {
		if (lcfs_digest_from_payload(payload, ino->payload_length, digest_buf) == 0)
			return digest_buf;
	}

	return NULL;
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

	n_dentries = dir->n_dentries = lcfs_u32_from_file(dir->n_dentries);

	/* Verify that array fits */
	if (ino->payload_length < lcfs_dir_size(n_dentries))
		goto corrupted;

	data = ((u8 *)dir) + lcfs_dir_size(n_dentries);
	data_end = ((u8 *)dir) + ino->payload_length;

	/* Verify and convert all dentries upfront */
	for (i = 0; i < n_dentries; i++) {
		struct lcfs_dentry_s *d = &dir->dentries[i];
		u16 name_len = d->name_len = lcfs_u16_from_file(d->name_len);
		d->inode_index = lcfs_u64_from_file(d->inode_index);

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

	n_xattrs = xattrs->n_attr = lcfs_u16_from_file (xattrs->n_attr);

	/* Verify that array fits */
	if (ino->xattrs.len < lcfs_xattr_header_size(n_xattrs))
		goto corrupted;

	data = ((u8 *)xattrs) + lcfs_xattr_header_size(n_xattrs);
	data_end = ((u8 *)xattrs) + ino->xattrs.len;

	/* Verify and convert all keys and value sizes upfront */
	for (i = 0; i < n_xattrs; i++) {
		struct lcfs_xattr_element_s *e = &xattrs->attr[i];
		uint16_t key_len = e->key_length = lcfs_u16_from_file(e->key_length);
		uint16_t value_len = e->value_length = lcfs_u16_from_file(e->value_length);
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

		this_key = (char *)data;
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

int lcfs_dir_iterate(struct lcfs_dir_s *dir, loff_t first, lcfs_dir_iter_cb cb, void *private)
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
		char *name = (char *)data;
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

u32 lcfs_dir_get_link_count(struct lcfs_dir_s *dir)
{
	size_t i, n_dentries;
	u8 *data;
	u32 count;

	count = 2; /* . and .. */

	if (dir == NULL)
		return count;

	/* dir is validated by lcfs_get_dir(), so we can trust it here. */
	n_dentries = dir->n_dentries;

	data = ((u8 *)dir) + lcfs_dir_size(n_dentries);

	for (i = 0; i < n_dentries; i++) {
		u32 name_len = dir->dentries[i].name_len;

		data += name_len;

		if (dir->dentries[i].d_type == DT_DIR)
			count++;
	}

	return count;
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
		char *entry_name = (char *)data;
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
	u8 *path;

	if ((ino->st_mode & S_IFMT) != S_IFREG &&
	    (ino->st_mode & S_IFMT) != S_IFLNK) {
		return ERR_PTR(-EINVAL);
	}

	if (ino->payload_length == 0 ||
	    ino->payload_length > PATH_MAX)
		return ERR_PTR(-EFSCORRUPTED);

	path = kmalloc(ino->payload_length + 1, GFP_KERNEL);
	if (!path)
		return ERR_PTR(-ENOMEM);

	v = lcfs_get_inode_payload(ctx, ino, index, path);
	if (IS_ERR(v)) {
		kfree(path);
		return ERR_CAST(v);
	}

	/* zero terminate */
	path[ino->payload_length] = 0;

	return (char *)path;
}
