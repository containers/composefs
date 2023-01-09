// SPDX-License-Identifier: GPL-2.0
/*
 * composefs
 *
 * Copyright (C) 2021 Giuseppe Scrivano
 * Copyright (C) 2022 Alexander Larsson
 *
 * This file is released under the GPL.
 */

#include "cfs-internals.h"

#include <linux/file.h>
#include <linux/pagemap.h>
#include <linux/unaligned/packed_struct.h>

struct cfs_buf {
	struct page *page;
	void *base;
};

#define CFS_VDATA_BUF_INIT                                                     \
	{                                                                      \
		NULL, NULL                                                     \
	}

static void cfs_buf_put(struct cfs_buf *buf)
{
	if (buf->page) {
		if (buf->base)
			kunmap(buf->page);
		put_page(buf->page);
		buf->base = NULL;
		buf->page = NULL;
	}
}

static void *cfs_get_buf(struct cfs_context_s *ctx, u64 offset, u32 size,
			 struct cfs_buf *buf)
{
	u64 index = offset >> PAGE_SHIFT;
	u32 page_offset = offset & (PAGE_SIZE - 1);
	struct page *page = buf->page;
	struct inode *inode = ctx->descriptor->f_inode;
	struct address_space *const mapping = inode->i_mapping;

	if (offset > ctx->descriptor_len)
		return ERR_PTR(-EFSCORRUPTED);

	if ((offset + size < offset) || (offset + size > ctx->descriptor_len))
		return ERR_PTR(-EFSCORRUPTED);

	if (size > PAGE_SIZE)
		return ERR_PTR(-EINVAL);

	if (PAGE_SIZE - page_offset < size)
		return ERR_PTR(-EINVAL);

	if (!page || page->index != index) {
		cfs_buf_put(buf);

		page = read_cache_page(mapping, index, NULL, NULL);
		if (IS_ERR(page))
			return page;

		buf->page = page;
		buf->base = kmap(page);
	}

	return buf->base + page_offset;
}

static void *cfs_read_data(struct cfs_context_s *ctx, u64 offset, u64 size,
			   u8 *dest)
{
	size_t copied;
	loff_t pos = offset;

	if (offset > ctx->descriptor_len)
		return ERR_PTR(-EFSCORRUPTED);

	if ((offset + size < offset) || (offset + size > ctx->descriptor_len))
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

int cfs_init_ctx(const char *descriptor_path, const u8 *required_digest,
		 struct cfs_context_s *ctx_out)
{
	struct cfs_header_s *header;
	struct file *descriptor;
	loff_t i_size;
	u8 verity_digest[FS_VERITY_MAX_DIGEST_SIZE];
	enum hash_algo verity_algo;
	struct cfs_context_s ctx;
	int res;

	descriptor = filp_open(descriptor_path, O_RDONLY, 0);
	if (IS_ERR(descriptor))
		return PTR_ERR(descriptor);

	if (required_digest) {
		res = fsverity_get_digest(d_inode(descriptor->f_path.dentry),
					  verity_digest, &verity_algo);
		if (res < 0) {
			pr_err("ERROR: composefs descriptor has no fs-verity digest\n");
			goto fail;
		}
		if (verity_algo != HASH_ALGO_SHA256 ||
		    memcmp(required_digest, verity_digest,
			   SHA256_DIGEST_SIZE) != 0) {
			pr_err("ERROR: composefs descriptor has wrong fs-verity digest\n");
			res = -EINVAL;
			goto fail;
		}
	}

	i_size = i_size_read(file_inode(descriptor));
	if (i_size <=
	    (sizeof(struct cfs_header_s) + sizeof(struct cfs_inode_s))) {
		res = -EINVAL;
		goto fail;
	}

	/* Need this temporary ctx for cfs_read_data() */
	ctx.descriptor = descriptor;
	ctx.descriptor_len = i_size;

	header = cfs_read_data(&ctx, 0, sizeof(struct cfs_header_s),
			       (u8 *)&ctx.header);
	if (IS_ERR(header)) {
		res = PTR_ERR(header);
		goto fail;
	}
	header->magic = le32_to_cpu(header->magic);
	header->data_offset = le64_to_cpu(header->data_offset);
	header->root_inode = le64_to_cpu(header->root_inode);

	if (header->magic != CFS_MAGIC ||
	    header->data_offset > ctx.descriptor_len ||
	    sizeof(struct cfs_header_s) + header->root_inode >
		    ctx.descriptor_len) {
		res = -EINVAL;
		goto fail;
	}

	*ctx_out = ctx;
	return 0;

fail:
	fput(descriptor);
	return res;
}

void cfs_ctx_put(struct cfs_context_s *ctx)
{
	if (ctx->descriptor) {
		fput(ctx->descriptor);
		ctx->descriptor = NULL;
	}
}

static void *cfs_get_inode_data(struct cfs_context_s *ctx, u64 offset, u64 size,
				u8 *dest)
{
	return cfs_read_data(ctx, offset + sizeof(struct cfs_header_s), size,
			     dest);
}

static void *cfs_get_inode_data_max(struct cfs_context_s *ctx, u64 offset,
				    u64 max_size, u64 *read_size, u8 *dest)
{
	u64 remaining = ctx->descriptor_len - sizeof(struct cfs_header_s);
	u64 size;

	if (offset > remaining)
		return ERR_PTR(-EINVAL);
	remaining -= offset;

	/* Read at most remaining bytes, and no more than max_size */
	size = min(remaining, max_size);
	*read_size = size;

	return cfs_get_inode_data(ctx, offset, size, dest);
}

static void *cfs_get_inode_payload_w_len(struct cfs_context_s *ctx,
					 u32 payload_length, u64 index,
					 u8 *dest, u64 offset, size_t len)
{
	/* Payload is stored before the inode, check it fits */
	if (payload_length > index)
		return ERR_PTR(-EINVAL);

	if (offset > payload_length)
		return ERR_PTR(-EINVAL);

	if (offset + len > payload_length)
		return ERR_PTR(-EINVAL);

	return cfs_get_inode_data(ctx, index - payload_length + offset, len,
				  dest);
}

static void *cfs_get_inode_payload(struct cfs_context_s *ctx,
				   struct cfs_inode_s *ino, u64 index, u8 *dest)
{
	return cfs_get_inode_payload_w_len(ctx, ino->payload_length, index,
					   dest, 0, ino->payload_length);
}

static void *cfs_get_vdata_buf(struct cfs_context_s *ctx, u64 offset, u32 len,
			       struct cfs_buf *buf)
{
	if (offset > ctx->descriptor_len - ctx->header.data_offset)
		return ERR_PTR(-EINVAL);

	if (len > ctx->descriptor_len - ctx->header.data_offset - offset)
		return ERR_PTR(-EINVAL);

	return cfs_get_buf(ctx, ctx->header.data_offset + offset, len, buf);
}

static u32 cfs_read_u32(u8 **data)
{
	u32 v = le32_to_cpu(__get_unaligned_cpu32(*data));
	*data += sizeof(u32);
	return v;
}

static u64 cfs_read_u64(u8 **data)
{
	u64 v = le64_to_cpu(__get_unaligned_cpu64(*data));
	*data += sizeof(u64);
	return v;
}

struct cfs_inode_s *cfs_get_ino_index(struct cfs_context_s *ctx, u64 index,
				      struct cfs_inode_s *ino)
{
	u64 offset = index;
	/* Buffer that fits the maximal encoded size: */
	u8 buffer[sizeof(struct cfs_inode_s)];
	u64 read_size;
	u64 inode_size;
	u8 *data;

	data = cfs_get_inode_data_max(ctx, offset, sizeof(buffer), &read_size,
				      buffer);
	if (IS_ERR(data))
		return ERR_CAST(data);

	/* Need to fit at least flags to decode */
	if (read_size < sizeof(u32))
		return ERR_PTR(-EFSCORRUPTED);

	memset(ino, 0, sizeof(struct cfs_inode_s));
	ino->flags = cfs_read_u32(&data);

	inode_size = cfs_inode_encoded_size(ino->flags);
	/* Shouldn't happen, but let's check */
	if (inode_size > sizeof(buffer))
		return ERR_PTR(-EFSCORRUPTED);

	if (CFS_INODE_FLAG_CHECK(ino->flags, PAYLOAD))
		ino->payload_length = cfs_read_u32(&data);
	else
		ino->payload_length = 0;

	if (CFS_INODE_FLAG_CHECK(ino->flags, MODE))
		ino->st_mode = cfs_read_u32(&data);
	else
		ino->st_mode = CFS_INODE_DEFAULT_MODE;

	if (CFS_INODE_FLAG_CHECK(ino->flags, NLINK)) {
		ino->st_nlink = cfs_read_u32(&data);
	} else {
		if ((ino->st_mode & S_IFMT) == S_IFDIR)
			ino->st_nlink = CFS_INODE_DEFAULT_NLINK_DIR;
		else
			ino->st_nlink = CFS_INODE_DEFAULT_NLINK;
	}

	if (CFS_INODE_FLAG_CHECK(ino->flags, UIDGID)) {
		ino->st_uid = cfs_read_u32(&data);
		ino->st_gid = cfs_read_u32(&data);
	} else {
		ino->st_uid = CFS_INODE_DEFAULT_UIDGID;
		ino->st_gid = CFS_INODE_DEFAULT_UIDGID;
	}

	if (CFS_INODE_FLAG_CHECK(ino->flags, RDEV))
		ino->st_rdev = cfs_read_u32(&data);
	else
		ino->st_rdev = CFS_INODE_DEFAULT_RDEV;

	if (CFS_INODE_FLAG_CHECK(ino->flags, TIMES)) {
		ino->st_mtim.tv_sec = cfs_read_u64(&data);
		ino->st_ctim.tv_sec = cfs_read_u64(&data);
	} else {
		ino->st_mtim.tv_sec = CFS_INODE_DEFAULT_TIMES;
		ino->st_ctim.tv_sec = CFS_INODE_DEFAULT_TIMES;
	}

	if (CFS_INODE_FLAG_CHECK(ino->flags, TIMES_NSEC)) {
		ino->st_mtim.tv_nsec = cfs_read_u32(&data);
		ino->st_ctim.tv_nsec = cfs_read_u32(&data);
	} else {
		ino->st_mtim.tv_nsec = 0;
		ino->st_ctim.tv_nsec = 0;
	}

	if (CFS_INODE_FLAG_CHECK(ino->flags, LOW_SIZE))
		ino->st_size = cfs_read_u32(&data);
	else
		ino->st_size = 0;

	if (CFS_INODE_FLAG_CHECK(ino->flags, HIGH_SIZE))
		ino->st_size += (u64)cfs_read_u32(&data) << 32;

	if (CFS_INODE_FLAG_CHECK(ino->flags, XATTRS)) {
		ino->xattrs.off = cfs_read_u64(&data);
		ino->xattrs.len = cfs_read_u32(&data);
	} else {
		ino->xattrs.off = 0;
		ino->xattrs.len = 0;
	}

	if (CFS_INODE_FLAG_CHECK(ino->flags, DIGEST)) {
		memcpy(ino->digest, data, SHA256_DIGEST_SIZE);
		data += 32;
	}

	return ino;
}

struct cfs_inode_s *cfs_get_root_ino(struct cfs_context_s *ctx,
				     struct cfs_inode_s *ino_buf, u64 *index)
{
	u64 root_ino = ctx->header.root_inode;

	*index = root_ino;
	return cfs_get_ino_index(ctx, root_ino, ino_buf);
}

static int cfs_get_digest(struct cfs_context_s *ctx, struct cfs_inode_s *ino,
			  const char *payload,
			  u8 digest_out[SHA256_DIGEST_SIZE])
{
	int r;

	if (CFS_INODE_FLAG_CHECK(ino->flags, DIGEST)) {
		memcpy(digest_out, ino->digest, SHA256_DIGEST_SIZE);
		return 1;
	}

	if (payload && CFS_INODE_FLAG_CHECK(ino->flags, DIGEST_FROM_PAYLOAD)) {
		r = cfs_digest_from_payload(payload, ino->payload_length,
					    digest_out);
		if (r < 0)
			return r;
		return 1;
	}

	return 0;
}

static bool cfs_validate_filename(const char *name, size_t name_len)
{
	if (name_len == 0)
		return false;

	if (name_len == 1 && name[0] == '.')
		return false;

	if (name_len == 2 && name[0] == '.' && name[1] == '.')
		return false;

	if (memchr(name, '/', name_len))
		return false;

	return true;
}

static struct cfs_dir_s *cfs_dir_read_chunk_header(struct cfs_context_s *ctx,
						   size_t payload_length,
						   u64 index, u8 *chunk_buf,
						   size_t chunk_buf_size,
						   size_t max_n_chunks)
{
	size_t n_chunks, i;
	struct cfs_dir_s *dir;

	/* Payload and buffer should be large enough to fit the n_chunks */
	if (payload_length < sizeof(struct cfs_dir_s) ||
	    chunk_buf_size < sizeof(struct cfs_dir_s))
		return ERR_PTR(-EFSCORRUPTED);

	/* Make sure we fit max_n_chunks in buffer before reading it */
	if (chunk_buf_size < cfs_dir_size(max_n_chunks))
		return ERR_PTR(-EINVAL);

	dir = cfs_get_inode_payload_w_len(ctx, payload_length, index, chunk_buf,
					  0,
					  min(chunk_buf_size, payload_length));
	if (IS_ERR(dir))
		return ERR_CAST(dir);

	n_chunks = le32_to_cpu(dir->n_chunks);
	dir->n_chunks = n_chunks;

	/* Don't support n_chunks == 0, the canonical version of that is payload_length == 0 */
	if (n_chunks == 0)
		return ERR_PTR(-EFSCORRUPTED);

	if (payload_length != cfs_dir_size(n_chunks))
		return ERR_PTR(-EFSCORRUPTED);

	max_n_chunks = min(n_chunks, max_n_chunks);

	/* Verify data (up to max_n_chunks) */
	for (i = 0; i < max_n_chunks; i++) {
		struct cfs_dir_chunk_s *chunk = &dir->chunks[i];

		chunk->n_dentries = le16_to_cpu(chunk->n_dentries);
		chunk->chunk_size = le16_to_cpu(chunk->chunk_size);
		chunk->chunk_offset = le64_to_cpu(chunk->chunk_offset);

		if (chunk->chunk_size <
		    sizeof(struct cfs_dentry_s) * chunk->n_dentries)
			return ERR_PTR(-EFSCORRUPTED);

		if (chunk->chunk_size > CFS_MAX_DIR_CHUNK_SIZE)
			return ERR_PTR(-EFSCORRUPTED);

		if (chunk->n_dentries == 0)
			return ERR_PTR(-EFSCORRUPTED);

		if (chunk->chunk_size == 0)
			return ERR_PTR(-EFSCORRUPTED);

		if (chunk->chunk_offset >
		    ctx->descriptor_len - ctx->header.data_offset)
			return ERR_PTR(-EFSCORRUPTED);
	}

	return dir;
}

static char *cfs_dup_payload_path(struct cfs_context_s *ctx,
				  struct cfs_inode_s *ino, u64 index)
{
	const char *v;
	u8 *path;

	if ((ino->st_mode & S_IFMT) != S_IFREG &&
	    (ino->st_mode & S_IFMT) != S_IFLNK) {
		return ERR_PTR(-EINVAL);
	}

	if (ino->payload_length == 0 || ino->payload_length > PATH_MAX)
		return ERR_PTR(-EFSCORRUPTED);

	path = kmalloc(ino->payload_length + 1, GFP_KERNEL);
	if (!path)
		return ERR_PTR(-ENOMEM);

	v = cfs_get_inode_payload(ctx, ino, index, path);
	if (IS_ERR(v)) {
		kfree(path);
		return ERR_CAST(v);
	}

	/* zero terminate */
	path[ino->payload_length] = 0;

	return (char *)path;
}

int cfs_init_inode_data(struct cfs_context_s *ctx, struct cfs_inode_s *ino,
			u64 index, struct cfs_inode_data_s *inode_data)
{
	u8 buf[cfs_dir_size(CFS_N_PRELOAD_DIR_CHUNKS)];
	struct cfs_dir_s *dir;
	int ret = 0;
	size_t i;
	char *path_payload = NULL;

	inode_data->payload_length = ino->payload_length;

	if ((ino->st_mode & S_IFMT) != S_IFDIR || ino->payload_length == 0) {
		inode_data->n_dir_chunks = 0;
	} else {
		u32 n_chunks;

		dir = cfs_dir_read_chunk_header(ctx, ino->payload_length, index,
						buf, sizeof(buf),
						CFS_N_PRELOAD_DIR_CHUNKS);
		if (IS_ERR(dir))
			return PTR_ERR(dir);

		n_chunks = dir->n_chunks;
		inode_data->n_dir_chunks = n_chunks;

		for (i = 0; i < n_chunks && i < CFS_N_PRELOAD_DIR_CHUNKS; i++)
			inode_data->preloaded_dir_chunks[i] = dir->chunks[i];
	}

	if ((ino->st_mode & S_IFMT) == S_IFLNK ||
	    ((ino->st_mode & S_IFMT) == S_IFREG && ino->payload_length > 0)) {
		path_payload = cfs_dup_payload_path(ctx, ino, index);
		if (IS_ERR(path_payload)) {
			ret = PTR_ERR(path_payload);
			goto fail;
		}
	}
	inode_data->path_payload = path_payload;

	ret = cfs_get_digest(ctx, ino, path_payload, inode_data->digest);
	if (ret < 0)
		goto fail;

	inode_data->has_digest = ret != 0;

	inode_data->xattrs_offset = ino->xattrs.off;
	inode_data->xattrs_len = ino->xattrs.len;

	if (inode_data->xattrs_len != 0) {
		/* Validate xattr size */
		if (inode_data->xattrs_len <
			    sizeof(struct cfs_xattr_header_s) ||
		    inode_data->xattrs_len > CFS_MAX_XATTRS_SIZE) {
			ret = -EFSCORRUPTED;
			goto fail;
		}
	}

	return 0;

fail:
	cfs_inode_data_put(inode_data);
	return ret;
}

void cfs_inode_data_put(struct cfs_inode_data_s *inode_data)
{
	inode_data->n_dir_chunks = 0;
	kfree(inode_data->path_payload);
	inode_data->path_payload = NULL;
}

ssize_t cfs_list_xattrs(struct cfs_context_s *ctx,
			struct cfs_inode_data_s *inode_data, char *names,
			size_t size)
{
	u8 *data, *data_end;
	size_t n_xattrs = 0, i;
	ssize_t copied = 0;
	const struct cfs_xattr_header_s *xattrs;
	struct cfs_buf vdata_buf = CFS_VDATA_BUF_INIT;

	if (inode_data->xattrs_len == 0)
		return 0;

	/* xattrs_len basic size req was verified in cfs_init_inode_data */

	xattrs = cfs_get_vdata_buf(ctx, inode_data->xattrs_offset,
				   inode_data->xattrs_len, &vdata_buf);
	if (IS_ERR(xattrs))
		return PTR_ERR(xattrs);

	n_xattrs = le16_to_cpu(xattrs->n_attr);

	/* Verify that array fits */
	if (inode_data->xattrs_len < cfs_xattr_header_size(n_xattrs)) {
		copied = -EFSCORRUPTED;
		goto exit;
	}

	data = ((u8 *)xattrs) + cfs_xattr_header_size(n_xattrs);
	data_end = ((u8 *)xattrs) + inode_data->xattrs_len;

	for (i = 0; i < n_xattrs; i++) {
		const struct cfs_xattr_element_s *e = &xattrs->attr[i];
		u16 this_key_len = le16_to_cpu(e->key_length);
		u16 this_value_len = le16_to_cpu(e->value_length);
		const char *this_key;

		if (this_key_len > XATTR_NAME_MAX ||
		    /* key and data needs to fit in data */
		    data_end - data < this_key_len + this_value_len) {
			copied = -EFSCORRUPTED;
			goto exit;
		}

		this_key = data;
		data += this_key_len + this_value_len;

		if (size) {
			if (size - copied < this_key_len + 1) {
				copied = -E2BIG;
				goto exit;
			}

			memcpy(names + copied, this_key, this_key_len);
			names[copied + this_key_len] = '\0';
		}

		copied += this_key_len + 1;
	}

exit:
	cfs_buf_put(&vdata_buf);

	return copied;
}

int cfs_get_xattr(struct cfs_context_s *ctx,
		  struct cfs_inode_data_s *inode_data, const char *name,
		  void *value, size_t size)
{
	size_t name_len = strlen(name);
	size_t n_xattrs = 0, i;
	struct cfs_xattr_header_s *xattrs;
	u8 *data, *data_end;
	struct cfs_buf vdata_buf = CFS_VDATA_BUF_INIT;
	int res;

	if (inode_data->xattrs_len == 0)
		return -ENODATA;

	/* xattrs_len basic size req was verified in cfs_init_inode_data */

	xattrs = cfs_get_vdata_buf(ctx, inode_data->xattrs_offset,
				   inode_data->xattrs_len, &vdata_buf);
	if (IS_ERR(xattrs))
		return PTR_ERR(xattrs);

	n_xattrs = le16_to_cpu(xattrs->n_attr);

	/* Verify that array fits */
	if (inode_data->xattrs_len < cfs_xattr_header_size(n_xattrs)) {
		res = -EFSCORRUPTED;
		goto exit;
	}

	data = ((u8 *)xattrs) + cfs_xattr_header_size(n_xattrs);
	data_end = ((u8 *)xattrs) + inode_data->xattrs_len;

	for (i = 0; i < n_xattrs; i++) {
		const struct cfs_xattr_element_s *e = &xattrs->attr[i];
		u16 this_key_len = le16_to_cpu(e->key_length);
		u16 this_value_len = le16_to_cpu(e->value_length);
		const char *this_key, *this_value;

		if (this_key_len > XATTR_NAME_MAX ||
		    /* key and data needs to fit in data */
		    data_end - data < this_key_len + this_value_len) {
			res = -EFSCORRUPTED;
			goto exit;
		}

		this_key = data;
		this_value = data + this_key_len;
		data += this_key_len + this_value_len;

		if (this_key_len != name_len ||
		    memcmp(this_key, name, name_len) != 0)
			continue;

		if (size > 0) {
			if (size < this_value_len) {
				res = -E2BIG;
				goto exit;
			}
			memcpy(value, this_value, this_value_len);
		}

		res = this_value_len;
		goto exit;
	}

	res = -ENODATA;

exit:
	return res;
}

static struct cfs_dir_s *
cfs_dir_read_chunk_header_alloc(struct cfs_context_s *ctx, u64 index,
				struct cfs_inode_data_s *inode_data)
{
	size_t chunk_buf_size = cfs_dir_size(inode_data->n_dir_chunks);
	u8 *chunk_buf;
	struct cfs_dir_s *dir;

	chunk_buf = kmalloc(chunk_buf_size, GFP_KERNEL);
	if (!chunk_buf)
		return ERR_PTR(-ENOMEM);

	dir = cfs_dir_read_chunk_header(ctx, inode_data->payload_length, index,
					chunk_buf, chunk_buf_size,
					inode_data->n_dir_chunks);
	if (IS_ERR(dir)) {
		kfree(chunk_buf);
		return ERR_CAST(dir);
	}

	return dir;
}

static struct cfs_dir_chunk_s *
cfs_dir_get_chunk_info(struct cfs_context_s *ctx, u64 index,
		       struct cfs_inode_data_s *inode_data, void **chunks_buf)
{
	struct cfs_dir_s *full_dir;

	if (inode_data->n_dir_chunks <= CFS_N_PRELOAD_DIR_CHUNKS) {
		*chunks_buf = NULL;
		return inode_data->preloaded_dir_chunks;
	}

	full_dir = cfs_dir_read_chunk_header_alloc(ctx, index, inode_data);
	if (IS_ERR(full_dir))
		return ERR_CAST(full_dir);

	*chunks_buf = full_dir;
	return full_dir->chunks;
}

static inline int memcmp2(const void *a, const size_t a_size, const void *b,
			  size_t b_size)
{
	size_t common_size = min(a_size, b_size);
	int res;

	res = memcmp(a, b, common_size);
	if (res != 0 || a_size == b_size)
		return res;

	return a_size < b_size ? -1 : 1;
}

int cfs_dir_iterate(struct cfs_context_s *ctx, u64 index,
		    struct cfs_inode_data_s *inode_data, loff_t first,
		    cfs_dir_iter_cb cb, void *private)
{
	size_t i, j, n_chunks;
	char *namedata, *namedata_end;
	struct cfs_dir_chunk_s *chunks;
	struct cfs_dentry_s *dentries;
	struct cfs_buf vdata_buf = CFS_VDATA_BUF_INIT;
	void *chunks_buf;
	loff_t pos;
	int res;

	n_chunks = inode_data->n_dir_chunks;
	if (n_chunks == 0)
		return 0;

	chunks = cfs_dir_get_chunk_info(ctx, index, inode_data, &chunks_buf);
	if (IS_ERR(chunks))
		return PTR_ERR(chunks);

	pos = 0;
	for (i = 0; i < n_chunks; i++) {
		/* Chunks info are verified/converted in cfs_dir_read_chunk_header */
		u64 chunk_offset = chunks[i].chunk_offset;
		size_t chunk_size = chunks[i].chunk_size;
		size_t n_dentries = chunks[i].n_dentries;

		/* Do we need to look at this chunk */
		if (first >= pos + n_dentries) {
			pos += n_dentries;
			continue;
		}

		/* Read chunk dentries from page cache */
		dentries = cfs_get_vdata_buf(ctx, chunk_offset, chunk_size,
					     &vdata_buf);
		if (IS_ERR(dentries)) {
			res = PTR_ERR(dentries);
			goto exit;
		}

		namedata = ((char *)dentries) +
			   sizeof(struct cfs_dentry_s) * n_dentries;
		namedata_end = ((char *)dentries) + chunk_size;

		for (j = 0; j < n_dentries; j++) {
			struct cfs_dentry_s *dentry = &dentries[j];
			size_t dentry_name_len = dentry->name_len;
			char *dentry_name =
				(char *)namedata + dentry->name_offset;

			/* name needs to fit in namedata */
			if (dentry_name >= namedata_end ||
			    namedata_end - dentry_name < dentry_name_len) {
				res = -EFSCORRUPTED;
				goto exit;
			}

			if (!cfs_validate_filename(dentry_name,
						   dentry_name_len)) {
				res = -EFSCORRUPTED;
				goto exit;
			}

			if (pos++ < first)
				continue;

			if (!cb(private, dentry_name, dentry_name_len,
				le64_to_cpu(dentry->inode_index),
				dentry->d_type)) {
				res = 0;
				goto exit;
			}
		}
	}

	res = 0;
exit:
	kfree(chunks_buf);
	cfs_buf_put(&vdata_buf);
	return res;
}

#define BEFORE_CHUNK 1
#define AFTER_CHUNK 2
// -1 => error, 0 == hit, 1 == name is before chunk, 2 == name is after chunk
static int cfs_dir_lookup_in_chunk(const char *name, size_t name_len,
				   struct cfs_dentry_s *dentries,
				   size_t n_dentries, char *namedata,
				   char *namedata_end, u64 *index_out)
{
	int start_dentry, end_dentry;
	int cmp;

	// This should not happen in a valid fs, and if it does we don't know if
	// the name is before or after the chunk.
	if (n_dentries == 0)
		return -EFSCORRUPTED;

	start_dentry = 0;
	end_dentry = n_dentries - 1;
	while (start_dentry <= end_dentry) {
		int mid_dentry = start_dentry + (end_dentry - start_dentry) / 2;
		struct cfs_dentry_s *dentry = &dentries[mid_dentry];
		size_t dentry_name_len = dentry->name_len;
		char *dentry_name = (char *)namedata + dentry->name_offset;

		/* name needs to fit in namedata */
		if (dentry_name >= namedata_end ||
		    namedata_end - dentry_name < dentry_name_len) {
			return -EFSCORRUPTED;
		}

		cmp = memcmp2(name, name_len, dentry_name, dentry_name_len);
		if (cmp == 0) {
			*index_out = le64_to_cpu(dentry->inode_index);
			return 0;
		}

		if (cmp > 0)
			start_dentry = mid_dentry + 1;
		else
			end_dentry = mid_dentry - 1;
	}

	return cmp > 0 ? AFTER_CHUNK : BEFORE_CHUNK;
}

int cfs_dir_lookup(struct cfs_context_s *ctx, u64 index,
		   struct cfs_inode_data_s *inode_data, const char *name,
		   size_t name_len, u64 *index_out)
{
	int n_chunks, start_chunk, end_chunk;
	char *namedata, *namedata_end;
	struct cfs_dir_chunk_s *chunks;
	struct cfs_dentry_s *dentries;
	void *chunks_buf;
	struct cfs_buf vdata_buf = CFS_VDATA_BUF_INIT;
	int res, r;

	n_chunks = inode_data->n_dir_chunks;
	if (n_chunks == 0)
		return 0;

	chunks = cfs_dir_get_chunk_info(ctx, index, inode_data, &chunks_buf);
	if (IS_ERR(chunks))
		return PTR_ERR(chunks);

	start_chunk = 0;
	end_chunk = n_chunks - 1;

	while (start_chunk <= end_chunk) {
		int mid_chunk = start_chunk + (end_chunk - start_chunk) / 2;

		/* Chunks info are verified/converted in cfs_dir_read_chunk_header */
		u64 chunk_offset = chunks[mid_chunk].chunk_offset;
		size_t chunk_size = chunks[mid_chunk].chunk_size;
		size_t n_dentries = chunks[mid_chunk].n_dentries;

		/* Read chunk dentries from page cache */
		dentries = cfs_get_vdata_buf(ctx, chunk_offset, chunk_size,
					     &vdata_buf);
		if (IS_ERR(dentries)) {
			res = PTR_ERR(dentries);
			goto exit;
		}

		namedata = ((u8 *)dentries) +
			   sizeof(struct cfs_dentry_s) * n_dentries;
		namedata_end = ((u8 *)dentries) + chunk_size;

		r = cfs_dir_lookup_in_chunk(name, name_len, dentries,
					    n_dentries, namedata, namedata_end,
					    index_out);
		if (r < 0) {
			res = r; /* error */
			goto exit;
		} else if (r == 0) {
			res = 1; /* found it */
			goto exit;
		} else if (r == AFTER_CHUNK) {
			start_chunk = mid_chunk + 1;
		} else { /* before */
			end_chunk = mid_chunk - 1;
		}
	}

	/* not found */
	res = 0;

exit:
	kfree(chunks_buf);
	cfs_buf_put(&vdata_buf);
	return res;
}
