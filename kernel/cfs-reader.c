/*
 * composefs
 *
 * Copyright (C) 2021 Giuseppe Scrivano
 * Copyright (C) 2022 Alexander Larsson
 *
 * This file is released under the GPL.
 */

#include "cfs-internals.h"

#include <linux/string.h>
#include <linux/kernel_read_file.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/bsearch.h>
#include <linux/overflow.h>
#include <linux/overflow.h>
#include <linux/pagemap.h>
#include <linux/unaligned/packed_struct.h>
#include <linux/sched/mm.h>

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
	struct folio *folio;
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

		folio = read_cache_folio(mapping, index, NULL, NULL);
		if (IS_ERR(folio))
			return folio;

		page = folio_file_page(folio, index);
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
			fput(descriptor);
			return res;
		}
		if (verity_algo != HASH_ALGO_SHA256 ||
		    memcmp(required_digest, verity_digest,
			   SHA256_DIGEST_SIZE) != 0) {
			pr_err("ERROR: composefs descriptor has wrong fs-verity digest\n");
			fput(descriptor);
			return -EINVAL;
		}
	}

	i_size = i_size_read(file_inode(descriptor));
	if (i_size <=
	    (sizeof(struct cfs_header_s) + sizeof(struct cfs_inode_s))) {
		fput(descriptor);
		return -EINVAL;
	}

	/* Need this temporary ctx for cfs_read_data() */
	ctx.descriptor = descriptor;
	ctx.descriptor_len = i_size;

	header = cfs_read_data(&ctx, 0, sizeof(struct cfs_header_s),
			       (u8 *)&ctx.header);
	if (IS_ERR(header)) {
		fput(descriptor);
		return PTR_ERR(header);
	}
	header->magic = cfs_u32_from_file(header->magic);
	header->data_offset = cfs_u64_from_file(header->data_offset);
	header->root_inode = cfs_u64_from_file(header->root_inode);

	if (header->magic != CFS_MAGIC ||
	    header->data_offset > ctx.descriptor_len ||
	    sizeof(struct cfs_header_s) + header->root_inode >
		    ctx.descriptor_len) {
		fput(descriptor);
		return -EINVAL;
	}

	*ctx_out = ctx;
	return 0;
}

void cfs_destroy_ctx(struct cfs_context_s *ctx)
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
	size = MIN(remaining, max_size);
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

static void *cfs_read_vdata(struct cfs_context_s *ctx, u64 offset, u32 len,
			    void *dest)
{
	if (!dest)
		return NULL;

	return cfs_read_data(ctx, ctx->header.data_offset + offset, len, dest);
}

static void *cfs_get_vdata(struct cfs_context_s *ctx,
			   const struct cfs_vdata_s vdata, void *dest)
{
	return cfs_read_vdata(ctx, vdata.off, vdata.len, dest);
}

static void *cfs_alloc_vdata(struct cfs_context_s *ctx,
			     const struct cfs_vdata_s vdata)
{
	u8 *buf;
	void *res;

	buf = kmalloc(vdata.len, GFP_KERNEL);
	if (!buf)
		return ERR_PTR(-ENOMEM);

	res = cfs_get_vdata(ctx, vdata, buf);
	if (IS_ERR(res))
		kfree(buf);

	return res;
}

static u32 cfs_read_u32(u8 **data)
{
	u32 v = cfs_u32_from_file(__get_unaligned_cpu32(*data));
	*data += sizeof(u32);
	return v;
}

static u64 cfs_read_u64(u8 **data)
{
	u64 v = cfs_u64_from_file(__get_unaligned_cpu64(*data));
	*data += sizeof(u64);
	return v;
}

struct cfs_inode_s *cfs_get_ino_index(struct cfs_context_s *ctx, u64 index,
				      struct cfs_inode_s *ino)
{
	u64 offset = index;
	u8 buffer[sizeof(
		struct cfs_inode_s)]; /* This will fix the maximal encoded size */
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
	/* Shouldn't happen, but lets check */
	if (inode_size > sizeof(buffer))
		return ERR_PTR(-EFSCORRUPTED);

	if (CFS_INODE_FLAG_CHECK(ino->flags, PAYLOAD)) {
		ino->payload_length = cfs_read_u32(&data);
	} else {
		ino->payload_length = 0;
	}

	if (CFS_INODE_FLAG_CHECK(ino->flags, MODE)) {
		ino->st_mode = cfs_read_u32(&data);
	} else {
		ino->st_mode = CFS_INODE_DEFAULT_MODE;
	}

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

	if (CFS_INODE_FLAG_CHECK(ino->flags, RDEV)) {
		ino->st_rdev = cfs_read_u32(&data);
	} else {
		ino->st_rdev = CFS_INODE_DEFAULT_RDEV;
	}

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

	if (CFS_INODE_FLAG_CHECK(ino->flags, LOW_SIZE)) {
		ino->st_size = cfs_read_u32(&data);
	} else {
		ino->st_size = 0;
	}

	if (CFS_INODE_FLAG_CHECK(ino->flags, HIGH_SIZE)) {
		ino->st_size += (u64)cfs_read_u32(&data) << 32;
	}

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

const uint8_t *cfs_get_digest(struct cfs_context_s *ctx,
			      struct cfs_inode_s *ino, const char *payload,
			      u8 digest_buf[SHA256_DIGEST_SIZE])
{
	if (CFS_INODE_FLAG_CHECK(ino->flags, DIGEST)) {
		return ino->digest;
	}

	if (CFS_INODE_FLAG_CHECK(ino->flags,
				 DIGEST_FROM_PAYLOAD && payload != NULL)) {
		if (cfs_digest_from_payload(payload, ino->payload_length,
					    digest_buf) == 0)
			return digest_buf;
	}

	return NULL;
}

static bool cfs_validate_filename(const char *name, size_t name_len)
{
	if (name_len == 0)
		return false;

	if (name_len == 1 && name[0] == '.')
		return false;

	if (name_len == 2 && name[0] == '.' && name[1] == '.')
		return false;

	if (memchr(name, '/', name_len) != NULL)
		return false;

	return true;
}

struct cfs_dir_s *cfs_dir_read_chunk_header(struct cfs_context_s *ctx,
					    u32 payload_length, u64 index,
					    u8 *chunk_buf,
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
					  MIN(chunk_buf_size, payload_length));
	if (IS_ERR(dir))
		return ERR_CAST(dir);

	n_chunks = dir->n_chunks = cfs_u32_from_file(dir->n_chunks);

	/* Don't support n_chunks == 0, the canonical version of that is payload_length == 0 */
	if (n_chunks == 0)
		return ERR_PTR(-EFSCORRUPTED);

	if (payload_length != cfs_dir_size(n_chunks))
		return ERR_PTR(-EFSCORRUPTED);

	max_n_chunks = MIN(n_chunks, max_n_chunks);

	/* Verify data (up to max_n_chunks) */
	for (i = 0; i < max_n_chunks; i++) {
		struct cfs_dir_chunk_s *chunk = &dir->chunks[i];
		chunk->n_dentries = cfs_u16_from_file(chunk->n_dentries);
		chunk->chunk_size = cfs_u16_from_file(chunk->chunk_size);
		chunk->chunk_offset = cfs_u64_from_file(chunk->chunk_offset);

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

int cfs_init_inode_data(struct cfs_context_s *ctx, struct cfs_inode_s *ino,
			u64 index, struct cfs_inode_data_s *inode_data)
{
	u8 buf[cfs_dir_size(CFS_N_PRELOAD_DIR_CHUNKS)];
	struct cfs_dir_s *dir;
	size_t i;

	inode_data->payload_length = ino->payload_length;

	if ((ino->st_mode & S_IFMT) != S_IFDIR || ino->payload_length == 0) {
		inode_data->n_dir_chunks = 0;
	} else {
		dir = cfs_dir_read_chunk_header(ctx, ino->payload_length, index,
						buf, sizeof(buf),
						CFS_N_PRELOAD_DIR_CHUNKS);
		if (IS_ERR(dir))
			return PTR_ERR(dir);

		inode_data->n_dir_chunks = dir->n_chunks;

		for (i = 0; i < inode_data->n_dir_chunks &&
			    i < CFS_N_PRELOAD_DIR_CHUNKS;
		     i++)
			inode_data->preloaded_dir_chunks[i] = dir->chunks[i];
	}

	return 0;
}

struct cfs_xattr_header_s *cfs_get_xattrs(struct cfs_context_s *ctx,
					  struct cfs_inode_s *ino)
{
	struct cfs_xattr_header_s *xattrs = NULL;
	u8 *data, *data_end;
	size_t n_xattrs, i;

	if (ino->xattrs.len == 0) {
		return NULL;
	}

	/* Gotta be large enought to fit the n_attr */
	if (ino->xattrs.len < sizeof(struct cfs_xattr_header_s))
		return ERR_PTR(-EFSCORRUPTED);

	/* Don't allocate arbitriary size xattrs */
	if (ino->xattrs.len > CFS_MAX_XATTRS_SIZE)
		return ERR_PTR(-EFSCORRUPTED);

	xattrs = cfs_alloc_vdata(ctx, ino->xattrs);
	if (IS_ERR(xattrs))
		return ERR_CAST(xattrs);

	n_xattrs = xattrs->n_attr = cfs_u16_from_file(xattrs->n_attr);

	/* Verify that array fits */
	if (ino->xattrs.len < cfs_xattr_header_size(n_xattrs))
		goto corrupted;

	data = ((u8 *)xattrs) + cfs_xattr_header_size(n_xattrs);
	data_end = ((u8 *)xattrs) + ino->xattrs.len;

	/* Verify and convert all keys and value sizes upfront */
	for (i = 0; i < n_xattrs; i++) {
		struct cfs_xattr_element_s *e = &xattrs->attr[i];
		uint16_t key_len = e->key_length =
			cfs_u16_from_file(e->key_length);
		uint16_t value_len = e->value_length =
			cfs_u16_from_file(e->value_length);
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

ssize_t cfs_list_xattrs(struct cfs_xattr_header_s *xattrs, char *names,
			size_t size)
{
	u8 *data;
	size_t n_xattrs = 0, i;
	ssize_t copied = 0;

	if (xattrs == NULL)
		return 0;

	/* The contents was verified in cfs_get_xattrs, so trust it here */
	n_xattrs = xattrs->n_attr;

	data = ((u8 *)xattrs) + cfs_xattr_header_size(n_xattrs);

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

int cfs_get_xattr(struct cfs_xattr_header_s *xattrs, const char *name,
		  void *value, size_t size)
{
	size_t name_len = strlen(name);
	size_t n_xattrs = 0, i;
	u8 *data;

	if (xattrs == 0)
		return -ENODATA;

	if (name_len > XATTR_NAME_MAX)
		return -ENODATA;

	/* The contents was verified in cfs_get_xattrs, so trust it here */
	n_xattrs = xattrs->n_attr;

	data = ((u8 *)xattrs) + cfs_xattr_header_size(n_xattrs);

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
	size_t common_size = MIN(a_size, b_size);
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
				cfs_u64_from_file(dentry->inode_index),
				dentry->d_type)) {
				res = 0;
				goto exit;
			}
		}
	}

	res = 0;
exit:
	if (chunks_buf)
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
	if (n_dentries == 0) {
		return -EFSCORRUPTED;
	}

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
			*index_out = cfs_u64_from_file(dentry->inode_index);
			return 0;
		}

		if (cmp > 0) {
			start_dentry = mid_dentry + 1;
		} else {
			end_dentry = mid_dentry - 1;
		}
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
	if (IS_ERR(chunks)) {
		return PTR_ERR(chunks);
	}

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
		} else /* before */ {
			end_chunk = mid_chunk - 1;
		}
	}

	/* not found */
	res = 0;

exit:
	if (chunks_buf)
		kfree(chunks_buf);
	cfs_buf_put(&vdata_buf);
	return res;
}

char *cfs_dup_payload_path(struct cfs_context_s *ctx, struct cfs_inode_s *ino,
			   u64 index)
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
