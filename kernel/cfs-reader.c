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
#include <linux/vmalloc.h>

#define CFS_BUF_MAXPAGES 256 /* arbitrary limit to avoid extreme memory use */
#define CFS_BUF_PREALLOC_SIZE 4

struct cfs_buf {
	struct page **pages;
	size_t n_pages;
	void *base;
	struct page *prealloc[CFS_BUF_PREALLOC_SIZE]; /* No need for allocation for small buffers */
};

static void cfs_buf_put(struct cfs_buf *buf)
{
	if (buf->pages) {
		if (buf->n_pages == 1)
			kunmap_local(buf->base);
		else
			vm_unmap_ram(buf->base, buf->n_pages);
		for (size_t i = 0; i < buf->n_pages; i++)
			put_page(buf->pages[i]);
		if (buf->n_pages > CFS_BUF_PREALLOC_SIZE)
			kfree(buf->pages);
		buf->pages = NULL;
	}
}

static void *cfs_get_buf(struct cfs_context *ctx, u64 offset, u32 size,
			 struct cfs_buf *buf)
{
	struct inode *inode = ctx->descriptor->f_inode;
	struct address_space *const mapping = inode->i_mapping;
	size_t n_pages, read_pages;
	u64 index, last_index;
	struct page **pages;
	void *base;

	if (buf->pages != NULL) {
		return ERR_PTR(-EINVAL);
	}

	if (offset > ctx->descriptor_len)
		return ERR_PTR(-EFSCORRUPTED);

	if ((offset + size < offset) || (offset + size > ctx->descriptor_len) ||
	    size == 0)
		return ERR_PTR(-EFSCORRUPTED);

	index = offset >> PAGE_SHIFT;
	last_index = (offset + size - 1) >> PAGE_SHIFT;
	n_pages = last_index - index + 1;

	if (n_pages > CFS_BUF_MAXPAGES)
		return ERR_PTR(-ENOMEM);

	if (n_pages > CFS_BUF_PREALLOC_SIZE) {
		pages = kmalloc_array(n_pages, sizeof(struct page *), GFP_KERNEL);
		if (!pages)
			return ERR_PTR(-ENOMEM);
	} else {
		/* Avoid allocation in common (small) cases */
		pages = buf->prealloc;
	}

	for (read_pages = 0; read_pages < n_pages; read_pages++) {
		struct page *page = read_cache_page(mapping, index + read_pages, NULL, NULL);
		if (IS_ERR(page))
			goto nomem;
		pages[read_pages] = page;
	}

	if (n_pages == 1) {
		base = kmap_local_page(pages[0]);
	} else {
		base = vm_map_ram(pages, n_pages, -1);
		if (!base)
			goto nomem;
	}

	buf->pages = pages;
	buf->n_pages = n_pages;
	buf->base = base;

	return base + (offset & (PAGE_SIZE - 1));

 nomem:
	for (size_t i = 0; i < read_pages; i++)
		put_page(pages[i]);
	if (n_pages > CFS_BUF_PREALLOC_SIZE)
		kfree(pages);

	return ERR_PTR(-ENOMEM);
}

static void *cfs_read_data(struct cfs_context *ctx, u64 offset, u64 size, u8 *dest)
{
	loff_t pos = offset;
	size_t copied;

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

static void *cfs_read_vdata(struct cfs_context *ctx, u64 offset, u32 len, char *buf)
{
	void *res;

	if (offset > ctx->descriptor_len - ctx->data_offset)
		return ERR_PTR(-EINVAL);

	if (len > ctx->descriptor_len - ctx->data_offset - offset)
		return ERR_PTR(-EINVAL);

	res = cfs_read_data(ctx, ctx->data_offset + offset, len, buf);
	if (IS_ERR(res)) {
		return ERR_CAST(res);
	}

	return buf;
}

static char *cfs_read_vdata_path(struct cfs_context *ctx, u64 offset, u32 len)
{
	char *path;
	void *res;

	if (len > PATH_MAX)
		return ERR_PTR(-EINVAL);

	path = kmalloc(len + 1, GFP_KERNEL);
	if (!path)
		return ERR_PTR(-ENOMEM);

	res = cfs_read_vdata(ctx, offset, len, path);
	if (IS_ERR(res)) {
		kfree(path);
		return ERR_CAST(res);
	}

	/* zero terminate */
	path[len] = 0;

	return path;
}

int cfs_init_ctx(const char *descriptor_path, const u8 *required_digest,
		 struct cfs_context *ctx_out)
{
	u8 verity_digest[FS_VERITY_MAX_DIGEST_SIZE];
	struct cfs_superblock superblock_buf;
	struct cfs_superblock *superblock;
	enum hash_algo verity_algo;
	struct cfs_context ctx;
	struct file *descriptor;
	loff_t i_size;
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
		    memcmp(required_digest, verity_digest, SHA256_DIGEST_SIZE) != 0) {
			pr_err("ERROR: composefs descriptor has wrong fs-verity digest\n");
			res = -EINVAL;
			goto fail;
		}
	}

	i_size = i_size_read(file_inode(descriptor));
	if (i_size <= (sizeof(struct cfs_superblock) + sizeof(struct cfs_inode_data))) {
		res = -EINVAL;
		goto fail;
	}

	/* Need this temporary ctx for cfs_read_data() */
	ctx.descriptor = descriptor;
	ctx.descriptor_len = i_size;

	superblock = cfs_read_data(&ctx, 0, sizeof(struct cfs_superblock),
				   (u8 *)&superblock_buf);
	if (IS_ERR(superblock)) {
		res = PTR_ERR(superblock);
		goto fail;
	}
	ctx.data_offset = le64_to_cpu(superblock->data_offset);
	ctx.root_inode = le64_to_cpu(superblock->root_inode);

	if (le32_to_cpu(superblock->version) != CFS_VERSION ||
	    le32_to_cpu(superblock->magic) != CFS_MAGIC ||
	    ctx.data_offset > ctx.descriptor_len ||
	    sizeof(struct cfs_superblock) + ctx.root_inode > ctx.descriptor_len) {
		res = -EINVAL;
		goto fail;
	}

	*ctx_out = ctx;
	return 0;

fail:
	fput(descriptor);
	return res;
}

void cfs_ctx_put(struct cfs_context *ctx)
{
	if (ctx->descriptor) {
		fput(ctx->descriptor);
		ctx->descriptor = NULL;
	}
}

static void *cfs_get_inode_buf(struct cfs_context *ctx, u64 offset, u32 len,
			       struct cfs_buf *buf)
{
	if (offset > ctx->descriptor_len - sizeof(struct cfs_superblock))
		return ERR_PTR(-EINVAL);

	if (len > ctx->descriptor_len - sizeof(struct cfs_superblock) - offset)
		return ERR_PTR(-EINVAL);

	return cfs_get_buf(ctx, sizeof(struct cfs_superblock) + offset, len, buf);
}

static void *cfs_get_vdata_buf(struct cfs_context *ctx, u64 offset, u32 len,
			       struct cfs_buf *buf)
{
	if (offset > ctx->descriptor_len - ctx->data_offset)
		return ERR_PTR(-EINVAL);

	if (len > ctx->descriptor_len - ctx->data_offset - offset)
		return ERR_PTR(-EINVAL);

	return cfs_get_buf(ctx, ctx->data_offset + offset, len, buf);
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

int cfs_init_inode(struct cfs_context *ctx, u64 index,
		   struct inode *inode,
		   struct cfs_inode_extra_data *inode_data)
{
	struct cfs_buf vdata_buf = { NULL };
	struct cfs_inode_data *disk_data;
	char *path_payload = NULL;
	void *res;
	int ret = 0;
	u64 variable_data_off;
	u32 variable_data_len;
	u64 digest_off;
	u32 digest_len;
	u32 st_type;

	disk_data = cfs_get_inode_buf(ctx, index, sizeof(struct cfs_inode_data), &vdata_buf);
	if (IS_ERR(disk_data))
		return PTR_ERR(disk_data);

	inode->i_ino = index;

	inode->i_mode = le32_to_cpu(disk_data->st_mode);
	set_nlink(inode, le32_to_cpu(disk_data->st_nlink));
	inode->i_uid = make_kuid(current_user_ns(), le32_to_cpu(disk_data->st_uid));
	inode->i_gid = make_kgid(current_user_ns(), le32_to_cpu(disk_data->st_gid));
	inode->i_rdev = le32_to_cpu(disk_data->st_rdev);
	inode->i_size = le64_to_cpu(disk_data->st_size);
	inode->i_mtime.tv_sec = le64_to_cpu(disk_data->st_mtim_sec);
	inode->i_mtime.tv_nsec = le32_to_cpu(disk_data->st_mtim_nsec);
	inode->i_ctime.tv_sec = le64_to_cpu(disk_data->st_ctim_sec);
	inode->i_ctime.tv_nsec = le32_to_cpu(disk_data->st_ctim_nsec);
	inode->i_atime = inode->i_mtime;

	variable_data_off = le64_to_cpu(disk_data->variable_data.off);
	variable_data_len = le32_to_cpu(disk_data->variable_data.len);

	st_type = inode->i_mode & S_IFMT;
	if (st_type == S_IFDIR) {
		inode_data->dirents_offset = variable_data_off;
		inode_data->dirents_len = variable_data_len;
	} else if ((st_type == S_IFLNK || st_type == S_IFREG) &&
		   variable_data_len > 0) {
		path_payload = cfs_read_vdata_path(ctx, variable_data_off, variable_data_len);
		if (IS_ERR(path_payload)) {
			ret = PTR_ERR(path_payload);
			goto fail;
		}
		inode_data->path_payload = path_payload;
	}

	if (st_type == S_IFLNK) {
		/* Symbolic link must have a non-empty target */
		if (!inode_data->path_payload) {
			ret = -EFSCORRUPTED;
			goto fail;
		}
	} else if (st_type == S_IFREG) {
		/* Regular file must have backing file except empty files */
		if ((inode_data->path_payload && inode->i_size == 0) ||
		    (!inode_data->path_payload && inode->i_size > 0)) {
			    ret = -EFSCORRUPTED;
			    goto fail;
		}
	}

	inode_data->xattrs_offset = le64_to_cpu(disk_data->xattrs.off);
	inode_data->xattrs_len = le32_to_cpu(disk_data->xattrs.len);

	if (inode_data->xattrs_len != 0) {
		/* Validate xattr size */
		if (inode_data->xattrs_len < sizeof(struct cfs_xattr_header)) {
			ret = -EFSCORRUPTED;
			goto fail;
		}
	}

	digest_off = le64_to_cpu(disk_data->digest.off);
	digest_len = le32_to_cpu(disk_data->digest.len);

	if (digest_len > 0) {
		if (digest_len != SHA256_DIGEST_SIZE) {
			ret = -EFSCORRUPTED;
			goto fail;
		}

		res = cfs_read_vdata(ctx, digest_off, digest_len, inode_data->digest);
		if (IS_ERR(res)) {
			ret = PTR_ERR(res);
			goto fail;
		}
		inode_data->has_digest = true;
	}

	cfs_buf_put(&vdata_buf);
	return 0;

fail:
	cfs_buf_put(&vdata_buf);
	return ret;
}

void cfs_inode_extra_data_put(struct cfs_inode_extra_data *inode_data)
{
	kfree(inode_data->path_payload);
	inode_data->path_payload = NULL;
}

ssize_t cfs_list_xattrs(struct cfs_context *ctx,
			struct cfs_inode_extra_data *inode_data, char *names, size_t size)
{
	const struct cfs_xattr_header *xattrs;
	struct cfs_buf vdata_buf = { NULL };
	size_t n_xattrs = 0;
	u8 *data, *data_end;
	ssize_t copied = 0;

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

	for (size_t i = 0; i < n_xattrs; i++) {
		const struct cfs_xattr_element *e = &xattrs->attr[i];
		u16 this_value_len = le16_to_cpu(e->value_length);
		u16 this_key_len = le16_to_cpu(e->key_length);
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

int cfs_get_xattr(struct cfs_context *ctx, struct cfs_inode_extra_data *inode_data,
		  const char *name, void *value, size_t size)
{
	struct cfs_xattr_header *xattrs;
	struct cfs_buf vdata_buf = { NULL };
	size_t name_len = strlen(name);
	size_t n_xattrs = 0;
	u8 *data, *data_end;
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

	for (size_t i = 0; i < n_xattrs; i++) {
		const struct cfs_xattr_element *e = &xattrs->attr[i];
		u16 this_value_len = le16_to_cpu(e->value_length);
		u16 this_key_len = le16_to_cpu(e->key_length);
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

		if (this_key_len != name_len || memcmp(this_key, name, name_len) != 0)
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

int cfs_dir_iterate(struct cfs_context *ctx, u64 index,
		    struct cfs_inode_extra_data *inode_data, loff_t first,
		    cfs_dir_iter_cb cb, void *private)
{
	struct cfs_buf vdata_buf = { NULL };
	const struct cfs_dir_header *dir;
	u32 n_dirents;
	char *namedata, *namedata_end;
	loff_t pos;
	int res;

	if (inode_data->dirents_len == 0)
		return 0;

	dir = cfs_get_vdata_buf(ctx, inode_data->dirents_offset,
				inode_data->dirents_len, &vdata_buf);
	if (IS_ERR(dir))
		return PTR_ERR(dir);

	n_dirents = le32_to_cpu(dir->n_dirents);

	// This should not happen in a valid fs, it should have had dirents_len ==  0
	if (n_dirents == 0) {
		res = -EFSCORRUPTED;
		goto exit;
	}

	if (first >= n_dirents) {
		res = 0;
		goto exit;
	}

	namedata = ((u8 *)dir) + cfs_dir_header_size(n_dirents);
	namedata_end = ((u8 *)dir) + inode_data->dirents_len;
	pos = 0;
	for (size_t i = 0; i < n_dirents; i++) {
		const struct cfs_dirent *dirent = &dir->dirents[i];
		char *dirent_name = (char *)namedata + le32_to_cpu(dirent->name_offset);
		size_t dirent_name_len = dirent->name_len;

		/* name needs to fit in namedata */
		if (dirent_name >= namedata_end ||
		    namedata_end - dirent_name < dirent_name_len) {
			res = -EFSCORRUPTED;
			goto exit;
		}

		if (!cfs_validate_filename(dirent_name, dirent_name_len)) {
			res = -EFSCORRUPTED;
			goto exit;
		}

		if (pos++ < first)
			continue;

		if (!cb(private, dirent_name, dirent_name_len,
			le64_to_cpu(dirent->inode_index), dirent->d_type)) {
			break;
		}
	}

	res = 0;
exit:
	cfs_buf_put(&vdata_buf);
	return res;
}

int cfs_dir_lookup(struct cfs_context *ctx, u64 index,
		   struct cfs_inode_extra_data *inode_data, const char *name,
		   size_t name_len, u64 *index_out)
{
	struct cfs_buf vdata_buf = { NULL };
	const struct cfs_dir_header *dir;
	u32 start_dirent, end_dirent, n_dirents;
	char *namedata, *namedata_end;
	int cmp, res;

	if (inode_data->dirents_len == 0)
		return 0;

	dir = cfs_get_vdata_buf(ctx, inode_data->dirents_offset,
				inode_data->dirents_len, &vdata_buf);
	if (IS_ERR(dir))
		return PTR_ERR(dir);

	n_dirents = le32_to_cpu(dir->n_dirents);

	// This should not happen in a valid fs, it should have had dirents_len ==  0
	if (n_dirents == 0) {
		res = -EFSCORRUPTED;
		goto exit;
	}

	namedata = ((u8 *)dir) + cfs_dir_header_size(n_dirents);
	namedata_end = ((u8 *)dir) + inode_data->dirents_len;

	start_dirent = 0;
	end_dirent = n_dirents - 1;
	while (start_dirent <= end_dirent) {
		int mid_dirent = start_dirent + (end_dirent - start_dirent) / 2;
		const struct cfs_dirent *dirent = &dir->dirents[mid_dirent];
		char *dirent_name = (char *)namedata + le32_to_cpu(dirent->name_offset);
		size_t dirent_name_len = dirent->name_len;

		/* name needs to fit in namedata */
		if (dirent_name >= namedata_end ||
		    namedata_end - dirent_name < dirent_name_len) {
			res = -EFSCORRUPTED;
			goto exit;
		}

		cmp = memcmp2(name, name_len, dirent_name, dirent_name_len);
		if (cmp == 0) {
			*index_out = le64_to_cpu(dirent->inode_index);
			res = 1;
			goto exit;
		}

		if (cmp > 0)
			start_dirent = mid_dirent + 1;
		else
			end_dirent = mid_dirent - 1;
	}

	/* not found */
	res = 0;

exit:
	cfs_buf_put(&vdata_buf);
	return res;
}
