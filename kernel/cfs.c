/*
 * composefs
 *
 * Copyright (C) 2000 Linus Torvalds.
 *               2000 Transmeta Corp.
 * Copyright (C) 2021 Giuseppe Scrivano
 * Copyright (C) 2022 Alexander Larsson
 *
 * This file is released under the GPL.
 */

#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/time.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/backing-dev.h>
#include <linux/sched.h>
#include <linux/parser.h>
#include <linux/xattr.h>
#include <linux/magic.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/fs_context.h>
#include <linux/fs_parser.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/exportfs.h>
#include <linux/version.h>

#include "cfs-internals.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Giuseppe Scrivano <gscrivan@redhat.com>");

struct cfs_info {
	struct cfs_context_s cfs_ctx;

	struct vfsmount *root_mnt;

	char *base_path;

	size_t n_bases;
	struct file **bases;

	bool noverity;
	bool has_digest;
	uint8_t digest[SHA256_DIGEST_SIZE]; /* fs-verity digest */
};

struct cfs_inode {
	/* must be first for clear in cfs_alloc_inode to work */
	struct inode vfs_inode;

	struct cfs_inode_data_s inode_data;
};

static inline struct cfs_inode *CFS_I(struct inode *inode)
{
	return container_of(inode, struct cfs_inode, vfs_inode);
}

static struct file empty_file;

static const struct file_operations cfs_file_operations;
static const struct vm_operations_struct generic_file_vm_ops;

static const struct super_operations cfs_ops;
static const struct file_operations cfs_dir_operations;
static const struct inode_operations cfs_dir_inode_operations;
static const struct inode_operations cfs_file_inode_operations;
static const struct inode_operations cfs_link_inode_operations;

static const struct xattr_handler *cfs_xattr_handlers[];
static const struct export_operations cfs_export_operations;

static const struct address_space_operations cfs_aops = {
	.direct_IO = noop_direct_IO,
};

static ssize_t cfs_listxattr(struct dentry *dentry, char *names, size_t size);

/* copied from overlayfs.  */
static unsigned int cfs_split_lowerdirs(char *str)
{
	unsigned int ctr = 1;
	char *s, *d;

	for (s = d = str;; s++, d++) {
		if (*s == '\\') {
			s++;
		} else if (*s == ':') {
			*d = '\0';
			ctr++;
			continue;
		}
		*d = *s;
		if (!*s)
			break;
	}
	return ctr;
}

static struct inode *cfs_make_inode(struct cfs_context_s *ctx,
				    struct super_block *sb, ino_t ino_num,
				    struct cfs_inode_s *ino,
				    const struct inode *dir)
{
	struct cfs_xattr_header_s *xattrs = NULL;
	struct cfs_inode *cino;
	struct inode *inode = NULL;
	struct cfs_inode_data_s inode_data = { 0 };
	int ret, res;

	res = cfs_init_inode_data(ctx, ino, ino_num, &inode_data);
	if (res < 0) {
		ret = res;
		goto fail;
	}

	inode = new_inode(sb);
	if (inode) {
		inode_init_owner(&init_user_ns, inode, dir, ino->st_mode);
		inode->i_mapping->a_ops = &cfs_aops;
		mapping_set_gfp_mask(inode->i_mapping, GFP_HIGHUSER);
		mapping_set_unevictable(inode->i_mapping);

		cino = CFS_I(inode);
		cino->inode_data = inode_data;

		inode->i_ino = ino_num;
		set_nlink(inode, ino->st_nlink);
		inode->i_rdev = ino->st_rdev;
		inode->i_uid = make_kuid(current_user_ns(), ino->st_uid);
		inode->i_gid = make_kgid(current_user_ns(), ino->st_gid);
		inode->i_mode = ino->st_mode;
		inode->i_atime = ino->st_mtim;
		inode->i_mtime = ino->st_mtim;
		inode->i_ctime = ino->st_ctim;

		switch (ino->st_mode & S_IFMT) {
		case S_IFREG:
			inode->i_op = &cfs_file_inode_operations;
			inode->i_fop = &cfs_file_operations;
			inode->i_size = ino->st_size;
			break;
		case S_IFLNK:
			inode->i_link = cino->inode_data.path_payload;
			inode->i_op = &cfs_link_inode_operations;
			inode->i_fop = &cfs_file_operations;
			break;
		case S_IFDIR:
			inode->i_op = &cfs_dir_inode_operations;
			inode->i_fop = &cfs_dir_operations;
			inode->i_size = 4096;
			break;
		case S_IFCHR:
		case S_IFBLK:
			if (current_user_ns() != &init_user_ns) {
				ret = -EPERM;
				goto fail;
			}
			fallthrough;
		default:
			inode->i_op = &cfs_file_inode_operations;
			init_special_inode(inode, ino->st_mode, ino->st_rdev);
			break;
		}
	}
	return inode;

fail:
	if (inode)
		iput(inode);
	if (xattrs)
		kfree(xattrs);
	cfs_inode_data_put(&inode_data);
	return ERR_PTR(ret);
}

static struct inode *cfs_get_root_inode(struct super_block *sb)
{
	struct cfs_info *fsi = sb->s_fs_info;
	struct cfs_inode_s ino_buf;
	struct cfs_inode_s *ino;
	u64 index;

	ino = cfs_get_root_ino(&fsi->cfs_ctx, &ino_buf, &index);
	if (IS_ERR(ino))
		return ERR_CAST(ino);

	return cfs_make_inode(&fsi->cfs_ctx, sb, index, ino, NULL);
}

static bool cfs_iterate_cb(void *private, const char *name, int name_len,
			   u64 ino, unsigned int dtype)
{
	struct dir_context *ctx = private;
	bool ret;

	ret = dir_emit(ctx, name, name_len, ino, dtype);
	if (ret == false)
		return ret;

	ctx->pos++;
	return ret;
}

static int cfs_iterate(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file->f_inode;
	struct cfs_info *fsi = inode->i_sb->s_fs_info;
	struct cfs_inode *cino = CFS_I(inode);

	if (!dir_emit_dots(file, ctx))
		return 0;

	return cfs_dir_iterate(&fsi->cfs_ctx, inode->i_ino, &cino->inode_data,
			       ctx->pos - 2, cfs_iterate_cb, ctx);
}

static struct dentry *cfs_lookup(struct inode *dir, struct dentry *dentry,
				 unsigned int flags)
{
	struct cfs_info *fsi = dir->i_sb->s_fs_info;
	struct cfs_inode *cino = CFS_I(dir);
	struct cfs_inode_s ino_buf;
	struct inode *inode;
	struct cfs_inode_s *ino_s;
	u64 index;
	int ret;

	if (dentry->d_name.len > NAME_MAX)
		return ERR_PTR(-ENAMETOOLONG);

	ret = cfs_dir_lookup(&fsi->cfs_ctx, dir->i_ino, &cino->inode_data,
			     dentry->d_name.name, dentry->d_name.len, &index);
	if (ret < 0)
		return ERR_PTR(ret);
	if (ret == 0)
		goto return_negative;

	ino_s = cfs_get_ino_index(&fsi->cfs_ctx, index, &ino_buf);
	if (IS_ERR(ino_s))
		return ERR_CAST(ino_s);

	inode = cfs_make_inode(&fsi->cfs_ctx, dir->i_sb, index, ino_s, dir);
	if (IS_ERR(inode))
		return ERR_CAST(inode);

	return d_splice_alias(inode, dentry);

return_negative:
	d_add(dentry, NULL);
	return NULL;
}

static const struct file_operations cfs_dir_operations = {
	.llseek = generic_file_llseek,
	.read = generic_read_dir,
	.iterate_shared = cfs_iterate,
};

static const struct inode_operations cfs_dir_inode_operations = {
	.lookup = cfs_lookup,
	.listxattr = cfs_listxattr,
};

static const struct inode_operations cfs_link_inode_operations = {
	.get_link = simple_get_link,
	.listxattr = cfs_listxattr,
};

static void digest_to_string(const uint8_t *digest, char *buf)
{
	static const char hexchars[] = "0123456789abcdef";
	uint32_t i, j;

	for (i = 0, j = 0; i < SHA256_DIGEST_SIZE; i++, j += 2) {
		uint8_t byte = digest[i];
		buf[j] = hexchars[byte >> 4];
		buf[j + 1] = hexchars[byte & 0xF];
	}
	buf[j] = '\0';
}

static int xdigit_value(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	return -1;
}

static int digest_from_string(const char *digest_str, uint8_t *digest)
{
	size_t i, j;

	for (i = 0, j = 0; i < SHA256_DIGEST_SIZE; i += 1, j += 2) {
		int big, little;

		if (digest_str[j] == 0 || digest_str[j + 1] == 0)
			return -EINVAL; /* Too short string */

		big = xdigit_value(digest_str[j]);
		little = xdigit_value(digest_str[j + 1]);

		if (big == -1 || little == -1)
			return -EINVAL; /* Not hex digit */

		digest[i] = (big << 4) | little;
	}

	if (digest_str[j] != 0)
		return -EINVAL; /* Too long string */

	return 0;
}

/*
 * Display the mount options in /proc/mounts.
 */
static int cfs_show_options(struct seq_file *m, struct dentry *root)
{
	struct cfs_info *fsi = root->d_sb->s_fs_info;

	if (fsi->noverity)
		seq_printf(m, ",noverity");
	if (fsi->base_path)
		seq_printf(m, ",basedir=%s", fsi->base_path);
	if (fsi->has_digest) {
		char buf[SHA256_DIGEST_SIZE * 2 + 1];
		digest_to_string(fsi->digest, buf);
		seq_printf(m, ",digest=%s", buf);
	}

	return 0;
}

static struct kmem_cache *cfs_inode_cachep;

static struct inode *cfs_alloc_inode(struct super_block *sb)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 18, 0))
	struct cfs_inode *cino = kmem_cache_alloc(cfs_inode_cachep, GFP_KERNEL);
#else
	struct cfs_inode *cino =
		alloc_inode_sb(sb, cfs_inode_cachep, GFP_KERNEL);
#endif

	if (!cino)
		return NULL;

	memset((u8 *)cino + sizeof(struct inode), 0,
	       sizeof(struct cfs_inode) - sizeof(struct inode));

	return &cino->vfs_inode;
}

static void cfs_destroy_inode(struct inode *inode)
{
	struct cfs_inode *cino = CFS_I(inode);

	cfs_inode_data_put(&cino->inode_data);
}

static void cfs_free_inode(struct inode *inode)
{
	struct cfs_inode *cino = CFS_I(inode);

	kmem_cache_free(cfs_inode_cachep, cino);
}

static void cfs_put_super(struct super_block *sb)
{
	struct cfs_info *fsi = sb->s_fs_info;
	size_t i;

	if (fsi->root_mnt)
		kern_unmount(fsi->root_mnt);
	cfs_ctx_put(&fsi->cfs_ctx);
	if (fsi->bases) {
		for (i = 0; i < fsi->n_bases; i++)
			fput(fsi->bases[i]);
		kfree(fsi->bases);
	}
	if (fsi->base_path)
		kfree(fsi->base_path);

	kfree(fsi);
}

static const struct super_operations cfs_ops = {
	.statfs = simple_statfs,
	.drop_inode = generic_delete_inode,
	.show_options = cfs_show_options,
	.put_super = cfs_put_super,
	.destroy_inode = cfs_destroy_inode,
	.alloc_inode = cfs_alloc_inode,
	.free_inode = cfs_free_inode,
};

enum cfs_param {
	Opt_base_path,
	Opt_digest,
	Opt_verity,
};

const struct fs_parameter_spec cfs_parameters[] = {
	fsparam_string("basedir", Opt_base_path),
	fsparam_string("digest", Opt_digest),
	fsparam_flag_no("verity", Opt_verity),
	{}
};

static int cfs_parse_param(struct fs_context *fc, struct fs_parameter *param)
{
	struct fs_parse_result result;
	struct cfs_info *fsi = fc->s_fs_info;
	int opt, r;

	opt = fs_parse(fc, cfs_parameters, param, &result);
	if (opt == -ENOPARAM)
		return vfs_parse_fs_param_source(fc, param);
	if (opt < 0)
		return opt;

	switch (opt) {
	case Opt_base_path:
		kfree(fsi->base_path);
		/* Take ownership.  */
		fsi->base_path = param->string;
		param->string = NULL;
		break;
	case Opt_digest:
		r = digest_from_string(param->string, fsi->digest);
		if (r < 0)
			return r;
		fsi->has_digest = true;
		break;
	case Opt_verity:
		fsi->noverity = !result.boolean;
		break;
	}

	return 0;
}

static int cfs_fill_super(struct super_block *sb, struct fs_context *fc)
{
	struct cfs_info *fsi = sb->s_fs_info;
	struct vfsmount *root_mnt = NULL;
	struct file **bases = NULL;
	struct path rootpath = {};
	size_t numlower = 0;
	struct inode *inode;
	int ret;

	if (sb->s_root)
		return -EINVAL;

	/* Set up the inode allocator early */
	sb->s_op = &cfs_ops;
	sb->s_flags |= SB_RDONLY;
	sb->s_magic = CFS_MAGIC;
	sb->s_xattr = cfs_xattr_handlers;
	sb->s_export_op = &cfs_export_operations;

	ret = kern_path("/", LOOKUP_DIRECTORY, &rootpath);
	if (ret) {
		pr_err("failed to resolve root path: %d\n", ret);
		goto fail;
	}

	root_mnt = clone_private_mount(&rootpath);
	path_put_init(&rootpath);
	if (IS_ERR(root_mnt)) {
		ret = PTR_ERR(root_mnt);
		goto fail;
	}

	if (fsi->base_path) {
		char *lower, *splitlower = NULL;
		size_t i;
		struct file *f;

		ret = -ENOMEM;
		splitlower = kstrdup(fsi->base_path, GFP_KERNEL);
		if (!splitlower)
			goto fail;

		ret = -EINVAL;
		numlower = cfs_split_lowerdirs(splitlower);
		if (numlower > CFS_MAX_STACK) {
			pr_err("too many lower directories, limit is %d\n",
			       CFS_MAX_STACK);
			kfree(splitlower);
			goto fail;
		}

		ret = -ENOMEM;
		bases = kcalloc(numlower, sizeof(struct file *), GFP_KERNEL);
		if (!bases) {
			kfree(splitlower);
			goto fail;
		}

		lower = splitlower;
		for (i = 0; i < numlower; i++) {
			f = filp_open(lower, O_PATH, 0);
			if (IS_ERR(f)) {
				ret = PTR_ERR(f);
				kfree(splitlower);
				goto fail;
			}
			bases[i] = f;

			lower = strchr(lower, '\0') + 1;
		}
		kfree(splitlower);
	}

	/* Must be inited before calling cfs_get_inode.  */
	ret = cfs_init_ctx(fc->source, fsi->has_digest ? fsi->digest : NULL,
			   &fsi->cfs_ctx);
	if (ret < 0)
		goto fail;

	inode = cfs_get_root_inode(sb);
	if (IS_ERR(inode)) {
		ret = PTR_ERR(inode);
		goto fail;
	}
	sb->s_root = d_make_root(inode);

	ret = -ENOMEM;
	if (!sb->s_root)
		goto fail;

	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_blocksize = PAGE_SIZE;
	sb->s_blocksize_bits = PAGE_SHIFT;

	sb->s_time_gran = 1;

	fsi->root_mnt = root_mnt;
	fsi->bases = bases;
	fsi->n_bases = numlower;
	return 0;
fail:
	if (bases) {
		size_t i;

		for (i = 0; i < numlower; i++) {
			if (bases[i])
				fput(bases[i]);
		}
		kfree(bases);
	}
	if (root_mnt)
		kern_unmount(root_mnt);
	cfs_ctx_put(&fsi->cfs_ctx);
	return ret;
}

static int cfs_get_tree(struct fs_context *fc)
{
	return get_tree_nodev(fc, cfs_fill_super);
}

static const struct fs_context_operations cfs_context_ops = {
	.parse_param = cfs_parse_param,
	.get_tree = cfs_get_tree,
};

static struct file *open_base_file(struct cfs_info *fsi, struct inode *inode,
				   struct file *file)
{
	struct cfs_inode *cino = CFS_I(inode);
	struct file *real_file;
	size_t i;

	for (i = 0; i < fsi->n_bases; i++) {
		real_file = file_open_root(&(fsi->bases[i]->f_path),
					   cino->inode_data.path_payload,
					   file->f_flags, 0);
		if (!IS_ERR(real_file) || PTR_ERR(real_file) != -ENOENT)
			return real_file;
	}

	return ERR_PTR(-ENOENT);
}

static int cfs_open_file(struct inode *inode, struct file *file)
{
	struct cfs_inode *cino = CFS_I(inode);
	struct cfs_info *fsi = inode->i_sb->s_fs_info;
	struct file *real_file;
	char *real_path = cino->inode_data.path_payload;

	if (WARN_ON(file == NULL))
		return -EIO;

	if (file->f_flags & (O_WRONLY | O_RDWR | O_CREAT | O_EXCL | O_TRUNC))
		return -EROFS;

	if (real_path == NULL) {
		file->private_data = &empty_file;
		return 0;
	}

	/* FIXME: prevent loops opening files.  */

	if (fsi->n_bases == 0 || real_path[0] == '/') {
		real_file = file_open_root_mnt(fsi->root_mnt, real_path,
					       file->f_flags, 0);
	} else {
		real_file = open_base_file(fsi, inode, file);
	}

	if (IS_ERR(real_file)) {
		return PTR_ERR(real_file);
	}

	/* If metadata records a digest for the file, ensure it is there and correct before using the contents */
	if (cino->inode_data.has_digest && !fsi->noverity) {
		u8 verity_digest[FS_VERITY_MAX_DIGEST_SIZE];
		enum hash_algo verity_algo;
		int res;
		res = fsverity_get_digest(d_inode(real_file->f_path.dentry),
					  verity_digest, &verity_algo);
		if (res < 0) {
			pr_warn("WARNING: composefs backing file '%pd' unexpectedly had no fs-verity digest\n",
				real_file->f_path.dentry);
			fput(real_file);
			return -EIO;
		}
		if (verity_algo != HASH_ALGO_SHA256 ||
		    memcmp(cino->inode_data.digest, verity_digest,
			   SHA256_DIGEST_SIZE) != 0) {
			pr_warn("WARNING: composefs backing file '%pd' has the wrong fs-verity digest\n",
				real_file->f_path.dentry);
			fput(real_file);
			return -EIO;
		}
	}

	file->private_data = real_file;
	return 0;
}

static unsigned long cfs_mmu_get_unmapped_area(struct file *file,
					       unsigned long addr,
					       unsigned long len,
					       unsigned long pgoff,
					       unsigned long flags)
{
	struct file *realfile = file->private_data;

	if (realfile == &empty_file)
		return 0;

	return current->mm->get_unmapped_area(file, addr, len, pgoff, flags);
}

static int cfs_release_file(struct inode *inode, struct file *file)
{
	struct file *realfile = file->private_data;

	if (WARN_ON(realfile == NULL))
		return -EIO;

	if (realfile == &empty_file)
		return 0;

	fput(file->private_data);

	return 0;
}

static int cfs_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct file *realfile = file->private_data;
	int ret;

	if (realfile == &empty_file)
		return 0;

	if (!realfile->f_op->mmap)
		return -ENODEV;

	if (WARN_ON(file != vma->vm_file))
		return -EIO;

	vma_set_file(vma, realfile);

	ret = call_mmap(vma->vm_file, vma);

	return ret;
}

static ssize_t cfs_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;
	struct file *realfile = file->private_data;
	int ret;

	if (realfile == &empty_file)
		return 0;

	if (!realfile->f_op->read_iter)
		return -ENODEV;

	iocb->ki_filp = realfile;
	ret = call_read_iter(realfile, iocb, iter);
	iocb->ki_filp = file;

	return ret;
}

static int cfs_fadvise(struct file *file, loff_t offset, loff_t len, int advice)
{
	struct file *realfile = file->private_data;

	if (realfile == &empty_file)
		return 0;

	return vfs_fadvise(realfile, offset, len, advice);
}

static int cfs_encode_fh(struct inode *inode, u32 *fh, int *max_len,
			 struct inode *parent)
{
	int len = 3;
	u64 nodeid;
	u32 generation;

	if (*max_len < len) {
		*max_len = len;
		return FILEID_INVALID;
	}

	nodeid = inode->i_ino;
	generation = inode->i_generation;

	fh[0] = (u32)(nodeid >> 32);
	fh[1] = (u32)(nodeid & 0xffffffff);
	fh[2] = generation;

	*max_len = len;

	return 0x91;
}

static struct dentry *cfs_fh_to_dentry(struct super_block *sb, struct fid *fid,
				       int fh_len, int fh_type)
{
	struct cfs_info *fsi = sb->s_fs_info;
	struct inode *ino;
	u64 inode_index;
	u32 generation;

	if ((fh_type != 0x91) || fh_len < 3)
		return NULL;

	inode_index = (u64)(fid->raw[0]) << 32;
	inode_index |= fid->raw[1];
	generation = fid->raw[2];

	ino = ilookup(sb, inode_index);
	if (!ino) {
		struct cfs_inode_s inode_buf;
		struct cfs_inode_s *inode;

		inode = cfs_get_ino_index(&fsi->cfs_ctx, inode_index,
					  &inode_buf);
		if (IS_ERR(inode))
			return ERR_CAST(inode);

		ino = cfs_make_inode(&fsi->cfs_ctx, sb, inode_index, inode,
				     NULL);
		if (IS_ERR(ino))
			return ERR_CAST(ino);
	}
	if (ino->i_generation != generation) {
		iput(ino);
		return ERR_PTR(-ESTALE);
	}
	return d_obtain_alias(ino);
}

static struct dentry *cfs_fh_to_parent(struct super_block *sb, struct fid *fid,
				       int fh_len, int fh_type)
{
	return ERR_PTR(-EACCES);
}

static int cfs_get_name(struct dentry *parent, char *name, struct dentry *child)
{
	WARN_ON_ONCE(1);
	return -EIO;
}

static struct dentry *cfs_get_parent(struct dentry *dentry)
{
	WARN_ON_ONCE(1);
	return ERR_PTR(-EIO);
}

static const struct export_operations cfs_export_operations = {
	.fh_to_dentry = cfs_fh_to_dentry,
	.fh_to_parent = cfs_fh_to_parent,
	.encode_fh = cfs_encode_fh,
	.get_parent = cfs_get_parent,
	.get_name = cfs_get_name,
};

static int cfs_getxattr(const struct xattr_handler *handler,
			struct dentry *unused2, struct inode *inode,
			const char *name, void *value, size_t size)
{
	struct cfs_info *fsi = inode->i_sb->s_fs_info;
	struct cfs_inode *cino = CFS_I(inode);

	return cfs_get_xattr(&fsi->cfs_ctx, &cino->inode_data, name, value,
			     size);
}

static ssize_t cfs_listxattr(struct dentry *dentry, char *names, size_t size)
{
	struct inode *inode = d_inode(dentry);
	struct cfs_info *fsi = inode->i_sb->s_fs_info;
	struct cfs_inode *cino = CFS_I(inode);

	return cfs_list_xattrs(&fsi->cfs_ctx, &cino->inode_data, names, size);
}

static const struct file_operations cfs_file_operations = {
	.read_iter = cfs_read_iter,
	.mmap = cfs_mmap,
	.fadvise = cfs_fadvise,
	.fsync = noop_fsync,
	.splice_read = generic_file_splice_read,
	.llseek = generic_file_llseek,
	.get_unmapped_area = cfs_mmu_get_unmapped_area,
	.release = cfs_release_file,
	.open = cfs_open_file,
};

static const struct xattr_handler cfs_xattr_handler = {
	.prefix = "", /* catch all */
	.get = cfs_getxattr,
};

static const struct xattr_handler *cfs_xattr_handlers[] = {
	&cfs_xattr_handler,
	NULL,
};

static const struct inode_operations cfs_file_inode_operations = {
	.setattr = simple_setattr,
	.getattr = simple_getattr,

	.listxattr = cfs_listxattr,
};

static int cfs_init_fs_context(struct fs_context *fc)
{
	struct cfs_info *fsi;

	fsi = kzalloc(sizeof(*fsi), GFP_KERNEL);
	if (!fsi)
		return -ENOMEM;

	fc->s_fs_info = fsi;
	fc->ops = &cfs_context_ops;
	return 0;
}

static struct file_system_type cfs_type = {
	.owner = THIS_MODULE,
	.name = "composefs",
	.init_fs_context = cfs_init_fs_context,
	.parameters = cfs_parameters,
	.kill_sb = kill_anon_super,
};

static void cfs_inode_init_once(void *foo)
{
	struct cfs_inode *cino = foo;

	inode_init_once(&cino->vfs_inode);
}

static int __init init_cfs(void)
{
	cfs_inode_cachep = kmem_cache_create(
		"cfs_inode", sizeof(struct cfs_inode), 0,
		(SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD | SLAB_ACCOUNT),
		cfs_inode_init_once);
	if (cfs_inode_cachep == NULL)
		return -ENOMEM;

	return register_filesystem(&cfs_type);
}

static void __exit exit_cfs(void)
{
	unregister_filesystem(&cfs_type);

	/* Ensure all RCU free inodes are safe to be destroyed. */
	rcu_barrier();

	kmem_cache_destroy(cfs_inode_cachep);
}

module_init(init_cfs);
module_exit(exit_cfs);
