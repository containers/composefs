// SPDX-License-Identifier: GPL-2.0
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

#include <linux/exportfs.h>
#include <linux/fs_parser.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/seq_file.h>
#include <linux/version.h>
#include <linux/xattr.h>
#include <linux/statfs.h>

#include "cfs-internals.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Giuseppe Scrivano <gscrivan@redhat.com>");

#define CFS_MAX_STACK 500

/* Backing file fs-verity check policy, ordered in strictness */
enum cfs_verity_policy {
	CFS_VERITY_CHECK_NONE = 0, /* Never verify digest */
	CFS_VERITY_CHECK_IF_SPECIFIED = 1, /* Verify if specified in image */
	CFS_VERITY_CHECK_REQUIRED = 2, /* Always verify, fail if not specified in image */
};

#define CFS_VERITY_CHECK_MAX_POLICY 2

struct cfs_info {
	struct cfs_context cfs_ctx;

	char *base_path;

	size_t n_bases;
	struct vfsmount **bases;

	enum cfs_verity_policy verity_check;
	bool has_digest;
	u8 digest[SHA256_DIGEST_SIZE]; /* fs-verity digest */
};

struct cfs_inode {
	struct inode vfs_inode;
	struct cfs_inode_extra_data inode_data;
};

static inline struct cfs_inode *CFS_I(struct inode *inode)
{
	return container_of(inode, struct cfs_inode, vfs_inode);
}

static struct file empty_file;

static const struct file_operations cfs_file_operations;

static const struct super_operations cfs_ops;
static const struct file_operations cfs_dir_operations;
static const struct inode_operations cfs_dir_inode_operations;
static const struct inode_operations cfs_file_inode_operations;
static const struct inode_operations cfs_link_inode_operations;

static const struct xattr_handler *cfs_xattr_handlers[];

static const struct address_space_operations cfs_aops = {
	.direct_IO = noop_direct_IO,
};

static ssize_t cfs_listxattr(struct dentry *dentry, char *names, size_t size);

/* split array of basedirs at ':', copied from overlayfs.  */
static unsigned int cfs_split_basedirs(char *str)
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

static struct inode *cfs_make_inode(struct cfs_context *ctx, struct super_block *sb,
				    ino_t ino_num, const struct inode *dir)
{
	struct inode *inode;
	struct cfs_inode *cino;
	int ret;

	inode = new_inode(sb);
	if (!inode)
		return ERR_PTR(-ENOMEM);

	cino = CFS_I(inode);

	ret = cfs_init_inode(ctx, ino_num, inode, &cino->inode_data);
	if (ret < 0)
		goto fail;

	inode_init_owner(&init_user_ns, inode, dir, inode->i_mode);
	inode->i_mapping->a_ops = &cfs_aops;

	switch (inode->i_mode & S_IFMT) {
	case S_IFREG:
		inode->i_op = &cfs_file_inode_operations;
		inode->i_fop = &cfs_file_operations;
		break;
	case S_IFLNK:
		inode->i_link = cino->inode_data.path_payload;
		inode->i_op = &cfs_link_inode_operations;
		inode->i_fop = &cfs_file_operations;
		break;
	case S_IFDIR:
		inode->i_op = &cfs_dir_inode_operations;
		inode->i_fop = &cfs_dir_operations;
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
		init_special_inode(inode, inode->i_mode, inode->i_rdev);
		break;
	}

	return inode;

fail:
	iput(inode);
	return ERR_PTR(ret);
}

static bool cfs_iterate_cb(void *private, const char *name, int name_len,
			   u64 ino, unsigned int dtype)
{
	struct dir_context *ctx = private;

	if (!dir_emit(ctx, name, name_len, ino, dtype))
		return 0;

	ctx->pos++;
	return 1;
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
	struct inode *inode = NULL;
	u64 index;
	int ret;

	if (dentry->d_name.len > NAME_MAX)
		return ERR_PTR(-ENAMETOOLONG);

	ret = cfs_dir_lookup(&fsi->cfs_ctx, dir->i_ino, &cino->inode_data,
			     dentry->d_name.name, dentry->d_name.len, &index);
	if (ret) {
		if (ret < 0)
			return ERR_PTR(ret);
		inode = cfs_make_inode(&fsi->cfs_ctx, dir->i_sb, index, dir);
	}

	return d_splice_alias(inode, dentry);
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

static int digest_from_string(const char *digest_str, u8 *digest)
{
	int res;

	res = hex2bin(digest, digest_str, SHA256_DIGEST_SIZE);
	if (res < 0)
		return res;

	if (digest_str[2 * SHA256_DIGEST_SIZE] != 0)
		return -EINVAL; /* Too long string */

	return 0;
}

/*
 * Display the mount options in /proc/mounts.
 */
static int cfs_show_options(struct seq_file *m, struct dentry *root)
{
	struct cfs_info *fsi = root->d_sb->s_fs_info;

	if (fsi->base_path)
		seq_show_option(m, "basedir", fsi->base_path);
	if (fsi->has_digest)
		seq_printf(m, ",digest=%*phN", SHA256_DIGEST_SIZE, fsi->digest);
	if (fsi->verity_check != 0)
		seq_printf(m, ",verity_check=%u", fsi->verity_check);

	return 0;
}

static struct kmem_cache *cfs_inode_cachep;

static struct inode *cfs_alloc_inode(struct super_block *sb)
{
	struct cfs_inode *cino = alloc_inode_sb(sb, cfs_inode_cachep, GFP_KERNEL);

	if (!cino)
		return NULL;

	memset(&cino->inode_data, 0, sizeof(cino->inode_data));

	return &cino->vfs_inode;
}

static void cfs_free_inode(struct inode *inode)
{
	struct cfs_inode *cino = CFS_I(inode);

	kfree(cino->inode_data.path_payload);
	kmem_cache_free(cfs_inode_cachep, cino);
}

static void cfs_put_super(struct super_block *sb)
{
	struct cfs_info *fsi = sb->s_fs_info;

	cfs_ctx_put(&fsi->cfs_ctx);
	if (fsi->bases) {
		kern_unmount_array(fsi->bases, fsi->n_bases);
		kfree(fsi->bases);
	}
	kfree(fsi->base_path);

	kfree(fsi);
}

static int cfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct cfs_info *fsi = dentry->d_sb->s_fs_info;
	int err = 0;

	/* We return the free space, etc from the first base dir. */
	if (fsi->n_bases > 0) {
		struct path root = { .mnt = fsi->bases[0],
				     .dentry = fsi->bases[0]->mnt_root };
		err = vfs_statfs(&root, buf);
	}

	if (!err) {
		buf->f_namelen = NAME_MAX;
		buf->f_type = dentry->d_sb->s_magic;
	}

	return err;
}

static const struct super_operations cfs_ops = {
	.statfs = cfs_statfs,
	.drop_inode = generic_delete_inode,
	.show_options = cfs_show_options,
	.put_super = cfs_put_super,
	.alloc_inode = cfs_alloc_inode,
	.free_inode = cfs_free_inode,
};

enum cfs_param {
	Opt_base_path,
	Opt_digest,
	Opt_verity_check,
};

static const struct fs_parameter_spec cfs_parameters[] = {
	fsparam_string("basedir", Opt_base_path),
	fsparam_string("digest", Opt_digest),
	fsparam_u32("verity_check", Opt_verity_check),
	{}
};

static int cfs_parse_param(struct fs_context *fc, struct fs_parameter *param)
{
	struct cfs_info *fsi = fc->s_fs_info;
	struct fs_parse_result result;
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
		fsi->verity_check = CFS_VERITY_CHECK_REQUIRED; /* Default to full verity check */
		break;
	case Opt_verity_check:
		if (result.uint_32 > CFS_VERITY_CHECK_MAX_POLICY)
			return invalfc(fc, "Invalid verity_check mode");
		fsi->verity_check = result.uint_32;
		break;
	}

	return 0;
}

static struct vfsmount *resolve_basedir(const char *name)
{
	struct path path = {};
	struct vfsmount *mnt;
	int err = -EINVAL;

	if (!*name) {
		pr_err("empty basedir\n");
		return ERR_PTR(-EINVAL);
	}
	err = kern_path(name, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &path);
	if (err) {
		pr_err("failed to resolve '%s': %i\n", name, err);
		return ERR_PTR(-EINVAL);
	}

	mnt = clone_private_mount(&path);
	path_put(&path);
	if (!IS_ERR(mnt)) {
		/* Don't inherit atime flags */
		mnt->mnt_flags &= ~(MNT_NOATIME | MNT_NODIRATIME | MNT_RELATIME);
	}

	return mnt;
}

static int cfs_fill_super(struct super_block *sb, struct fs_context *fc)
{
	struct cfs_info *fsi = sb->s_fs_info;
	struct vfsmount **bases = NULL;
	size_t numbasedirs = 0;
	struct inode *inode;
	struct vfsmount *mnt;
	int ret;

	/* Set up the inode allocator early */
	sb->s_op = &cfs_ops;
	sb->s_flags |= SB_RDONLY;
	sb->s_magic = CFS_MAGIC;
	sb->s_xattr = cfs_xattr_handlers;

	if (fsi->base_path == NULL) {
		pr_warn("WARNING: composefs mount without a basedir, all lookups will fail\n");
	} else {
		char *lower, *splitlower = NULL;

		ret = -ENOMEM;
		splitlower = kstrdup(fsi->base_path, GFP_KERNEL);
		if (!splitlower)
			goto fail;

		ret = -EINVAL;
		numbasedirs = cfs_split_basedirs(splitlower);
		if (numbasedirs > CFS_MAX_STACK) {
			pr_err("too many lower directories, limit is %d\n",
			       CFS_MAX_STACK);
			kfree(splitlower);
			goto fail;
		}

		ret = -ENOMEM;
		bases = kcalloc(numbasedirs, sizeof(struct vfsmount *), GFP_KERNEL);
		if (!bases) {
			kfree(splitlower);
			goto fail;
		}

		lower = splitlower;
		for (size_t i = 0; i < numbasedirs; i++) {
			mnt = resolve_basedir(lower);
			if (IS_ERR(mnt)) {
				ret = PTR_ERR(mnt);
				kfree(splitlower);
				goto fail;
			}
			bases[i] = mnt;

			lower = strchr(lower, '\0') + 1;
		}
		kfree(splitlower);
	}

	/* Must be inited before calling cfs_get_inode.  */
	ret = cfs_init_ctx(fc->source, fsi->has_digest ? fsi->digest : NULL,
			   &fsi->cfs_ctx);
	if (ret < 0)
		goto fail;

	inode = cfs_make_inode(&fsi->cfs_ctx, sb, CFS_ROOT_INO, NULL);
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

	fsi->bases = bases;
	fsi->n_bases = numbasedirs;
	return 0;
fail:
	if (bases) {
		for (size_t i = 0; i < numbasedirs; i++) {
			if (bases[i])
				kern_unmount(bases[i]);
		}
		kfree(bases);
	}
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
	char *real_path = cino->inode_data.path_payload;

	for (size_t i = 0; i < fsi->n_bases; i++) {
		real_file = file_open_root_mnt(fsi->bases[i], real_path,
					       file->f_flags, 0);
		if (real_file != ERR_PTR(-ENOENT))
			return real_file;
	}

	return ERR_PTR(-ENOENT);
}

static int cfs_open_file(struct inode *inode, struct file *file)
{
	struct cfs_info *fsi = inode->i_sb->s_fs_info;
	struct cfs_inode *cino = CFS_I(inode);
	char *real_path = cino->inode_data.path_payload;
	struct file *faked_file;
	struct file *real_file;

	if (file->f_flags & (O_WRONLY | O_RDWR | O_CREAT | O_EXCL | O_TRUNC))
		return -EROFS;

	if (!real_path) {
		file->private_data = &empty_file;
		return 0;
	}

	if (fsi->verity_check >= CFS_VERITY_CHECK_REQUIRED &&
	    !cino->inode_data.has_digest) {
		pr_warn("WARNING: composefs image file '%pD' specified no fs-verity digest\n",
			file);
		return -EIO;
	}

	real_file = open_base_file(fsi, inode, file);

	if (IS_ERR(real_file))
		return PTR_ERR(real_file);

	/* If metadata records a digest for the file, ensure it is there
	 * and correct before using the contents.
	 */
	if (cino->inode_data.has_digest &&
	    fsi->verity_check >= CFS_VERITY_CHECK_IF_SPECIFIED) {
		u8 verity_digest[FS_VERITY_MAX_DIGEST_SIZE];
		enum hash_algo verity_algo;
		int res;

		res = fsverity_get_digest(d_inode(real_file->f_path.dentry),
					  verity_digest, &verity_algo);
		if (res < 0) {
			pr_warn("WARNING: composefs backing file '%pD' has no fs-verity digest\n",
				real_file);
			fput(real_file);
			return -EIO;
		}
		if (verity_algo != HASH_ALGO_SHA256 ||
		    memcmp(cino->inode_data.digest, verity_digest,
			   SHA256_DIGEST_SIZE) != 0) {
			pr_warn("WARNING: composefs backing file '%pD' has the wrong fs-verity digest\n",
				real_file);
			fput(real_file);
			return -EIO;
		}
	}

	faked_file = open_with_fake_path(&file->f_path, file->f_flags,
					 real_file->f_inode, current_cred());
	fput(real_file);

	if (IS_ERR(faked_file))
		return PTR_ERR(faked_file);

	file->private_data = faked_file;
	return 0;
}

#ifdef CONFIG_MMU
static unsigned long cfs_mmu_get_unmapped_area(struct file *file, unsigned long addr,
					       unsigned long len, unsigned long pgoff,
					       unsigned long flags)
{
	struct file *realfile = file->private_data;

	if (realfile == &empty_file)
		return 0;

	return current->mm->get_unmapped_area(file, addr, len, pgoff, flags);
}
#endif

static int cfs_release_file(struct inode *inode, struct file *file)
{
	struct file *realfile = file->private_data;

	if (WARN_ON(!realfile))
		return -EIO;

	if (realfile == &empty_file)
		return 0;

	fput(realfile);

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

static int cfs_getxattr(const struct xattr_handler *handler,
			struct dentry *unused2, struct inode *inode,
			const char *name, void *value, size_t size)
{
	struct cfs_info *fsi = inode->i_sb->s_fs_info;
	struct cfs_inode *cino = CFS_I(inode);

	return cfs_get_xattr(&fsi->cfs_ctx, &cino->inode_data, name, value, size);
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
#ifdef CONFIG_MMU
	.get_unmapped_area = cfs_mmu_get_unmapped_area,
#endif
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
	if (!cfs_inode_cachep)
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
