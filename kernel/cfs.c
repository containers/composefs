/*
 * composefs
 *
 * Copyright (C) 2000 Linus Torvalds.
 *               2000 Transmeta Corp.
 * Copyright (C) 2021 Giuseppe Scrivano
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

#include "lcfs-reader.h"

#ifdef STANDALONE_COMPOSEFS
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Giuseppe Scrivano <gscrivan@redhat.com>");
#else
#include "cfs.h"
#endif

#define CFS_MAGIC 0x12345678

struct cfs_info {
	struct lcfs_context_s *lcfs_ctx;

	struct vfsmount *root_mnt;

	char *descriptor_path;
	char *base_path;
	struct file *base;
};

struct cfs_inode {
	struct inode vfs_inode; /* must be first for clear in otfs_alloc_inode to work */
	struct lcfs_inode_s cfs_ino;
	char *real_path;
	struct lcfs_xattr_header_s *xattrs;
	struct lcfs_dir_s *dir;
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

static const struct xattr_handler *cfs_xattr_handlers[];
static const struct export_operations cfs_export_operations;

static const struct address_space_operations cfs_aops = {
	.direct_IO = noop_direct_IO,
};

static struct inode *cfs_make_inode(struct lcfs_context_s *ctx,
                                    struct super_block *sb,
				    ino_t ino_num,
				    struct lcfs_inode_s *ino,
				    const struct inode *dir)
{
	char *target_link = NULL;
	char *real_path = NULL;
	struct lcfs_xattr_header_s *xattrs = NULL;
	struct cfs_inode *cino;
	struct inode *inode = NULL;
	struct lcfs_dir_s *dirdata = NULL;
	int ret;
	int r;

	if ((ino->st_mode & S_IFMT) == S_IFLNK) {
		target_link = lcfs_dup_payload_path(ctx, ino, ino_num);
		if (IS_ERR(target_link)) {
			ret = PTR_ERR(target_link);
			target_link = NULL;
			goto fail;
		}
	}

	if ((ino->st_mode & S_IFMT) == S_IFREG && ino->payload_length != 0) {
		real_path = lcfs_dup_payload_path(ctx, ino, ino_num);
		if (r < 0) {
			ret = PTR_ERR(real_path);
			real_path = NULL;
			goto fail;
		}
	}

	if ((ino->st_mode & S_IFMT) == S_IFDIR) {
		dirdata = lcfs_get_dir(ctx, ino, ino_num);
		if (IS_ERR(dirdata)) {
			ret = PTR_ERR(dirdata);
			dirdata = NULL;
			goto fail;
		}
	}

	xattrs = lcfs_get_xattrs(ctx, ino);
	if (IS_ERR(xattrs)) {
		ret = PTR_ERR(xattrs);
		xattrs = NULL;
		goto fail;
	}

	inode = new_inode(sb);
	if (inode) {
		inode_init_owner(&init_user_ns, inode, dir, ino->st_mode);
		inode->i_mapping->a_ops = &cfs_aops;
		mapping_set_gfp_mask(inode->i_mapping, GFP_HIGHUSER);
		mapping_set_unevictable(inode->i_mapping);

		cino = CFS_I(inode);
		cino->cfs_ino = *ino;
		cino->xattrs = xattrs;
		cino->dir = dirdata;

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
			cino->real_path = real_path;
			break;
		case S_IFLNK:
			inode->i_link = target_link;
			inode->i_op = &simple_symlink_inode_operations;
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
			init_special_inode(inode, ino->st_mode,
					   ino->st_rdev);
			break;
		}
	}
	return inode;

 fail:
	if (inode)
		iput(inode);
	if (real_path)
		kfree(real_path);
	if (xattrs)
		kfree(xattrs);
	if (dirdata)
		kfree(dirdata);
	if (target_link)
		kfree(target_link);
	return ERR_PTR(ret);
}

static struct inode *cfs_get_root_inode(struct super_block *sb)
{
	struct cfs_info *fsi = sb->s_fs_info;
	struct lcfs_inode_s ino_buf;
	struct lcfs_inode_s *ino;

	ino = lcfs_get_ino_index(fsi->lcfs_ctx, LCFS_ROOT_INODE, &ino_buf);
	if (IS_ERR(ino))
		return ERR_CAST(ino);

	return cfs_make_inode(fsi->lcfs_ctx, sb, LCFS_ROOT_INODE, ino, NULL);
}

static int cfs_rmdir(struct inode *ino, struct dentry *dir)
{
	return -EROFS;
}

static int cfs_rename(struct user_namespace *userns, struct inode *source_ino,
		      struct dentry *src_dir, struct inode *target_ino,
		      struct dentry *target, unsigned int flags)
{
	return -EROFS;
}

static int cfs_link(struct dentry *src, struct inode *i, struct dentry *target)
{
	return -EROFS;
}

static int cfs_unlink(struct inode *inode, struct dentry *dir)
{
	return -EROFS;
}

static int cfs_mknod(struct user_namespace *mnt_userns, struct inode *dir,
		     struct dentry *dentry, umode_t mode, dev_t dev)
{
	return -EROFS;
}

static int cfs_mkdir(struct user_namespace *mnt_userns, struct inode *dir,
		     struct dentry *dentry, umode_t mode)
{
	return -EROFS;
}

static int cfs_create(struct user_namespace *mnt_userns, struct inode *dir,
		      struct dentry *dentry, umode_t mode, bool excl)
{
	return -EROFS;
}

static int cfs_symlink(struct user_namespace *mnt_userns, struct inode *dir,
		       struct dentry *dentry, const char *symname)
{
	return -EROFS;
}

static int cfs_tmpfile(struct user_namespace *mnt_userns, struct inode *dir,
		       struct dentry *dentry, umode_t mode)
{
	return -EROFS;
}

static bool cfs_iterate_cb(void *private, const char *name, int name_len, u64 ino, unsigned int dtype)
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
	struct cfs_inode *cino = CFS_I(file->f_inode);

	if (!dir_emit_dots(file, ctx))
		return 0;

	return lcfs_iterate_dir(cino->dir, ctx->pos - 2, cfs_iterate_cb, ctx);
}

struct dentry *cfs_lookup(struct inode *dir, struct dentry *dentry,
			  unsigned int flags)
{
	struct cfs_info *fsi = dir->i_sb->s_fs_info;
	struct cfs_inode *cino = CFS_I(dir);
	struct lcfs_inode_s ino_buf;
	struct inode *inode;
        struct lcfs_inode_s *ino_s;
	lcfs_off_t index;
	int ret;

	if (dentry->d_name.len > NAME_MAX)
		return ERR_PTR(-ENAMETOOLONG);

	ret = lcfs_lookup(cino->dir, dentry->d_name.name, dentry->d_name.len, &index);
	if (ret == 0)
		goto return_negative;

	ino_s = lcfs_get_ino_index(fsi->lcfs_ctx, index, &ino_buf);
	if (IS_ERR(ino_s))
		return ERR_CAST(ino_s);

	inode = cfs_make_inode(fsi->lcfs_ctx, dir->i_sb, index,
			       ino_s, dir);
	if (inode)
		return d_splice_alias(inode, dentry);

return_negative:
	d_add(dentry, NULL);
	return NULL;
}

static const struct file_operations cfs_dir_operations = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.iterate_shared = cfs_iterate,
};

static const struct inode_operations cfs_dir_inode_operations = {
	.create = cfs_create,
	.lookup = cfs_lookup,
	.link = cfs_link,
	.unlink = cfs_unlink,
	.symlink = cfs_symlink,
	.mkdir = cfs_mkdir,
	.rmdir = cfs_rmdir,
	.mknod = cfs_mknod,
	.rename = cfs_rename,
	.tmpfile = cfs_tmpfile,
};

/*
 * Display the mount options in /proc/mounts.
 */
static int cfs_show_options(struct seq_file *m, struct dentry *root)
{
	struct cfs_info *fsi = root->d_sb->s_fs_info;

	seq_printf(m, ",descriptor=%s", fsi->descriptor_path);
	if (fsi->base_path)
		seq_printf(m, ",base=%s", fsi->base_path);
	return 0;
}

static struct kmem_cache *cfs_inode_cachep;

static struct inode *cfs_alloc_inode(struct super_block *sb)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 18, 0))
	struct cfs_inode *cino = kmem_cache_alloc(cfs_inode_cachep, GFP_KERNEL);
#else
	struct cfs_inode *cino = alloc_inode_sb(sb, cfs_inode_cachep, GFP_KERNEL);
#endif

	if (!cino)
		return NULL;

	memset((u8*)cino + sizeof(struct inode), 0, sizeof(struct cfs_inode) - sizeof(struct inode));

	return &cino->vfs_inode;
}

static void cfs_destroy_inode(struct inode *inode)
{
	struct cfs_inode *cino = CFS_I(inode);

	if (S_ISLNK(inode->i_mode) && inode->i_link)
		kfree(inode->i_link);

	if (cino->real_path)
		kfree(cino->real_path);
	if (cino->xattrs)
		kfree(cino->xattrs);
	if (cino->dir)
		kfree(cino->dir);
}

static void cfs_free_inode(struct inode *inode)
{
	struct cfs_inode *cino = CFS_I(inode);

	kmem_cache_free(cfs_inode_cachep, cino);
}

static void cfs_put_super(struct super_block *sb)
{
	struct cfs_info *fsi = sb->s_fs_info;

	if (fsi->root_mnt)
		kern_unmount(fsi->root_mnt);
	if (fsi->lcfs_ctx)
		lcfs_destroy_ctx(fsi->lcfs_ctx);
	if (fsi->descriptor_path)
		kfree(fsi->descriptor_path);
	if (fsi->base)
		fput(fsi->base);
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
	Opt_descriptor_file,
	Opt_base_path,
};

const struct fs_parameter_spec cfs_parameters[] = {
	fsparam_string("descriptor", Opt_descriptor_file),
	fsparam_string("basedir", Opt_base_path),
	{}
};

static int cfs_parse_param(struct fs_context *fc, struct fs_parameter *param)
{
	struct fs_parse_result result;
	struct cfs_info *fsi = fc->s_fs_info;
	int opt;

	opt = fs_parse(fc, cfs_parameters, param, &result);
	if (opt < 0)
		return opt;

	switch (opt) {
	case Opt_descriptor_file:
		kfree(fsi->descriptor_path);
		/* Take ownership.  */
		fsi->descriptor_path = param->string;
		param->string = NULL;
		break;
	case Opt_base_path:
		kfree(fsi->base_path);
		/* Take ownership.  */
		fsi->base_path = param->string;
		param->string = NULL;
		break;
	}

	return 0;
}

static int cfs_fill_super(struct super_block *sb, struct fs_context *fc)
{
	struct cfs_info *fsi = sb->s_fs_info;
	struct vfsmount *root_mnt = NULL;
	struct path rootpath = {};
	struct file *base = NULL;
	struct inode *inode;
	void *ctx;
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
		struct file *f;

		f = filp_open(fsi->base_path, O_PATH, 0);
		if (IS_ERR(f)) {
			ret = PTR_ERR(f);
			goto fail;
		}
		base = f;
	}

	ctx = lcfs_create_ctx(fsi->descriptor_path);
	if (IS_ERR(ctx)) {
		ret = PTR_ERR(ctx);
		goto fail;
	}
	/* Must be set before calling cfs_get_inode.  */
	fsi->lcfs_ctx = ctx;

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
	fsi->base = base;
	return 0;
fail:
	if (base)
		fput(base);
	if (root_mnt)
		kern_unmount(root_mnt);
	if (fsi->lcfs_ctx) {
		lcfs_destroy_ctx(fsi->lcfs_ctx);
		fsi->lcfs_ctx = NULL;
	}
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

static int cfs_open_file(struct inode *inode, struct file *file)
{
	struct cfs_inode *cino = CFS_I(inode);
	struct cfs_info *fsi = inode->i_sb->s_fs_info;
	struct file *real_file;

	if (WARN_ON(file == NULL))
		return -EIO;

	if (file->f_flags & (O_WRONLY | O_RDWR | O_CREAT | O_EXCL | O_TRUNC))
		return -EROFS;

	if (cino->real_path == NULL) {
		file->private_data = &empty_file;
		return 0;
	}

	/* FIXME: prevent loops opening files.  */

	if (fsi->base == NULL || cino->real_path[0] == '/') {
		real_file = file_open_root_mnt(fsi->root_mnt, cino->real_path,
					       file->f_flags, 0);
	} else {
		real_file = file_open_root(&(fsi->base->f_path), cino->real_path,
					   file->f_flags, 0);
	}

	if (IS_ERR(real_file)) {
		return PTR_ERR(real_file);
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

	ino = ilookup(sb, (lcfs_off_t)inode_index);
	if (!ino) {
		struct lcfs_inode_s inode_buf;
		struct lcfs_inode_s *inode;

		inode = lcfs_get_ino_index(fsi->lcfs_ctx, inode_index, &inode_buf);
		if (IS_ERR(inode))
			return ERR_CAST(inode);

		ino = cfs_make_inode(fsi->lcfs_ctx, sb, inode_index, inode, NULL);
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

static int cfs_setxattr(const struct xattr_handler *handler,
			struct user_namespace *mnt_userns,
			struct dentry *unused, struct inode *inode,
			const char *name, const void *value, size_t size,
			int flags)
{
	return -EROFS;
}

static int cfs_getxattr(const struct xattr_handler *handler,
			struct dentry *unused2, struct inode *inode,
			const char *name, void *value, size_t size)
{
	struct cfs_inode *cino = CFS_I(inode);

	return lcfs_get_xattr(cino->xattrs, name, value, size);
}

static ssize_t cfs_listxattr(struct dentry *dentry, char *names, size_t size)
{
	struct inode *inode = d_inode(dentry);
	struct cfs_inode *cino = CFS_I(inode);

	return lcfs_list_xattrs(cino->xattrs, names, size);
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
	.set = cfs_setxattr,
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
	.name = "composefs",
	.init_fs_context = cfs_init_fs_context,
	.parameters = cfs_parameters,
	.fs_flags = FS_USERNS_MOUNT,
	.kill_sb = kill_anon_super,
};

static void cfs_inode_init_once(void *foo)
{
	struct cfs_inode *cino = foo;

	inode_init_once(&cino->vfs_inode);
}

#ifdef STANDALONE_COMPOSEFS
static int __init init_cfs(void)
{
	cfs_inode_cachep = kmem_cache_create("cfs_inode",
					      sizeof(struct cfs_inode), 0,
					      (SLAB_RECLAIM_ACCOUNT|
					       SLAB_MEM_SPREAD|SLAB_ACCOUNT),
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

#else

struct vfsmount *cfs_mount(void *raw_data)
{
	return vfs_kern_mount(&cfs_type, 0, "", raw_data);
}

#endif
