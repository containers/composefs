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
#include <linux/bsearch.h>

#include "lcfs-reader.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Giuseppe Scrivano <gscrivan@redhat.com>");

#define CFS_MAGIC 0x12345678

struct cfs_info {
	struct lcfs_context_s *lcfs_ctx;

	struct vfsmount *root_mnt;

	char *descriptor_path;
	char *base_path;
	struct file *base;
};

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

static struct inode *cfs_make_inode(struct super_block *sb,
				    struct lcfs_inode_s *ino,
				    const struct inode *dir)
{
	struct lcfs_inode_data_s *ino_data;
	struct cfs_info *fsi = sb->s_fs_info;
	char *target_link;
	struct inode *inode;

	ino_data = lcfs_inode_data(fsi->lcfs_ctx, ino);
	if (IS_ERR(ino_data))
		return ERR_CAST(ino_data);

	if ((ino_data->st_mode & S_IFMT) == S_IFLNK) {
		if (ino->u.file.payload == 0)
			return ERR_PTR(-EINVAL);

		target_link = (char *)lcfs_c_string(
			fsi->lcfs_ctx, ino->u.file.payload, NULL, PATH_MAX);
		if (IS_ERR(target_link))
			return ERR_CAST(target_link);
	}

	inode = new_inode(sb);
	if (inode) {
		inode_init_owner(&init_user_ns, inode, dir, ino_data->st_mode);
		inode->i_mapping->a_ops = &cfs_aops;
		mapping_set_gfp_mask(inode->i_mapping, GFP_HIGHUSER);
		mapping_set_unevictable(inode->i_mapping);

		inode->i_private = ino;

		inode->i_ino = lcfs_ino_num(fsi->lcfs_ctx, ino);
		set_nlink(inode, ino_data->st_nlink);
		inode->i_rdev = ino_data->st_rdev;
		inode->i_uid = make_kuid(current_user_ns(), ino_data->st_uid);
		inode->i_gid = make_kgid(current_user_ns(), ino_data->st_gid);
		inode->i_mode = ino_data->st_mode;
#if LCFS_USE_TIMESPEC
		inode->i_atime = ino->st_mtim;
		inode->i_mtime = ino->st_mtim;
		inode->i_ctime = ino->st_ctim;
#else
		inode->i_atime.tv_sec = ino->st_mtim;
		inode->i_mtime.tv_sec = ino->st_mtim;
		inode->i_ctime.tv_sec = ino->st_ctim;
#endif
		switch (ino_data->st_mode & S_IFMT) {
		case S_IFREG:
			inode->i_op = &cfs_file_inode_operations;
			inode->i_fop = &cfs_file_operations;
			inode->i_size = ino->u.file.st_size;
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
			if (current_user_ns() != &init_user_ns)
				return ERR_PTR(-EPERM);
			fallthrough;
		default:
			inode->i_op = &cfs_file_inode_operations;
			init_special_inode(inode, ino_data->st_mode,
					   ino_data->st_rdev);
			break;
		}
	}
	return inode;
}

static struct inode *cfs_get_inode(struct super_block *sb, size_t index,
				   const struct inode *dir)
{
	struct cfs_info *fsi = sb->s_fs_info;
	struct lcfs_inode_s *ino;
	struct lcfs_dentry_s *node;

	node = lcfs_get_dentry(fsi->lcfs_ctx, index);
	if (IS_ERR(node))
		return ERR_CAST(node);

	ino = lcfs_dentry_inode(fsi->lcfs_ctx, node);
	if (IS_ERR(ino))
		return ERR_CAST(ino);

	return cfs_make_inode(sb, ino, dir);
}

static struct inode *cfs_get_root_inode(struct super_block *sb)
{
	struct cfs_info *fsi = sb->s_fs_info;
	lcfs_off_t index = lcfs_get_root_index(fsi->lcfs_ctx);
	struct lcfs_inode_s *ino;

	ino = lcfs_get_ino_index(fsi->lcfs_ctx, index);
	if (IS_ERR(ino))
		return ERR_CAST(ino);

	return cfs_make_inode(sb, ino, NULL);
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

static int cfs_dir_release(struct inode *inode, struct file *file)
{
	return 0;
}

static int cfs_dir_open(struct inode *inode, struct file *file)
{
	return 0;
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
	struct cfs_info *fsi = file->f_inode->i_sb->s_fs_info;
	struct lcfs_inode_s *ino = file->f_inode->i_private;

	if (!dir_emit_dots(file, ctx))
		return 0;

	return lcfs_iterate_dir(fsi->lcfs_ctx, ctx->pos - 2, ino,
				cfs_iterate_cb, ctx);
}

static loff_t cfs_dir_llseek(struct file *file, loff_t offset, int origin)
{
	loff_t res = -EINVAL;

	switch (origin) {
	case SEEK_CUR:
		offset += file->f_pos;
		break;
	case SEEK_SET:
		break;
	default:
		return res;
	}
	if (offset < 0)
		return res;

	file->f_pos = offset;

	return offset;
}

struct bsearch_key_s {
	const char *name;
	struct cfs_info *fsi;
	int err;
};

/* The first argument is the KEY, so take advantage to pass additional data.  */
static int compare_names(const void *a, const void *b)
{
	struct bsearch_key_s *key = (struct bsearch_key_s *)a;
	const struct lcfs_dentry_s *dentry = b;
	const char *name;

	name = lcfs_c_string(key->fsi->lcfs_ctx, dentry->name, NULL, NAME_MAX);
	if (IS_ERR(name)) {
		key->err = PTR_ERR(name);
		return 0;
	}
	return strcmp(key->name, name);
}

struct dentry *cfs_lookup(struct inode *dir, struct dentry *dentry,
			  unsigned int flags)
{
	struct lcfs_dentry_s *dir_content_end, *dir_content;
	struct lcfs_inode_s *cfs_ino = dir->i_private;
	struct cfs_info *fsi = dir->i_sb->s_fs_info;
	struct lcfs_dentry_s *found;
	struct inode *inode;
	struct bsearch_key_s key = {
		.name = dentry->d_name.name,
		.fsi = fsi,
		.err = 0,
	};
	lcfs_off_t index;

	if (dentry->d_name.len > NAME_MAX)
		return ERR_PTR(-ENAMETOOLONG);

	if (!dentry->d_sb->s_d_op)
		d_set_d_op(dentry, &simple_dentry_operations);

	dir_content = lcfs_get_dentry(fsi->lcfs_ctx, cfs_ino->u.dir.off);
	if (IS_ERR(dir_content))
		goto return_negative;

	/* Check that the last index is valid as well.  */
	dir_content_end = lcfs_get_dentry(
		fsi->lcfs_ctx, cfs_ino->u.dir.off + cfs_ino->u.dir.len);
	if (dir_content_end == NULL)
		goto return_negative;

	found = bsearch(&key, dir_content,
			cfs_ino->u.dir.len / sizeof(struct lcfs_dentry_s),
			sizeof(struct lcfs_dentry_s), compare_names);
	if (found == NULL || key.err)
		goto return_negative;

	index = lcfs_get_dentry_index(fsi->lcfs_ctx, found);

	inode = cfs_get_inode(dir->i_sb, index, dir);
	if (IS_ERR(inode)) {
		return ERR_CAST(inode);
	}
	if (inode)
		return d_splice_alias(inode, dentry);

return_negative:
	d_add(dentry, NULL);
	return NULL;
}

static const struct file_operations cfs_dir_operations = {
	.open = cfs_dir_open,
	.iterate = cfs_iterate,
	.release = cfs_dir_release,
	.llseek = cfs_dir_llseek,
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

static const struct super_operations cfs_ops = {
	.statfs = simple_statfs,
	.drop_inode = generic_delete_inode,
	.show_options = cfs_show_options,
};

enum cfs_param {
	Opt_descriptor_file,
	Opt_base_path,
};

const struct fs_parameter_spec cfs_parameters[] = {
	fsparam_string("descriptor", Opt_descriptor_file),
	fsparam_string("base", Opt_base_path),
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
	sb->s_magic = CFS_MAGIC;
	sb->s_xattr = cfs_xattr_handlers;
	sb->s_export_op = &cfs_export_operations;

	sb->s_op = &cfs_ops;
#if LCFS_USE_TIMESPEC
	sb->s_time_gran = 1;
#else
	sb->s_time_gran = NSEC_PER_SEC;
#endif

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
	struct cfs_info *fsi = inode->i_sb->s_fs_info;
	struct lcfs_inode_s *cfs_ino = inode->i_private;
	struct file *real_file;
	const char *real_path;

	if (WARN_ON(file == NULL))
		return -EIO;

	if (file->f_flags & (O_WRONLY | O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC))
		return -EROFS;

	if (cfs_ino->u.file.payload == 0)
		return -EINVAL;

	real_path = lcfs_c_string(fsi->lcfs_ctx, cfs_ino->u.file.payload, NULL,
				  PATH_MAX);
	if (real_path == NULL)
		return -EIO;

	if (IS_ERR(real_path))
		return PTR_ERR(real_path);

	/* FIXME: prevent loops opening files.  */

	if (fsi->base == NULL || real_path[0] == '/') {
		real_file = file_open_root_mnt(fsi->root_mnt, real_path,
					       file->f_flags, 0);
	} else {
		real_file = file_open_root(&(fsi->base->f_path), real_path,
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
	return current->mm->get_unmapped_area(file, addr, len, pgoff, flags);
}

static int cfs_release_file(struct inode *inode, struct file *file)
{
	if (WARN_ON(file->private_data == NULL))
		return -EIO;
	fput(file->private_data);

	return 0;
}

static int cfs_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct file *realfile = file->private_data;
	int ret;

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

	return vfs_fadvise(realfile, offset, len, advice);
}

static int cfs_encode_fh(struct inode *inode, u32 *fh, int *max_len,
			 struct inode *parent)
{
	struct cfs_info *fsi = inode->i_sb->s_fs_info;
	struct lcfs_inode_s *cfs_ino = inode->i_private;
	int len = 3;
	u64 nodeid;
	u32 generation;

	if (*max_len < len) {
		*max_len = len;
		return FILEID_INVALID;
	}

	nodeid = lcfs_ino_num(fsi->lcfs_ctx, cfs_ino);
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
		struct lcfs_inode_s *inode;
		struct lcfs_vdata_s vdata = {
			.off = inode_index,
			.len = sizeof(struct lcfs_inode_s),
		};

		inode = lcfs_get_vdata(fsi->lcfs_ctx, &vdata);
		if (IS_ERR(inode))
			return ERR_CAST(inode);

		ino = cfs_make_inode(sb, inode, NULL);
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
	struct lcfs_inode_s *cfs_ino = inode->i_private;
	struct cfs_info *fsi = inode->i_sb->s_fs_info;

	return lcfs_get_xattr(fsi->lcfs_ctx, cfs_ino, name, value, size);
}

static ssize_t cfs_listxattr(struct dentry *dentry, char *names, size_t size)
{
	struct inode *inode = d_inode(dentry);
	struct lcfs_inode_s *cfs_ino = inode->i_private;
	struct cfs_info *fsi = inode->i_sb->s_fs_info;

	return lcfs_list_xattrs(fsi->lcfs_ctx, cfs_ino, names, size);
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

static void cfs_kill_sb(struct super_block *sb)
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
	kill_litter_super(sb);
}

static struct file_system_type cfs_type = {
	.name = "composefs",
	.init_fs_context = cfs_init_fs_context,
	.parameters = cfs_parameters,
	.kill_sb = cfs_kill_sb,
	.fs_flags = FS_USERNS_MOUNT,
};

static int __init init_cfs(void)
{
	return register_filesystem(&cfs_type);
}

static void __exit exit_cfs(void)
{
	unregister_filesystem(&cfs_type);
}

module_init(init_cfs);
module_exit(exit_cfs);
