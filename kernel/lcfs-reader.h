#ifndef _LCFS_READER_H
#define _LCFS_READER_H

#include "lcfs.h"

#define EFSCORRUPTED       EUCLEAN         /* Filesystem is corrupted */

#ifdef FUZZING
# define ERR_CAST(x)((void *)x)
# define ERR_PTR(x)((void *)((long)x))
# define PTR_ERR(x)((long)x)
# define IS_ERR(x) ((unsigned long)(void *)(x) >= (unsigned long)-4096)
#endif

struct lcfs_context_s;

struct lcfs_context_s *lcfs_create_ctx(char *descriptor_path);

void lcfs_destroy_ctx(struct lcfs_context_s *ctx);

struct lcfs_dentry_s *lcfs_get_dentry(struct lcfs_context_s *ctx, size_t index,
				      struct lcfs_dentry_s *buffer);

/* Copy the specified VDATA to DEST.  DEST must be preallocated and must be at least
   vdata.len bytes.  */
void *lcfs_get_vdata(struct lcfs_context_s *ctx,
		     const struct lcfs_vdata_s vdata,
		     void *dest);

struct lcfs_inode_s *lcfs_get_ino_index(struct lcfs_context_s *ctx,
					lcfs_off_t index,
					struct lcfs_inode_s *buffer);

struct lcfs_inode_s *lcfs_dentry_inode(struct lcfs_context_s *ctx,
				       struct lcfs_dentry_s *node,
				       struct lcfs_inode_s *buffer);

struct lcfs_inode_data_s *lcfs_inode_data(struct lcfs_context_s *ctx,
					  struct lcfs_inode_s *ino,
					  struct lcfs_inode_data_s *buffer);

const char *lcfs_c_string(struct lcfs_context_s *ctx, struct lcfs_vdata_s vdata,
			  char *buf, size_t max);

static inline u64 lcfs_dentry_ino(struct lcfs_dentry_s *d)
{
	return d->inode_index;
}

lcfs_off_t lcfs_get_root_index(struct lcfs_context_s *ctx);

ssize_t lcfs_list_xattrs(struct lcfs_context_s *ctx, struct lcfs_inode_s *ino, char *names, size_t size);

int lcfs_get_xattr(struct lcfs_context_s *ctx, struct lcfs_inode_s *ino, const char *name, void *value, size_t size);

typedef bool (*lcfs_dir_iter_cb)(void *private, const char *name, int namelen, u64 ino, unsigned int dtype);

int lcfs_iterate_dir(struct lcfs_context_s *ctx, loff_t first, struct lcfs_inode_s *dir_ino, lcfs_dir_iter_cb cb, void *private);

int lcfs_lookup(struct lcfs_context_s *ctx, struct lcfs_inode_s *dir, const char *name, lcfs_off_t *index);

const char *lcfs_get_payload(struct lcfs_context_s *ctx, struct lcfs_inode_s *ino, void *buf);

char *lcfs_dup_payload_path(struct lcfs_context_s *ctx, struct lcfs_inode_s *ino);

const char *lcfs_get_extend(struct lcfs_context_s *ctx, struct lcfs_inode_s *ino, size_t n_extend, off_t *off, void *buf);

int lcfs_get_file_size(struct lcfs_context_s *ctx, struct lcfs_inode_s *ino, loff_t *size);

#endif
