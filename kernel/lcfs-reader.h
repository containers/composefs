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

struct lcfs_context_s *lcfs_create_ctx(char *descriptor_path,
                                       const u8 *required_digest);

void lcfs_destroy_ctx(struct lcfs_context_s *ctx);

struct lcfs_inode_s *lcfs_get_root_ino(struct lcfs_context_s *ctx,
				       struct lcfs_inode_s *ino_buf,
				       lcfs_off_t *index);

struct lcfs_inode_s *lcfs_get_ino_index(struct lcfs_context_s *ctx,
					lcfs_off_t index,
					struct lcfs_inode_s *buffer);

const uint8_t *lcfs_get_digest(struct lcfs_context_s *ctx, struct lcfs_inode_s *ino, const char *payload, u8 digest_buf[LCFS_DIGEST_SIZE]);

struct lcfs_dir_s *lcfs_get_dir(struct lcfs_context_s *ctx, struct lcfs_inode_s *ino, lcfs_off_t index);

struct lcfs_xattr_header_s *lcfs_get_xattrs(struct lcfs_context_s *ctx, struct lcfs_inode_s *ino);
ssize_t lcfs_list_xattrs(struct lcfs_xattr_header_s *xattrs, char *names, size_t size);
int lcfs_get_xattr(struct lcfs_xattr_header_s *xattrs, const char *name, void *value, size_t size);

typedef bool (*lcfs_dir_iter_cb)(void *private, const char *name, int namelen, u64 ino, unsigned int dtype);

int lcfs_dir_iterate(struct lcfs_dir_s *dir, loff_t first, lcfs_dir_iter_cb cb, void *private);
u32 lcfs_dir_get_link_count(struct lcfs_dir_s *dir);

int lcfs_lookup(struct lcfs_dir_s *dir, const char *name, size_t name_len, lcfs_off_t *index);

char *lcfs_dup_payload_path(struct lcfs_context_s *ctx, struct lcfs_inode_s *ino, lcfs_off_t index);

#endif
