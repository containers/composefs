/* lcfs
   Copyright (C) 2021 Giuseppe Scrivano <giuseppe@scrivano.org>

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _LCFS_OPS_H
#define _LCFS_OPS_H

#include <stdlib.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#define LCFS_DIGEST_SIZE 32

enum {
	LCFS_BUILD_SKIP_XATTRS = (1 << 0),
	LCFS_BUILD_USE_EPOCH = (1 << 1),
	LCFS_BUILD_SKIP_DEVICES = (1 << 2),
	LCFS_BUILD_COMPUTE_DIGEST = (1 << 3),
};

enum lcfs_format_t {
	LCFS_FORMAT_EROFS,
	LCFS_FORMAT_COMPOSEFS,
};

enum lcfs_flags_t {
	LCFS_FLAGS_NONE = 0,
	LCFS_FLAGS_MASK = 0,
};

typedef ssize_t (*lcfs_read_cb)(void *file, void *buf, size_t count);
typedef ssize_t (*lcfs_write_cb)(void *file, void *buf, size_t count);

struct lcfs_write_options_s {
	uint32_t format;
	uint32_t version;
	uint32_t flags;
	uint8_t *digest_out;
	void *file;
	lcfs_write_cb file_write_cb;
	uint32_t reserved[4];
	void *reserved2[4];
};

struct lcfs_node_s *lcfs_node_new(void);
struct lcfs_node_s *lcfs_node_ref(struct lcfs_node_s *node);
void lcfs_node_unref(struct lcfs_node_s *node);
struct lcfs_node_s *lcfs_node_clone(struct lcfs_node_s *node);
struct lcfs_node_s *lcfs_node_clone_deep(struct lcfs_node_s *node);
struct lcfs_node_s *lcfs_load_node_from_file(int dirfd, const char *fname,
					     int buildflags);

const char *lcfs_node_get_xattr(struct lcfs_node_s *node, const char *name,
				size_t *length);
int lcfs_node_set_xattr(struct lcfs_node_s *node, const char *name,
			const char *value, size_t value_len);
int lcfs_node_unset_xattr(struct lcfs_node_s *node, const char *name);
size_t lcfs_node_get_n_xattr(struct lcfs_node_s *node);
const char *lcfs_node_get_xattr_name(struct lcfs_node_s *node, size_t index);

int lcfs_node_set_payload(struct lcfs_node_s *node, const char *payload);

struct lcfs_node_s *lcfs_node_lookup_child(struct lcfs_node_s *node,
					   const char *name);
struct lcfs_node_s *lcfs_node_get_parent(struct lcfs_node_s *node);
int lcfs_node_add_child(struct lcfs_node_s *parent,
			struct lcfs_node_s *child, /* Takes ownership on success */
			const char *name);
int lcfs_node_remove_child(struct lcfs_node_s *parent, const char *name);
const char *lcfs_node_get_name(struct lcfs_node_s *node);
size_t lcfs_node_get_n_children(struct lcfs_node_s *node);
struct lcfs_node_s *lcfs_node_get_child(struct lcfs_node_s *node, size_t i);
void lcfs_node_make_hardlink(struct lcfs_node_s *node, struct lcfs_node_s *target);

bool lcfs_node_dirp(struct lcfs_node_s *node);
uint32_t lcfs_node_get_mode(struct lcfs_node_s *node);
void lcfs_node_set_mode(struct lcfs_node_s *node, uint32_t mode);
uint32_t lcfs_node_get_uid(struct lcfs_node_s *node);
void lcfs_node_set_uid(struct lcfs_node_s *node, uint32_t uid);
uint32_t lcfs_node_get_gid(struct lcfs_node_s *node);
void lcfs_node_set_gid(struct lcfs_node_s *node, uint32_t gid);
uint32_t lcfs_node_get_rdev(struct lcfs_node_s *node);
void lcfs_node_set_rdev(struct lcfs_node_s *node, uint32_t rdev);
uint32_t lcfs_node_get_nlink(struct lcfs_node_s *node);
void lcfs_node_set_nlink(struct lcfs_node_s *node, uint32_t nlink);
uint64_t lcfs_node_get_size(struct lcfs_node_s *node);
void lcfs_node_set_size(struct lcfs_node_s *node, uint64_t size);
void lcfs_node_set_mtime(struct lcfs_node_s *node, struct timespec *time);
void lcfs_node_get_mtime(struct lcfs_node_s *node, struct timespec *time);
void lcfs_node_set_ctime(struct lcfs_node_s *node, struct timespec *time);
void lcfs_node_get_ctime(struct lcfs_node_s *node, struct timespec *time);

const uint8_t *lcfs_node_get_fsverity_digest(struct lcfs_node_s *node);
void lcfs_node_set_fsverity_digest(struct lcfs_node_s *node, uint8_t digest[32]);

int lcfs_node_set_fsverity_from_content(struct lcfs_node_s *node, void *file,
					lcfs_read_cb read_cb);

int lcfs_node_set_fsverity_from_fd(struct lcfs_node_s *node, int fd);

struct lcfs_node_s *lcfs_build(int dirfd, const char *fname, const char *name,
			       int buildflags, char **failed_path_out);

int lcfs_write_to(struct lcfs_node_s *root, struct lcfs_write_options_s *options);

#endif
