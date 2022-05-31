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

#include "lcfs.h"

enum {
	BUILD_SKIP_XATTRS = (1 << 0),
	BUILD_USE_EPOCH = (1 << 1),
	BUILD_SKIP_DEVICES = (1 << 2),
	BUILD_COMPUTE_DIGEST = (1 << 3),
};

struct lcfs_node_s *lcfs_node_new(void);
void lcfs_node_free(struct lcfs_node_s *node);
struct lcfs_node_s *lcfs_load_node_from_file(int dirfd,
					     const char *fname,
					     int buildflags);
int lcfs_node_append_xattr(struct lcfs_node_s *node,
			   const char *key,
			   const char *value, size_t value_len);
int lcfs_node_set_payload(struct lcfs_node_s *node,
			  const char *payload);

struct lcfs_node_s *lcfs_node_lookup_child(struct lcfs_node_s *node,
					   const char *name);
struct lcfs_node_s *lcfs_node_get_parent(struct lcfs_node_s *node);
int lcfs_node_add_child(struct lcfs_node_s *parent,
			struct lcfs_node_s *child,
			const char *name);
const char *lcfs_node_get_name(struct lcfs_node_s *node);
size_t lcfs_node_get_n_children(struct lcfs_node_s *node);
struct lcfs_node_s * lcfs_node_get_child(struct lcfs_node_s *node, size_t i);
void lcfs_node_make_hardlink(struct lcfs_node_s *node,
			     struct lcfs_node_s *target);

bool lcfs_node_dirp(struct lcfs_node_s *node);
uint32_t lcfs_node_get_mode(struct lcfs_node_s *node);
void lcfs_node_set_mode(struct lcfs_node_s *node,
			uint32_t mode);
uint32_t lcfs_node_get_uid(struct lcfs_node_s *node);
void lcfs_node_set_uid(struct lcfs_node_s *node,
		       uint32_t uid);
uint32_t lcfs_node_get_gid(struct lcfs_node_s *node);
void lcfs_node_set_gid(struct lcfs_node_s *node,
		       uint32_t gid);
uint32_t lcfs_node_get_rdev(struct lcfs_node_s *node);
void lcfs_node_set_rdev(struct lcfs_node_s *node,
			uint32_t rdev);
uint32_t lcfs_node_get_nlink(struct lcfs_node_s *node);
void lcfs_node_set_nlink(struct lcfs_node_s *node,
			 uint32_t nlink);
uint64_t lcfs_node_get_size(struct lcfs_node_s *node);
void lcfs_node_set_size(struct lcfs_node_s *node,
			uint64_t size);


void lcfs_node_set_fsverity_digest(struct lcfs_node_s *node,
                                   uint8_t digest[32]);

typedef int (*lcfs_read_cb)(void *file, void *buf, size_t count);
int lcfs_node_set_fsverity_from_content(struct lcfs_node_s *node,
                                        void *file,
                                        uint64_t size,
                                        lcfs_read_cb read_cb);

struct lcfs_node_s *lcfs_build(struct lcfs_node_s *parent, int dirfd,
			       const char *fname, const char *name,
			       int buildflags);

int lcfs_write_to(struct lcfs_node_s *root, FILE *out);


#endif
