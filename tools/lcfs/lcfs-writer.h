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

struct lcfs_ctx_s;

/* In memory representation used to build the file.  */

struct lcfs_node_s {
	struct lcfs_node_s *next;

	struct lcfs_node_s *parent;

	struct lcfs_node_s **children;
	size_t children_size;

	/* Used to create hard links.  */
	struct lcfs_node_s *link_to;

	size_t index;

	bool inode_written;

	char *name;
	struct lcfs_dentry_s data;

	struct lcfs_inode_s inode;
	struct lcfs_inode_data_s inode_data;

	struct lcfs_extend_s extend;
};

enum {
	BUILD_SKIP_XATTRS = (1 << 0),
	BUILD_USE_EPOCH = (1 << 1),
	BUILD_SKIP_DEVICES = (1 << 2),
};

bool lcfs_node_dirp(struct lcfs_node_s *node);

struct lcfs_ctx_s *lcfs_new_ctx();
int lcfs_close(struct lcfs_ctx_s *ctx);

struct lcfs_node_s *lcfs_node_new(void);
struct lcfs_node_s *lcfs_load_node_from_file(struct lcfs_ctx_s *ctx, int dirfd,
					     const char *fname,
					     const char *name, int flags,
					     int buildflags);
int lcfs_add_child(struct lcfs_ctx_s *ctx, struct lcfs_node_s *parent,
		   struct lcfs_node_s *child);

int lcfs_free_node(struct lcfs_node_s *node);

int lcfs_set_payload(struct lcfs_ctx_s *ctx, struct lcfs_node_s *node,
		     const char *payload, size_t len);

int lcfs_set_xattrs(struct lcfs_ctx_s *ctx, struct lcfs_node_s *node,
		    const char *xattrs, size_t len);

void lcfs_set_root(struct lcfs_ctx_s *ctx, struct lcfs_node_s *parent);

int lcfs_write_to(struct lcfs_ctx_s *ctx, FILE *out);

struct lcfs_node_s *lcfs_build(struct lcfs_ctx_s *ctx,
			       struct lcfs_node_s *parent, int fd,
			       const char *fname, const char *name, int flags,
			       int buildflags);

int lcfs_write_to(struct lcfs_ctx_s *ctx, FILE *out);

int lcfs_get_vdata(struct lcfs_ctx_s *ctx, char **vdata, size_t *len);

int lcfs_append_xattr_to_buffer(struct lcfs_ctx_s *ctx, char **buffer,
				size_t *len, const char *key, size_t key_len,
				const char *value, size_t value_len);

int lcfs_append_vdata(struct lcfs_ctx_s *ctx, struct lcfs_vdata_s *out,
		      const void *data, size_t len);

int lcfs_append_vdata_no_dedup(struct lcfs_ctx_s *ctx, struct lcfs_vdata_s *out,
			       const void *data, size_t len);

#endif
