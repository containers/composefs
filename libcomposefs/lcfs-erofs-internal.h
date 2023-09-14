/* lcfs
   Copyright (C) 2023 Alexander Larsson <alexl@redhat.com>

   This file is free software: you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 2.1 of the
   License, or (at your option) any later version.

   This file is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

#ifndef _LCFS_EROFS_INTERNAL_H
#define _LCFS_EROFS_INTERNAL_H

#include <string.h>

#include "lcfs-internal.h"
#include "lcfs-erofs.h"
#include "erofs_fs_wrapper.h"

typedef union {
	__le16 i_format;
	struct erofs_inode_compact compact;
	struct erofs_inode_extended extended;
} erofs_inode;

static const char *erofs_xattr_prefixes[] = {
	"",
	"user.",
	"system.posix_acl_access",
	"system.posix_acl_default",
	"trusted.",
	"lustre.",
	"security.",
};

static inline uint16_t erofs_inode_version(const erofs_inode *cino)
{
	uint16_t i_format = lcfs_u16_from_file(cino->i_format);
	return (i_format >> EROFS_I_VERSION_BIT) & EROFS_I_VERSION_MASK;
}

static inline bool erofs_inode_is_compact(const erofs_inode *cino)
{
	return erofs_inode_version(cino) == 0;
}

static inline uint16_t erofs_inode_datalayout(const erofs_inode *cino)
{
	uint16_t i_format = lcfs_u16_from_file(cino->i_format);
	return (i_format >> EROFS_I_DATALAYOUT_BIT) & EROFS_I_DATALAYOUT_MASK;
}

static inline bool erofs_inode_is_tailpacked(const erofs_inode *cino)
{
	return erofs_inode_datalayout(cino) == EROFS_INODE_FLAT_INLINE;
}

static inline bool erofs_inode_is_flat(const erofs_inode *cino)
{
	return erofs_inode_datalayout(cino) == EROFS_INODE_FLAT_INLINE ||
	       erofs_inode_datalayout(cino) == EROFS_INODE_FLAT_PLAIN;
}

static inline size_t erofs_xattr_inode_size(uint16_t xattr_icount)
{
	size_t xattr_size = 0;
	if (xattr_icount > 0)
		xattr_size = sizeof(struct erofs_xattr_ibody_header) +
			     (xattr_icount - 1) * 4;
	return xattr_size;
}

#define EROFS_N_XATTR_PREFIXES (sizeof(erofs_xattr_prefixes) / sizeof(char *))

static inline bool erofs_is_acl_xattr(int prefix, const char *name, size_t name_len)
{
	const char *const nfs_acl = "system.nfs4_acl";

	if ((prefix == EROFS_XATTR_INDEX_POSIX_ACL_ACCESS ||
	     prefix == EROFS_XATTR_INDEX_POSIX_ACL_DEFAULT) &&
	    name_len == 0)
		return true;
	if (prefix == 0 && name_len == strlen(nfs_acl) &&
	    memcmp(name, nfs_acl, strlen(nfs_acl)) == 0)
		return true;
	return false;
}

static inline int erofs_get_xattr_prefix(const char *str)
{
	for (int i = 1; i < EROFS_N_XATTR_PREFIXES; i++) {
		const char *prefix = erofs_xattr_prefixes[i];
		if (strlen(str) >= strlen(prefix) &&
		    memcmp(str, prefix, strlen(prefix)) == 0) {
			return i;
		}
	}
	return 0;
}

static inline char *erofs_get_xattr_name(uint8_t index, const char *name,
					 size_t name_len)
{
	char *res;
	const char *prefix;
	size_t prefix_len;

	if (index >= EROFS_N_XATTR_PREFIXES) {
		errno = EINVAL;
		return NULL;
	}

	prefix = erofs_xattr_prefixes[index];
	prefix_len = strlen(prefix);

	res = malloc(prefix_len + name_len + 1);
	if (res == NULL) {
		errno = ENOMEM;
		return NULL;
	}
	memcpy(res, prefix, prefix_len);
	memcpy(res + prefix_len, name, name_len);
	res[prefix_len + name_len] = 0;

	return res;
}

#endif
