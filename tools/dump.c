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

#define _GNU_SOURCE

#include "lcfs.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <error.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/mman.h>

static int get_file_size(int fd, off_t *out)
{
	struct stat sb;
	int ret;

	ret = fstat(fd, &sb);
	if (ret < 0)
		return ret;

	*out = sb.st_size;
	return 0;
}

static const uint8_t *get_vdata(const uint8_t *x)
{
	return x + sizeof(struct lcfs_header_s);
}

static uint64_t get_size(bool symlink_p,
			 const struct lcfs_inode_s *ino,
			 const struct lcfs_extend_s *extends,
			 const uint8_t *vdata)
{
	off_t res = 0;
	size_t i;

	if (symlink_p)
		return 0;

	for (i = 0; i < ino->u.extends.len; i += sizeof(struct lcfs_extend_s)) {
		res += extends[i / sizeof(struct lcfs_extend_s)].st_size;
	}

	return res;
}

static const char *get_v_payload(bool symlink_p,
				 const struct lcfs_inode_s *ino,
				 const struct lcfs_extend_s *extends,
				 const uint8_t *vdata)
{
	if (symlink_p)
		return (const char *)(vdata + ino->u.payload.off);

	if (ino->u.extends.len == 0)
		return "";

	return (const char *)(vdata + extends[0].payload.off);
}

static bool is_dir(const struct lcfs_inode_s *d)
{
	return (d->st_mode & S_IFMT) == S_IFDIR;
}

static bool is_symlink(const struct lcfs_inode_s *d)
{
	return (d->st_mode & S_IFMT) == S_IFLNK;
}

static int dump_dentry(const uint8_t *vdata, const char *name, size_t index,
		       size_t rec, bool extended, bool xattrs)
{
	struct lcfs_extend_s *extends;
	struct lcfs_inode_s *ino;
	bool dirp;
	size_t i;

	ino = (struct lcfs_inode_s *)(vdata + index);
	extends = (struct lcfs_extend_s *)(vdata + ino->u.extends.off);
	dirp = is_dir(ino);

	putchar('|');
	for (i = 0; i < rec; i++)
		putchar('-');

	if (xattrs) {
		for (i = ino->xattrs.off; i < ino->xattrs.off + ino->xattrs.len;
		     i += sizeof(struct lcfs_xattr_header_s)) {
			struct lcfs_xattr_header_s *h =
				(struct lcfs_xattr_header_s *)(vdata + i);
			printf("%.*s -> %.*s\n", (int)h->key.len,
			       (const char *)(vdata + h->key.off),
			       (int)h->value.len,
			       (const char *)(vdata + h->value.off));
		}
	} else if (!extended)
		printf("%s\n", name);
	else {
		printf("name:%s|ino:%zu|mode:%o|nlinks:%u|uid:%d|gid:%d|size:%lu|payload:%s\n",
		       name, index, ino->st_mode, ino->st_nlink,
		       ino->st_uid, ino->st_gid,
		       dirp ? 0 : get_size(is_symlink(ino), ino, extends, vdata),
		       dirp ? "" : get_v_payload(is_symlink(ino), ino, extends, vdata));
	}

	if (dirp) {
		for (i = ino->u.dir.off; i < ino->u.dir.off + ino->u.dir.len;
		     i += sizeof(struct lcfs_dentry_s)) {
			const struct lcfs_dentry_s *de = (const struct lcfs_dentry_s *)(vdata + i);

			dump_dentry(vdata, (char *)(vdata + de->name.off),
                                    de->inode_index,
				    rec + 1, extended, xattrs);
		}
	}

	return 0;
}

struct bsearch_key_s {
	const char *name;
	const char *vdata;
};

/* The first argument is the KEY, so take advantage to pass additional data.  */
static int compare_names(const void *a, const void *b)
{
	struct bsearch_key_s *key = (struct bsearch_key_s *)a;
	const struct lcfs_dentry_s *de = b;

	const char *name = key->vdata + de->name.off;

	return strcmp(key->name, name);
}

static size_t find_child(const uint8_t *vdata, size_t current, const char *name)
{
	const struct lcfs_inode_s *i = (const struct lcfs_inode_s *)(vdata + current);
	const uint8_t *found;
	size_t dentry_size = sizeof(struct lcfs_dentry_s);
	struct bsearch_key_s key = {
		.name = name,
		.vdata = (void *)vdata,
	};

	if (!is_dir(i))
		return SIZE_MAX;

	found = bsearch(&key, vdata + i->u.dir.off, i->u.dir.len / dentry_size,
			dentry_size, compare_names);
	if (found == NULL)
		return SIZE_MAX;

	return (found - vdata);
}

static const struct lcfs_dentry_s *lookup(const uint8_t *vdata, size_t current,
					  const void *what)
{
	char *it;
	char *dpath, *path;

	if (strcmp(what, "/") == 0)
		return (struct lcfs_dentry_s *)what + current;

	path = strdup(what);
	if (path == NULL)
		error(EXIT_FAILURE, errno, "strdup");

	dpath = path;
	while ((it = strsep(&dpath, "/"))) {
		current = find_child(vdata, current, it);
		if (current == SIZE_MAX) {
			errno = ENOENT;
			free(path);
			return NULL;
		}
	}

	free(path);
	return (struct lcfs_dentry_s *)(vdata + current);
}

#define DUMP 1
#define LOOKUP 2
#define XATTRS 3
#define DUMP_EXTENDED 4

int main(int argc, char *argv[])
{
	uint8_t *data;
	off_t size;
	int ret;
	int fd;
	int mode;
	size_t root_index;

	if (argc < 3)
		error(EXIT_FAILURE, errno, "argument not specified");

	if (strcmp(argv[1], "dump") == 0) {
		mode = DUMP;
	} else if (strcmp(argv[1], "lookup") == 0) {
		if (argc < 4)
			error(EXIT_FAILURE, errno, "argument not specified");
		mode = LOOKUP;
	} else if (strcmp(argv[1], "xattrs") == 0) {
		if (argc < 4)
			error(EXIT_FAILURE, errno, "argument not specified");
		mode = XATTRS;
	} else if (strcmp(argv[1], "dump-extended") == 0) {
		mode = DUMP_EXTENDED;
	} else {
		error(EXIT_FAILURE, 0, "invalid mode");
	}

	fd = open(argv[2], O_RDONLY);
	if (fd < 0)
		error(EXIT_FAILURE, errno, "open %s", argv[1]);

	ret = get_file_size(fd, &size);
	if (ret < 0)
		error(EXIT_FAILURE, errno, "read file size %s", argv[1]);

	data = (uint8_t *)mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
	if (data == NULL)
		error(EXIT_FAILURE, errno, "fstat %s", argv[1]);

	root_index = size - sizeof(struct lcfs_header_s) -
		     sizeof(struct lcfs_inode_s);
	if (mode == DUMP) {
		dump_dentry(get_vdata(data), "", root_index, 0, false, false);
	} else if (mode == DUMP_EXTENDED) {
		dump_dentry(get_vdata(data), "", root_index, 0, true, false);
	} else if (mode == LOOKUP) {
		const struct lcfs_dentry_s *dentry;
		size_t index;

		dentry = lookup(get_vdata(data), root_index, argv[3]);
		if (dentry == NULL)
			error(EXIT_FAILURE, 0, "file %s not found", argv[3]);

		index = (uint8_t *)dentry - get_vdata(data);
		dump_dentry(get_vdata(data), "", index, 0, true, false);
	} else if (mode == XATTRS) {
		const struct lcfs_dentry_s *dentry;
		size_t index;

		dentry = lookup(get_vdata(data), root_index, argv[3]);
		if (dentry == NULL)
			error(EXIT_FAILURE, 0, "file %s not found", argv[3]);

		index = (uint8_t *)dentry - get_vdata(data);
		dump_dentry(get_vdata(data), "", index, 0, true, true);
	}

	munmap(data, size);
}
