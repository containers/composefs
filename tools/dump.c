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

static const void *get_vdata(const char *x)
{
	return x + sizeof(struct lcfs_header_s);
}

static const char *get_v_payload(const struct lcfs_inode_s *ino,
				 const char *vdata)
{
	if (ino->u.file.payload.len == 0)
		return "";

	return vdata + ino->u.file.payload.off;
}

static bool is_dir(const struct lcfs_inode_data_s *d)
{
	return (d->st_mode & S_IFMT) == S_IFDIR;
}

static int dump_dentry(const void *vdata, const char *name, size_t index,
		       size_t rec, bool extended, bool xattrs)
{
	struct lcfs_inode_data_s *ino_data;
	struct lcfs_inode_s *ino;
	bool dirp;
	size_t i;

	ino = (struct lcfs_inode_s *)(vdata + index);
	ino_data = (struct lcfs_inode_data_s *)(vdata + ino->inode_data_index);

	dirp = is_dir(ino_data);

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
		       name, index, ino_data->st_mode, ino_data->st_nlink,
		       ino_data->st_uid, ino_data->st_gid,
		       dirp ? 0 : ino->u.file.st_size,
		       dirp ? "" : get_v_payload(ino, vdata));
	}

	if (dirp) {
		for (i = ino->u.dir.off; i < ino->u.dir.off + ino->u.dir.len;
		     i += sizeof(struct lcfs_dentry_s)) {
			const struct lcfs_dentry_s *de = vdata + i;

			dump_dentry(vdata, vdata + de->name.off,
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

static size_t find_child(const void *vdata, size_t current, const char *name)
{
	const struct lcfs_inode_s *i = vdata + current;
	const void *found;
	size_t dentry_size = sizeof(struct lcfs_dentry_s);
	struct bsearch_key_s key = {
		.name = name,
		.vdata = vdata,
	};

	if (!is_dir(vdata + i->inode_data_index))
		return SIZE_MAX;

	found = bsearch(&key, vdata + i->u.dir.off, i->u.dir.len / dentry_size,
			dentry_size, compare_names);
	if (found == NULL)
		return SIZE_MAX;

	return (found - vdata);
}

static const struct lcfs_dentry_s *lookup(const void *vdata, size_t current,
					  const void *what)
{
	char *it;
	char *dpath, *path;

	if (strcmp(what, "/") == 0)
		return what + current;

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
	return vdata + current;
}

#define DUMP 1
#define LOOKUP 2
#define XATTRS 3
#define DUMP_EXTENDED 4

int main(int argc, char *argv[])
{
	char *data;
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

	data = (char *)mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
	if (data == NULL)
		error(EXIT_FAILURE, errno, "fstat %s", argv[1]);

	root_index = size - sizeof(struct lcfs_header_s) -
		     sizeof(struct lcfs_inode_s);
	if (mode == DUMP) {
		dump_dentry(get_vdata(data), "", root_index, 0, false, false);
	} else if (mode == DUMP_EXTENDED) {
		dump_dentry(get_vdata(data), "", root_index, 0, true, false);
	} else if (mode == LOOKUP) {
		const void *node;
		size_t index;

		node = lookup(get_vdata(data), root_index, argv[3]);
		if (node == NULL)
			error(EXIT_FAILURE, 0, "file %s not found", argv[3]);

		index = node - get_vdata(data);
		dump_dentry(get_vdata(data), "", index, 0, true, false);
	} else if (mode == XATTRS) {
		const void *node;
		size_t index;

		node = lookup(get_vdata(data), root_index, argv[3]);
		if (node == NULL)
			error(EXIT_FAILURE, 0, "file %s not found", argv[3]);

		index = node - get_vdata(data);
		dump_dentry(get_vdata(data), "", index, 0, true, true);
	}

	munmap(data, size);
}
