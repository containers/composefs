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

#include "config.h"

#include "libcomposefs/lcfs.h"

#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <error.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <inttypes.h>

static bool is_dir(const struct lcfs_inode_s *d)
{
	return (d->st_mode & S_IFMT) == S_IFDIR;
}

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

static const void *get_v_data(struct lcfs_inode_s *ino, const uint8_t *vdata, void *default_val)
{
	if (ino->variable_data.len == 0)
		return default_val;

	return vdata + ino->variable_data.off;
}

static uint32_t decode_uint32(const uint8_t **data)
{
	uint32_t *d = (uint32_t *)*data;
	*data += sizeof(uint32_t);
	return lcfs_u32_from_file(*d);
}

static uint64_t decode_uint64(const uint8_t **data)
{
	uint64_t *d = (uint64_t *)*data;
	*data += sizeof(uint64_t);
	return lcfs_u64_from_file(*d);
}

static void decode_inode(const uint8_t *inode_data, uint64_t inod_num,
			 struct lcfs_inode_s *ino)
{
	const uint8_t *data = inode_data + inod_num;

	memset(ino, 0, sizeof(struct lcfs_inode_s));

	ino->flags = decode_uint32(&data);
        ino->variable_data.off = decode_uint64(&data);
        ino->variable_data.len = decode_uint32(&data);

	if (LCFS_INODE_FLAG_CHECK(ino->flags, MODE)) {
		ino->st_mode = decode_uint32(&data);
	} else {
		ino->st_mode = LCFS_INODE_DEFAULT_MODE;
	}

	if (LCFS_INODE_FLAG_CHECK(ino->flags, NLINK)) {
		ino->st_nlink = decode_uint32(&data);
	} else {
		ino->st_nlink = LCFS_INODE_DEFAULT_NLINK;
	}

	if (LCFS_INODE_FLAG_CHECK(ino->flags, UIDGID)) {
		ino->st_uid = decode_uint32(&data);
		ino->st_gid = decode_uint32(&data);
	} else {
		ino->st_uid = LCFS_INODE_DEFAULT_UIDGID;
		ino->st_gid = LCFS_INODE_DEFAULT_UIDGID;
	}

	if (LCFS_INODE_FLAG_CHECK(ino->flags, RDEV)) {
		ino->st_rdev = decode_uint32(&data);
	} else {
		ino->st_rdev = LCFS_INODE_DEFAULT_RDEV;
	}

	if (LCFS_INODE_FLAG_CHECK(ino->flags, TIMES)) {
		ino->st_mtim.tv_sec = decode_uint64(&data);
		ino->st_ctim.tv_sec = decode_uint64(&data);
	} else {
		ino->st_mtim.tv_sec = LCFS_INODE_DEFAULT_TIMES;
		ino->st_ctim.tv_sec = LCFS_INODE_DEFAULT_TIMES;
	}

	if (LCFS_INODE_FLAG_CHECK(ino->flags, TIMES_NSEC)) {
		ino->st_mtim.tv_nsec = decode_uint32(&data);
		ino->st_ctim.tv_nsec = decode_uint32(&data);
	} else {
		ino->st_mtim.tv_nsec = 0;
		ino->st_ctim.tv_nsec = 0;
	}

	if (LCFS_INODE_FLAG_CHECK(ino->flags, LOW_SIZE)) {
		ino->st_size = decode_uint32(&data);
	} else {
		ino->st_size = 0;
	}

	if (LCFS_INODE_FLAG_CHECK(ino->flags, HIGH_SIZE)) {
		ino->st_size += (uint64_t)decode_uint32(&data) << 32;
	}

	if (LCFS_INODE_FLAG_CHECK(ino->flags, XATTRS)) {
		ino->xattrs.off = decode_uint64(&data);
		ino->xattrs.len = decode_uint32(&data);
	} else {
		ino->xattrs.off = 0;
		ino->xattrs.len = 0;
	}

	if (LCFS_INODE_FLAG_CHECK(ino->flags, DIGEST)) {
		memcpy(ino->digest, data, LCFS_DIGEST_SIZE);
		data += LCFS_DIGEST_SIZE;
	}
}

static void digest_to_string(const uint8_t *csum, char *buf)
{
	static const char hexchars[] = "0123456789abcdef";
	uint32_t i, j;

	for (i = 0, j = 0; i < LCFS_DIGEST_SIZE; i++, j += 2) {
		uint8_t byte = csum[i];
		buf[j] = hexchars[byte >> 4];
		buf[j + 1] = hexchars[byte & 0xF];
	}
	buf[j] = '\0';
}

static int dump_inode(const uint8_t *inode_data, const uint8_t *vdata,
		      const char *name, size_t name_len, uint64_t index,
		      size_t rec, bool extended, bool xattrs, bool recurse)
{
	struct lcfs_inode_s ino;
	bool dirp;
	size_t i;

	decode_inode(inode_data, index, &ino);

	dirp = is_dir(&ino);

	putchar('|');
	for (i = 0; i < rec; i++)
		putchar('-');

	if (xattrs) {
		if (ino.xattrs.len != 0) {
			struct lcfs_xattr_header_s *header =
				(struct lcfs_xattr_header_s *)(vdata +
							       ino.xattrs.off);
			uint16_t n_attr = lcfs_u16_from_file(header->n_attr);
			uint8_t *data;

			data = ((uint8_t *)header) + lcfs_xattr_header_size(n_attr);
			for (i = 0; i < n_attr; i++) {
				struct lcfs_xattr_element_s *e = &header->attr[i];
				uint16_t key_length =
					lcfs_u16_from_file(e->key_length);
				uint16_t value_length =
					lcfs_u16_from_file(e->value_length);

				printf("%.*s -> %.*s\n", (int)key_length, data,
				       (int)value_length, data + key_length);
				data += key_length + value_length;
			}
		}
	} else if (!extended)
		if (is_dir(&ino))
			printf("%.*s/\n", (int)name_len, name);
		else {
			const char *payload = get_v_data(&ino, vdata, "");
			if ((ino.st_mode & S_IFMT) == S_IFLNK) {
				printf("%.*s -> %s\n", (int)name_len, name, payload);
			} else {
				printf("%.*s [%s]\n", (int)name_len, name, payload);
			}
		}
	else {
		int n_xattrs = 0;
		char digest_str[LCFS_DIGEST_SIZE * 2 + 1] = { 0 };
		const char *payload = "";

		if (!is_dir(&ino))
			payload = get_v_data(&ino, vdata, "");

		if (ino.xattrs.len != 0) {
			struct lcfs_xattr_header_s *header =
				(struct lcfs_xattr_header_s *)(vdata +
							       ino.xattrs.off);
			n_xattrs = lcfs_u16_from_file(header->n_attr);
		}

		if (ino.flags & LCFS_INODE_FLAGS_DIGEST) {
			digest_to_string(ino.digest, digest_str);
		}

		printf("name:%.*s|ino:%" PRIu64
		       "|mode:%o|nlinks:%u|uid:%d|gid:%d|rdev:%d|size:%" PRIu64
		       "|mtim:%ld.%ld|ctim:%ld.%ld|nxargs:%d|digest:%s|payload:%s\n",
		       (int)name_len, name, index, ino.st_mode, ino.st_nlink,
		       ino.st_uid, ino.st_gid, ino.st_rdev, ino.st_size,
		       ino.st_mtim.tv_sec, ino.st_mtim.tv_nsec, ino.st_ctim.tv_sec,
		       ino.st_ctim.tv_nsec, n_xattrs, digest_str, payload);
	}

	if (dirp && recurse && ino.variable_data.len != 0) {
		const struct lcfs_dir_header_s *dir = (const struct lcfs_dir_header_s *)(vdata + ino.variable_data.off);
		uint32_t n_dirents = lcfs_u32_from_file(dir->n_dirents);
		const char *namedata = (const char *)dir + lcfs_dir_header_size(n_dirents);

		for (i = 0; i < n_dirents; i++) {
			size_t child_name_len = dir->dirents[i].name_len;
			size_t child_name_offset = lcfs_u32_from_file(dir->dirents[i].name_offset);

			dump_inode(inode_data, vdata, namedata + child_name_offset, child_name_len,
				   lcfs_u64_from_file(dir->dirents[i].inode_index),
				   rec + 1, extended, xattrs, recurse);
		}
	}

	return 0;
}

static uint64_t find_child(const uint8_t *inode_data, const uint8_t *vdata,
                           uint64_t current, const char *name)
{
	struct lcfs_inode_s ino;
	const struct lcfs_dir_header_s *dir;
	size_t i, name_len;

	decode_inode(inode_data, current, &ino);

	if (!is_dir(&ino))
		return UINT64_MAX;

	if (ino.variable_data.len == 0)
		return UINT64_MAX;

	dir = (const struct lcfs_dir_header_s *)(vdata + ino.variable_data.off);
	size_t n_dirents = lcfs_u32_from_file(dir->n_dirents);
	const char *namedata;

	namedata = (const char *)dir + lcfs_dir_header_size(n_dirents);

	name_len = strlen(name);
	for (i = 0; i < n_dirents; i++) {
		size_t child_name_len = dir->dirents[i].name_len;
		size_t child_name_offset = lcfs_u32_from_file(dir->dirents[i].name_offset);
		if (name_len == child_name_len &&
		    memcmp(name, namedata + child_name_offset, name_len) == 0) {
			return lcfs_u64_from_file(dir->dirents[i].inode_index);
		}
	}

	return UINT64_MAX;
}

static uint64_t lookup(const uint8_t *inode_data, const uint8_t *vdata,
                       uint64_t parent, const void *what)
{
	char *it;
	char *dpath, *path;
	uint64_t current;

	if (strcmp(what, "/") == 0)
		return parent;

	path = strdup(what);
	if (path == NULL)
		error(EXIT_FAILURE, errno, "strdup");

	current = parent;
	dpath = path;
	while ((it = strsep(&dpath, "/"))) {
		if (strlen(it) == 0)
			continue; /* Skip initial, terminal or repeated slashes */
		current = find_child(inode_data, vdata, current, it);
		if (current == UINT64_MAX) {
			errno = ENOENT;
			free(path);
			return current;
		}
	}

	free(path);
	return current;
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
	const uint8_t *inode_data;
	uint8_t *vdata;
	size_t root_index;
	struct lcfs_superblock_s *superblock;
	size_t data_offset;

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
	if (data == MAP_FAILED)
		error(EXIT_FAILURE, errno, "fstat %s", argv[1]);

	superblock = (struct lcfs_superblock_s *)data;

	if (lcfs_u64_from_file(superblock->data_offset) > size)
		error(EXIT_FAILURE, EINVAL, "Invalid data offset");

	inode_data = data + sizeof(struct lcfs_superblock_s);
	data_offset = lcfs_u64_from_file(superblock->data_offset);
	assert(data_offset % 4 == 0);
	vdata = data + data_offset;
	root_index = lcfs_u64_from_file(superblock->root_inode);
	if (mode == DUMP) {
		dump_inode(inode_data, vdata, "", 0, root_index, 0, false,
			   false, true);
	} else if (mode == DUMP_EXTENDED) {
		dump_inode(inode_data, vdata, "", 0, root_index, 0, true, false, true);
	} else if (mode == LOOKUP) {
		uint64_t index;

		index = lookup(inode_data, vdata, root_index, argv[3]);
		if (index == UINT64_MAX)
			error(EXIT_FAILURE, 0, "file %s not found", argv[3]);

		dump_inode(inode_data, vdata, "", 0, index, 0, true, false, false);
	} else if (mode == XATTRS) {
		uint64_t index;

		index = lookup(inode_data, vdata, root_index, argv[3]);
		if (index == UINT64_MAX)
			error(EXIT_FAILURE, 0, "file %s not found", argv[3]);

		dump_inode(inode_data, vdata, "", 0, index, 0, true, true, false);
	}

	munmap(data, size);
}
