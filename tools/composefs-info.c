/* lcfs
   Copyright (C) 2023 Alexander Larsson <alexl@redhat.com>

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

#include "libcomposefs/lcfs-writer.h"
#include "libcomposefs/lcfs-utils.h"
#include "libcomposefs/lcfs-internal.h"
#include "libcomposefs/hash.h"

#include <stdio.h>
#include <string.h>
#include <err.h>
#include <error.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <ctype.h>

#define ESCAPE_STANDARD 0
#define NOESCAPE_SPACE (1 << 0)
#define ESCAPE_EQUAL (1 << 1)
#define ESCAPE_LONE_DASH (1 << 2)

static void print_escaped(const char *val, ssize_t len, int escape)
{
	bool noescape_space = (escape & NOESCAPE_SPACE) != 0;
	bool escape_equal = (escape & ESCAPE_EQUAL) != 0;
	bool escape_lone_dash = (escape & ESCAPE_LONE_DASH) != 0;

	if (len < 0)
		len = strlen(val);

	if (escape_lone_dash && len == 1 && val[0] == '-') {
		printf("\\x%.2x", val[0]);
		return;
	}

	for (size_t i = 0; i < len; i++) {
		uint8_t c = val[i];
		bool hex_escape = false;
		const char *special = NULL;
		switch (c) {
		case '\\':
			special = "\\\\";
			break;
		case '\n':
			special = "\\n";
			break;
		case '\r':
			special = "\\r";
			break;
		case '\t':
			special = "\\t";
			break;
		case '=':
			hex_escape = escape_equal;
			break;
		default:
			if (noescape_space)
				hex_escape = !isprint(c);
			else
				hex_escape = !isgraph(c);
			break;
		}

		if (special != NULL)
			printf("%s", special);
		else if (hex_escape)
			printf("\\x%.2x", c);
		else
			printf("%c", c);
	}
}

static void print_node(struct lcfs_node_s *node, char *parent_path)
{
	for (size_t i = 0; i < lcfs_node_get_n_children(node); i++) {
		struct lcfs_node_s *child = lcfs_node_get_child(node, i);
		cleanup_free char *path = NULL;

		asprintf(&path, "%s/%s", parent_path, lcfs_node_get_name(child));

		uint32_t mode = lcfs_node_get_mode(child);
		uint32_t type = mode & S_IFMT;
		const char *payload = lcfs_node_get_payload(child);

		print_escaped(path, -1, NOESCAPE_SPACE);

		if (type == S_IFDIR) {
			printf("/\t");
		} else if (type == S_IFLNK) {
			printf("\t-> ");
			print_escaped(payload, -1, ESCAPE_STANDARD);
		} else if (type == S_IFREG && payload) {
			printf("\t@ ");
			print_escaped(payload, -1, ESCAPE_STANDARD);
		}
		printf("\n");

		print_node(child, path);
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

static void dump_node(struct lcfs_node_s *node, char *path)
{
	struct lcfs_node_s *target;
	struct timespec mtime;
	const char *payload;
	const uint8_t *digest;

	target = lcfs_node_get_hardlink_target(node);
	if (target == NULL)
		target = node;

	lcfs_node_get_mtime(target, &mtime);
	payload = lcfs_node_get_payload(target);
	digest = lcfs_node_get_fsverity_digest(target);

	print_escaped(*path == 0 ? "/" : path, -1, ESCAPE_STANDARD);
	printf(" %" PRIu64 " %s%o %u %u %u %u %" PRIi64 ".%u ",
	       lcfs_node_get_size(target), target == node ? "" : "@",
	       lcfs_node_get_mode(target), lcfs_node_get_nlink(target),
	       lcfs_node_get_uid(target), lcfs_node_get_gid(target),
	       lcfs_node_get_rdev(target), (int64_t)mtime.tv_sec,
	       (unsigned int)mtime.tv_nsec);
	print_escaped(payload ? payload : "-", -1, ESCAPE_LONE_DASH);

	if (digest) {
		char digest_str[LCFS_DIGEST_SIZE * 2 + 1] = { 0 };
		digest_to_string(digest, digest_str);
		printf(" %s", digest_str);
	} else {
		printf(" -");
	}

	size_t n_xattr = lcfs_node_get_n_xattr(target);
	for (size_t i = 0; i < n_xattr; i++) {
		const char *name = lcfs_node_get_xattr_name(target, i);
		size_t value_len;
		const char *value = lcfs_node_get_xattr(target, name, &value_len);

		printf(" ");
		print_escaped(name, -1, ESCAPE_EQUAL);
		printf("=");
		print_escaped(value, value_len, ESCAPE_EQUAL);
	}

	printf("\n");

	for (size_t i = 0; i < lcfs_node_get_n_children(node); i++) {
		struct lcfs_node_s *child = lcfs_node_get_child(node, i);
		cleanup_free char *child_path = NULL;

		asprintf(&child_path, "%s/%s", path, lcfs_node_get_name(child));

		dump_node(child, child_path);
	}
}

static void get_objects(struct lcfs_node_s *node, Hash_table *ht)
{
	uint32_t mode = lcfs_node_get_mode(node);
	uint32_t type = mode & S_IFMT;
	const char *payload = lcfs_node_get_payload(node);

	if (type == S_IFREG && payload) {
		if (hash_insert(ht, payload) == NULL) {
			errx(EXIT_FAILURE, "Out of memory");
		}
	}

	for (size_t i = 0; i < lcfs_node_get_n_children(node); i++) {
		struct lcfs_node_s *child = lcfs_node_get_child(node, i);
		get_objects(child, ht);
	}
}

static size_t str_ht_hash(const void *entry, size_t table_size)
{
	return hash_string(entry, table_size);
}

static bool str_ht_eq(const void *entry1, const void *entry2)
{
	return strcmp(entry1, entry2) == 0;
}

static int cmp_obj(const void *_a, const void *_b)
{
	const char *const *a = _a;
	const char *const *b = _b;
	return strcmp(*a, *b);
}

static void print_objects(struct lcfs_node_s *node)
{
	Hash_table *ht = hash_initialize(0, NULL, str_ht_hash, str_ht_eq, NULL);
	if (ht == NULL)
		errx(EXIT_FAILURE, "Out of memory");

	get_objects(node, ht);

	size_t n_objects = hash_get_n_entries(ht);
	char **objects = calloc(n_objects, sizeof(char *));

	hash_get_entries(ht, (void **)objects, n_objects);

	qsort(objects, n_objects, sizeof(char *), cmp_obj);

	for (size_t i = 0; i < n_objects; i++)
		printf("%s\n", objects[i]);

	hash_free(ht);
}

static void usage(const char *argv0)
{
	fprintf(stderr, "usage: %s [ls|objects|dump] IMAGE\n", argv0);
}

int main(int argc, char **argv)
{
	const char *bin = argv[0];
	int fd;
	cleanup_node struct lcfs_node_s *root = NULL;
	const char *image_path = NULL;
	const char *command;

	if (argc <= 1) {
		fprintf(stderr, "No command specified\n");
		usage(bin);
		exit(1);
	}
	command = argv[1];

	if (argc <= 2) {
		fprintf(stderr, "No image path specified\n");
		usage(bin);
		exit(1);
	}
	image_path = argv[2];

	fd = open(image_path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		err(EXIT_FAILURE, "Failed to open '%s'", image_path);
	}

	root = lcfs_load_node_from_fd(fd);
	if (root == NULL) {
		err(EXIT_FAILURE, "Failed to load '%s'", image_path);
	}

	if (strcmp(command, "ls") == 0) {
		print_node(root, "");
	} else if (strcmp(command, "dump") == 0) {
		dump_node(root, "");
	} else if (strcmp(command, "objects") == 0) {
		print_objects(root);
	} else {
		errx(EXIT_FAILURE, "Unknown command '%s'\n", command);
	}

	return 0;
}
