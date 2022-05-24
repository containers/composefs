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
#include "lcfs-writer.h"
#include "read-file.h"

#include <stdio.h>
#include <linux/limits.h>
#include <string.h>
#include <error.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <yajl/yajl_tree.h>
#include <getopt.h>

/* Adapted from mailutils 0.6.91(distributed under LGPL 2.0+)  */
static int b64_input(char c)
{
	const char table[64] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	int i;

	for (i = 0; i < 64; i++) {
		if (table[i] == c)
			return i;
	}
	return -1;
}

static int base64_decode(const char *iptr, size_t isize, char *optr,
			 size_t osize, size_t *nbytes)
{
	int i = 0, tmp = 0, pad = 0;
	size_t consumed = 0;
	unsigned char data[4];

	*nbytes = 0;
	while (consumed < isize && (*nbytes) + 3 < osize) {
		while ((i < 4) && (consumed < isize)) {
			tmp = b64_input(*iptr++);
			consumed++;
			if (tmp != -1)
				data[i++] = tmp;
			else if (*(iptr - 1) == '=') {
				data[i++] = '\0';
				pad++;
			}
		}

		/* I have a entire block of data 32 bits get the output data.  */
		if (i == 4) {
			*optr++ = (data[0] << 2) | ((data[1] & 0x30) >> 4);
			*optr++ = ((data[1] & 0xf) << 4) |
				  ((data[2] & 0x3c) >> 2);
			*optr++ = ((data[2] & 0x3) << 6) | data[3];
			(*nbytes) += 3 - pad;
		} else {
			/* I did not get all the data.  */
			consumed -= i;
			return consumed;
		}
		i = 0;
	}
	return consumed;
}

static yajl_val parse_file(FILE *f)
{
	size_t l;
	yajl_val node;
	char *content;
	char errbuf[1024];

	content = fread_file(f, &l);
	if (content == NULL)
		return NULL;

	errbuf[0] = '\0';

	node = yajl_tree_parse(content, errbuf, sizeof(errbuf));
	free(content);
	if (node == NULL) {
		fprintf(stderr, "parse_error: %s\n", errbuf);
		return NULL;
	}

	return node;
}

static yajl_val get_child(yajl_val node, const char *name, int type)
{
	const char *path[] = { name, NULL };

	return yajl_tree_get(node, path, type);
}

static inline const char *get_fname(struct lcfs_ctx_s *ctx,
				    const struct lcfs_dentry_s *d)
{
	char *out = NULL;
	size_t len;

	if (d->name.len == 0)
		return "";

	if (lcfs_get_vdata(ctx, &out, &len) < 0)
		return NULL;

	return out + d->name.off;
}

static struct lcfs_node_s *get_node_child(struct lcfs_ctx_s *ctx,
					  struct lcfs_node_s *root,
					  const char *name)
{
	size_t i;

	for (i = 0; i < root->children_size; ++i) {
		const char *v;

		v = get_fname(ctx, &(root->children[i]->data));
		if (v && strcmp(v, name) == 0)
			return root->children[i];
	}
	return NULL;
}

static struct lcfs_node_s *
append_child(struct lcfs_ctx_s *ctx, struct lcfs_node_s *dir, const char *name)
{
	struct lcfs_node_s **tmp;
	struct lcfs_node_s *child;

	tmp = realloc(dir->children,
		      sizeof(struct lcfs_node_s) * (dir->children_size + 1));
	if (tmp == NULL)
		return NULL;
	dir->children = tmp;

	child = lcfs_node_new();
	if (child == NULL)
		return NULL;

	child->name = strdup(name);
	if (child->name == NULL) {
		lcfs_node_free(child);
		return NULL;
        }

	dir->children[dir->children_size++] = child;
	child->parent = dir;

	while (dir) {
		if (dir->inode_data.st_mode == 0) {
			dir->inode_data.st_mode = 0755 | S_IFDIR;
		}
		dir = dir->parent;
	}

	return child;
}

static struct lcfs_node_s *
fill_xattrs(struct lcfs_ctx_s *ctx, struct lcfs_node_s *node, yajl_val xattrs)
{
	size_t i;
	char v_buffer[4096];

	if (!YAJL_IS_OBJECT(xattrs))
		return node;

	for (i = 0; i < YAJL_GET_OBJECT(xattrs)->len; i++) {
		int r;
		size_t written;
		const char *v, *k = YAJL_GET_OBJECT(xattrs)->keys[i];

		if (!YAJL_IS_STRING(YAJL_GET_OBJECT(xattrs)->values[i])) {
			lcfs_node_free(node);
			error(0, 0, "xattr value is not a string");
			return NULL;
		}

		v = YAJL_GET_STRING(YAJL_GET_OBJECT(xattrs)->values[i]);

		r = base64_decode(v, strlen(v), v_buffer, sizeof(v_buffer),
				  &written);
		if (r < 0) {
			lcfs_node_free(node);
			error(0, 0, "xattr value is not valid b64");
			return NULL;
		}

		r = lcfs_node_append_xattr(node, k, v_buffer, written);
		if (r < 0) {
			lcfs_node_free(node);
			error(0, 0, "append xattr");
			return NULL;
		}
	}

	return node;
}

static struct lcfs_node_s *get_node(struct lcfs_ctx_s *ctx,
				    struct lcfs_node_s *root, const char *what)
{
	char *path, *dpath, *it;
	struct lcfs_node_s *node = root;

	path = strdup(what);
	if (path == NULL)
		return NULL;

	dpath = path;
	while ((it = strsep(&dpath, "/"))) {
		if (node == root && strcmp(it, "..") == 0)
			continue;
		node = get_node_child(ctx, node, it);
		if (!node)
			break;
	}

	free(path);
	return node;
}

static struct lcfs_node_s *fill_file(struct lcfs_ctx_s *ctx, const char *typ,
				     struct lcfs_node_s *root,
				     struct lcfs_node_s *node, yajl_val entry)
{
	const char *payload = NULL;
	char payload_buffer[128];
	uint16_t min = 0, maj = 0;
	mode_t mode = 0;
	yajl_val v;
	bool is_regular_file = false;
	bool is_hardlink = false;

	if (node == NULL) {
		error(0, 0, "node is NULL");
		return node;
	}

	if (strcmp(typ, "reg") == 0) {
		mode |= S_IFREG;
		is_regular_file = true;
	} else if (strcmp(typ, "dir") == 0)
		mode |= S_IFDIR;
	else if (strcmp(typ, "char") == 0)
		mode |= S_IFCHR;
	else if (strcmp(typ, "block") == 0)
		mode |= S_IFBLK;
	else if (strcmp(typ, "fifo") == 0)
		mode |= S_IFIFO;
	else if (strcmp(typ, "symlink") == 0) {
		mode |= S_IFLNK;

		v = get_child(entry, "linkName", yajl_t_string);
		if (!v) {
			error(0, 0, "linkName not specified");
			lcfs_node_free(node);
			return NULL;
		}

		payload = YAJL_GET_STRING(v);
	} else if (strcmp(typ, "hardlink") == 0) {
		struct lcfs_node_s *target;

		mode |= S_IFREG;

		v = get_child(entry, "linkName", yajl_t_string);
		if (!v) {
			error(0, 0, "linkName not specified");
			lcfs_node_free(node);
			return NULL;
		}

		target = get_node(ctx, root, YAJL_GET_STRING(v));
		if (!target) {
 			error(0, 0, "could not find target %s",
			      YAJL_GET_STRING(v));
			lcfs_node_free(node);
			return NULL;
		}

		is_hardlink = true;

		node->link_to = target;
		target->inode_data.st_nlink++;
	}

	if (!is_hardlink)
		node->inode_data.st_nlink = 1;

	v = get_child(entry, "mode", yajl_t_number);
	if (v)
		mode |= (YAJL_GET_INTEGER(v));

	node->inode_data.st_mode = mode;

	v = get_child(entry, "uid", yajl_t_number);
	if (v)
		node->inode_data.st_uid = YAJL_GET_INTEGER(v);

	v = get_child(entry, "gid", yajl_t_number);
	if (v)
		node->inode_data.st_uid = YAJL_GET_INTEGER(v);

	if ((mode & S_IFMT) != S_IFDIR) {
		v = get_child(entry, "size", yajl_t_number);
		if (v)
			node->extend.st_size = YAJL_GET_INTEGER(v);
	}

	v = get_child(entry, "devMinor", yajl_t_number);
	if (v)
		min = YAJL_GET_INTEGER(v);
	v = get_child(entry, "devMajor", yajl_t_number);
	if (v)
		maj = YAJL_GET_INTEGER(v);

	node->inode_data.st_rdev = makedev(maj, min);

	/* custom extension to the CRFS format.  */
	v = get_child(entry, "x-payload", yajl_t_string);
	if (v)
		payload = YAJL_GET_STRING(v);
	if (payload == NULL && is_regular_file) {
		char *tmp = NULL;
		v = get_child(entry, "digest", yajl_t_string);
		if (v) {
			tmp = YAJL_GET_STRING(v);
		}
		if (tmp) {
			if (strncmp(tmp, "sha256:", 7) == 0)
				tmp += 7;
			snprintf(payload_buffer, sizeof(payload_buffer) - 1, "%.*s/%s", 2, tmp, tmp+2);
			payload_buffer[sizeof(payload_buffer) - 1] = '\0';
			payload = payload_buffer;
		}
	}

	if (payload) {
		int r;

		r = lcfs_node_set_payload(node, payload);
		if (r < 0) {
			lcfs_node_free(node);
			error(0, 0, "set_payload");
			return NULL;
		}
	}

	v = get_child(entry, "xattrs", yajl_t_object);
	if (v)
		return fill_xattrs(ctx, node, v);

	return node;
}

static struct lcfs_node_s *get_or_add_node(struct lcfs_ctx_s *ctx,
					   const char *typ,
					   struct lcfs_node_s *root,
					   yajl_val entry)
{
	yajl_val tmp;
	char *path, *dpath, *it;
	struct lcfs_node_s *node = root;

	tmp = get_child(entry, "name", yajl_t_string);
	if (tmp == NULL) {
		error(0, 0, "entry has no name");
		return NULL;
	}

	it = YAJL_GET_STRING(tmp);
	if (it == NULL) {
		error(0, 0, "name is not a string");
		return NULL;
	}

	path = strdup(it);
	if (path == NULL)
		error(EXIT_FAILURE, errno, "strdup");

	dpath = path;
	while ((it = strsep(&dpath, "/"))) {
		struct lcfs_node_s *c;

		c = get_node_child(ctx, node, it);
		if (c) {
			node = c;
			continue;
		}

		node = append_child(ctx, node, it);
		if (node == NULL) {
			error(0, errno, "append_child");
			return NULL;
		}
	}

	free(path);
	return fill_file(ctx, typ, root, node, entry);
}

static void do_file(struct lcfs_ctx_s *ctx, struct lcfs_node_s *root, FILE *file)
{
	yajl_val entries, root_val, tmp;
	size_t i;

	root_val = parse_file(file);
	if (root_val == NULL)
		error(EXIT_FAILURE, errno, "parse_file");

	if (!YAJL_IS_OBJECT(root_val))
		error(EXIT_FAILURE, 0, "invalid type for root");

	entries = get_child(root_val, "entries", yajl_t_array);
	if (entries == NULL)
		error(EXIT_FAILURE, 0, "cannot find any entry");

	for (i = 0; i < YAJL_GET_ARRAY(entries)->len; i++) {
		static struct lcfs_node_s *n;
		const char *typ;
		yajl_val entry = YAJL_GET_ARRAY(entries)->values[i];

		tmp = get_child(entry, "type", yajl_t_string);
		if (tmp == NULL)
			error(EXIT_FAILURE, 0, "entry has no name");

		typ = YAJL_GET_STRING(tmp);

		/* Skip chunks.  */
		if (typ == NULL || (strcmp(typ, "chunk") == 0))
			continue;

		n = get_or_add_node(ctx, typ, root, entry);
		if (n == NULL)
			error(EXIT_FAILURE, 0, "get_or_add_node");
	}

	yajl_tree_free(root_val);
}

#define OPT_OUT 100

static void usage(const char *argv0)
{
	fprintf(stderr,
		"usage: %s [--out=filedname] jsonfile...\n",
		argv0);
}

int main(int argc, char **argv)
{
	const struct option longopts[] = {
		{
			name: "out",
			has_arg: required_argument,
			flag: NULL,
			val: OPT_OUT
		},
		{},
	};
	struct lcfs_node_s *root;
	struct lcfs_ctx_s *ctx;
	char cwd[PATH_MAX];
	size_t i;
	int opt;
	const char *out = NULL;
	FILE *out_file;

	while ((opt = getopt_long(argc, argv, ":CR", longopts, NULL)) != -1) {
		switch (opt) {
		case OPT_OUT:
			out = optarg;
			break;
		case ':':
			fprintf(stderr, "option needs a value\n");
			exit(EXIT_FAILURE);
		default:
			usage(argv[0]);
			exit(1);
		}
	}

	argv += optind;
	argc -= optind;

	if (out != NULL) {
		out_file = fopen(out, "w");
		if (out_file == NULL)
			error(EXIT_FAILURE, errno, "Failed to open output file");
	} else {
		if (isatty(1))
			error(EXIT_FAILURE, 0, "stdout is a tty.  Refusing to use it");
		out_file = stdout;
	}

	ctx = lcfs_new_ctx();
	if (ctx == NULL)
		error(EXIT_FAILURE, errno, "new_ctx");

	root = lcfs_node_new();
	if (root == NULL)
		error(EXIT_FAILURE, errno, "malloc");

	for (i = 0; i < argc; i++) {
		FILE *f;

		f = fopen(argv[i], "r");
		if (f == NULL)
			error(EXIT_FAILURE, errno, "open `%s`", argv[i]);
		do_file(ctx, root, f);
		fclose(f);
	}

	lcfs_set_root(ctx, root);

	getcwd(cwd, sizeof(cwd));

	if (lcfs_write_to(ctx, out_file) < 0)
		error(EXIT_FAILURE, errno, "cannot write to stdout");

	lcfs_close(ctx);
	return 0;
}
