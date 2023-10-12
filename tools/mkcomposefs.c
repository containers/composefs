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

#include "libcomposefs/lcfs-writer.h"
#include "libcomposefs/lcfs-utils.h"
#include "libcomposefs/lcfs-internal.h"
#include "sandbox.h"

#include <stdio.h>
#include <linux/limits.h>
#include <string.h>
#include <stdlib.h>
#include <err.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <linux/fsverity.h>
#include <linux/fs.h>

static void oom(void)
{
	errx(EXIT_FAILURE, "Out of memory");
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

static int ensure_dir(const char *path, mode_t mode)
{
	struct stat buf;

	/* We check this ahead of time, otherwise
	   the mkdir call can fail in the read-only
	   case with EROFS instead of EEXIST on some
	   filesystems (such as NFS) */
	if (stat(path, &buf) == 0) {
		if (!S_ISDIR(buf.st_mode)) {
			errno = ENOTDIR;
			return -1;
		}

		return 0;
	}

	if (mkdir(path, mode) == -1 && errno != EEXIST)
		return -1;

	return 0;
}

static int mkdir_parents(const char *pathname, int mode)
{
	cleanup_free char *fn = strdup(pathname);
	if (fn == NULL) {
		errno = ENOMEM;
		return -1;
	}

	char *p = fn;
	while (*p == '/')
		p++;

	do {
		while (*p && *p != '/')
			p++;

		if (!*p)
			break;
		*p = '\0';

		if (ensure_dir(fn, mode) != 0) {
			return -1;
		}

		*p++ = '/';
		while (*p && *p == '/')
			p++;
	} while (p);

	return 0;
}

static int write_to_fd(int fd, const char *content, ssize_t len)
{
	ssize_t res;

	while (len > 0) {
		res = write(fd, content, len);
		if (res < 0 && errno == EINTR)
			continue;
		if (res <= 0) {
			if (res == 0) /* Unexpected short write, should not happen when writing to a file */
				errno = ENOSPC;
			return -1;
		}
		len -= res;
		content += res;
	}

	return 0;
}

#define BUFSIZE 8192
static int copy_file_data(int sfd, int dfd)
{
	char buffer[BUFSIZE];
	ssize_t bytes_read;

	while (true) {
		bytes_read = read(sfd, buffer, BUFSIZE);
		if (bytes_read == -1) {
			if (errno == EINTR)
				continue;
			return -1;
		}

		if (bytes_read == 0)
			break;

		if (write_to_fd(dfd, buffer, bytes_read) != 0)
			return -1;
	}

	return 0;
}

static int join_paths(char **out, const char *path1, const char *path2)
{
	const char *sep = (path1[0] == '\0') ? "" : "/";
	int len = strlen(path1);

	while (len && path1[len - 1] == '/')
		len--;

	return asprintf(out, "%.*s%s%s", len, path1, sep, path2);
}

static errint_t enable_verity(int fd)
{
	struct fsverity_enable_arg arg = {};

	arg.version = 1;
	arg.hash_algorithm = FS_VERITY_HASH_ALG_SHA256;
	arg.block_size = 4096;
	arg.salt_size = 0;
	arg.salt_ptr = 0;
	arg.sig_size = 0;
	arg.sig_ptr = 0;

	if (ioctl(fd, FS_IOC_ENABLE_VERITY, &arg) != 0) {
		return -errno;
	}
	return 0;
}

static void cleanup_unlink_freep(void *pp)
{
	char *filename = *(char **)pp;
	if (!filename)
		return;
	PROTECT_ERRNO;
	(void)unlink(filename);
	free(filename);
}
#define cleanup_unlink_free __attribute__((cleanup(cleanup_unlink_freep)))

static int copy_file_with_dirs_if_needed(const char *src, const char *dst_base,
					 const char *dst, bool try_enable_fsverity)
{
	cleanup_free char *pathbuf = NULL;
	cleanup_unlink_free char *tmppath = NULL;
	int ret, res;
	errint_t err;
	cleanup_fd int sfd = -1;
	cleanup_fd int dfd = -1;
	struct stat statbuf;

	ret = join_paths(&pathbuf, dst_base, dst);
	if (ret < 0)
		return ret;

	ret = mkdir_parents(pathbuf, 0755);
	if (ret < 0)
		return ret;

	if (lstat(pathbuf, &statbuf) == 0)
		return 0; /* Already exists, no need to copy */

	ret = join_paths(&tmppath, dst_base, ".tmpXXXXXX");
	if (ret < 0)
		return ret;

	dfd = mkostemp(tmppath, O_CLOEXEC);
	if (dfd == -1)
		return -1;

	sfd = open(src, O_CLOEXEC | O_RDONLY);
	if (sfd == -1) {
		return -1;
	}

	// First try reflinking, which is fast and efficient if available.
	if (ioctl(dfd, FICLONE, sfd) != 0) {
		// Fall back to copying bits by hand
		res = copy_file_data(sfd, dfd);
		if (res < 0) {
			return res;
		}
	}
	cleanup_fdp(&sfd);

	/* Make sure file is readable by all */
	res = fchmod(dfd, 0644);
	if (res < 0) {
		return res;
	}

	res = fsync(dfd);
	if (res < 0) {
		return res;
	}
	cleanup_fdp(&dfd);

	if (try_enable_fsverity) {
		/* Try to enable fsverity */
		dfd = open(tmppath, O_CLOEXEC | O_RDONLY);
		if (dfd < 0) {
			return -1;
		}

		if (fstat(dfd, &statbuf) == 0) {
			err = enable_verity(dfd);
			if (err < 0) {
				/* Ignore errors, we're only trying to enable it */
			}
		}
	}

	res = rename(tmppath, pathbuf);
	if (res < 0) {
		return res;
	}
	// Avoid a spurious extra unlink() from the cleanup
	free(steal_pointer(&tmppath));

	return 0;
}

static int fill_store(struct lcfs_node_s *node, const char *path,
		      const char *digest_store_path)
{
	cleanup_free char *tmp_path = NULL;
	const char *fname;
	int ret;

	fname = lcfs_node_get_name(node);
	if (fname) {
		ret = join_paths(&tmp_path, path, fname);
		if (ret < 0)
			return ret;
		path = tmp_path;
	}

	if (lcfs_node_dirp(node)) {
		size_t n_children = lcfs_node_get_n_children(node);
		for (size_t i = 0; i < n_children; i++) {
			struct lcfs_node_s *child = lcfs_node_get_child(node, i);
			ret = fill_store(child, path, digest_store_path);
			if (ret < 0)
				return ret;
		}
	} else if ((lcfs_node_get_mode(node) & S_IFMT) == S_IFREG &&
		   lcfs_node_get_content(node) == NULL &&
		   lcfs_node_get_payload(node) != NULL) {
		const char *payload = lcfs_node_get_payload(node);

		ret = copy_file_with_dirs_if_needed(path, digest_store_path,
						    payload, true);
		if (ret < 0)
			return ret;
	}

	return 0;
}

static void usage(const char *argv0)
{
	const char *bin = basename(argv0);
	fprintf(stderr,
		"Usage: %s [OPTIONS] SOURCE IMAGE\n"
		"Options:\n"
		"  --digest-store=PATH   Store content files in this directory\n"
		"  --use-epoch           Make all mtimes zero\n"
		"  --skip-xattrs         Don't store file xattrs\n"
		"  --user-xattrs         Only store user.* xattrs\n"
		"  --print-digest        Print the digest of the image\n"
		"  --print-digest-only   Print the digest of the image, don't write image\n"
		"  --from-file           The source is a dump file, not a directory\n"
		"  --no-sandbox          Disable sandboxing code\n",
		bin);
}

#define OPT_SKIP_XATTRS 102
#define OPT_USE_EPOCH 103
#define OPT_SKIP_DEVICES 104
#define OPT_DIGEST_STORE 108
#define OPT_PRINT_DIGEST 109
#define OPT_PRINT_DIGEST_ONLY 111
#define OPT_USER_XATTRS 112
#define OPT_FROM_FILE 113
#define OPT_NO_SANDBOX 114

static ssize_t write_cb(void *_file, void *buf, size_t count)
{
	FILE *file = _file;

	return fwrite(buf, 1, count, file);
}

static size_t split_at(const char **start, size_t *length, char split_char,
		       bool *partial)
{
	char *end = memchr(*start, split_char, *length);
	if (end == NULL) {
		size_t part_len = *length;
		*start = *start + *length;
		;
		*length = 0;
		if (partial)
			*partial = true;
		return part_len;
	}

	size_t part_len = end - *start;
	*start += part_len + 1;
	*length -= part_len + 1;
	if (partial)
		*partial = false;

	return part_len;
}

enum {
	FIELD_PATH,
	FIELD_SIZE,
	FIELD_MODE,
	FIELD_NLINK,
	FIELD_UID,
	FIELD_GID,
	FIELD_RDEV,
	FIELD_MTIME,
	FIELD_PAYLOAD,
	FIELD_CONTENT,
	FIELD_DIGEST,

	FIELD_XATTRS_START,
};

const char *names[] = {
	"PATH",		"SIZE",	 "MODE",    "NLINK",   "UID",	 "GID",
	"RDEV",		"MTIME", "PAYLOAD", "CONTENT", "DIGEST",

	"XATTRS_START",
};

static char *unescape_string(const char *escaped, size_t escaped_size,
			     size_t *unescaped_size)
{
	const char *escaped_end = escaped + escaped_size;
	char *res = malloc(escaped_size + 1);
	if (res == NULL)
		oom();

	char *out = res;

	while (escaped < escaped_end) {
		char c = *escaped++;
		if (c == '\\') {
			if (escaped >= escaped_end)
				errx(EXIT_FAILURE, "No character after escape");
			c = *escaped++;
			switch (c) {
			case '\\':
				*out++ = '\\';
				break;
			case 'n':
				*out++ = '\n';
				break;
			case 'r':
				*out++ = '\r';
				break;
			case 't':
				*out++ = '\t';
				break;
			case 'x':
				if (escaped >= escaped_end)
					errx(EXIT_FAILURE,
					     "No hex characters after hex escape");
				int x1 = hexdigit(*escaped++);
				if (escaped >= escaped_end)
					errx(EXIT_FAILURE,
					     "No hex characters after hex escape");
				int x2 = hexdigit(*escaped++);
				if (x1 < 0 || x2 < 0)
					errx(EXIT_FAILURE,
					     "Invalid hex characters after hex escape");

				*out++ = x1 << 4 | x2;
				break;
			default:
				errx(EXIT_FAILURE, "Unsupported escape type %c", c);
			}
		} else {
			*out++ = c;
		}
	}

	if (unescaped_size)
		*unescaped_size = out - res;

	*out = 0; /* Null terminate */

	return res;
}

static char *unescape_optional_string(const char *escaped, size_t escaped_size,
				      size_t *unescaped_size)
{
	/* Optional */
	if (escaped_size == 1 && escaped[0] == '-')
		return NULL;

	return unescape_string(escaped, escaped_size, unescaped_size);
}

static struct lcfs_node_s *lookup_parent_path(struct lcfs_node_s *node,
					      const char *path, const char **name_out)
{
	while (*path == '/')
		path++;

	const char *start = path;
	while (*path != 0 && *path != '/')
		path++;

	if (*path == 0) {
		*name_out = start;
		return node;
	}

	cleanup_free char *name = strndup(start, path - start);

	struct lcfs_node_s *child = lcfs_node_lookup_child(node, name);
	if (child == NULL)
		return NULL;

	return lookup_parent_path(child, path, name_out);
}

static struct lcfs_node_s *lookup_path(struct lcfs_node_s *node, const char *path)
{
	while (*path == '/')
		path++;

	if (*path == 0)
		return node;

	const char *start = path;
	while (*path != 0 && *path != '/')
		path++;

	cleanup_free char *name = strndup(start, path - start);

	struct lcfs_node_s *child = lcfs_node_lookup_child(node, name);
	if (child == NULL)
		return NULL;

	return lookup_path(child, path);
}

static uint64_t parse_int_field(const char *str, size_t length, int base)
{
	cleanup_free char *s = strndup(str, length);
	if (s == NULL)
		oom();

	char *endptr = NULL;
	unsigned long long v = strtoull(s, &endptr, base);
	if (*s == 0 || *endptr != 0)
		errx(EXIT_FAILURE, "Invalid integer %s\n", s);

	return (uint64_t)v;
}

static void parse_mtime(const char *str, size_t length, struct timespec *mtime)
{
	const char *mtime_sec_s = str;
	size_t mtime_sec_len = split_at(&str, &length, '.', NULL);
	uint64_t mtime_sec = parse_int_field(mtime_sec_s, mtime_sec_len, 10);
	uint64_t mtime_nsec = parse_int_field(str, length, 10);
	mtime->tv_sec = mtime_sec;
	mtime->tv_nsec = mtime_nsec;
}

static void parse_xattr(const char *data, size_t data_len, struct lcfs_node_s *node)
{
	const char *xattr_name = data;
	size_t xattr_name_len = split_at(&data, &data_len, '=', NULL);

	cleanup_free char *key = unescape_string(xattr_name, xattr_name_len, NULL);
	size_t value_len;
	cleanup_free char *value = unescape_string(data, data_len, &value_len);

	if (lcfs_node_set_xattr(node, key, value, value_len) != 0)
		errx(EXIT_FAILURE, "Can't set xattr");
}

typedef struct hardlink_fixup hardlink_fixup;
struct hardlink_fixup {
	struct lcfs_node_s *node;
	char *target_path;
	hardlink_fixup *next;
};

typedef struct dump_info dump_info;
struct dump_info {
	struct lcfs_node_s *root;
	hardlink_fixup *hardlink_fixups;
};

typedef struct field_info field_info;
struct field_info {
	const char *data;
	size_t len;
};

static void tree_add_node(dump_info *info, const char *path, struct lcfs_node_s *node)
{
	if (strcmp(path, "/") == 0) {
		if (!lcfs_node_dirp(node))
			errx(EXIT_FAILURE, "Root must be a directory");

		if (info->root == NULL)
			info->root = lcfs_node_ref(node);
		else
			errx(EXIT_FAILURE, "Can't have multiple roots");
	} else {
		const char *name;
		struct lcfs_node_s *parent =
			lookup_parent_path(info->root, path, &name);

		if (parent == NULL)
			errx(EXIT_FAILURE, "Parent directory missing for %s", path);

		if (!lcfs_node_dirp(parent))
			errx(EXIT_FAILURE, "Parent must be a directory for %s", path);

		int r = lcfs_node_add_child(parent, node, name);
		if (r < 0) {
			if (r == -EEXIST)
				err(EXIT_FAILURE, "Path %s already exist", path);
			err(EXIT_FAILURE, "Can't add child");
		}
		/* add_child took ownership, ref again */
		lcfs_node_ref(node);
	}
}

static void tree_add_hardlink_fixup(dump_info *info, char *target_path,
				    struct lcfs_node_s *node)
{
	hardlink_fixup *fixup = calloc(1, sizeof(hardlink_fixup));
	if (fixup == NULL)
		oom();

	fixup->node = node;
	fixup->target_path = target_path; /* Takes ownership */

	fixup->next = info->hardlink_fixups;
	info->hardlink_fixups = fixup;
}

static void tree_resolve_hardlinks(dump_info *info)
{
	hardlink_fixup *fixup = info->hardlink_fixups;
	while (fixup != NULL) {
		hardlink_fixup *next = fixup->next;
		struct lcfs_node_s *target =
			lookup_path(info->root, fixup->target_path);
		if (target == NULL)
			errx(EXIT_FAILURE, "No target at %s for hardlink",
			     fixup->target_path);

		/* Don't override existing value from image for target nlink */
		uint32_t old_nlink = lcfs_node_get_nlink(target);

		lcfs_node_make_hardlink(fixup->node, target);

		lcfs_node_set_nlink(target, old_nlink);

		free(fixup->target_path);
		free(fixup);

		fixup = next;
	}
}

static void tree_from_dump_line(dump_info *info, const char *line, size_t line_len)
{
	/* Split out all fixed fields */
	field_info fields[FIELD_XATTRS_START];
	for (int i = 0; i < FIELD_XATTRS_START; i++) {
		fields[i].data = line;
		fields[i].len = split_at(&line, &line_len, ' ', NULL);
	}

	cleanup_free char *path = unescape_string(fields[FIELD_PATH].data,
						  fields[FIELD_PATH].len, NULL);

	bool is_hardlink = false;
	/* First char in mode is @ if hardlink */
	if (fields[FIELD_MODE].len > 0 && fields[FIELD_MODE].data[0] == '@') {
		is_hardlink = true;
		fields[FIELD_MODE].len -= 1;
		fields[FIELD_MODE].data += 1;
	}
	uint64_t mode = parse_int_field(fields[FIELD_MODE].data,
					fields[FIELD_MODE].len, 8);

	cleanup_node struct lcfs_node_s *node = lcfs_node_new();
	lcfs_node_set_mode(node, mode);

	tree_add_node(info, path, node);

	/* For hardlinks, bail out early and handle in a fixup at the
         * end when we can resolve the target path. */
	if (is_hardlink) {
		if (lcfs_node_dirp(node))
			errx(EXIT_FAILURE, "Directories can't be hardlinked");
		cleanup_free char *target_path =
			unescape_optional_string(fields[FIELD_PAYLOAD].data,
						 fields[FIELD_PAYLOAD].len, NULL);
		tree_add_hardlink_fixup(info, steal_pointer(&target_path), node);
		return;
	}

	/* Handle regular files/dir data from fixed fields */
	uint64_t size = parse_int_field(fields[FIELD_SIZE].data,
					fields[FIELD_SIZE].len, 10);
	uint64_t nlink = parse_int_field(fields[FIELD_NLINK].data,
					 fields[FIELD_NLINK].len, 10);
	uint64_t uid =
		parse_int_field(fields[FIELD_UID].data, fields[FIELD_UID].len, 10);
	uint64_t gid =
		parse_int_field(fields[FIELD_GID].data, fields[FIELD_GID].len, 10);
	uint64_t rdev = parse_int_field(fields[FIELD_RDEV].data,
					fields[FIELD_RDEV].len, 10);

	struct timespec mtime;
	parse_mtime(fields[FIELD_MTIME].data, fields[FIELD_MTIME].len, &mtime);

	cleanup_free char *payload = unescape_optional_string(
		fields[FIELD_PAYLOAD].data, fields[FIELD_PAYLOAD].len, NULL);
	size_t content_len;
	cleanup_free char *content =
		unescape_optional_string(fields[FIELD_CONTENT].data,
					 fields[FIELD_CONTENT].len, &content_len);
	if (content && content_len != size)
		errx(EXIT_FAILURE, "Invalid content size %lld, must match size %lld",
		     (long long)content_len, (long long)size);

	cleanup_free char *digest = unescape_optional_string(
		fields[FIELD_DIGEST].data, fields[FIELD_DIGEST].len, NULL);

	lcfs_node_set_mode(node, mode);
	lcfs_node_set_size(node, size);
	lcfs_node_set_nlink(node, nlink);
	lcfs_node_set_uid(node, uid);
	lcfs_node_set_gid(node, gid);
	lcfs_node_set_rdev(node, rdev);
	lcfs_node_set_mtime(node, &mtime);
	lcfs_node_set_payload(node, payload);
	if (content)
		lcfs_node_set_content(node, (uint8_t *)content, size);

	if (digest) {
		uint8_t raw[LCFS_DIGEST_SIZE];
		digest_to_raw(digest, raw, LCFS_DIGEST_SIZE);
		lcfs_node_set_fsverity_digest(node, raw);
	}

	/* Handle trailing xattrs */
	while (line_len > 0) {
		const char *xattr = line;
		size_t xattr_len = split_at(&line, &line_len, ' ', NULL);

		parse_xattr(xattr, xattr_len, node);
	}
}

struct buffer {
	char *buf;
	size_t size;
	size_t capacity;
};

static void buffer_ensure_space(struct buffer *buf, size_t free_size_needed)
{
	size_t min_capacity = buf->size + free_size_needed;
	if (buf->capacity >= min_capacity)
		return;

	/* No space, grow */
	if (buf->capacity == 0)
		buf->capacity = 64 * 1024;
	else
		buf->capacity = buf->capacity * 2;

	if (buf->capacity < min_capacity)
		buf->capacity = min_capacity;

	buf->buf = realloc(buf->buf, buf->capacity);
	if (buf->buf == NULL)
		oom();
}

/* Fills buffer and returns the amount read. 0 on file end */
static size_t buffer_fill(struct buffer *buf, FILE *input)
{
	/* Grow buffer if needed */
	buffer_ensure_space(buf, 1);

	size_t bytes_read =
		fread(buf->buf + buf->size, 1, buf->capacity - buf->size, input);
	if (bytes_read == 0 && ferror(input))
		errx(EXIT_FAILURE, "Error reading from file");
	buf->size += bytes_read;

	return bytes_read;
}

static void buffer_reset(struct buffer *buf)
{
	/* NOTE: Leaves buffer data as is, just modified size */
	buf->size = 0;
}

static void buffer_add(struct buffer *buf, const char *src, size_t len)
{
	buffer_ensure_space(buf, len);

	/* memmove, as src may be in the buf */
	memmove(buf->buf + buf->size, src, len);
	buf->size += len;
}

static void buffer_free(struct buffer *buf)
{
	free(buf->buf);
}

static struct lcfs_node_s *tree_from_dump(FILE *input)
{
	dump_info info = { NULL };

	struct buffer buf = { NULL };

	while (!feof(input)) {
		size_t bytes_read = buffer_fill(&buf, input);
		bool short_read = bytes_read == 0;

		const char *data = buf.buf;
		size_t remaining_data = buf.size;
		buffer_reset(&buf);

		while (remaining_data > 0) {
			const char *line = data;
			bool partial;
			size_t line_len =
				split_at(&data, &remaining_data, '\n', &partial);

			if (!partial || short_read) {
				tree_from_dump_line(&info, line, line_len);
			} else {
				/* Last line didn't have a newline and
				 * this wasn't a short read, so keep
				 * this for next read.
				 */
				buffer_add(&buf, line, line_len);
			}
		}
	}

	buffer_free(&buf);

	/* Fixup hardlinks now that we have all other files */
	tree_resolve_hardlinks(&info);

	return info.root;
}

int main(int argc, char **argv)
{
	const struct option longopts[] = {
		{
			name: "skip-xattrs",
			has_arg: no_argument,
			flag: NULL,
			val: OPT_SKIP_XATTRS
		},
		{
			name: "user-xattrs",
			has_arg: no_argument,
			flag: NULL,
			val: OPT_USER_XATTRS
		},
		{
			name: "skip-devices",
			has_arg: no_argument,
			flag: NULL,
			val: OPT_SKIP_DEVICES
		},
		{
			name: "use-epoch",
			has_arg: no_argument,
			flag: NULL,
			val: OPT_USE_EPOCH
		},
		{
			name: "digest-store",
			has_arg: required_argument,
			flag: NULL,
			val: OPT_DIGEST_STORE
		},
		{
			name: "print-digest",
			has_arg: no_argument,
			flag: NULL,
			val: OPT_PRINT_DIGEST
		},
		{
			name: "print-digest-only",
			has_arg: no_argument,
			flag: NULL,
			val: OPT_PRINT_DIGEST_ONLY
		},
		{
			name: "from-file",
			has_arg: no_argument,
			flag: NULL,
			val: OPT_FROM_FILE
		},
		{
			name: "no-sandbox",
			has_arg: no_argument,
			flag: NULL,
			val: OPT_NO_SANDBOX
		},
		{},
	};
	struct lcfs_write_options_s options = { 0 };
	const char *bin = argv[0];
	int buildflags = 0;
	bool print_digest = false;
	bool print_digest_only = false;
	bool from_file = false;
	bool no_sandbox = false;
	struct lcfs_node_s *root;
	const char *out = NULL;
	const char *src_path = NULL;
	const char *digest_store_path = NULL;
	cleanup_free char *pathbuf = NULL;
	uint8_t digest[LCFS_DIGEST_SIZE];
	int opt;
	FILE *out_file;
	char *failed_path;

	/* We always compute the digest and reference by digest */
	buildflags |= LCFS_BUILD_COMPUTE_DIGEST | LCFS_BUILD_BY_DIGEST;

	while ((opt = getopt_long(argc, argv, ":CR", longopts, NULL)) != -1) {
		switch (opt) {
		case OPT_USE_EPOCH:
			buildflags |= LCFS_BUILD_USE_EPOCH;
			break;
		case OPT_SKIP_XATTRS:
			buildflags |= LCFS_BUILD_SKIP_XATTRS;
			break;
		case OPT_USER_XATTRS:
			buildflags |= LCFS_BUILD_USER_XATTRS;
			break;
		case OPT_SKIP_DEVICES:
			buildflags |= LCFS_BUILD_SKIP_DEVICES;
			break;
		case OPT_DIGEST_STORE:
			digest_store_path = optarg;
			break;
		case OPT_PRINT_DIGEST:
			print_digest = true;
			break;
		case OPT_PRINT_DIGEST_ONLY:
			print_digest = print_digest_only = true;
			break;
		case OPT_FROM_FILE:
			from_file = true;
			break;
		case OPT_NO_SANDBOX:
			no_sandbox = true;
			break;
		case ':':
			fprintf(stderr, "option needs a value\n");
			exit(EXIT_FAILURE);
		default:
			usage(bin);
			exit(1);
		}
	}

	argv += optind;
	argc -= optind;

	if (argc < 1) {
		fprintf(stderr, "No source path specified\n");
		usage(bin);
		exit(1);
	}
	src_path = argv[0];

	if (src_path[0] == '\0')
		errx(EXIT_FAILURE, "Empty source path specified");

	if (argc > 2) {
		fprintf(stderr, "Too many arguments\n");
		usage(bin);
		exit(1);
	}
	if (argc == 1) {
		if (!print_digest_only) {
			fprintf(stderr, "No destination path specified\n");
			usage(bin);
			exit(1);
		}
	} else if (!print_digest_only) {
		assert(argc == 2);
		out = argv[1];
	} else {
		fprintf(stderr,
			"Cannot specify destination path with --print-digest-only\n");
		usage(bin);
		exit(1);
	}

	assert(out || print_digest_only);

	if (print_digest_only) {
		out_file = NULL;
	} else if (strcmp(out, "-") == 0) {
		if (isatty(1))
			errx(EXIT_FAILURE, "stdout is a tty.  Refusing to use it");
		out_file = stdout;
	} else {
		out_file = fopen(out, "we");
		if (out_file == NULL)
			err(EXIT_FAILURE, "failed to open output file");
	}

	if (from_file) {
		FILE *input = NULL;
		bool close_input = false;
		if (strcmp(src_path, "-") == 0) {
			input = stdin;
		} else {
			input = fopen(src_path, "r");
			if (input == NULL)
				err(EXIT_FAILURE, "open `%s`", src_path);
			close_input = true;
		}

		if (!no_sandbox)
			sandbox();

		root = tree_from_dump(input);
		if (root == NULL)
			errx(EXIT_FAILURE, "No files in dump file");

		if (close_input)
			fclose(input);
	} else {
		root = lcfs_build(AT_FDCWD, src_path, buildflags, &failed_path);
		if (root == NULL)
			err(EXIT_FAILURE, "error accessing %s", failed_path);

		if (digest_store_path &&
		    fill_store(root, src_path, digest_store_path) < 0)
			err(EXIT_FAILURE, "cannot fill store");
	}

	if (out_file) {
		options.file = out_file;
		options.file_write_cb = write_cb;
	}
	if (print_digest)
		options.digest_out = digest;

	options.format = LCFS_FORMAT_EROFS;

	if (lcfs_write_to(root, &options) < 0)
		err(EXIT_FAILURE, "cannot write file");

	if (print_digest) {
		char digest_str[LCFS_DIGEST_SIZE * 2 + 1] = { 0 };
		digest_to_string(digest, digest_str);
		printf("%s\n", digest_str);
	}

	lcfs_node_unref(root);
	return 0;
}
