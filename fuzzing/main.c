#define _GNU_SOURCE

#include "../kernel/cfs-reader.h"

#include <stddef.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include "../tools/read-file.h"

struct test_context_s
{
	struct cfs_context_s *ctx;
	int dirs_left;
};

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	return 0;
}

bool iter_cb(void *private, const char *name, int namelen, u64 ino, unsigned int dtype)
{
	struct test_context_s *test_ctx = private;
	struct cfs_xattr_header_s *xattrs;
	struct cfs_inode_s *s_ino;
	struct cfs_inode_s buffer;
	struct cfs_dir_s *dir;
	loff_t out_size;
	char *out_path;
	char *payload;

        if (test_ctx->dirs_left == 0)
		return false;

	test_ctx->dirs_left--;

	s_ino = cfs_get_ino_index(test_ctx->ctx, ino, &buffer);
	if (IS_ERR(s_ino))
		return true;

	payload = cfs_dup_payload_path(test_ctx->ctx, s_ino, ino);
	if (!IS_ERR(payload)) {
		u8 digest_buf[SHA256_DIGEST_SIZE];
		cfs_get_digest(test_ctx->ctx, s_ino, payload, digest_buf);
		free(payload);
	}

	xattrs = cfs_get_xattrs(test_ctx->ctx, s_ino);
	if (!IS_ERR(xattrs)) {
		ssize_t xattrs_len;
		char names[512] = {0, };
		char value[512];
                char *it;

		xattrs_len = cfs_list_xattrs(xattrs, names, sizeof(names));
		if (xattrs_len < 0)
			return true;

                for (it = names; *it; it += strlen (it))
                  cfs_get_xattr(xattrs, it, value, sizeof(value));

		free(xattrs);
	}

	dir = cfs_get_dir(test_ctx->ctx, s_ino, ino);
	if (!IS_ERR(dir)) {
		cfs_dir_get_link_count(dir);
		cfs_dir_iterate(dir, 0, iter_cb, test_ctx);
		free(dir);
	}
	return true;
}

ssize_t safe_write(int fd, const void *buf, ssize_t count)
{
	ssize_t written = 0;
	if (count < 0) {
		errno = EINVAL;
		return -1;
	}
	while (written < count) {
		ssize_t w = write (fd, buf + written, count - written);
		if (w < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			return w;
		}
		written += w;
	}
	return written;
}

static struct cfs_context_s *create_ctx(uint8_t *buf, size_t len)
{
	struct cfs_context_s *ctx;
	char proc_path[64];
	int fd;

	fd = open(".", O_TMPFILE | O_RDWR, S_IRUSR | S_IWUSR);
	if (fd < -1)
		return NULL;

	if(safe_write(fd, buf, len) < 0) {
		close(fd);
		return NULL;
	}

	sprintf(proc_path, "/proc/self/fd/%d", fd);
	ctx = cfs_create_ctx(proc_path, NULL);
	close(fd);
	if (IS_ERR(ctx)) {
		return NULL;
	}

	return ctx;
}

int LLVMFuzzerTestOneInput(uint8_t *buf, size_t len)
{
	struct cfs_xattr_header_s *xattrs = NULL;
	const size_t max_dirs = 10;
	u8 digest_out[SHA256_DIGEST_SIZE];
	struct test_context_s test_ctx;
	struct cfs_context_s *ctx;
	struct cfs_inode_s ino_buf;
	struct cfs_inode_s *ino;
	struct cfs_dir_s *dir;
	char name[NAME_MAX];
	char value[256];
	u64 index;
	u64 off;
	int fd;

	cfs_digest_from_payload((const char *) buf, len, digest_out);

	ctx = create_ctx(buf, len);
	if (ctx == NULL)
		return 0;

	test_ctx.ctx = ctx;
	test_ctx.dirs_left = max_dirs;

	if (len >= sizeof (u64)) {
		off = *((u64 *) buf);
		cfs_get_ino_index(ctx, off, &ino_buf);
	}

	memcpy(name, buf, min(len, NAME_MAX - 1));
	name[min(len, NAME_MAX - 1)] = '\0';

	for (off = 0; off < 1000; off++) {
		ino = cfs_get_ino_index(ctx, off, &ino_buf);
		if (!IS_ERR(ino)) {
			struct cfs_dir_s *dir;

			dir = cfs_get_dir(ctx, ino, off);
			if (!IS_ERR(dir)) {
				cfs_dir_get_link_count(dir);
	                        if (dir) {
					cfs_dir_lookup(dir, name, strlen(name), &index);
					cfs_dir_iterate(dir, 0, iter_cb, &test_ctx);
                                }
				free(dir);
			}
		}
	}

	ino = cfs_get_root_ino(ctx, &ino_buf, &index);
	if (IS_ERR(ino))
		goto cleanup;

	xattrs = cfs_get_xattrs(ctx, ino);
	if (!IS_ERR(xattrs))
		free(xattrs);

	dir = cfs_get_dir(ctx, ino, index);
	if (IS_ERR(dir))
		goto cleanup;

	cfs_dir_iterate(dir, 0, iter_cb, &test_ctx);
	free(dir);

cleanup:
	cfs_destroy_ctx(ctx);

	return 0;
}

int main (int argc, char **argv)
{
#ifdef FUZZING_RUN_SINGLE
	size_t i;

	for (i = 1; i < argc; i++) {
		size_t len;
		char *content;

		content = read_file(argv[i], &len);
		if (content == NULL)
			continue;

		LLVMFuzzerTestOneInput(content, len);
		free(content);
	}
#else
	extern void HF_ITER(uint8_t** buf, size_t* len);
	for (;;) {
		size_t len;
		uint8_t *buf;

		HF_ITER(&buf, &len);

		LLVMFuzzerTestOneInput(buf, len);
	}
#endif
	return 0;
}
