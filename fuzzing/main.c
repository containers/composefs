#define _GNU_SOURCE

#include "../kernel/lcfs-reader.h"

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
	struct lcfs_context_s *ctx;
	int recursion_left;
};

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	return 0;
}

bool iter_cb(void *private, const char *name, int namelen, u64 ino, unsigned int dtype)
{
	struct test_context_s *test_ctx = private;
	struct lcfs_context_s *ctx = test_ctx->ctx;
	struct lcfs_inode_s cfs_ino_buf;
	struct lcfs_inode_s *cfs_ino;
	struct lcfs_inode_data_s cfs_ino_data_buf;
	struct lcfs_inode_data_s *cfs_ino_data;
	struct lcfs_dentry_s dentry_buf;
	ssize_t i, size_xattrs;
	char xattrs[256+1];
	const char *cstr;
	int ret;

	if (test_ctx->recursion_left <= 0)
		return true;

	cstr = name;
	/* Consume the C string.  */
	while (*cstr)
		cstr++;

	cfs_ino = lcfs_get_ino_index(ctx, ino, &cfs_ino_buf);
	if (IS_ERR(cfs_ino))
		return true;


	cfs_ino_data = lcfs_inode_data(ctx, cfs_ino, &cfs_ino_data_buf);
	if (IS_ERR(cfs_ino_data))
		return true;

	if ((dtype & S_IFMT) == S_IFDIR) {
		lcfs_off_t index;

		lcfs_lookup(ctx, cfs_ino, name, &index);
		lcfs_get_dentry(ctx, index, &dentry_buf);
	} else {
		char *path_buf = malloc(PATH_MAX);
		size_t len;

		if (path_buf == NULL)
			return true;

		cstr = lcfs_c_string(ctx, cfs_ino->u.file.payload, &len, path_buf, PATH_MAX);
		if (!IS_ERR(cstr)) {
			/* Consume the C string.  */
			while (*cstr)
				cstr++;
		}
		free(path_buf);
	}

	size_xattrs = lcfs_list_xattrs(ctx, cfs_ino, xattrs, sizeof(xattrs)-1);
	if (size_xattrs < 0)
		return true;
	xattrs[size_xattrs] = '\0';

	for (i = 0; i < size_xattrs;) {
		char value[256];
		char *xattr = &(xattrs[i]);
		size_t len = strlen(xattr) ? : 1;

		lcfs_get_xattr(ctx, cfs_ino, xattr, value, sizeof(value));

		i += len;
	}

	if ((dtype & S_IFMT) == S_IFDIR) {
		test_ctx->recursion_left--;
		lcfs_iterate_dir(ctx, 0, cfs_ino, iter_cb, test_ctx);
		test_ctx->recursion_left++;
	}

	return true;
}

#define min(a,b) ((a)<(b)?(a):(b))

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

int LLVMFuzzerTestOneInput(uint8_t *buf, size_t len)
{
	const size_t max_recursion = 10;
	struct test_context_s test_ctx;
	struct lcfs_context_s *ctx;
	struct lcfs_inode_s ino_buf;
	struct lcfs_inode_s *ino;
	char name[NAME_MAX];
	char proc_path[64];
	lcfs_off_t index;
	lcfs_off_t off;
	int fd;

	fd = open(".", O_TMPFILE | O_RDWR, S_IRUSR | S_IWUSR);
	if (fd < 0)
		return 0;

	if(safe_write(fd, buf, len) < 0) {
		close(fd);
		return 0;
	}

	sprintf(proc_path, "/proc/self/fd/%d", fd);
	ctx = lcfs_create_ctx(proc_path);
	close(fd);
	if (IS_ERR(ctx)) {
		return 0;
	}

	off = lcfs_get_root_index(ctx);

	ino = lcfs_get_ino_index(ctx, off, &ino_buf);
	if (IS_ERR (ino))
		return 0;

	memcpy(name, buf, min(len, NAME_MAX - 1));
	name[min(len, NAME_MAX - 1)] = '\0';
	lcfs_lookup(ctx, ino, name, &index);

	test_ctx.ctx = ctx;
	test_ctx.recursion_left = max_recursion;

	lcfs_iterate_dir(ctx, 0, ino, iter_cb, &test_ctx);

	lcfs_destroy_ctx(ctx);

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
