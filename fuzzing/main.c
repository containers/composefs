#include "../kernel/lcfs-reader.h"

#include <stddef.h>
#include <fcntl.h>
#include <stdint.h>
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
	struct lcfs_inode_s *cfs_ino;
	struct lcfs_inode_data_s *cfs_ino_data;
	ssize_t i, size_xattrs;
	char xattrs[256+1];
	const char *cstr;

	if (test_ctx->recursion_left <= 0)
		return true;

	cstr = name;
	/* Consume the C string.  */
	while (*cstr)
		cstr++;

	cfs_ino = lcfs_get_ino_index(ctx, ino);
	if (IS_ERR(cfs_ino))
		return true;

	cfs_ino_data = lcfs_inode_data(ctx, cfs_ino);
	if (IS_ERR(cfs_ino_data))
		return true;

	if ((dtype & S_IFMT) != S_IFDIR) {
		size_t len;

		cstr = lcfs_c_string(ctx, cfs_ino->u.file.payload, &len, PATH_MAX);
		if (!IS_ERR(cstr)) {
			/* Consume the C string.  */
			while (*cstr)
				cstr++;
		}
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

int LLVMFuzzerTestOneInput(uint8_t *buf, size_t len)
{
	const size_t max_recursion = 10;
	struct lcfs_context_s *ctx;
	struct lcfs_inode_s *ino;
	lcfs_off_t off;
	char *copy;
	struct test_context_s test_ctx;

	copy = malloc(len+1);
	if (copy == NULL)
		return 0;

	memcpy(copy, buf, len);

	ctx = lcfs_create_ctx_from_memory(copy, len);
	if (IS_ERR(ctx)) {
		free(copy);
		return 0;
	}

	off = lcfs_get_root_index(ctx);

	ino = lcfs_get_ino_index(ctx, off);

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
		char *content = read_file(argv[1], &len);
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
