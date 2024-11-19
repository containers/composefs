/* SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0 */
#define _GNU_SOURCE

#include "lcfs-writer.h"
#include "lcfs-mount.h"
#include <assert.h>
#include <unistd.h>
#include <errno.h>

static inline void lcfs_node_unrefp(struct lcfs_node_s **nodep)
{
	if (*nodep != NULL) {
		lcfs_node_unref(*nodep);
		*nodep = NULL;
	}
}
#define cleanup_node __attribute__((cleanup(lcfs_node_unrefp)))

static ssize_t write_cb(void *_file, void *buf, size_t count)
{
	FILE *file = _file;

	return fwrite(buf, 1, count, file);
}

static int testwrite_node(struct lcfs_node_s *node)
{
	char *bufp = NULL;
	size_t bufsz = 0;
	FILE *buf = open_memstream(&bufp, &bufsz);

	struct lcfs_write_options_s options = { 0 };
	options.format = LCFS_FORMAT_EROFS;
	options.version = 1;
	options.max_version = 1;
	options.file = buf;
	options.file_write_cb = write_cb;

	int r = lcfs_write_to(node, &options);
	int saved_errno = errno;
	fclose(buf);
	free(bufp);
	errno = saved_errno;
	return r;
}

static void test_basic(void)
{
	cleanup_node struct lcfs_node_s *node = lcfs_node_new();
	lcfs_node_set_mode(node, S_IFDIR | 0755);
	cleanup_node struct lcfs_node_s *child = lcfs_node_new();
	lcfs_node_set_mode(child, S_IFDIR | 0700);
	int r = lcfs_node_add_child(node, child, "somechild");
	assert(r == 0);
	// Adding child took ownership
	child = NULL;
	r = testwrite_node(node);
	assert(r == 0);
}

static void test_add_uninitialized_child(void)
{
	cleanup_node struct lcfs_node_s *node = lcfs_node_new();
	lcfs_node_set_mode(node, S_IFDIR | 0755);
	// libostree today does this pattern of creating an empty (uninitialized)
	// child and passing it to lcfs_node_add_child first. Verify this
	// continues to work for the forseeable future.
	cleanup_node struct lcfs_node_s *child = lcfs_node_new();
	int r = lcfs_node_add_child(node, child, "somechild");
	assert(r == 0);
	// Adding child took ownership
	child = NULL;

	// But we should fail to write an EROFS with this
	r = testwrite_node(node);
	assert(r == -1);
	assert(errno == EINVAL);
}

// Verifies that lcfs_fd_measure_fsverity fails on a fd without fsverity
static void test_no_verity(void)
{
	char buf[] = "/tmp/test-verity.XXXXXX";
	int tmpfd = mkstemp(buf);
	assert(tmpfd > 0);

	uint8_t digest[LCFS_DIGEST_SIZE];
	int r = lcfs_fd_measure_fsverity(digest, tmpfd);
	int errsv = errno;
	assert(r != 0);
	// We may get ENOSYS from qemu userspace emulation not implementing the ioctl
	if (getenv("CFS_TEST_ARCH_EMULATION") == NULL)
		assert(errsv == ENOVERITY);
	close(tmpfd);
}

int main(int argc, char **argv)
{
	test_basic();
	test_no_verity();
	test_add_uninitialized_child();
}
