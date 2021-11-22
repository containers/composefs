#ifdef FUZZING
# define GFP_KERNEL 0
# include <stdio.h>
# include <errno.h>
# include <stdlib.h>
# include <string.h>
# include <fcntl.h>
# include <unistd.h>
# include <sys/stat.h>

# define kfree free
# define vfree free
# define min(a, b) ((a)<(b)?(a):(b))
# define check_add_overflow(a, b, d) __builtin_add_overflow(a, b, d)
# define ENOTSUPP ENOTSUP

struct file
{
	int fd;
};

static inline void *kzalloc(size_t len, int ignored)
{
	return calloc(1, len);
}

static inline void *kmalloc(size_t len, int ignored)
{
	return malloc(len);
}

static inline struct file *filp_open(const char *path, int flags, int mode)
{
	struct file *r;
	int fd;

	fd = open(path, flags, mode);
	if (fd < 0)
		return ERR_PTR(-errno);

	r = malloc(sizeof(struct file));
	if (r == NULL) {
		close(fd);
		return ERR_PTR(-ENOMEM);
	}

	r->fd = fd;
	return r;
}

static inline ssize_t kernel_read(struct file *f, void *buf, size_t count, loff_t *off)
{
	ssize_t bytes;
	do {
		bytes = pread(f->fd, buf, count, *off);
	} while (bytes < 0 && errno == EINTR);
	if (bytes > 0)
		*off += bytes;
	return bytes;
}

static inline struct file *file_inode(struct file *f)
{
	return f;
}

static inline loff_t i_size_read(struct file *f)
{
	struct stat st;
	int r;

	r = fstat(f->fd, &st);
	if (r < 0)
		return -errno;

	return st.st_size;
}

static inline void fput(struct file *f)
{
	close(f->fd);
	free(f);
}

#endif
