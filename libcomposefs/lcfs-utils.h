#ifndef _LCFS_UTILS_H
#define _LCFS_UTILS_H

#include <assert.h>

static inline void cleanup_freep(void *p)
{
	void **pp = (void **)p;

	if (*pp)
		free(*pp);
}

static inline void cleanup_fdp(int *fdp)
{
	int fd;

	assert(fdp);

	fd = *fdp;
	if (fd != -1)
		(void)close(fd);
}

#define cleanup_free __attribute__((cleanup(cleanup_freep)))
#define cleanup_fd __attribute__((cleanup(cleanup_fdp)))

static inline void *steal_pointer(void *pp)
{
	void **ptr = (void **)pp;
	void *ref;

	ref = *ptr;
	*ptr = NULL;

	return ref;
}

/* type safety */
#define steal_pointer(pp) (0 ? (*(pp)) : (steal_pointer)(pp))

#endif
