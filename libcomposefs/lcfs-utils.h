/* lcfs
   Copyright (C) 2023 Alexander Larsson <alexl@redhat.com>

   This file is free software: you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 2.1 of the
   License, or (at your option) any later version.

   This file is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

#ifndef _LCFS_UTILS_H
#define _LCFS_UTILS_H

#include <assert.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

#define max(a, b) ((a > b) ? (a) : (b))

static inline void _lcfs_reset_errno_(int *saved_errno)
{
	if (*saved_errno < 0)
		return;
	errno = *saved_errno;
}

// This helper was taken from systemd; it ensures that the value of errno
// is reset.
#define PROTECT_ERRNO                                                          \
	__attribute__((cleanup(_lcfs_reset_errno_)))                           \
	__attribute__((unused)) int _saved_errno_ = errno

static inline void cleanup_freep(void *p)
{
	void **pp = (void **)p;

	if (*pp)
		free(*pp);
}

static inline void cleanup_fdp(int *fdp)
{
	PROTECT_ERRNO;
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
