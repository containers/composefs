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
#include <string.h>
#include <errno.h>
#include <unistd.h>

#define max(a, b) ((a > b) ? (a) : (b))
#define min(a, b) (((a) < (b)) ? (a) : (b))

static inline bool str_has_prefix(const char *str, const char *prefix)
{
	return strncmp(str, prefix, strlen(prefix)) == 0;
}

static inline char *memdup(const char *s, size_t len)
{
	char *s2 = malloc(len);
	if (s2 == NULL) {
		errno = ENOMEM;
		return NULL;
	}
	memcpy(s2, s, len);
	return s2;
}

static inline char *str_join(const char *a, const char *b)
{
	size_t a_len = strlen(a);
	size_t b_len = strlen(b);
	char *res = malloc(a_len + b_len + 1);
	if (res) {
		memcpy(res, a, a_len);
		memcpy(res + a_len, b, b_len + 1);
	}
	return res;
}

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

// A wrapper around close() that takes a pointer to a file descriptor (integer):
// - Never returns an error (and preserves errno)
// - Sets the value to -1 after closing to make cleanup idempotent
static inline void cleanup_fdp(int *fdp)
{
	PROTECT_ERRNO;
	int fd;

	assert(fdp);

	fd = *fdp;
	if (fd != -1)
		(void)close(fd);
	*fdp = -1;
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
