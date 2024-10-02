/* lcfs
   Copyright (C) 2023 Alexander Larsson <alexl@redhat.com>

   SPDX-License-Identifier: GPL-2.0-or-later OR Apache-2.0
*/
#ifndef _LCFS_UTILS_H
#define _LCFS_UTILS_H

#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
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

static inline bool size_multiply_overflow(size_t size, size_t nmemb)
{
	return nmemb != 0 && size > (SIZE_MAX / nmemb);
}

#ifndef HAVE_REALLOCARRAY
static inline void *reallocarray(void *ptr, size_t nmemb, size_t size)
{
	if (size_multiply_overflow(size, nmemb))
		return NULL;

	return realloc(ptr, size * nmemb ?: 1);
}
#endif

static inline int hexdigit(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return 10 + (c - 'a');
	if (c >= 'A' && c <= 'F')
		return 10 + (c - 'A');
	return -1;
}

void digest_to_string(const uint8_t *csum, char *buf);
int digest_to_raw(const char *digest, uint8_t *raw, int max_size);

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

static inline const char *gnu_basename(const char *filename)
{
	const char *p = strrchr(filename, '/');
	return p ? p + 1 : filename;
}

#endif
