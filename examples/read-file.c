/*
  Copyright 2017 Giuseppe Scrivano <giuseppe@scrivano.org>

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

#include "read-file.h"

#include <sys/stat.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>

char *fread_file(FILE *stream, size_t *length)
{
	char *buf = NULL;
	size_t alloc = BUFSIZ;
	{
		struct stat st;

		if (fstat(fileno(stream), &st) >= 0 && S_ISREG(st.st_mode)) {
			off_t pos = ftello(stream);

			if (pos >= 0 && pos < st.st_size) {
				off_t alloc_off = st.st_size - pos;
				if (SIZE_MAX - 1 < (uintmax_t)(alloc_off)) {
					errno = ENOMEM;
					return NULL;
				}

				alloc = alloc_off + 1;
			}
		}
	}

	if (!(buf = malloc(alloc)))
		return NULL;

	{
		size_t size = 0;
		int save_errno;

		for (;;) {
			size_t requested = alloc - size;
			size_t count = fread(buf + size, 1, requested, stream);
			size += count;

			if (count != requested) {
				save_errno = errno;
				if (ferror(stream))
					break;

				if (size < alloc - 1) {
					char *reduce_buf = realloc(buf, size + 1);
					if (reduce_buf != NULL)
						buf = reduce_buf;
				}

				buf[size] = '\0';
				*length = size;
				return buf;
			}

			{
				char *temp_buf;

				if (alloc == SIZE_MAX) {
					save_errno = ENOMEM;
					break;
				}

				if (alloc < SIZE_MAX - alloc / 2)
					alloc = alloc + alloc / 2;
				else {
					save_errno = E2BIG;
					break;
				}

				if (!(temp_buf = realloc(buf, alloc))) {
					save_errno = errno;
					break;
				}

				buf = temp_buf;
			}
		}

		free(buf);
		errno = save_errno;
		return NULL;
	}
}

char *read_file(const char *path, size_t *length)
{
	FILE *f = fopen(path, "re");
	char *buf;
	int save_errno;

	if (!f)
		return NULL;

	buf = fread_file(f, length);

	save_errno = errno;

	if (fclose(f) != 0) {
		if (buf) {
			save_errno = errno;
			free(buf);
		}
		errno = save_errno;
		return NULL;
	}

	return buf;
}
