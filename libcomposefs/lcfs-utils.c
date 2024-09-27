/* lcfs
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

#define _GNU_SOURCE

#include "config.h"

#include "lcfs-utils.h"
#include "lcfs-writer.h"

void digest_to_string(const uint8_t *csum, char *buf)
{
	static const char hexchars[] = "0123456789abcdef";
	uint32_t i, j;

	for (i = 0, j = 0; i < LCFS_DIGEST_SIZE; i++, j += 2) {
		uint8_t byte = csum[i];
		buf[j] = hexchars[byte >> 4];
		buf[j + 1] = hexchars[byte & 0xF];
	}
	buf[j] = '\0';
}

int digest_to_raw(const char *digest, uint8_t *raw, int max_size)
{
	int size = 0;

	while (*digest) {
		char c1, c2;
		int n1, n2;

		if (size >= max_size)
			return -1;

		c1 = *digest++;
		n1 = hexdigit(c1);
		if (n1 < 0)
			return -1;

		c2 = *digest++;
		n2 = hexdigit(c2);
		if (n2 < 0)
			return -1;

		raw[size++] = (n1 & 0xf) << 4 | (n2 & 0xf);
	}

	return size;
}
