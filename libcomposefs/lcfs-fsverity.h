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

#include <stdint.h>

typedef struct FsVerityContext FsVerityContext;

#define LCFS_SHA256_DIGEST_LEN 32

FsVerityContext *lcfs_fsverity_context_new(void);
void lcfs_fsverity_context_free(FsVerityContext *ctx);
void lcfs_fsverity_context_update(FsVerityContext *ctx, void *data, size_t data_len);
void lcfs_fsverity_context_get_digest(FsVerityContext *ctx,
				      uint8_t digest[LCFS_SHA256_DIGEST_LEN]);
