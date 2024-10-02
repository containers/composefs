/* lcfs
   Copyright (C) 2023 Alexander Larsson <alexl@redhat.com>

   SPDX-License-Identifier: GPL-2.0-or-later OR Apache-2.0
*/
#include <stdint.h>
#include <stddef.h>

typedef struct FsVerityContext FsVerityContext;

#define LCFS_SHA256_DIGEST_LEN 32

FsVerityContext *lcfs_fsverity_context_new(void);
void lcfs_fsverity_context_free(FsVerityContext *ctx);
void lcfs_fsverity_context_update(FsVerityContext *ctx, void *data, size_t data_len);
void lcfs_fsverity_context_get_digest(FsVerityContext *ctx,
				      uint8_t digest[LCFS_SHA256_DIGEST_LEN]);
