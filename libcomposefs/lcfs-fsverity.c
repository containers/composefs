#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <endian.h>
#include <assert.h>
#include <string.h>
#include <sys/param.h>

/* For sha256 computation */
#include <openssl/evp.h>

#include "lcfs-fsverity.h"

struct fsverity_descriptor {
	uint8_t version;
	uint8_t hash_algorithm;
	uint8_t log_blocksize;
	uint8_t salt_size;
	uint32_t reserved1;
	uint64_t data_size_be;
	uint8_t root_hash[64];
	uint8_t salt[32];
	uint8_t reserved2[144];
};

#define FSVERITY_BLOCK_SIZE 4096
#define FSVERITY_MAX_LEVELS 8 /* enough for 64bit file size */

struct FsVerityContext {
	uint8_t buffer[FSVERITY_MAX_LEVELS][FSVERITY_BLOCK_SIZE];
	uint32_t buffer_pos[FSVERITY_MAX_LEVELS];
	uint32_t max_level;
	uint64_t file_size;
	EVP_MD_CTX *md_ctx;
};

FsVerityContext *lcfs_fsverity_context_new(void)
{
	FsVerityContext *ctx;

	ctx = calloc(1, sizeof(FsVerityContext));
	if (ctx == NULL)
		return NULL;

	ctx->md_ctx = EVP_MD_CTX_create();
	if (ctx->md_ctx == NULL) {
		free(ctx);
		return NULL;
	}

	return ctx;
}

void lcfs_fsverity_context_free(FsVerityContext *ctx)
{
	EVP_MD_CTX_destroy(ctx->md_ctx);
	free(ctx);
}

static void do_sha256(FsVerityContext *ctx, const uint8_t *data,
		      size_t data_len, uint8_t *digest)
{
	const EVP_MD *md = EVP_sha256();
	int ret;

	assert(md != NULL);

	ret = EVP_DigestInit_ex(ctx->md_ctx, md, NULL);
	assert(ret == 1);

	ret = EVP_DigestUpdate(ctx->md_ctx, data, data_len);
	assert(ret == 1);

	ret = EVP_DigestFinal_ex(ctx->md_ctx, digest, NULL);
	assert(ret == 1);
}

static void lcfs_fsverity_context_update_level(FsVerityContext *ctx,
					       uint8_t *data, size_t data_len,
					       uint32_t level)
{
	assert(level < FSVERITY_MAX_LEVELS);

	if (level > ctx->max_level)
		ctx->max_level = level;

	while (data_len > 0) {
		/* First check if block is already full, we want to do this lazyly
		   so we only flush to the next level if there is more data after
		   the block is full */
		if (ctx->buffer_pos[level] == FSVERITY_BLOCK_SIZE) {
			uint8_t digest[32];
			do_sha256(ctx, ctx->buffer[level], FSVERITY_BLOCK_SIZE,
				  digest);
			lcfs_fsverity_context_update_level(ctx, digest, 32,
							   level + 1);
			ctx->buffer_pos[level] = 0;
		}

		size_t to_copy = MIN(
			FSVERITY_BLOCK_SIZE - ctx->buffer_pos[level], data_len);

		memcpy(ctx->buffer[level] + ctx->buffer_pos[level], data,
		       to_copy);
		ctx->buffer_pos[level] += to_copy;

		data += to_copy;
		data_len -= to_copy;
	}
}

void lcfs_fsverity_context_update(FsVerityContext *ctx, void *data,
				  size_t data_len)
{
	lcfs_fsverity_context_update_level(ctx, data, data_len, 0);
	ctx->file_size += data_len;
}

static void lcfs_fsverity_context_flush_level(FsVerityContext *ctx,
					      uint32_t level)
{
	uint8_t digest[32];

	if (ctx->buffer_pos[level] < FSVERITY_BLOCK_SIZE) {
		memset(ctx->buffer[level] + ctx->buffer_pos[level], 0,
		       FSVERITY_BLOCK_SIZE - ctx->buffer_pos[level]);
		ctx->buffer_pos[level] = FSVERITY_BLOCK_SIZE;
	}

	if (level == ctx->max_level)
		return;

	do_sha256(ctx, ctx->buffer[level], FSVERITY_BLOCK_SIZE, digest);
	lcfs_fsverity_context_update_level(ctx, digest, 32, level + 1);

	lcfs_fsverity_context_flush_level(ctx, level + 1);
}

void lcfs_fsverity_context_get_digest(FsVerityContext *ctx, uint8_t digest[32])
{
	struct fsverity_descriptor descriptor;

	lcfs_fsverity_context_flush_level(ctx, 0);

	memset(&descriptor, 0, sizeof(descriptor));
	descriptor.version = 1;
	descriptor.hash_algorithm = 1;
	descriptor.log_blocksize = 12;
	descriptor.salt_size = 0;
	descriptor.data_size_be = htole64(ctx->file_size);

	do_sha256(ctx, ctx->buffer[ctx->max_level], FSVERITY_BLOCK_SIZE,
		  descriptor.root_hash);

	do_sha256(ctx, (uint8_t *)&descriptor, sizeof(descriptor), digest);
}
