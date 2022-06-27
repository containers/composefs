/*
 * composefs
 *
 * Copyright (C) 2000 Linus Torvalds.
 *               2000 Transmeta Corp.
 * Copyright (C) 2022 Alexander Larsson
 *
 * This file is released under the GPL.
 */

#ifdef FUZZING

#define FS_VERITY_MAX_DIGEST_SIZE SHA512_DIGEST_SIZE

enum hash_algo { HASH_ALGO_SHA256 };

static inline int fsverity_get_digest(struct inode *inode,
				      u8 digest[FS_VERITY_MAX_DIGEST_SIZE],
				      enum hash_algo *alg)
{
	return -ENODATA; /* not a verity file */
}

#else

#include <crypto/hash_info.h>
#include <crypto/sha2.h>
#include <linux/fsverity.h>
#include <linux/mempool.h>

/* Copy of fsverity_get_digest(), supporting only sha256 from linux 5.19-rc1 for older kernels. */

/* FS_VERITY_MAX_DIGEST_SIZE was made public at the same time as fsverity_get_digest() */
#ifndef FS_VERITY_MAX_DIGEST_SIZE

/* Copied from fsverity_private.h */
#define FS_VERITY_MAX_LEVELS 8
#define FS_VERITY_MAX_DIGEST_SIZE SHA512_DIGEST_SIZE

struct fsverity_hash_alg {
	struct crypto_ahash *tfm; /* hash tfm, allocated on demand */
	const char *name; /* crypto API name, e.g. sha256 */
	unsigned int digest_size; /* digest size in bytes, e.g. 32 for SHA-256 */
	unsigned int block_size; /* block size in bytes, e.g. 64 for SHA-256 */
	mempool_t req_pool; /* mempool with a preallocated hash request */
};

struct merkle_tree_params {
	struct fsverity_hash_alg *hash_alg; /* the hash algorithm */
	const u8 *hashstate; /* initial hash state or NULL */
	unsigned int digest_size; /* same as hash_alg->digest_size */
	unsigned int block_size; /* size of data and tree blocks */
	unsigned int hashes_per_block; /* number of hashes per tree block */
	unsigned int log_blocksize; /* log2(block_size) */
	unsigned int log_arity; /* log2(hashes_per_block) */
	unsigned int num_levels; /* number of levels in Merkle tree */
	u64 tree_size; /* Merkle tree size in bytes */
	unsigned long level0_blocks; /* number of blocks in tree level 0 */

	/*
         * Starting block index for each tree level, ordered from leaf level (0)
         * to root level ('num_levels - 1')
         */
	u64 level_start[FS_VERITY_MAX_LEVELS];
};
struct fsverity_info {
	struct merkle_tree_params tree_params;
	u8 root_hash[FS_VERITY_MAX_DIGEST_SIZE];
	u8 file_digest[FS_VERITY_MAX_DIGEST_SIZE];
	const struct inode *inode;
};

static inline int fsverity_get_digest(struct inode *inode,
				      u8 digest[FS_VERITY_MAX_DIGEST_SIZE],
				      enum hash_algo *alg)
{
	const struct fsverity_info *vi;
	const struct fsverity_hash_alg *hash_alg;
	int i;

	vi = fsverity_get_info(inode);
	if (!vi)
		return -ENODATA; /* not a verity file */

	hash_alg = vi->tree_params.hash_alg;
	memset(digest, 0, FS_VERITY_MAX_DIGEST_SIZE);

	/* convert the verity hash algorithm name to a hash_algo_name enum */
	i = match_string(hash_algo_name, HASH_ALGO__LAST, hash_alg->name);
	if (i < 0)
		return -EINVAL;
	*alg = i;

	if (WARN_ON_ONCE(hash_alg->digest_size != hash_digest_size[*alg]))
		return -EINVAL;
	memcpy(digest, vi->file_digest, hash_alg->digest_size);

	pr_debug("file digest %s:%*phN\n", hash_algo_name[*alg],
		 hash_digest_size[*alg], digest);

	return 0;
}

#endif

#endif /* !FUZZING */
