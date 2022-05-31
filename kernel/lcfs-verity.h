/*
 * composefs
 *
 * Copyright (C) 2000 Linus Torvalds.
 *               2000 Transmeta Corp.
 * Copyright (C) 2022 Alexander Larsson
 *
 * This file is released under the GPL.
 */

#include <crypto/sha2.h>
#include <linux/fsverity.h>

#ifdef STANDALONE_COMPOSEFS
/* For whatever reason, struct fsverity_info is in a private header, even though
   fsverity_get_info() is in the public header. For now, just duplicate enough
   to implement lcfs_fsverity_info_get_digest() locally, but for upstreaming we
   should make that a publically exported function. */

/* Copied from fsverity_private.h */
#define FS_VERITY_MAX_LEVELS            8
#define FS_VERITY_MAX_DIGEST_SIZE       SHA512_DIGEST_SIZE
struct merkle_tree_params {
        struct fsverity_hash_alg *hash_alg; /* the hash algorithm */
        const u8 *hashstate;            /* initial hash state or NULL */
        unsigned int digest_size;       /* same as hash_alg->digest_size */
        unsigned int block_size;        /* size of data and tree blocks */
        unsigned int hashes_per_block;  /* number of hashes per tree block */
        unsigned int log_blocksize;     /* log2(block_size) */
        unsigned int log_arity;         /* log2(hashes_per_block) */
        unsigned int num_levels;        /* number of levels in Merkle tree */
        u64 tree_size;                  /* Merkle tree size in bytes */
        unsigned long level0_blocks;    /* number of blocks in tree level 0 */

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
#else
#include <fs/verity/fsverity_private.h>
#endif

static inline u8 *lcfs_fsverity_info_get_digest(struct fsverity_info *verity_info, size_t *digest_size) {
	*digest_size = verity_info->tree_params.digest_size;
	return verity_info->file_digest;
}
