#include <stdbool.h>
#include <linux/types.h>

#define __packed                        __attribute__((__packed__))
typedef __u8 u8;

static inline __u16 cpu_to_le16(__u16 val)
{
	return htole16(val);
}

static inline __u32 cpu_to_le32(__u32 val)
{
	return htole32(val);
}

static inline __u64 cpu_to_le64(__u64 val)
{
	return htole64(val);
}

static inline __u16 le16_to_cpu(__u16 val)
{
	return le16toh(val);
}

static inline __u32 le32_to_cpu(__u32 val)
{
	return le32toh(val);
}

static inline __u64 le64_to_cpu(__u64 val)
{
	return le64toh(val);
}

/* Note: These only do power of 2 */
#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define round_up(x, y) ((((x)-1) | __round_mask(x, y)) + 1)
#define round_down(x, y) ((x) & ~__round_mask(x, y))

#define ALIGN_TO(_offset, _align_size)                                         \
	(((_offset) + _align_size - 1) & ~(_align_size - 1))

#define BIT(nr)  (((uint64_t) 1) << (nr))
#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2 * !!(condition)]))
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))

/* We use a fixed block size for all arches of 4k */
#define EROFS_BLKSIZ 4096
#define EROFS_BLKSIZ_BITS 12

#define EROFS_ISLOTBITS		5
#define EROFS_SLOTSIZE		(1U << EROFS_ISLOTBITS)

#define EROFS_SUPER_MAGIC_V1 0xE0F5E1E2

#define CRC32C_POLY_LE	0x82F63B78
static inline uint32_t erofs_crc32c(uint32_t crc, const uint8_t *in, size_t len)
{
	int i;

	while (len--) {
		crc ^= *in++;
		for (i = 0; i < 8; i++)
			crc = (crc >> 1) ^ ((crc & 1) ? CRC32C_POLY_LE : 0);
	}
	return crc;
}

enum {
	EROFS_FT_UNKNOWN,
	EROFS_FT_REG_FILE,
	EROFS_FT_DIR,
	EROFS_FT_CHRDEV,
	EROFS_FT_BLKDEV,
	EROFS_FT_FIFO,
	EROFS_FT_SOCK,
	EROFS_FT_SYMLINK,
	EROFS_FT_MAX
};

#define ilog2(n)			\
(					\
	(n) & (1ULL << 63) ? 63 :	\
	(n) & (1ULL << 62) ? 62 :	\
	(n) & (1ULL << 61) ? 61 :	\
	(n) & (1ULL << 60) ? 60 :	\
	(n) & (1ULL << 59) ? 59 :	\
	(n) & (1ULL << 58) ? 58 :	\
	(n) & (1ULL << 57) ? 57 :	\
	(n) & (1ULL << 56) ? 56 :	\
	(n) & (1ULL << 55) ? 55 :	\
	(n) & (1ULL << 54) ? 54 :	\
	(n) & (1ULL << 53) ? 53 :	\
	(n) & (1ULL << 52) ? 52 :	\
	(n) & (1ULL << 51) ? 51 :	\
	(n) & (1ULL << 50) ? 50 :	\
	(n) & (1ULL << 49) ? 49 :	\
	(n) & (1ULL << 48) ? 48 :	\
	(n) & (1ULL << 47) ? 47 :	\
	(n) & (1ULL << 46) ? 46 :	\
	(n) & (1ULL << 45) ? 45 :	\
	(n) & (1ULL << 44) ? 44 :	\
	(n) & (1ULL << 43) ? 43 :	\
	(n) & (1ULL << 42) ? 42 :	\
	(n) & (1ULL << 41) ? 41 :	\
	(n) & (1ULL << 40) ? 40 :	\
	(n) & (1ULL << 39) ? 39 :	\
	(n) & (1ULL << 38) ? 38 :	\
	(n) & (1ULL << 37) ? 37 :	\
	(n) & (1ULL << 36) ? 36 :	\
	(n) & (1ULL << 35) ? 35 :	\
	(n) & (1ULL << 34) ? 34 :	\
	(n) & (1ULL << 33) ? 33 :	\
	(n) & (1ULL << 32) ? 32 :	\
	(n) & (1ULL << 31) ? 31 :	\
	(n) & (1ULL << 30) ? 30 :	\
	(n) & (1ULL << 29) ? 29 :	\
	(n) & (1ULL << 28) ? 28 :	\
	(n) & (1ULL << 27) ? 27 :	\
	(n) & (1ULL << 26) ? 26 :	\
	(n) & (1ULL << 25) ? 25 :	\
	(n) & (1ULL << 24) ? 24 :	\
	(n) & (1ULL << 23) ? 23 :	\
	(n) & (1ULL << 22) ? 22 :	\
	(n) & (1ULL << 21) ? 21 :	\
	(n) & (1ULL << 20) ? 20 :	\
	(n) & (1ULL << 19) ? 19 :	\
	(n) & (1ULL << 18) ? 18 :	\
	(n) & (1ULL << 17) ? 17 :	\
	(n) & (1ULL << 16) ? 16 :	\
	(n) & (1ULL << 15) ? 15 :	\
	(n) & (1ULL << 14) ? 14 :	\
	(n) & (1ULL << 13) ? 13 :	\
	(n) & (1ULL << 12) ? 12 :	\
	(n) & (1ULL << 11) ? 11 :	\
	(n) & (1ULL << 10) ? 10 :	\
	(n) & (1ULL <<  9) ?  9 :	\
	(n) & (1ULL <<  8) ?  8 :	\
	(n) & (1ULL <<  7) ?  7 :	\
	(n) & (1ULL <<  6) ?  6 :	\
	(n) & (1ULL <<  5) ?  5 :	\
	(n) & (1ULL <<  4) ?  4 :	\
	(n) & (1ULL <<  3) ?  3 :	\
	(n) & (1ULL <<  2) ?  2 :	\
	(n) & (1ULL <<  1) ?  1 : 0	\
)

#include "erofs_fs.h"
