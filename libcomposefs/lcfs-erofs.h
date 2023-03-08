#ifndef _LCFS_EROFS_H
#define _LCFS_EROFS_H

#include <stdint.h>

#define LCFS_EROFS_VERSION 1
#define LCFS_EROFS_MAGIC 0xd078629aU

typedef enum {
	LCFS_EROFS_FLAGS_HAS_ACL = (1 << 0),
} lcfs_erofs_flag_t;

struct lcfs_erofs_header_s {
	uint32_t magic;
	uint32_t version;
	uint32_t flags;
	uint32_t unused[5];
} __attribute__((__packed__));

#endif
