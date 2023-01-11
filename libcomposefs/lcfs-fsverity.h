#include <stdint.h>

typedef struct FsVerityContext FsVerityContext;

FsVerityContext *lcfs_fsverity_context_new(void);
void lcfs_fsverity_context_free(FsVerityContext *ctx);
void lcfs_fsverity_context_update(FsVerityContext *ctx, void *data, size_t data_len);
void lcfs_fsverity_context_get_digest(FsVerityContext *ctx, uint8_t digest[32]);
