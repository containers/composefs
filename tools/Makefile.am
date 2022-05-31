bin_PROGRAMS = dump writer writer-json

HASH_CFLAGS = -DUSE_OBSTACK=0 -DTESTING=0 -DUSE_DIFF_HASH=0

AM_CFLAGS = -I $(abs_top_srcdir)/lcfs $(WARN_CFLAGS) $(HASH_CFLAGS)  $(FSVERITY_CFLAGS)

LCFS_FILES = lcfs/bitrotate.h lcfs/hash.c lcfs/hash.h lcfs/lcfs.h lcfs/lcfs-writer.c lcfs/lcfs-writer.h lcfs/xalloc-oversized.h

dump_SOURCES = dump.c $(LCFS_FILES)
dump_LDADD = $(FSVERITY_LIBS)

writer_SOURCES = writer.c $(LCFS_FILES)
writer_LDADD = $(FSVERITY_LIBS)

writer_json_SOURCES = writer-json.c read-file.c read-file.h $(LCFS_FILES)
writer_json_LDADD = $(LIBS_YAJL) $(FSVERITY_LIBS)
