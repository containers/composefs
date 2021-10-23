bin_PROGRAMS = dump writer writer-json

AM_CFLAGS = -I $(abs_top_srcdir)/lcfs

LCFS_FILES = lcfs/bitrotate.h lcfs/hash.c lcfs/hash.h lcfs/lcfs.h lcfs/lcfs-writer.c lcfs/lcfs-writer.h lcfs/xalloc-oversized.h

dump_SOURCES = dump.c $(LCFS_FILES)

writer_SOURCES = writer.c $(LCFS_FILES)

writer_json_SOURCES = writer-json.c read-file.c read-file.h $(LCFS_FILES)
writer_json_LDADD = $(LIBS_YAJL)
