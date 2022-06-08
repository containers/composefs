HASH_CFLAGS = -DUSE_OBSTACK=0 -DTESTING=0 -DUSE_DIFF_HASH=0

lib_LTLIBRARIES = libcomposefs.la

libcomposefsincludedir = $(includedir)/libcomposefs
libcomposefsinclude_HEADERS = lcfs-writer.h

libcomposefs_la_SOURCES = bitrotate.h hash.c hash.h lcfs.h lcfs-writer.c lcfs-writer.h xalloc-oversized.h
libcomposefs_la_CFLAGS = $(WARN_CFLAGS) $(HASH_CFLAGS)  $(FSVERITY_CFLAGS)
libcomposefs_la_LIBADD = $(FSVERITY_LIBS)
