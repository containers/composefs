COMPOSEFS_HASH_CFLAGS = -DUSE_OBSTACK=0 -DTESTING=0 -DUSE_DIFF_HASH=0

bin_PROGRAMS = mkcomposefs composefs-info
sbin_PROGRAMS = mount.composefs
noinst_PROGRAMS = composefs-dump

if USE_YAJL
noinst_PROGRAMS += composefs-from-json
endif

if USE_FUSE3
noinst_PROGRAMS += composefs-fuse
endif

AM_CFLAGS = $(WARN_CFLAGS) -I$(top_srcdir)/

mkcomposefs_SOURCES = mkcomposefs.c
mkcomposefs_LDADD =  ../libcomposefs/libcomposefs.la $(LIBCRYPTO_LIBS)

mount_composefs_SOURCES = mountcomposefs.c
mount_composefs_LDADD = ../libcomposefs/libcomposefs.la $(LIBCRYPTO_LIBS)

composefs_from_json_SOURCES = composefs-from-json.c read-file.c read-file.h
composefs_from_json_LDADD = ../libcomposefs/libcomposefs.la $(LIBS_YAJL) $(LIBCRYPTO_LIBS) $(LIBS_SECCOMP)

composefs_info_SOURCES = composefs-info.c ../libcomposefs/hash.c
composefs_info_CFLAGS = $(AM_CFLAGS) $(COMPOSEFS_HASH_CFLAGS)
composefs_info_LDADD = ../libcomposefs/libcomposefs.la

composefs_dump_SOURCES = composefs-dump.c
composefs_dump_LDADD = ../libcomposefs/libcomposefs.la

composefs_fuse_SOURCES = cfs-fuse.c
composefs_fuse_LDADD =   ../libcomposefs/libcomposefs.la $(FUSE3_LIBS)
composefs_fuse_CFLAGS =  $(AM_CFLAGS) $(FUSE3_CFLAGS)
