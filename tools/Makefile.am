bin_PROGRAMS = mkcomposefs
sbin_PROGRAMS = mount.composefs
noinst_PROGRAMS =

if USE_FUSE3
noinst_PROGRAMS += composefs-fuse
endif

AM_CFLAGS = $(WARN_CFLAGS) -I$(top_srcdir)/

mkcomposefs_SOURCES = mkcomposefs.c
mkcomposefs_LDADD =  ../libcomposefs/libcomposefs.la $(LIBCRYPTO_LIBS)

mount_composefs_SOURCES = mountcomposefs.c
mount_composefs_LDADD = ../libcomposefs/libcomposefs.la $(LIBCRYPTO_LIBS)

composefs_fuse_SOURCES = cfs-fuse.c
composefs_fuse_LDADD =   ../libcomposefs/libcomposefs.la $(FUSE3_LIBS)
composefs_fuse_CFLAGS = $(FUSE3_CFLAGS)
