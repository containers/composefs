bin_PROGRAMS = mkcomposefs
sbin_PROGRAMS = mount.composefs
noinst_PROGRAMS = dump

if USE_YAJL
noinst_PROGRAMS += writer-json
endif

AM_CFLAGS = $(WARN_CFLAGS) $(FSVERITY_CFLAGS)

dump_SOURCES = dump.c
dump_LDADD = ../libcomposefs/libcomposefs.la $(LIBCRYPTO_LIBS)

mkcomposefs_SOURCES = mkcomposefs.c
mkcomposefs_LDADD =  ../libcomposefs/libcomposefs.la $(LIBCRYPTO_LIBS) $(FSVERITY_LIBS)

mount_composefs_SOURCES = mountcomposefs.c
mount_composefs_LDADD = ../libcomposefs/libcomposefs.la $(LIBCRYPTO_LIBS)

writer_json_SOURCES = writer-json.c read-file.c read-file.h
writer_json_LDADD = ../libcomposefs/libcomposefs.la $(LIBS_YAJL) $(LIBCRYPTO_LIBS)

TEST_ASSETS = \
	config.json config-with-hard-link.json \
	cs9-x86_64-developer.json.gz cs9-x86_64-minimal.json.gz	\
	f36-x86_64-silverblue.json.gz

check-checksums:
	$(srcdir)/test-checksums.sh "$(builddir)/writer-json" "$(srcdir)/test-assets" "${TEST_ASSETS}"

check: check-checksums
