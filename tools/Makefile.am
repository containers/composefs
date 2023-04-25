bin_PROGRAMS = mkcomposefs
sbin_PROGRAMS = mount.composefs
noinst_PROGRAMS = dump

if USE_YAJL
noinst_PROGRAMS += writer-json
endif

AM_CFLAGS = $(WARN_CFLAGS) -I$(top_srcdir)/

dump_SOURCES = dump.c
dump_LDADD = ../libcomposefs/libcomposefs.la $(LIBCRYPTO_LIBS)

mkcomposefs_SOURCES = mkcomposefs.c
mkcomposefs_LDADD =  ../libcomposefs/libcomposefs.la $(LIBCRYPTO_LIBS)

mount_composefs_SOURCES = mountcomposefs.c
mount_composefs_LDADD = ../libcomposefs/libcomposefs.la $(LIBCRYPTO_LIBS)

writer_json_SOURCES = writer-json.c read-file.c read-file.h
writer_json_LDADD = ../libcomposefs/libcomposefs.la $(LIBS_YAJL) $(LIBCRYPTO_LIBS)

TEST_ASSETS_SMALL = \
	config.json.gz config-with-hard-link.json.gz

TEST_ASSETS = ${TEST_ASSETS_SMALL} \
	cs9-x86_64-developer.json.gz cs9-x86_64-minimal.json.gz	\
	f36-x86_64-silverblue.json.gz

if ENABLE_VALGRIND
WRITER_JSON_PREFIX=libtool --mode=execute ${VALGRIND} --quiet --leak-check=yes --error-exitcode=42
endif

EXTRA_DIST = test-checksums.sh $(patsubst %,test-assets/%,${TEST_ASSETS_SMALL}) $(patsubst %,test-assets/%.sha256_erofs,${TEST_ASSETS_SMALL})  $(patsubst %,test-assets/%.sha256_composefs,${TEST_ASSETS_SMALL})

check-checksums:
	$(srcdir)/test-checksums.sh "${WRITER_JSON_PREFIX} $(builddir)/writer-json" "$(srcdir)/test-assets" "${TEST_ASSETS}"

check: check-checksums
