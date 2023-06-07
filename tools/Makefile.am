bin_PROGRAMS = mkcomposefs
sbin_PROGRAMS = mount.composefs
noinst_PROGRAMS = 

if USE_YAJL
noinst_PROGRAMS += composefs-from-json
endif

AM_CFLAGS = $(WARN_CFLAGS) -I$(top_srcdir)/

mkcomposefs_SOURCES = mkcomposefs.c
mkcomposefs_LDADD =  ../libcomposefs/libcomposefs.la $(LIBCRYPTO_LIBS)

mount_composefs_SOURCES = mountcomposefs.c
mount_composefs_LDADD = ../libcomposefs/libcomposefs.la $(LIBCRYPTO_LIBS)

composefs_from_json_SOURCES = composefs-from-json.c read-file.c read-file.h
composefs_from_json_LDADD = ../libcomposefs/libcomposefs.la $(LIBS_YAJL) $(LIBCRYPTO_LIBS) $(LIBS_SECCOMP)

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
	$(srcdir)/test-checksums.sh "${WRITER_JSON_PREFIX} $(builddir)/composefs-from-json" "$(srcdir)/test-assets" "${TEST_ASSETS}"

check: check-checksums
