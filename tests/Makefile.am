TEST_ASSETS_SMALL = \
	config.json.gz config-with-hard-link.json.gz special.json

TEST_ASSETS = ${TEST_ASSETS_SMALL} \
	cs9-x86_64-developer.json.gz cs9-x86_64-minimal.json.gz	\
	f36-x86_64-silverblue.json.gz

if ENABLE_VALGRIND
WRITER_JSON_PREFIX=libtool --mode=execute ${VALGRIND} --quiet --leak-check=yes --error-exitcode=42
endif

EXTRA_DIST = test-checksums.sh $(patsubst %,assets/%,${TEST_ASSETS_SMALL}) $(patsubst %,assets/%.sha256_erofs,${TEST_ASSETS_SMALL})

check-checksums:
	$(srcdir)/test-checksums.sh "${WRITER_JSON_PREFIX} $(builddir)/../tools/" "$(srcdir)/assets" "${TEST_ASSETS}"

check: check-checksums
