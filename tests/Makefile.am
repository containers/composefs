TEST_ASSETS_SMALL = \
	config.dump.gz config-with-hard-link.dump.gz special.dump special_v1.dump

TEST_ASSETS_SMALL_EXTRA = \
	special.dump.version special_v1.dump.version

TEST_ASSETS_SHOULD_FAIL = should-fail-long-link.dump
TEST_ASSETS = ${TEST_ASSETS_SMALL} \
	cs9-x86_64-developer.dump.gz cs9-x86_64-minimal.dump.gz	\
	f36-x86_64-silverblue.dump.gz

if ENABLE_VALGRIND
VALGRIND_PREFIX=libtool --mode=execute ${VALGRIND} --quiet --leak-check=yes --error-exitcode=42
endif

EXTRA_DIST = \
	gendir \
	dumpdir \
	test-lib.sh \
	test-units.sh \
	test-random-fuse.sh \
	test-checksums.sh \
	test-should-fail.sh \
	integration.sh \
	$(patsubst %,assets/%,${TEST_ASSETS_SMALL_EXTRA}) \
	$(patsubst %,assets/%,${TEST_ASSETS_SHOULD_FAIL}) \
	$(patsubst %,assets/%,${TEST_ASSETS_SMALL}) $(patsubst %,assets/%.sha256,${TEST_ASSETS_SMALL})

check-checksums:
	VALGRIND_PREFIX="${VALGRIND_PREFIX}" $(srcdir)/test-checksums.sh "$(builddir)/../tools/" "$(srcdir)/assets" "${TEST_ASSETS}"

check-should-fail:
	$(srcdir)/test-should-fail.sh ${TEST_ASSETS_SHOULD_FAIL}

check-units:
	VALGRIND_PREFIX="${VALGRIND_PREFIX}" $(srcdir)/test-units.sh "$(builddir)/../tools/"

check-random-fuse:
	VALGRIND_PREFIX="${VALGRIND_PREFIX}" $(srcdir)/test-random-fuse.sh "$(builddir)/../tools/"

check: check-units check-checksums check-random-fuse check-should-fail
