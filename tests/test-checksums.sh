#!/bin/bash

BINDIR="$1"
ASSET_DIR="$2"
TEST_ASSETS="$3"
TEST_ASSETS_SHOULD_FAIL="$4"

. $(dirname $0)/test-lib.sh

has_fsck=$(check_erofs_fsck)

set -e
tmpfile=$(mktemp --tmpdir lcfs-test.XXXXXX)
tmpfile2=$(mktemp --tmpdir lcfs-test.XXXXXX)
trap 'rm -rf -- "$tmpfile" "$tmpfile2"' EXIT

for format in erofs ; do
    for file in ${TEST_ASSETS} ; do
        if [ ! -f $ASSET_DIR/$file ] ; then
            continue;
        fi

        VERSION=""
        VERSION_ARG=""
        if test -f $ASSET_DIR/$file.version ; then
            VERSION="$(cat $ASSET_DIR/$file.version)"
            VERSION_ARG="--min-version=$VERSION --max-version=$VERSION"
        fi

        echo Verifying $file $VERSION_ARG
        EXPECTED_SHA=$(cat $ASSET_DIR/$file.sha256);
        if [[ $file == *.gz ]] ; then
            CAT=zcat
        else
            CAT=cat
        fi

        $CAT $ASSET_DIR/$file | ${VALGRIND_PREFIX} ${BINDIR}/mkcomposefs $VERSION_ARG --from-file - $tmpfile
        SHA=$(sha256sum $tmpfile | awk "{print \$1}")

        # Run fsck.erofs to make sure we're not generating anything weird
        if [ $has_fsck == y ]; then
            fsck.erofs $tmpfile
        fi

        if [ $SHA != $EXPECTED_SHA ]; then
            echo Invalid $format checksum of file generated from $file: $SHA, expected $EXPECTED_SHA
            exit 1
        fi

        # Ensure dump reproduces the same file
        ${VALGRIND_PREFIX} ${BINDIR}/composefs-dump $tmpfile $tmpfile2
        if ! cmp $tmpfile $tmpfile2; then
            echo Dump is not reproducible
            exit 1
        fi

        ${VALGRIND_PREFIX} ${BINDIR}/composefs-info dump $tmpfile | ${VALGRIND_PREFIX} ${BINDIR}/mkcomposefs $VERSION_ARG --from-file - $tmpfile2
        if ! cmp $tmpfile $tmpfile2; then
            echo Dump is not reproducible via composefs-info dump
            exit 1
        fi
    done
done
