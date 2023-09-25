#!/usr/bin/bash

BINDIR="$1"
ASSET_DIR="$2"
TEST_ASSETS="$3"

. $(dirname $0)/test-lib.sh

has_fsck=$(check_erofs_fsck)

set -e
tmpfile=$(mktemp /tmp/lcfs-test.XXXXXX)
tmpfile2=$(mktemp /tmp/lcfs-test.XXXXXX)
trap 'rm -rf -- "$tmpfile" "$tmpfile2"' EXIT

for format in erofs ; do
    for file in ${TEST_ASSETS} ; do
        if [ ! -f $ASSET_DIR/$file ] ; then
            continue;
        fi
        echo Verifying $file with $format
        EXPECTED_SHA=$(cat $ASSET_DIR/$file.sha256_${format});
        if [[ $file == *.gz ]] ; then
            CAT=zcat
        else
            CAT=cat
        fi

        $CAT $ASSET_DIR/$file | ${VALGRIND_PREFIX} ${BINDIR}/composefs-from-json --format=$format --out=$tmpfile -
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
    done
done
