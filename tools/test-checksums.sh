#!/usr/bin/bash

WRITER_JSON="$1"
ASSET_DIR="$2"
TEST_ASSETS="$3"

set -e
tmpfile=$(mktemp /tmp/lcfs-test.XXXXXX)
trap 'rm -rf -- "$tmpfile"' EXIT

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

        $CAT $ASSET_DIR/$file | $WRITER_JSON --format=$format --out=$tmpfile -
        SHA=$(sha256sum $tmpfile | awk "{print \$1}")

        if [ $SHA != $EXPECTED_SHA ]; then
            echo Invalid $format checksum of file generated from $file: $SHA, expected $EXPECTED_SHA
            exit 1
        fi
    done
done
