#!/usr/bin/bash

WRITER_JSON="$1"
ASSET_DIR="$2"
TEST_ASSETS="$3"

for format in composefs erofs ; do
    for file in ${TEST_ASSETS} ; do
        echo Verifying $file with $format
        EXPECTED_SHA=$(cat $ASSET_DIR/$file.sha256_${format});
        if [[ $file == *.gz ]] ; then
            CAT=zcat
        else
            CAT=cat
        fi
        SHA=$($CAT $ASSET_DIR/$file | $WRITER_JSON --format=$format - | sha256sum | awk "{print \$1}")
        if [ $SHA != $EXPECTED_SHA ]; then
            echo Invalid $format checksum of file generated from $file: $SHA, expected $EXPECTED_SHA
        fi
    done
done
