#!/bin/bash
cases=$1
. $(dirname $0)/test-lib.sh

set -e
tmpfile=$(mktemp -d -t lcfs-test.XXXXXX)
cd $tmpfile
trap 'rm -rf -- "$tmpfile"' EXIT
for f in $cases; do
    if mkcomposefs --from-file $f >/dev/null 2>err.txt; then
        fatal "Test case $f should have failed"
    fi
    echo "ok $f"
done
