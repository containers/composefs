#!/bin/bash
set -e
bindir=$(cd $1 && pwd)
shift
. $(dirname $0)/test-lib.sh

tmpd=$(mktemp -d -t lcfs-test.XXXXXX)
trap 'rm -rf -- "$tmpd"' EXIT
for f in $@; do
    if $bindir/mkcomposefs --from-file $f $tmpd/out.cfs >/dev/null 2>err.txt; then
        fatal "Test case $f should have failed"
    fi
    echo "ok $f"
done
