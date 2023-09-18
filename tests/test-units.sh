#!/usr/bin/bash

BINDIR="$1"

set -e

workdir=$(mktemp -d /var/tmp/lcfs-test.XXXXXX)
trap 'rm -rf -- "$workdir"' EXIT

function makeimage () {
    local dir=$1
    ${VALGRIND_PREFIX} $BINDIR/mkcomposefs --digest-store=$dir/objects $dir/root $dir/test.cfs
}

function countobjects () {
    local dir=$1
    find $dir/objects -type f | wc -l
}

# Ensure small files are inlined
function  test_inline () {
    local dir=$1

    echo foo > $dir/root/a-file

    makeimage $dir

    objects=$(countobjects $dir)
    if [ $objects != 0 ]; then
        return 1
    fi
}

# Ensure we generate objects for large files
function  test_objects () {
    local dir=$1
    dd if=/dev/zero bs=1 count=1024 2>/dev/null > $dir/root/a-file

    makeimage $dir

    objects=$(countobjects $dir)
    if [ $objects != 1 ]; then
        return 1
    fi
}

TESTS="test_inline test_objects"
res=0
for i in $TESTS; do
    testdir=$(mktemp -d $workdir/$i.XXXXXX)
    mkdir $testdir/root
    mkdir $testdir/objects
    if $i $testdir ; then
        echo "Test $i: OK"
    else
        res=1
        echo "Test $i Failed"
    fi

    rm -rf $testdir
done

exit $res
