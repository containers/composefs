#!/usr/bin/bash

BINDIR="$1"

set -e

workdir=$(mktemp -d /var/tmp/lcfs-test.XXXXXX)
trap 'rm -rf -- "$workdir"' EXIT

. $(dirname $0)/test-lib.sh

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

function  test_mount_digest () {
    local dir=$1

    if [ $has_fsverity = y ]; then
        echo foo > $dir/root/a-file
        makeimage $dir

        $BINDIR/mount.composefs -o basedir=$dir/objects,digest=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa $dir/test.cfs $dir/mnt 2> $dir/stderr && fatal "non-fsverity mount should not succeed"
        assert_file_has_content $dir/stderr "Image has no fs-verity"

        fsverity enable $dir/test.cfs

        $BINDIR/mount.composefs -o basedir=$dir/objects,digest=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa $dir/test.cfs $dir/mnt 2> $dir/stderr && fatal "wrong fsverity mount should not succeed"
        assert_file_has_content $dir/stderr "Image has wrong fs-verity"

        local DIGEST=$(fsverity measure $dir/test.cfs | awk "{ print \$1 }" | sed s/sha256://)

        $BINDIR/mount.composefs -o basedir=$dir/objects,digest=$DIGEST $dir/test.cfs $dir/mnt 2> $dir/stderr || assert_file_has_content $dir/stderr "Permission denied"
        umount $dir/mnt 2> $dir/stderr || true
    fi
}

TESTS="test_inline test_objects test_mount_digest"
res=0
for i in $TESTS; do
    testdir=$(mktemp -d $workdir/$i.XXXXXX)
    mkdir $testdir/root $testdir/objects $testdir/mnt
    if $i $testdir ; then
        echo "Test $i: OK"
    else
        res=1
        echo "Test $i Failed"
    fi

    rm -rf $testdir
done

exit $res
