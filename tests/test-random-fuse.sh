#!/usr/bin/bash

BINDIR="$1"

set -e

workdir=$(mktemp -d /var/tmp/lcfs-test.XXXXXX)
exit_cleanup() {
    umount "$workdir/mnt" &> /dev/null || true
    rm -rf -- "$workdir"
}

trap exit_cleanup EXIT

. $(dirname $0)/test-lib.sh

GENDIRARGS=""
if [ ${can_whiteout} == "n" ]; then
    GENDIRARGS="$GENDIRARGS --nowhiteout"
fi

if [[ -v seed ]]; then
    GENDIRARGS="$GENDIRARGS --seed=$seed"
fi

test_random() {
    echo Generating root dir
    $(dirname $0)/gendir $GENDIRARGS $workdir/root
    $(dirname $0)/dumpdir --userxattr --whiteout $workdir/root >  $workdir/root.dump
    echo Generating composefs image
    ${VALGRIND_PREFIX} ${BINDIR}/mkcomposefs --digest-store=$workdir/objects $workdir/root $workdir/root.cfs
    if [ $has_fsck == y ]; then
        fsck.erofs $workdir/root.cfs
    fi

    # Loading and dumping should produce the identical results
    echo Dumping composefs image
    ${VALGRIND_PREFIX} ${BINDIR}/composefs-dump $workdir/root.cfs $workdir/dump.cfs
    if ! cmp $workdir/root.cfs $workdir/dump.cfs; then
        echo Dump is not reproducible
        diff -u <(${BINDIR}/composefs-info dump $workdir/root.cfs) <(${BINDIR}/composefs-info dump $workdir/dump.cfs)
        exit 1
    fi

    if [ $has_fuse == 'n' ]; then
        return;
    fi

    mkdir -p $workdir/mnt
    echo Mounting composefs image using fuse
    ${BINDIR}/composefs-fuse -o source=$workdir/root.cfs,basedir=$workdir/objects $workdir/mnt
    $(dirname $0)/dumpdir --userxattr --whiteout $workdir/mnt >  $workdir/fuse.dump

    ${VALGRIND_PREFIX} ${BINDIR}/mkcomposefs --digest-store=$workdir/objects $workdir/mnt $workdir/fuse.cfs
    if [ $has_fsck == y ]; then
        fsck.erofs $workdir/fuse.cfs
    fi

    umount $workdir/mnt

    if ! cmp $workdir/root.dump $workdir/fuse.dump; then
        echo Real dir and fuse dump differ
        diff -u $workdir/root.dump $workdir/fuse.dump
        exit 1
    fi

    ${BINDIR}/composefs-fuse -o source=$workdir/fuse.cfs,basedir=$workdir/objects $workdir/mnt
    $(dirname $0)/dumpdir --userxattr --whiteout $workdir/mnt >  $workdir/fuse2.dump
    umount $workdir/mnt

    # fuse.cfs and fuse2.cfs files differ due to whiteout conversions and non-user xattrs.
    # However, the listed output should be the same:
    if ! cmp $workdir/fuse.dump $workdir/fuse2.dump; then
        echo Fuse and fuse2 dump differ
        diff -u $workdir/fuse.dump $workdir/fuse2.dump
        exit 1
    fi
}

if [[ -v seed ]]; then
    test_random
else
    for i in $(seq 10) ; do
        test_random
        rm -rf $workdir/*
    done
fi
