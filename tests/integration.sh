#!/bin/bash
# A basic integration test for composefs; we capture /usr/bin
# from the host environment into a cfs, then mount it and compare
# the output of ls -lR (without hardlink counts).
set -xeuo pipefail

orig=$(pwd)
cfsroot=${cfsroot:-/composefs}
rm ${cfsroot}/tmp -rf
mkdir -p ${cfsroot}/{objects,roots,tmp}

cd ${cfsroot}/tmp

run_test() {
    local testsrc=$1
    local dumpdir_args="$2"
    mkcomposefs --print-digest --digest-store=${cfsroot}/objects ${testsrc} ${cfsroot}/roots/test.cfs | tee digest.txt
    prev_digest=$(cat digest.txt)
    new_digest=$(mkcomposefs --print-digest-only ${testsrc})
    test "$prev_digest" = "$new_digest"

    if which fsck.erofs &>/dev/null; then
        fsck.erofs ${cfsroot}/roots/test.cfs
    fi

    mkdir -p mnt
    mount.composefs -o basedir=${cfsroot}/objects ${cfsroot}/roots/test.cfs mnt
    $orig/tests/dumpdir $dumpdir_args ${testsrc} > src-dump.txt
    $orig/tests/dumpdir $dumpdir_args mnt > mnt-dump.txt
    failed=
    if ! diff -u src-dump.txt mnt-dump.txt; then
        failed=1
    fi
    if test -n "${failed}"; then
        umount mnt
        exit 1
    fi

    new_digest=$(mkcomposefs --print-digest-only mnt)
    test "$prev_digest" = "$new_digest"

    umount mnt
}

run_test /usr/bin "--no-nlink"

# Don't create whiteouts, as they depend on a very recent kernel to work at all
$orig/tests/gendir --privileged --nowhiteout ${cfsroot}/tmp/rootfs
# nlink doesn't work for the toplevel dir in composefs, because that is from overlayfs, not erofs
run_test ${cfsroot}/tmp/rootfs "--no-root-nlink"
