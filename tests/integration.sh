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
testsrc=/usr/bin
mkcomposefs --print-digest --digest-store=${cfsroot}/objects ${testsrc} ${cfsroot}/roots/test.cfs | tee digest.txt
prev_digest=$(cat digest.txt)
new_digest=$(mkcomposefs --by-digest --print-digest-only ${testsrc})
test "$prev_digest" = "$new_digest"

if which fsck.erofs &>/dev/null; then
    fsck.erofs ${cfsroot}/roots/test.cfs
fi

mkdir -p mnt
mount.composefs -o basedir=${cfsroot}/objects ${cfsroot}/roots/test.cfs mnt
$orig/tests/dumpdir --no-nlink ${testsrc} > src-dump.txt
$orig/tests/dumpdir --no-nlink mnt > mnt-dump.txt
failed=
if ! diff -u src-dump.txt mnt-dump.txt; then
    failed=1
fi
if test -n "${failed}"; then
    umount mnt
    exit 1
fi

new_digest=$(mkcomposefs --by-digest --print-digest-only mnt)
test "$prev_digest" = "$new_digest"

umount mnt
