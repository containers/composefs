#!/bin/bash
# A basic integration test for composefs; we capture /usr/bin
# from the host environment into a cfs, then mount it and compare
# the output of ls -lR (without hardlink counts).
set -xeuo pipefail

# ls -l but without hardlinks
nonhardlink_ls() {
    ls "$@" | sed -e 's,^\([^ ]*\)  *\([0-9][0-9]*\)\(.*\)$,\1\3,'
}

cfsroot=/composefs
rm ${cfsroot}/tmp -rf
mkdir -p ${cfsroot}/{objects,roots,tmp}

cd ${cfsroot}/tmp
testsrc=/usr/bin
mkcomposefs --digest-store=${cfsroot}/objects ${testsrc} ${cfsroot}/roots/test.cfs

mkdir -p mnt
mount.composefs -o basedir=${cfsroot}/objects ${cfsroot}/roots/test.cfs mnt
(cd ${testsrc} && nonhardlink_ls -lR .) > src-ls.txt
(cd mnt && nonhardlink_ls -lR .) > mnt-ls.txt
failed=
if ! diff -u src-ls.txt mnt-ls.txt; then
    failed=1
fi
umount mnt
if test -n "${failed}"; then
    exit 1
fi
