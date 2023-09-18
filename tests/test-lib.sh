#!/usr/bin/bash

check_whiteout () {
    tmpfile=$(mktemp /tmp/lcfs-whiteout.XXXXXX)
    rm -f $tmpfile
    if mknod $tmpfile c 0 0 &> /dev/null; then
        echo y
    else
        echo n
    fi
    rm -f $tmpfile
}

check_fuse () {
    fusermount --version >/dev/null 2>&1 || return 1

    capsh --print | grep -q 'Bounding set.*[^a-z]cap_sys_admin' || \
        return 1

    [ -w /dev/fuse ] || return 1
    [ -e /etc/mtab ] || return 1

    return 0
}

check_erofs_fsck () {
    if which fsck.erofs &>/dev/null; then
        echo y
    else
        echo n
    fi
}

[[ -v can_whiteout ]] || can_whiteout=$(check_whiteout)
[[ -v has_fuse ]] || has_fuse=$(if check_fuse; then echo y; else echo n; fi)
[[ -v has_fsck ]] || has_fsck=$(check_erofs_fsck)

echo Test options: can_whiteout=$can_whiteout has_fuse=$has_fuse has_fsck=$has_fsck
