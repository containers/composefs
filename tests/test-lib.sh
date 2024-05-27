#!/bin/bash

fatal() {
    echo $@ 1>&2; exit 1
}

# Dump ls -al + file contents to stderr, then fatal()
_fatal_print_file() {
    file="$1"
    shift
    ls -al "$file" >&2
    sed -e 's/^/# /' < "$file" >&2
    fatal "$@"
}

assert_file_has_content () {
    fpath=$1
    shift
    for re in "$@"; do
        if ! grep -q -e "$re" "$fpath"; then
            _fatal_print_file "$fpath" "File '$fpath' doesn't match regexp '$re'"
        fi
    done
}

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

check_fsverity () {
    fsverity --version >/dev/null 2>&1 || return 1
    tmpfile=$(mktemp /var/tmp/lcfs-fsverity.XXXXXX)
    echo foo > $tmpfile
    fsverity enable $tmpfile >/dev/null 2>&1  || return 1
    return 0
}

assert_streq () {
    if test "$1" != "$2"; then
        echo "assertion failed: $1 = $2" 1>&2
        return 1
    fi
}

[[ -v can_whiteout ]] || can_whiteout=$(check_whiteout)
[[ -v has_fuse ]] || has_fuse=$(if check_fuse; then echo y; else echo n; fi)
[[ -v has_fsck ]] || has_fsck=$(check_erofs_fsck)
[[ -v has_fsverity ]] || has_fsverity=$(if check_fsverity; then echo y; else echo n; fi)

echo Test options: can_whiteout=$can_whiteout has_fuse=$has_fuse has_fsck=$has_fsck has_fsverity=$has_fsverity
