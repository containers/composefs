#!/usr/bin/python3
# lcfs
# Copyright (C) 2021 Giuseppe Scrivano <giuseppe@scrivano.org>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import json
import sys
import stat
import gi
import base64

gi.require_version('OSTree', '1.0')
from gi.repository import Gio, GLib, OSTree

fast_query_info = "standard::name,standard::type,standard::size,standard::is-symlink,standard::symlink-target,unix::device,unix::inode,unix::mode,unix::uid,unix::gid,unix::rdev"

def get_type(t):
    types = {
        Gio.FileType.DIRECTORY: "dir",
        Gio.FileType.REGULAR: "reg",
        Gio.FileType.SYMBOLIC_LINK: "symlink",
    }
    return types[t]

def get_path(parent, name):
    if parent == "":
        return name
    return "%s/%s" % (parent, name)

def get_payload(csum):
    return "%s/%s.file" % (csum[:2], csum[2:])

def recurse_dir(repo, parent, d):
    ret = []
    children = d.enumerate_children(fast_query_info, 0, None)
    while True:
        it = children.iterate()
        if it[1] == None:
            break

        i = it[1]
        f = it[2]

        xattrs = {
        }
        for k, v in f.get_xattrs()[1]:
            if bytearray(k) != bytearray(b'security.selinux\x00'):
                xattrs[bytearray(k[:-1]).decode('ascii')] = base64.b64encode(bytearray(v)).decode('ascii')
        
        entry = {
            "type": get_type(i.get_file_type()),
            "name": get_path(parent, i.get_name()),
            "mode": i.get_attribute_uint32("unix::mode"),
            "uid": i.get_attribute_uint32("unix::uid"),
            "gid": i.get_attribute_uint32("unix::gid"),
            "size": i.get_attribute_uint64("standard::size"),
        }
        if i.get_file_type() == Gio.FileType.REGULAR:
            csum = f.get_checksum()
            entry["x-payload"] = get_payload(csum)
        elif i.get_file_type() == Gio.FileType.SYMBOLIC_LINK:
            entry["linkName"] = i.get_attribute_byte_string("standard::symlink-target")

        if len(xattrs) > 0:
            entry["xattrs"] = xattrs

        ret.append(entry)

        if i.get_file_type() == Gio.FileType.DIRECTORY:
            name = i.get_name()
            child = Gio.File.get_child(d, name)
            entries = recurse_dir(repo, get_path(parent, name), child)
            ret = ret + entries
    return ret

def read_commit(repo, rev):
    commit = repo.read_commit(rev)[1]

    return recurse_dir(repo, "", commit)

if __name__ == "__main__":
    repo = OSTree.Repo.new(Gio.File.new_for_path(sys.argv[1]))
    repo.open(None)

    entries = read_commit(repo, sys.argv[2])

    j = {
        "version": 1,
        "entries": entries,
    }

    json.dump(j, sys.stdout, indent=4)
