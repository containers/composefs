.. SPDX-License-Identifier: GPL-2.0

====================
Composefs Filesystem
====================

Introduction
============

Composefs is a read-only file system that is backed by regular files
(rather than a block device). It is designed to help easily share
content between different directory trees, such as container images in
a local store or ostree checkouts. In addition it also has support for
integrity validation of file content and directory metadata, in an
efficient way (using fs-verity).

The filesystem mount source is a binary blob called the descriptor. It
contains all the inode and directory entry data for the entire
filesystem. However, instead of storing the file content each regular
file inode stores a relative path name, and the filesystem gets the
file content from the filesystem by looking up that filename in a set
of base directories.

Given such a descriptor called "image.cfs" and a directory with files
called "/dir" you can mount it like:

  mount -t composefs image.cfs -o basedir=/dir /mnt

Content sharing
===============

Suppose you have a single basedir where the files are content
addressed (i.e. named by content digest), and a set of composefs
descriptors using this basedir. Any file that happen to be shared
between two images (same content, so same digest) will now only be
stored once on the disk.

Such sharing is possible even if the metadata for the file in the
image differs (common reasons for metadata difference are mtime,
permissions, xattrs, etc). The sharing is also anonymous in the sense
that you can't tell the difference on the mounted files from a
non-shared file (for example by looking at the link count for a
hardlinked file).

In addition, any shared files that are actively in use will share
page-cache, because the page cache for the file contents will be
addressed by the backing file in the basedir, This means (for example)
that shared libraries between images will only be mmap:ed once across
all mounts.

Integrity validation
====================

Composefs uses `fs-verity
<https://www.kernel.org/doc/Documentation/filesystems/fsverity.rst>`
for integrity validation, and extends it by making the validation also
apply to the directory metadata.  This happens on two levels,
validation of the descriptor and validation of the backing files.

For descriptor validation, the idea is that you enable fs-verity on
the descriptor file which seals it from changes that would affect the
directory metadata. Additionally you can pass a `digest` mount option,
which composefs verifies against the descriptor fs-verity
measure. Such a mount option could be encoded in a trusted source
(like a signed kernel command line) and be used as a root of trust if
using composefs for the root filesystem.

For file validation, the descriptor can contain digest for each
backing file, and you can enable fs-verity on the backing
files. Composefs will validate the digest before using the backing
files. This means any (accidental or malicious) modification of the
basedir will be detected at the time the file is used.

Expected use-cases
=================

Container Image Storage
```````````````````````

Typically a container image is stored as a set of "layer"
directories. merged into one mount by using overlayfs.  The lower
layers are read-only image content and the upper layer is the
writable state of a running container. Multiple uses of the same
layer can be shared this way, but it is hard to share individual
files between unrelated layers.

Using composefs, we can instead use a shared, content-addressed
store for all the images in the system, and use a composefs image
for the read-only image content of each image, pointing into the
shared store. Then for a running container we use an overlayfs
with the lower dir being the composefs and the upper dir being
the writable state.


Ostree root filesystem validation
`````````````````````````````````

Ostree uses a content-addressed on-disk store for file content,
allowing efficient updates and sharing of content. However to actually
use these as a root filesystem it needs to create a real
"chroot-style" directory, containing hard links into the store. The
store itself is validated when created, but once the hard-link
directory is created, nothing validates the directory structure of
that.

Instead of a chroot we can we can use composefs. We create a composefs
image pointing into the object store, enable fs-verity for everything
and encode the fs-verity digest of the descriptor in the
kernel-command line. This will allow booting a trusted system where
all directory metadata and file content is validated lazily at use.


Mount options
=============

`basedir`: A colon separated list of directories to use as a base when resolving relative content paths.
`verity_check=[0,1,2]`: When to verify backing file fs-verity: 0 == never, 1 == if specified in image, 2 == always and require it in image.
`digest`: A fs-verity sha256 digest that the descriptor file must match. If set, `verity_check` defaults to 2.


Filesystem format
=================

The format of the descriptor is contains three sections: header,
inodes and variable data. All data in the file is stored in
little-endian form.

The header starts at the beginning of the file and contains version,
magic value, offsets to the variable data and the root inode nr.

The inode section starts at a fixed location right after the
header. It is a array of inode data, where for each inode there is
first a variable length chunk and then a fixed size chunk. An inode nr
is the offset in the inode data to the start of the fixed chunk.

The fixed inode chunk starts with a flag that tells what parts of the
inode are stored in the file (meaning it is only the maximal size that
is fixed). After that the various inode attributes are serialized in
order, such as mode, ownership, xattrs, and payload length. The
payload length attribute gives the size of the variable chunk.

The inode variable chunk contains different things depending on the
file type.  For regular files it is the backing filename. For symlinks
it is the symlink target. For directories it is a list of references to
dentries, stored in chunks of maximum 4k. The dentry chunks themselves
are stored in the variable data section.

The variable data section is stored after the inode section, and you
can find it from the offset in the header. It contains dentries and
Xattrs data. The xattrs are referred to by offset and size in the
xattr attribute in the inode data. Each xattr data can be used by many
inodes in the filesystem. The variable data chunks are all smaller than
a page (4K) and are padded to not span pages.

Tools
=====

Tools for composefs can be found at https://github.com/containers/composefs

There is a mkcomposefs tool which can be used to create images on the
CLI, and a library that applications can use to create composefs
images.
