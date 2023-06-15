# composefs

The composefs project combines several underlying Linux features
to provide a very flexible mechanism to support read-only
mountable filesystem trees, stacking on top of an underlying
"lower" Linux filesystem.

The key technologies composefs uses are:

- [overlayfs](https://www.kernel.org/doc/Documentation/filesystems/overlayfs.txt) as the kernel interface
- [EROFS](https://www.kernel.org/doc/Documentation/filesystems/erofs.txt) for a mountable metadata tree
- [fs-verity](https://www.kernel.org/doc/html/next/filesystems/fsverity.html) (optional) from the lower filesystem

The manner in which these technologies are combined is important.
First, to emphasize: composefs does not store any persistent data itself.
The underlying metadata and data files must be stored in a valid
"lower" Linux filesystem.  Usually on most systems, this will be a
traditional writable persistent Linux filesystem such as `ext4`, `xfs,`, `btrfs` etc.

# Separation between metadata and data

A key aspect of the way composefs works is that it's designed to
store "data" (i.e. non-empty regular files) distinct from "metadata"
(i.e. everything else).

composefs reads and writes a filesystem image which is really
just an [EROFS](https://www.kernel.org/doc/Documentation/filesystems/erofs.txt)
which today is loopback mounted.

However, this EROFS filesystem tree is just metadata; the underlying
non-empty data files can be shared in a distinct "backing store"
directory.  The EROFS filesystem includes `trusted.overlay.redirect`
extended attributes which tell the `overlayfs` mount
how to find the real underlying files.

# Mounting multiple composefs with a shared backing store

The key targeted use case for composefs is versioned, immutable executable
filesystem trees (i.e. container images and bootable host systems), where
some of these filesystems may share *parts* of their storage (i.e. some
files may be different, but not all).

Composefs ships with a mount helper that allows you to easily mount
images by pass the image filename and the base directory for
the content files like this:

```
# mount -t composefs /path/to/image  -o basedir=/path/to/content /mnt
```

By storing the files content-addressed (e.g. using the hash of the content to name
the file) shared files need only be stored once, yet can appear in
multiple mounts. 

# Backing store shared on disk *and* in page cache

A crucial advantage of composefs in contrast to other approaches
is that data files are shared in the [page cache](https://static.lwn.net/kerneldoc/admin-guide/mm/concepts.html#page-cache).

This allows launching multiple container images that will
reliably share memory.

# Filesystem integrity

Composefs also supports [fs-verity](https://www.kernel.org/doc/html/latest/filesystems/fsverity.html)
validation of the content files.  When using this, the digest of the
content files is stored in the image, and composefs will validate that
the content file it uses has a matching enabled fs-verity digest. This
means that the backing content cannot be changed in any way (by
mistake or by malice) without this being detected when the file is
used.

You can also use fs-verity on the image file itself, and pass the
expected fs-verity digest as a mount option, which composefs will
validate. In this case we have full trust of both data and metadata of
the mounted file. This solves a weakness that fs-verity has when used
on on its own, in that it can only verify file data, not
metadata.

## Usecase: container images

There are multiple container image systems; for those using e.g.
[OCI](https://github.com/opencontainers/image-spec/blob/main/spec.md)
a common approach (implemented by both docker and podman for example)
is to just untar each layer by itself, and then use `overlayfs`
to stitch them together at runtime.  This is a partial inspiration
for composefs; notably this approach does ensure that *identical
layers* are shared.

However if instead we store the file content in a content-addressed
fashion, and then we can generate a composefs file for each layer,
continuing to mount them with a chain of `overlayfs` *or* we
can generate a single composefs for the final merged filesystem tree.

This allows sharing of content files between images, even if the
metadata (like the timestamps or file ownership) vary between images.

Together with something like
[zstd:chunked](https://github.com/containers/storage/pull/775) this
will speed up pulling container images and make them available for
usage, without the need to even create these files if already present!

## Usecase: Bootable host systems (e.g. OSTree)

[OSTree](https://github.com/ostreedev/ostree) already uses a content-addressed
object store. However, normally this has to be checked out into a regular directory (using hardlinks
into the object store for regular files). This directory is then
bind-mounted as the rootfs when the system boots.

OSTree already supports enabling fs-verity on the files in the store,
but nothing can protect against changes to the checkout directories. A
malicious user can add, remove or replace files there. We want to use
composefs to avoid this.

Instead of checking out to a directory we generate a composefs image
pointing into the object store and mount that as the root fs. We can
then enable fs-verity of the composefs image and embed the digest of
that in the kernel commandline which specifies the rootfs. Since
composefs generation is reproducible, we can even verify that the
composefs image we generated is correct by comparing its digest to one
in the ostree metadata that was generated when the ostree image was built.

For more information on ostree and composefs, see [this tracking issue](https://github.com/ostreedev/ostree/issues/2867).

## tools

Composefs installs two main tools:

- `mkcomposefs`: Creates a composefs image given a directory pathname. Can also compute digests and create a content store directory.
- `mount.composefs`: A mount helper that supports mounting composefs images.

## mounting a composefs image

The mount.composefs helper allows you to mount composefs images (of both types).

The basic use is:

```
# mount -t composefs /path/to/image.cfs -o basedir=/path/to/datafiles  /mnt
```

The default behaviour for fs-verity is that any image files that
specifies an expected digest needs the backing file to match that
fs-verity digest, at least if this is supported in the kernel. This
can be modified with the `verity` and `noverity` options.

Mount options:

- `basedir`: is the directory to use as a base when resolving relative content paths.
- `verity`: All image files must specify a fs-verity image.
- `noverity`: Don't verfy fs-verity digests (useful for example if fs-verity is not supported on basedir).
- `digest`: A fs-verity sha256 digest that the image file must match. If set, `verity_check` defaults to 2.
- `signed`: The image file must contain an fs-verity signature.
- `upperdir`: Sepcify an upperdir for the overlayfs filesystem.
- `workdir`: Sepcify an upperdir for the overlayfs filesystem.
- `idmap`: Specify a path to a user namespace that is useda as an idmap.

## Experimental user space tools

The directory `tools/` contains some experimental user space tools to work with composefs images.

- `composefs-from-json`: convert from a [CRFS](https://github.com/google/crfs) metadata file to the binary blob.
- `ostree-convert-commit.py`: converts an OSTree commit into a CRFS config file that writer-json can use.
