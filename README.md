# composefs

Composefs is a native Linux file system designed to help sharing
filesystem contents, as well as ensuring said content is not
modified. The initial target usecase are container images and ostree
commits.

The basic idea is to have a single binary file that contains all the
metadata of the filesystem, including the filenames, the permissions,
the timestamps, etc. However, it doesn't contain the actual contents,
but rather filenames to the real files that contain the contents. This
is somewhat similar to overlayfs, which also doesn't store the file.

You pass the filename of the blob as well as the base directory for the
content files when you mount the filesystem like this:

```
# mount /path/to/blob -t composefs -o basedir=/path/to/content /mnt
```

This by itself doesn't seem very useful. You could use a single
squashfs image, or regular directory with the files instead. However,
the advantage comes if you want to store many such images. By storing
the files content-addressed (e.g. using the hash of the content to name
the file) shared files need only be stored once, yet can appear in
multiple mounts. Since these are normal files they will also only be
stored once in the page cache, meaning that the duplication is avoided
both on disk and in ram.

Composefs also supports
[fs-verity](https://www.kernel.org/doc/html/latest/filesystems/fsverity.html)
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

When pulling a container image to the local storage we normally just
untar each layer by itself. Instead we can store the file content
in an content-addressed fashion, and then generate a composefs file
for the layer (or perhaps the combined layers).

This allows sharing of content files between images, even if the
metadata (like the timestamps or file ownership) vary between images.

Together with something like
[zstd:chunked](https://github.com/containers/storage/pull/775) this
will speed up pulling container images and make them available for
usage, without the need to even create these files if already present!

## Usecase: OSTree

OSTree already uses a content-address object store. However, normally
this has to be checked out into a regular directory (using hardlinks
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
composefs generation is reproducable, we can even verify that the
composefs image we generated is correct by comparing its digest to one
in the ostree metadata that was generated when the ostree image was built.

## user space tools

The directory `tools/` contains some user space tools to create the binary blob to pass to the client.  They are all experimental and lack documentation.

- `mkcomposefs`: Creates a composefs image given a directory pathname. Can also compute digests and create a content store directory.
- `writer-json`: convert from a [CRFS](https://github.com/google/crfs) metadata file to the binary blob.
- `dump`: prints the content of the binary blob.
- `ostree-convert-commit.py`: converts an OSTree commit into a CRFS config file that writer-json can use.

## kernel module

How to build:
```
# make -C $KERNEL_SOURCE modules M=$PWD &&  make -C $KERNEL_SOURCE modules_install M=$PWD
# insmod /lib/modules/$(uname -r)/extra/composefs.ko
```

Once it is loaded, it can be used as:

```
# mount /path/to/blob -t composefs -o basedir=$BASE_DIR  /mnt
```

Mount options:

- `basedir`: is the directory to use as a base when resolving relative content paths.
- `noverity`: Don't verify that target files have the right fs-verity digest. Useful if the fs doesn't support fs-verity but the image has digests enabled.
- `digest`: A fs-verity sha256 digest that the image file must match.

## SELinux issues

Composefs support xattrs natively, and selinux normally uses xattrs to
store selinux file contexts. However, this only works if the local
policy allows a particular filesystem type to use xattrs for selinux,
and the default is to not allow it. So, until the default selinux
contexts supports composefs, you need to manually install a local
policy for this.

To enable composefs selinux support, run:

```
# semodule -i composefs.cil
```

And, to later revert it, run:

```
# semodule -r composefs
```
