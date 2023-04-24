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
in a content-addressed fashion, and then generate a composefs file
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
composefs generation is reproducible, we can even verify that the
composefs image we generated is correct by comparing its digest to one
in the ostree metadata that was generated when the ostree image was built.

## Multiple Implementations

Composefs currently has two implementations. One is a (currently out
of tree) kernel module which directly implements the composefs
features as an in-kernel filesystem. The second one is based on a
combination of erofs, loopback mounts and overlayfs. The later
implementations works in a basic mode with the current kernel, but
the fs-verity support needs some (currently out of tree) overlayfs
patches.

The discussion about upstreaming composefs is currently ongoing, but
currently seems to lean towards the erofs+overlayfs implementation.

## tools

Composefs installs two main tools:

- `mkcomposefs`: Creates a composefs image given a directory pathname. Can also compute digests and create a content store directory.
- `mount.composefs`: A mount helper that supports mounting composefs images.

## mounting a composefs image

The mount.composefs helper allows you to mount composefs images (of both types).

The basic use is:

```
# mount /path/to/image.cfs -t composefs -o basedir=/path/to/datafiles  /mnt
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

- `writer-json`: convert from a [CRFS](https://github.com/google/crfs) metadata file to the binary blob.
- `dump`: prints the content of the binary blob.
- `ostree-convert-commit.py`: converts an OSTree commit into a CRFS config file that writer-json can use.

## composefs kernel module

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
- `verity_check=0,1,2`: When to verify backing file fs-verity: 0 == never, 1 == if specified in image, 2 == always and require it in image.
- `digest`: A fs-verity sha256 digest that the image file must match. If set, `verity_check` defaults to 2.

## SELinux issues with the kernel module

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
