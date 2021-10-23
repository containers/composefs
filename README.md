# composefs

PoC of a native Linux file system to mount container images.

It is unfinished and just a few days of work.

The idea is to pass a binary blob to the kernel that contains all the dentries and inodes information to present a file system to userspace.

The binary blob itself doesn't contain any files payload.  Instead, each inode in the blob points to a different file on a different file system. Thus, it is somehow similar to overlayfs, which doesn't store any file on its own but relies on the underlying file system to store them.

The binary blob format is meant to be simple so that the kernel doesn't need to do any parsing to be used from an unprivileged user namespace.

The main goal of composefs is to facilitate sharing of files among different container images.

Sharing a file with the same payload across different images is not entirely possible when overlayfs is used because it either requires hard links or reflinks.
Reflinks require support from the underlying file system.  At the moment, only BTRFS and XFS support them.  A disadvantage with reflinks is that while there is deduplication happening at the storage level, the file is not deduplicated in memory.  So if there are two images using the same file that is deduplicated in the storage, it will still be loaded twice in memory.

Hard links do not have the memory deduplication issue as reflinks have, but there are a couple of limitations: all the inode metadata must be the same for all the files to be deduplicated, and they are not transparent since the `st_nlink` attribute is changed once a hard link is created, and this is visible in a container.

Another limitation with reflinks and hard links have is that the source and the destination must be on the same file system.

With such a model, there won't be any need to use layered images, since deduplication both memory and storage wise, is performed per file.

It is a first step towards a CAS storage model for containers where each file is stored just once in the storage, even if it is present in multiple images.  Together with something like [zstd:chunked](https://github.com/containers/storage/pull/775) will speed up pulling container images and make them available for usage, without the need to even create these files if already present!

## user space tools

The directory `tools/` contains some user space tools to create the binary blob to pass to the client.  They are all experimental and lack documentation.

- `writer`: takes a snapshot of the current directory and prints the binary blob to stdout.  If `--relative` is passed as an option, then the files path are relative to the current directory.
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
# mount composefs -t composefs -o descriptor=/path/to/blob,base=$BASE_DIR  /mnt
```

`descriptor` is the path to the binary blob that was generated with  the user space tools.
`base` is the directory to use as a base when resolving relative paths.
