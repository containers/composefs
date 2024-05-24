# composefs-oci

The high level goal of this crate is to be an opinionated
generic storage layer using composefs, with direct support
for OCI.  Note not just OCI *containers* but also including
OCI artifacts too.
    
This crate is intended to be the successor to
the "storage core" of both ostree and containers/storage.

## Design

The composefs core just offers the primitive of creating
"superblocks" which can have regular file data point
to underlying "loose" objects stored in an arbitrary place.

cfs-oci (for short) roughly matches the goal of both
ostree and containers/storage in supporting multiple
versioned filesystem trees with associated metadata,
including support for e.g. garbage collection.

### Layout

By default, a cfs-ocidir augments an [OCI image layout](https://github.com/opencontainers/image-spec/blob/main/image-layout.md).

However, media types of `application/vnd.oci.image.layer.v1.tar` may optionally be stored
in a way that they can be natively mounted via composefs. This storage can be
*additional* (which means storage cost is effectively the compressed size, plus uncompressed size)
or an image can be "consumed" which means the compressed version is discarded.
The tradeoff with this is that it is in general *not* possible to bit-for-bit
reproduce the compressed blob again.

#### Composefs ready layout

cfs-ocidir augments the OCI image layout with a new `cfs/` directory.

##### "split-checksum" format

Side note: This follows a longstanding tradition of splitting up a checksum into (first two bytes, remaining bytes)
creating subdirectories for the first two bytes. It is used by composefs by default.

A cfs-ocidir has the following subdirectories:

##### layers/

This has "split-checksum" entries of the form `<diffid>.cfs` which are a composefs corresponding to the given diffid (tar layer).
Each file MAY have xattrs of the form `user.cfs.compressed` which include the original compressed digest.

##### objects/

A composefs objects directory containing regular files, all of mode 0 (when run as root) or 0400 (when run as an unprivileged user)

##### manifests

This plays a role similar to the `manifests` array in https://github.com/opencontainers/image-spec/blob/main/image-index.md 

This is also an object directory using the `sha256:` of the manifest digest.

Each entry is a manifest (JSON). It is also recommended to make this a hardlink into the objects/ directory to enable sharing across cfs-oci directories.

It is possible that the manifest has an native annotation `composefs.rootfs.digest` which is the composefs digest of the flattened/merged root. This is called a "composefs-enabled" manifest, which allows a signature that covers the manifest
to also cover the composefs digest and allow efficient verification of the root filesystem for the image.

If the manifest does not have that annotation, then the composefs digest is stored as an extended attribute `user.composefs.rootfs.digest`.

That composefs digest can be used to look up the actual composefs superblock for the rootfs in the objects/ directory.

## CLI sketch: OCI container images

`cfs-oci --repo=/path/to/repo image list|pull|rm|mount`

## CLI sketch: OCI artifacts

`cfs-oci --repo=/path/to/repo artifact list|pull|rm`

## CLI sketch: Other

### Efficiently clone a repo

`cfs-oci clone /path/to/repo /path/to/clone`
This would use reflinks (if available) or hardlinks if not
for all the loose objects, but allow fully distinct namespacing/ownership
of images.

For example, it would probably make sense to have
bootc and podman use separate physical stores in
`/ostree` and `/var/lib/containers` - but if they're
on the same filesystem, we can efficiently and safely share
backing objects!

### Injecting "flattened" composefs digests

Another verb that should be supported here is:
`cfs-oci --repo=/path/to/repo image finalize <imagename>`

This would compute the *flattened* final filesystem tree
for the container image, and inject its metadata into
the manifest as an annotation e.g. `containers.composefs.digest`.

Then, a signature which covers the manifest such as Sigstore
can also cover verification of the filesystem tree. Of course,
one could use any signature scheme desired to sign images.
