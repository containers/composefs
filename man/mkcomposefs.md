% mkcomposefs(1) composefs | User Commands

# NAME

mkcomposefs - create a composefs filesystem image

# SYNOPSIS
**mkcomposefs** *SOURCE* *IMAGE*

# DESCRIPTION

The composefs project uses EROFS image file to store metadata, and one
or more separate directories containing content-addressed backing data
for regular files.

**mkcomposefs** constructs the mountable "composefs image" using the
source as input. It can also create the backing store directory.
Typically the source is a directory, but with *--from-file* it can
also be a file.

# OPTIONS

The provided *SOURCEDIR* argument must be a directory and its entire
contents will be read recursively.  The provided *IMAGE* argument
will be a mountable composefs image.

**mkcomposefs** accepts the following options:


**\-\-digest-store**=*PATH*
:   This path will become a composefs "object store". Non-empty
    regular files in the *SOURCEDIR* will be copied (reflinked if
    possible) into this target directory, named after their fsverity
    digest. If possible, the added files will have fs-verity enabled.

    This directory should be passed to the basedir option when you
    mount the image.

**\-\-print-digest**
:   Print the fsverity digest of the composefs metadata file.

**\-\-print-digest-only**
:   Print the fsverity digest of the composefs metadata file, but
    don't write the image. If this is passed, the *IMAGE* argument should
    be left out.

**\-\-use-epoch**
:   Use a zero time (unix epoch) as the modification time for all files.

**\-\-skip-devices**
:   Don't add device nodes to the image.

**\-\-skip-xattrs**
:   Don't add xattrs to files in the image.

**\-\-user-xattrs**
:   Only add xattrs with the "user." prefix to files in the image.

**\-\-from-file**
:   The source is a file in the **composefs-dump(5)** format. If
    the specified file is "-", the data is read from stdin.

**\-\-version**
:   The base version to use for the image format.

**\-\-max-version**
:   If this specifies a version higher than --versions, then the
    actual image format version used will be adjusted upwards if that
    is benefitial for the image, up to the max version.

# FORMAT VERSIONING

Composefs iamges are binary reproduceable, meaning that for a given
input the result is always the same, giving the same digest of the
image. This is important as the digest is used to validate the image,
even if the image was re-created rather than transferred as
is. However, sometimes the format needs to be changed, such as for
example when a new type of file is introduced or a bug is fixed. This
is handled by introducing a format version.

Specifying the version is done with two options, the base version
(\-\-version) and the max version (\-\-max-version). When building an
image, mkcomposefs tries to keep the image format as low as possible,
but if some particular requested feature is not available with the
base feature, but is accessible in the max version then the version
used will be increased. This allows us to introduce new features and
fix bugs in a later version and migrate to that using max versions,
but still keeping the digests identical for unaffected images.

If you need 100% binary reproducibliliy over time, specify the same
version and a max version each time.

Format version history:

- 0 - Initial version
- 1 - Supports overlay whiteout files in the image (added in 1.0.3)

The default if no version arguments are specified is version 0 and max
version 1.

# SEE ALSO
**composefs-info(1)**, **mount.composefs(1)**, **composefs-dump(5)**

[composefs upstream](https://github.com/containers/composefs)
