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

**\-\-no-sandbox**
:   Normally, when using **--from-file** a sandbox is set up to protect
    the parsing code. This option disables this.


# SEE ALSO
**composefs-info(1)**, **mount.composefs(1)**, **composefs-dump(5)**

[composefs upstream](https://github.com/containers/composefs)
