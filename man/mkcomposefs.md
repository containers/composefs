% mkcomposefs(1) composefs | User Commands

# NAME

mkcomposefs - create a composefs filesystem image

# SYNOPSIS
**mkcomposefs** *SOURCEDIR* *IMAGE*

# DESCRIPTION

The composefs project uses EROFS to store metadata, and a distinct
underlying backing store for regular files.

**mkcomposefs** constructs the mountable "composefs image" using the
source directory as input.

# OPTIONS

The provided *SOURCEDIR* argument must be a directory and its entire
contents will be read recursively.  The provided *IMAGE* argument
will be a mountable composefs image.

**mkcomposefs** accepts the following options:

**\-\-digest-store**=*PATH*
:   This path will become a composefs "object store".  Non-empty regular files
    in the *SOURCEDIR* will be copied (reflinked if possible) into this target
    directory, named after their fsverity digest.

**\-\-print-digest**
:   Print the fsverity digest of the composefs metadata file.

# SEE ALSO

- [composefs upstream](https://github.com/containers/composefs)
