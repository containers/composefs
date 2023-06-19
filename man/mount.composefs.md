% mount.composefs(1) composefs | User Commands

# NAME

mount.composefs - mount a composefs filesystem image

# SYNOPSIS
**mount.composefs** *IMAGE* *TARGETDIR*

# DESCRIPTION

The composefs project uses EROFS to store metadata, and a distinct
underlying backing store for regular files.  At runtime, composefs
uses `overlayfs` on top of a loopback mount.

**mount.composefs** 

# OPTIONS

The provided *IMAGE* argument must be a valid composefs (EROFS)
metadata image.  The *TARGETDIR* will be used as a mount target.

**mount.composefs** accepts the following options:

**\-\-basedir**=*PATH*
:   This path will be used to resolve non-empty file references
    stored in the composefs metadata image.  A primary use case is to have
    this be the same path provided to `mkcomposefs --digest-store`.

# SEE ALSO

- [composefs upstream](https://github.com/containers/composefs)
