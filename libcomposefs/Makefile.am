lib_LTLIBRARIES = libcomposefs.la

libcomposefsincludedir = $(includedir)/libcomposefs
libcomposefsinclude_HEADERS = lcfs-writer.h lcfs-erofs.h lcfs-mount.h

# We split the library out so it can be used easily as a git submodule
COMPOSEFSDIR = .
include Makefile-lib.am
