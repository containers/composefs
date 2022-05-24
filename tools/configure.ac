AC_PREREQ([2.69])
AC_INIT([composefs], [0.1], [giuseppe@scrivano.org])
AC_CONFIG_SRCDIR([dump.c])
AC_CONFIG_HEADERS([config.h])
AC_SYS_LARGEFILE

AM_INIT_AUTOMAKE([1.11.2 -Wno-portability foreign tar-ustar no-dist-gzip dist-xz subdir-objects])

AC_PROG_CC

old_LIBS=$LIBS
AC_SEARCH_LIBS(yajl_tree_get, [yajl], [AC_DEFINE([HAVE_YAJL], 1, [Define if libyajl is available])], [AC_MSG_ERROR([*** libyajl headers not found])])
LIBS=$old_LIBS

LIBS_YAJL=$ac_cv_search_yajl_tree_get
AC_SUBST([LIBS_YAJL])


AC_FUNC_ERROR_AT_LINE
AC_FUNC_FSEEKO
AC_HEADER_MAJOR
AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_FUNC_REALLOC
AC_CHECK_FUNCS([getcwd memset munmap strdup])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
