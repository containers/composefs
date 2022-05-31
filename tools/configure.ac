AC_PREREQ([2.69])
AC_INIT([composefs], [0.1], [giuseppe@scrivano.org])
AC_CONFIG_SRCDIR([dump.c])
AC_CONFIG_HEADERS([config.h])
AC_SYS_LARGEFILE

AM_INIT_AUTOMAKE([1.11.2 -Wno-portability foreign tar-ustar no-dist-gzip dist-xz subdir-objects])

AC_PROG_CC

PKG_CHECK_MODULES(FSVERITY, libfsverity)

AC_DEFUN([CC_CHECK_FLAG_APPEND], [
  AC_CACHE_CHECK([if $CC supports flag $3 in envvar $2],
                 AS_TR_SH([cc_cv_$2_$3]),
          [eval "AS_TR_SH([cc_save_$2])='${$2}'"
           eval "AS_TR_SH([$2])='${cc_save_$2} -Werror `echo "$3" | sed 's/^-Wno-/-W/'`'"
           AC_LINK_IFELSE([AC_LANG_SOURCE(ifelse([$4], [],
                                                 [int main(void) { return 0; } ],
                                                 [$4]))],
                          [eval "AS_TR_SH([cc_cv_$2_$3])='yes'"],
                          [eval "AS_TR_SH([cc_cv_$2_$3])='no'"])
           eval "AS_TR_SH([$2])='$cc_save_$2'"])

  AS_IF([eval test x$]AS_TR_SH([cc_cv_$2_$3])[ = xyes],
        [eval "$1='${$1} $3'"])
])

AC_DEFUN([CC_CHECK_FLAGS_APPEND], [
  for flag in [$3]; do
    CC_CHECK_FLAG_APPEND([$1], [$2], $flag, [$4])
  done
])


AS_IF([echo "$CFLAGS" | grep -q -E -e '-Werror($| )'], [], [
CC_CHECK_FLAGS_APPEND([WARN_CFLAGS], [CFLAGS], [\
  -pipe \
  -Wall \
  -Werror=shadow \
  -Werror=empty-body \
  -Werror=strict-prototypes \
  -Werror=missing-prototypes \
  -Werror=implicit-function-declaration \
  "-Werror=format=2 -Werror=format-security -Werror=format-nonliteral" \
  -Werror=pointer-arith -Werror=init-self \
  -Werror=missing-declarations \
  -Werror=return-type \
  -Werror=switch \
  -Werror=overflow \
  -Werror=int-conversion \
  -Werror=parentheses \
  -Werror=undef \
  -Werror=incompatible-pointer-types \
  -Werror=misleading-indentation \
  -Werror=missing-include-dirs  \
  -Wstrict-aliasing=2 \
  -Werror=unused-result \
])])
AC_SUBST(WARN_CFLAGS)


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
