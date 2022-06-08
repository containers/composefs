AC_PREREQ([2.69])
AC_INIT([composefs], [0.1], [giuseppe@scrivano.org])
AC_CONFIG_SRCDIR([tools/mkcomposefs.c])
AC_CONFIG_HEADERS([config.h])
AC_SYS_LARGEFILE

LT_PREREQ([2.2.6])
LT_INIT()

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

AC_ARG_WITH(yajl,
        AS_HELP_STRING([--with-yajl], [Build with yajl support [default=auto]]),
        , with_yajl=auto)
if test "x$with_yajl" != "xno"; then
  old_LIBS=$LIBS
  AC_SEARCH_LIBS(yajl_tree_get, [yajl], [have_libyajl=yes], [have_libyajl=no])
  LIBS=$old_LIBS
  if test $have_libyajl = yes; then
    AC_DEFINE(HAVE_LIBYAJL, 1, [Define if libyajl is available])
    LIBS_YAJL=$ac_cv_search_yajl_tree_get
    AC_SUBST([LIBS_YAJL])
  elif test "x$with_yajl" == "xyes"; then
    AC_MSG_ERROR([yajl was requested but it could not be found])
  fi
else
  have_libyajl=no
fi
AM_CONDITIONAL([USE_YAJL],[test "$have_libyajl" = "yes"])

AC_FUNC_ERROR_AT_LINE
AC_FUNC_FSEEKO
AC_HEADER_MAJOR
AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_FUNC_REALLOC
AC_CHECK_FUNCS([getcwd memset munmap strdup])

AC_CONFIG_FILES([Makefile libcomposefs/Makefile tools/Makefile])
AC_OUTPUT
