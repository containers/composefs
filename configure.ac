AC_PREREQ([2.69])
AC_INIT([composefs], [1.0.5], [giuseppe@scrivano.org])
AC_CONFIG_SRCDIR([tools/mkcomposefs.c])
AC_CONFIG_HEADERS([config.h])
AC_SYS_LARGEFILE

# Library soname versioning:
#
# Note that this is different from the package version, as the package
# version is more of a human-oriented version for the tools, and does
# not encode library compatibility.
#
# Making releases:
#  If library added functions or features:
#   LIBCOMPOSEFS_VERSION_MICRO = 0;
#   LIBCOMPOSEFS_VERSION_MINOR += 1;
# else, if library code changes:
#   LIBCOMPOSEFS_VERSION_MICRO += 1;
#
# Only touch LIBCOMPOSEFS_VERSION_MAJOR if breaking ABI.
# (And never do that lightly)

m4_define([LIBCOMPOSEFS_VERSION_MAJOR], [1])
m4_define([LIBCOMPOSEFS_VERSION_MINOR], [3])
m4_define([LIBCOMPOSEFS_VERSION_MICRO], [0])

LT_PREREQ([2.2.6])
LT_INIT()

AM_INIT_AUTOMAKE([1.11.2 -Wno-portability foreign tar-ustar no-dist-gzip dist-xz subdir-objects])

m4_define([lt_current], [m4_eval(LIBCOMPOSEFS_VERSION_MINOR + LIBCOMPOSEFS_VERSION_MAJOR)])
m4_define([lt_revision], [LIBCOMPOSEFS_VERSION_MICRO])
m4_define([lt_age], [LIBCOMPOSEFS_VERSION_MINOR])
LT_VERSION_INFO="lt_current:lt_revision:lt_age"
AC_SUBST(LT_VERSION_INFO)

LIBCOMPOSEFS_RELEASE_ARGS="-version-info $LT_VERSION_INFO"
AC_SUBST([LIBCOMPOSEFS_RELEASE_ARGS])

AC_PROG_CC
PKG_PROG_PKG_CONFIG
m4_ifdef([PKG_INSTALLDIR], [PKG_INSTALLDIR], AC_SUBST([pkgconfigdir], ${libdir}/pkgconfig))

PKGCONFIG_REQUIRES=
PKGCONFIG_REQUIRES_PRIVATELY=

AC_MSG_CHECKING([for MOUNT_ATTR_IDMAP])
AC_COMPILE_IFELSE(
	[AC_LANG_PROGRAM([
			#include <sys/mount.h>
			#include <linux/mount.h>
	],[int foo = MOUNT_ATTR_IDMAP;]
	)],
	[AC_MSG_RESULT(yes)
		AC_DEFINE([HAVE_MOUNT_ATTR_IDMAP], 1, [Define if MOUNT_ATTR_IDMAP is available in linux/mount.h])],
	[AC_MSG_RESULT(no)])

AC_MSG_CHECKING([for new mount API (fsconfig)])
AC_COMPILE_IFELSE(
	[AC_LANG_SOURCE([[
			#include <sys/mount.h>
			int cmd = FSCONFIG_CMD_CREATE;
	]])],
	[AC_MSG_RESULT(yes)
		 AC_DEFINE([HAVE_FSCONFIG_CMD_CREATE_SYS_MOUNT_H], 1, [Define if FSCONFIG_CMD_CREATE is available in sys/mount.h])],
	[AC_MSG_RESULT(no)])
AC_COMPILE_IFELSE(
	[AC_LANG_SOURCE([[
			/* also make sure it doesn't conflict with <sys/mount.h> since it is always used.  */
			#include <sys/mount.h>
			#include <linux/mount.h>
			int cmd = FSCONFIG_CMD_CREATE;
	]])],
	[AC_MSG_RESULT(yes)
		 AC_DEFINE([HAVE_FSCONFIG_CMD_CREATE_LINUX_MOUNT_H], 1, [Define if FSCONFIG_CMD_CREATE is available in linux/mount.h])],
	[AC_MSG_RESULT(no)])

PKG_CHECK_MODULES(LCFS_DEP_CRYPTO, libcrypto,[
      AC_DEFINE([HAVE_OPENSSL], 1, [Define if we have openssl])
      with_openssl=yes
      PKGCONFIG_REQUIRES_PRIVATELY="$PKGCONFIG_REQUIRES_PRIVATELY libcrypto"
],[
      with_openssl=no
])
AM_CONDITIONAL(USE_OPENSSL, test $with_openssl != no)

AC_CHECK_HEADERS([sys/capability.h endian.h sys/endian.h machine/endian.h])

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

AC_ARG_ENABLE(man,
              [AS_HELP_STRING([--enable-man],
                              [generate man pages [default=auto]])],,
              enable_man=maybe)

AS_IF([test "$enable_man" != no], [
  AC_PATH_PROG([MD2MAN], [go-md2man])
  AS_IF([test -z "$MD2MAN"], [
    AS_IF([test "$enable_man" = yes], [
      AC_MSG_ERROR([go-md2man is required for --enable-man])
    ])
    enable_man=no
  ],[
    enable_man=yes
  ])
])
AM_CONDITIONAL(ENABLE_MAN, test "$enable_man" != no)

##################################################
# Visibility handling
##################################################

HIDDEN_VISIBILITY_CFLAGS=""
case "$host" in
  *)
    dnl on other compilers, check if we can do -fvisibility=hidden
    SAVED_CFLAGS="${CFLAGS}"
    CFLAGS="-fvisibility=hidden"
    AC_MSG_CHECKING([for -fvisibility=hidden compiler flag])
    AC_TRY_COMPILE([], [int main (void) { return 0; }],
                   AC_MSG_RESULT(yes)
                   enable_fvisibility_hidden=yes,
                   AC_MSG_RESULT(no)
                   enable_fvisibility_hidden=no)
    CFLAGS="${SAVED_CFLAGS}"

    AS_IF([test "${enable_fvisibility_hidden}" = "yes"], [
      AC_DEFINE([LCFS_EXTERN], [__attribute__((visibility("default"))) extern],
                [defines how to decorate public symbols while building])
      HIDDEN_VISIBILITY_CFLAGS="-fvisibility=hidden"
    ], [
      AC_DEFINE([LCFS_EXTERN], [extern],
                [defines how to decorate public symbols while building])
    ])
    ;;
esac
AC_SUBST(HIDDEN_VISIBILITY_CFLAGS)

#################################################
# Enable testing with Valgrind? Default is "no".
#################################################
AC_ARG_ENABLE([valgrind-test],
        AS_HELP_STRING([--enable-valgrind-test], [Enable running tests with Valgrind (slow)]),
        [use_valgrind=$enableval], [use_valgrind=no])
AC_MSG_CHECKING([whether to run tests with Valgrind])
AC_MSG_RESULT([$use_valgrind])
AC_PATH_PROG([VALGRIND], [valgrind], [no])
AS_IF([test "${use_valgrind}" != "no" -a "${VALGRIND}" = "no"],
      [AC_MSG_ERROR([Valgrind test are enabled, but "valgrind" not found in PATH!])])
AM_CONDITIONAL([ENABLE_VALGRIND], [test "${use_valgrind}" != "no"])

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

AC_ARG_WITH(fuse,
        AS_HELP_STRING([--with-fuse], [Build fuse support [default=auto]]),
        , with_fuse=auto)
if test "x$with_fuse" != "xno"; then
  PKG_CHECK_MODULES(FUSE3, [fuse3 >= 3.10.0], [have_fuse3=yes], [have_fuse3=no])
  if test $have_fuse3 = yes; then
    AC_DEFINE(HAVE_FUSE3, 1, [Define if fuse3 is available])
  elif test "x$with_fuse" == "xyes"; then
    AC_MSG_ERROR([fuse was requested but fuse3 it could not be found])
  fi
else
   have_fuse3=no
fi
AM_CONDITIONAL([USE_FUSE3],[test "$have_fuse3" = "yes"])

AC_FUNC_ERROR_AT_LINE
AC_FUNC_FSEEKO
AC_HEADER_MAJOR
AC_FUNC_MMAP
AC_CHECK_FUNCS([getcwd memset munmap reallocarray strdup])

AC_SUBST(PKGCONFIG_REQUIRES)
AC_SUBST(PKGCONFIG_REQUIRES_PRIVATELY)

AC_CONFIG_FILES([
Makefile
libcomposefs/Makefile
tools/Makefile
tests/Makefile
composefs.spec
composefs.pc
])
AC_OUTPUT
