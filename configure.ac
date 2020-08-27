#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.64)
AC_INIT([libimobiledevice], [1.3.1], [https://github.com/libimobiledevice/libimobiledevice/issues],, [https://libimobiledevice.org])
AM_INIT_AUTOMAKE([dist-bzip2 no-dist-gzip check-news])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES])
AC_CONFIG_SRCDIR([src/])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

dnl libtool versioning
# +1 : 0 : +1  == adds new functions to the interface
# +1 : 0 : 0   == changes or removes functions (changes include both
#                 changes to the signature and the semantic)
#  ? :+1 : ?   == just internal changes
# CURRENT : REVISION : AGE
LIBIMOBILEDEVICE_SO_VERSION=6:0:0

dnl Minimum package versions
LIBUSBMUXD_VERSION=2.0.2
LIBPLIST_VERSION=2.2.0

AC_SUBST(LIBIMOBILEDEVICE_SO_VERSION)
AC_SUBST(LIBUSBMUXD_VERSION)
AC_SUBST(LIBPLIST_VERSION)

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AM_PROG_CC_C_O
AC_PROG_LIBTOOL

# Checks for libraries.
PKG_CHECK_MODULES(libusbmuxd, libusbmuxd-2.0 >= $LIBUSBMUXD_VERSION)
PKG_CHECK_MODULES(libplist, libplist-2.0 >= $LIBPLIST_VERSION)

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([stdint.h stdlib.h string.h gcrypt.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_CHECK_FUNCS([asprintf strcasecmp strdup strerror strndup stpcpy vasprintf])

AC_CHECK_HEADER(endian.h, [ac_cv_have_endian_h="yes"], [ac_cv_have_endian_h="no"])
if test "x$ac_cv_have_endian_h" = "xno"; then
  AC_DEFINE(__LITTLE_ENDIAN,1234,[little endian])
  AC_DEFINE(__BIG_ENDIAN,4321,[big endian])
  AC_C_BIGENDIAN([ac_cv_c_bigendian="yes"], [ac_cv_c_bigendian="no"], [], [])
  if test "x$ac_cv_c_bigendian" = "xyes"; then
    AC_DEFINE(__BYTE_ORDER,4321,[big endian byte order])
  else
    AC_DEFINE(__BYTE_ORDER,1234,[little endian byte order])
  fi
fi

# Check for operating system
AC_MSG_CHECKING([for platform-specific build settings])
case ${host_os} in
  *mingw32*|*cygwin*)
    AC_MSG_RESULT([${host_os}])
    win32=true
    AC_DEFINE(WINVER, 0x0501, [minimum Windows version])
    ;;
  darwin*)
    AC_MSG_RESULT([${host_os}])
    ;;
  *)
    AC_MSG_RESULT([${host_os}])
    AX_PTHREAD([], [AC_MSG_ERROR([pthread is required to build $PACKAGE_NAME])])
    AC_CHECK_LIB(pthread, [pthread_once], [], [AC_MSG_ERROR([pthread with pthread_once required to build $PACKAGE_NAME])])
    ;;
esac
AM_CONDITIONAL(WIN32, test x$win32 = xtrue)

AC_CHECK_MEMBER(struct dirent.d_type, AC_DEFINE(HAVE_DIRENT_D_TYPE, 1, [define if struct dirent has member d_type]),, [#include <dirent.h>])

# Cython Python Bindings
AC_ARG_WITH([cython],
            [AS_HELP_STRING([--without-cython],
            [build Python bindings using Cython (default is yes)])],
            [build_cython=false],
            [build_cython=true])
if test "$build_cython" = "true"; then
            AC_PROG_CYTHON([0.17.0])
            if [test "x$CYTHON" != "xfalse"]; then
              AM_PATH_PYTHON([2.3], [
                CYTHON_PYTHON
                AS_COMPILER_FLAG([-Wno-cast-function-type -Werror], [
                  CYTHON_CFLAGS+=" -Wno-cast-function-type"
                  AC_SUBST([CYTHON_CFLAGS])
                ], [])
              ])
            else
              AC_MSG_WARN([Use the "--without-cython" option to avoid this warning.])
            fi
else
            CYTHON=false
fi
if [test "x$CYTHON" != "xfalse"]; then
            PKG_PROG_PKG_CONFIG
            AC_MSG_CHECKING([for libplist Cython bindings])
            CYTHON_PLIST_INCLUDE_DIR=$($PKG_CONFIG --variable=includedir libplist-2.0)/plist/cython
            if [test ! -d "$CYTHON_PLIST_INCLUDE_DIR"]; then
                CYTHON=false
                CYTHON_SUB=
                cython_python_bindings=no
                AC_MSG_RESULT([no])
                AC_MSG_WARN([Unable to find libplist Cython bindings. You should install your distribution specific libplist Cython bindings package.])
            else
                AC_SUBST([CYTHON_PLIST_INCLUDE_DIR])
                AC_MSG_RESULT([$CYTHON_PLIST_INCLUDE_DIR])
                CYTHON_SUB=cython
                cython_python_bindings=yes
            fi
else
            CYTHON_SUB=
            cython_python_bindings=no
fi
AM_CONDITIONAL([HAVE_CYTHON],[test "x$CYTHON_SUB" = "xcython"])
AC_SUBST([CYTHON_SUB])

AC_ARG_ENABLE([openssl],
            [AS_HELP_STRING([--disable-openssl],
            [Do not look for OpenSSL])],
            [use_openssl=$enableval],
            [use_openssl=yes])

pkg_req_openssl="openssl >= 0.9.8"
PKG_CHECK_MODULES(openssl, $pkg_req_openssl, have_openssl=yes, have_openssl=no)
if test "x$have_openssl" = "xyes"; then
  if test "x$use_openssl" != "xyes"; then
    enable_openssl=no
    echo "*** Note: OpenSSL support explicitly disabled ***"
  else
    enable_openssl=yes
  fi
else
  if test "x$use_openssl" == "xyes" -a "x$have_openssl" != "xyes"; then
    AC_MSG_ERROR([OpenSSL support explicitly requested but OpenSSL could not be found])
  fi
fi

if test "x$enable_openssl" = "xyes"; then
  AC_DEFINE(HAVE_OPENSSL, 1, [Define if you have OpenSSL support])
  AC_SUBST(openssl_CFLAGS)
  AC_SUBST(openssl_LIBS)
  ssl_provider="OpenSSL";
  ssl_requires="$pkg_req_openssl"
  AC_SUBST(ssl_requires)
else
  pkg_req_gnutls="gnutls >= 2.2.0"
  pkg_req_libtasn1="libtasn1 >= 1.1"
  PKG_CHECK_MODULES(libgnutls, $pkg_req_gnutls)
  AC_CHECK_LIB(gcrypt, gcry_control, [AC_SUBST(libgcrypt_LIBS,[-lgcrypt])], [AC_MSG_ERROR([libgcrypt is required to build libimobiledevice with GnuTLS])])
  PKG_CHECK_MODULES(libtasn1, $pkg_req_libtasn1)
  ssl_provider="GnuTLS"
  ssl_requires="$pkg_req_gnutls $pkg_req_libtasn1"
  AC_SUBST(ssl_requires)
fi

AC_ARG_ENABLE([debug],
            [AS_HELP_STRING([--enable-debug],
            [build debug message output code (default is no)])],
            [no_debug_code=false],
            [no_debug_code=true])
if test "$no_debug_code" = true; then
	building_debug_code=no
	AC_DEFINE(STRIP_DEBUG_CODE,1,[Define if debug message output code should not be built.])
else
	building_debug_code=yes
fi

AS_COMPILER_FLAGS(GLOBAL_CFLAGS, "-Wall -Wextra -Wmissing-declarations -Wredundant-decls -Wshadow -Wpointer-arith -Wwrite-strings -Wswitch-default -Wno-unused-parameter -fsigned-char -fvisibility=hidden")
AC_SUBST(GLOBAL_CFLAGS)

case "$GLOBAL_CFLAGS" in
  *-fvisibility=hidden*)
    AC_DEFINE([HAVE_FVISIBILITY], [1], [Define if compiled with -fvisibility=hidden])
esac

# check for large file support
AC_SYS_LARGEFILE

m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])])

AC_OUTPUT([
Makefile
common/Makefile
src/Makefile
src/libimobiledevice-1.0.pc
include/Makefile
tools/Makefile
cython/Makefile
docs/Makefile
doxygen.cfg
])

echo "
Configuration for $PACKAGE $VERSION:
-------------------------------------------

  Install prefix: .........: $prefix
  Debug code ..............: $building_debug_code
  Python bindings .........: $cython_python_bindings
  SSL support backend .....: $ssl_provider

  Now type 'make' to build $PACKAGE $VERSION,
  and then 'make install' for installation.
"
