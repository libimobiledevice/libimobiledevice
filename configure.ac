#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([libimobiledevice], [m4_esyscmd(./git-version-gen $RELEASE_VERSION)], [https://github.com/libimobiledevice/libimobiledevice/issues], [], [https://libimobiledevice.org])
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

AC_SUBST(LIBIMOBILEDEVICE_SO_VERSION)

# Check if we have a version defined
if test -z $PACKAGE_VERSION; then
  AC_MSG_ERROR([PACKAGE_VERSION is not defined. Make sure to configure a source tree checked out from git or that .tarball-version is present.])
fi

dnl Minimum package versions
LIBUSBMUXD_VERSION=2.0.2
LIBPLIST_VERSION=2.3.0
LIMD_GLUE_VERSION=1.3.0
LIBTATSU_VERSION=1.0.3

AC_SUBST(LIBUSBMUXD_VERSION)
AC_SUBST(LIBPLIST_VERSION)
AC_SUBST(LIMD_GLUE_VERSION)

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AM_PROG_CC_C_O
LT_INIT

# Checks for libraries.
PKG_CHECK_MODULES(libusbmuxd, libusbmuxd-2.0 >= $LIBUSBMUXD_VERSION)
PKG_CHECK_MODULES(libplist, libplist-2.0 >= $LIBPLIST_VERSION)
PKG_CHECK_MODULES(limd_glue, libimobiledevice-glue-1.0 >= $LIMD_GLUE_VERSION)
PKG_CHECK_MODULES(libtatsu, libtatsu-1.0 >= $LIBTATSU_VERSION)
AC_ARG_WITH([readline],
            [AS_HELP_STRING([--without-readline],
            [build without support for libreadline (default is yes)])],
            [check_libreadline=false],
            [check_libreadline=true])
if test "$check_libreadline" = "true"; then
  PKG_CHECK_MODULES(readline, readline >= 1.0, have_readline=yes, have_readline=no)
  if test "x$have_readline" = "xyes"; then
    AC_DEFINE(HAVE_READLINE, 1, [Define if readline library is available])
  fi
fi
AM_CONDITIONAL([HAVE_READLINE],[test "x$have_readline" = "xyes"])

# Checks for header files.
AC_CHECK_HEADERS([stdint.h stdlib.h string.h sys/time.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_CHECK_FUNCS([asprintf strcasecmp strdup strerror strndup stpcpy vasprintf getifaddrs])

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

AC_CHECK_DECL([plist_from_json], [AC_DEFINE([HAVE_PLIST_JSON], [1], [Define if libplist has JSON support])], [], [[#include <plist/plist.h>]])

# Check for operating system
AC_MSG_CHECKING([for platform-specific build settings])
case ${host_os} in
  *mingw32*|*cygwin*)
    AC_MSG_RESULT([${host_os}])
    win32=true
    AC_DEFINE(WINVER, 0x0501, [minimum Windows version])
    deplibs_check_method='pass_all'
    ;;
  darwin*)
    AC_MSG_RESULT([${host_os}])
    darwin=true
    ;;
  *)
    AC_MSG_RESULT([${host_os}])
    AX_PTHREAD([], [AC_MSG_ERROR([pthread is required to build $PACKAGE_NAME])])
    AC_CHECK_LIB(pthread, [pthread_once], [], [AC_MSG_ERROR([pthread with pthread_once required to build $PACKAGE_NAME])])
    ;;
esac
AM_CONDITIONAL(WIN32, test x$win32 = xtrue)
AM_CONDITIONAL(DARWIN, test x$darwin = xtrue)

AC_CHECK_MEMBER(struct dirent.d_type, AC_DEFINE(HAVE_DIRENT_D_TYPE, 1, [define if struct dirent has member d_type]),, [#include <dirent.h>])

# Cython Python Bindings
AC_ARG_WITH([cython],
            [AS_HELP_STRING([--without-cython],
            [build Python bindings using Cython (default is yes)])],
            [build_cython=false],
            [build_cython=true])
if test "$build_cython" = "true"; then
            AC_PROG_CYTHON([3.0.0])
            if [test "x$CYTHON" != "xfalse"]; then
              AM_PATH_PYTHON([3.0], [
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

default_openssl=yes

AC_ARG_WITH([mbedtls],
            [AS_HELP_STRING([--without-mbedtls],
            [Do not look for mbedtls])],
            [use_mbedtls=$withval],
            [use_mbedtls=no])
if test "x$use_mbedtls" = "xyes"; then
  default_openssl=no
fi
AC_ARG_WITH([gnutls],
            [AS_HELP_STRING([--without-gnutls],
            [Do not look for GnuTLS])],
            [use_gnutls=$withval],
            [use_gnutls=no])
if test "x$use_gnutls" = "xyes"; then
  default_openssl=no
fi
AC_ARG_WITH([openssl],
            [AS_HELP_STRING([--without-openssl],
            [Do not look for OpenSSL])],
            [use_openssl=$withval],
            [use_openssl=$default_openssl])

if test "x$use_mbedtls" = "xyes"; then
  CACHED_CFLAGS="$CFLAGS"
  conf_mbedtls_CFLAGS=""
  if test -n "$mbedtls_INCLUDES"; then
    CFLAGS=" -I$mbedtls_INCLUDES"
    conf_mbedtls_CFLAGS="-I$mbedtls_INCLUDES"
  fi
  conf_mbedtls_LIBS=""
  if test -n "$mbedtls_LIBDIR"; then
    conf_mbedtls_LIBS+=" -L$mbedtls_LIBDIR"
  fi
  if test -n "$mbedtls_LIBS"; then
    conf_mbedtls_LIBS+=" $mbedtls_LIBS"
  else
    conf_mbedtls_LIBS+=" -lmbedtls -lmbedx509 -lmbedcrypto"
  fi
  AC_CHECK_HEADER(mbedtls/ssl.h, [break], [AC_MSG_ERROR([MbedTLS support explicitly requested, but includes could not be found. Try setting mbedtls_INCLUDES=/path/to/mbedtls/include])])
  CFLAGS="$CACHED_CFLAGS"
  AC_DEFINE(HAVE_MBEDTLS, 1, [Define if you have MbedTLS support])
  ssl_lib_CFLAGS="$conf_mbedtls_CFLAGS"
  ssl_lib_LIBS="$conf_mbedtls_LIBS"
  AC_SUBST(ssl_lib_CFLAGS)
  AC_SUBST(ssl_lib_LIBS)
  ssl_provider="MbedTLS";
  ssl_requires=""
  AC_SUBST(ssl_requires)
else
  if test "x$use_openssl" = "xyes"; then
    pkg_req_openssl="openssl >= 0.9.8"
    PKG_CHECK_MODULES(openssl, $pkg_req_openssl, have_openssl=yes, have_openssl=no)
    if test "x$have_openssl" != "xyes"; then
      AC_MSG_ERROR([OpenSSL support explicitly requested but OpenSSL could not be found])
    else
      AC_DEFINE(HAVE_OPENSSL, 1, [Define if you have OpenSSL support])
      ssl_lib_CFLAGS="$openssl_CFLAGS"
      ssl_lib_LIBS="$openssl_LIBS"
      AC_SUBST(ssl_lib_CFLAGS)
      AC_SUBST(ssl_lib_LIBS)
      ssl_provider="OpenSSL";
      ssl_requires="$pkg_req_openssl"
      # test if we have LibreSSL
      CACHED_CFLAGS="$CFLAGS"
      CFLAGS="$openssl_CFLAGS"
      ac_cv_is_libressl=no
      AC_COMPILE_IFELSE([AC_LANG_PROGRAM(
        [[
          #include <openssl/opensslv.h>
        ]], [
          #ifndef LIBRESSL_VERSION_NUMBER
          #error No LibreSSL
          #endif
        ])],
        [
          ac_cv_is_libressl=yes
        ],
      )
      CFLAGS="$CACHED_CFLAGS"
      if test "x$ac_cv_is_libressl" = "xyes"; then
        ssl_provider="LibreSSL"
        case ${host_os} in
          darwin*)
            case ${openssl_LIBS} in
              *.tbd*)
                # using system LibreSSL on Darwin
                ssl_requires=""
                ;;
            esac
            ;;
        esac
      fi
      AC_SUBST(ssl_requires)
    fi
  else
    if test "x$use_gnutls" = "xyes"; then
      pkg_req_gnutls="gnutls >= 2.2.0"
      pkg_req_libtasn1="libtasn1 >= 1.1"
      PKG_CHECK_MODULES(libgnutls, $pkg_req_gnutls)
      AC_CHECK_HEADERS([gcrypt.h])
      AC_CHECK_LIB(gcrypt, gcry_control, [AC_SUBST(libgcrypt_LIBS,[-lgcrypt])], [AC_MSG_ERROR([libgcrypt is required to build libimobiledevice with GnuTLS])])
      PKG_CHECK_MODULES(libtasn1, $pkg_req_libtasn1)
      AC_DEFINE(HAVE_GCRYPT, 1, [Define if you have libgcrypt support])
      AC_DEFINE(HAVE_GNUTLS, 1, [Define if you have GnuTLS support])
      ssl_lib_CFLAGS="$libgnutls_CFLAGS $libtasn1_CFLAGS $libgcrypt_CFLAGS"
      ssl_lib_LIBS="$libgnutls_LIBS $libtasn1_LIBS $libgcrypt_LIBS"
      AC_SUBST(ssl_lib_CFLAGS)
      AC_SUBST(ssl_lib_LIBS)
      ssl_provider="GnuTLS"
      ssl_requires="$pkg_req_gnutls $pkg_req_libtasn1"
      AC_SUBST(ssl_requires)
    else
      AC_MSG_ERROR([No SSL library configured. $PACKAGE cannot be built without a supported SSL library.])
    fi
  fi
fi
AM_CONDITIONAL(HAVE_MBEDTLS, test "x$use_mbedtls" = "xyes")
AM_CONDITIONAL(HAVE_OPENSSL, test "x$use_openssl" = "xyes")
AM_CONDITIONAL(HAVE_GCRYPT, test "x$use_gnutls" = "xyes")

AC_ARG_ENABLE([wireless-pairing],
            [AS_HELP_STRING([--disable-wireless-pairing],
            [Do not build with wirless pairing support (default is yes)])])
if test "$enable_wireless_pairing" != "no"; then
  AC_DEFINE(HAVE_WIRELESS_PAIRING,1,[Define if building with wireless pairing support])
fi
AM_CONDITIONAL(HAVE_WIRELESS_PAIRING, test "$enable_wireless_pairing" != "no")

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

if test "x$enable_static" = "xyes" -a "x$enable_shared" = "xno"; then
  GLOBAL_CFLAGS+=" -DLIBIMOBILEDEVICE_STATIC"
fi

AC_SUBST(GLOBAL_CFLAGS)

# check for large file support
AC_SYS_LARGEFILE

m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])])

AC_CONFIG_FILES([
Makefile
3rd_party/Makefile
3rd_party/ed25519/Makefile
3rd_party/libsrp6a-sha512/Makefile
common/Makefile
src/Makefile
src/libimobiledevice-1.0.pc
include/Makefile
tools/Makefile
cython/Makefile
docs/Makefile
doxygen.cfg
])
AC_OUTPUT

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
