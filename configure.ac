#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT(libimobiledevice, 0.9.7, nospam@nowhere.com)
AM_INIT_AUTOMAKE([dist-bzip2 no-dist-gzip])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES])
AC_CONFIG_SRCDIR([src/])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

AM_PATH_PYTHON(2.3)
AC_PROG_SWIG(1.3.21)
AX_SWIG_ENABLE_CXX
SWIG_PYTHON

dnl libtool versioning
# +1 : 0 : +1  == adds new functions to the interface
# +1 : 0 : 0   == changes or removes functions (changes include both
#                 changes to the signature and the semantic)
#  ? :+1 : ?   == just internal changes
# CURRENT : REVISION : AGE
LIBIMOBILEDEVICE_SO_VERSION=0:0:0

AC_SUBST(LIBIMOBILEDEVICE_SO_VERSION)

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_LIBTOOL

# Checks for libraries.
PKG_CHECK_MODULES(libusbmuxd, libusbmuxd >= 0.1.4)
PKG_CHECK_MODULES(libglib2, glib-2.0 >= 2.14.1)
PKG_CHECK_MODULES(libgthread2, gthread-2.0 >= 2.14.1)
PKG_CHECK_MODULES(libgnutls, gnutls >= 1.6.3 )
PKG_CHECK_MODULES(libtasn1, libtasn1 >= 1.1)
PKG_CHECK_MODULES(libplist, libplist >= 0.15)
PKG_CHECK_MODULES(libplistmm, libplist++ >= 0.15)
AC_CHECK_LIB(gcrypt, gcry_control, [AC_SUBST(libgcrypt_LIBS,[-lgcrypt])], ["libgcrypt is required to build libimobiledevice"])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h stdint.h stdlib.h string.h gcrypt.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([strcasecmp strdup strerror strndup])

python_bindings=yes
AC_ARG_WITH([swig],
            [AS_HELP_STRING([--without-swig],
            [build Python bindings using swig (default is yes)])],
            [build_swig=false],
	    [build_swig=true])
if test "$build_swig" = "true" -a "$SWIG" != "false" ; then
            SWIG_SUB=swig
else
            SWIG_SUB=
	    python_bindings=no
fi

AM_CONDITIONAL([HAVE_SWIG],[test "x$SWIG_SUB" = "xswig"])

AC_SUBST([DEV_SUB])


AC_ARG_ENABLE([dev-tools],
            [AS_HELP_STRING([--enable-dev-tools],
            [build development helper tools (default is no)])],
            [build_dev_tools=true],
            [build_dev_tools=false])
if test "$build_dev_tools" = true; then
            DEV_SUB=dev
            AC_CHECK_HEADERS([readline/readline.h],
			     [],
			     [AC_MSG_ERROR([Please install readline development headers])]
	    )
	    building_dev_tools=yes
else
            DEV_SUB=
	    building_dev_tools=no
fi

AM_CONDITIONAL([ENABLE_DEVTOOLS],[test "x$DEV_SUB" = "xdev"])

AC_SUBST([DEV_SUB])

AC_ARG_ENABLE([debug-code],
            [AS_HELP_STRING([--disable-debug-code],
            [disable debug message reporting in library (default is yes)])],
            [no_debug_code=false],
            [no_debug_code=true])
if test "$no_debug_code" = true; then
	building_debug_code=no
	AC_DEFINE(STRIP_DEBUG_CODE,1,[Strip debug reporting code])
else
	building_debug_code=yes
fi

AS_COMPILER_FLAGS(GLOBAL_CFLAGS, "-Wall -Wextra -Wmissing-declarations -Wredundant-decls -Wshadow -Wpointer-arith  -Wwrite-strings -Wswitch-default -Wno-unused-parameter")
AC_SUBST(GLOBAL_CFLAGS)

# check for large file support
AC_SYS_LARGEFILE
LFS_CFLAGS=''
if test "$enable_largefile" != no; then
    if test "$ac_cv_sys_file_offset_bits" != 'no'; then
	LFS_CFLAGS="$LFS_CFLAGS -D_FILE_OFFSET_BITS=$ac_cv_sys_file_offset_bits"
    else
	AC_MSG_CHECKING(for native large file support)
	AC_RUN_IFELSE([#include <unistd.h>
	  int main (int argc, char **argv)
	  {
	      exit(!(sizeof(off_t) == 8));
	  }],
	[ac_cv_sys_file_offset_bits=64; AC_DEFINE(_FILE_OFFSET_BITS,64)
	 AC_MSG_RESULT(yes)],
	[AC_MSG_RESULT(no)])
    fi
    if test "$ac_cv_sys_large_files" != 'no'; then
	LFS_CFLAGS="$LFS_CFLAGS -D_LARGE_FILES=1"
    fi
    AC_FUNC_FSEEKO
    if test "$ac_cv_sys_largefile_source" != 'no'; then
	LFS_CFLAGS="$LFS_CFLAGS -D_LARGEFILE_SOURCE=1"
    fi
fi
AC_SUBST(LFS_CFLAGS)

m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])])

AC_OUTPUT([
Makefile
src/Makefile
include/Makefile
fdi/Makefile
dev/Makefile
tools/Makefile
swig/Makefile
libimobiledevice-1.0.pc
])

echo "
Configuration for $PACKAGE $VERSION:
-------------------------------------------

  Install prefix: .........: $prefix
  Debug code ..............: $building_debug_code
  Dev tools ...............: $building_dev_tools
  Python bindings .........: $python_bindings

  Now type 'make' to build $PACKAGE $VERSION,
  and then 'make install' for installation.
"
