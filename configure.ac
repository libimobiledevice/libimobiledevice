#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT(libiphone, 0.1.0, nospam@nowhere.com)
AM_INIT_AUTOMAKE(libiphone, 0.1.0)
AC_CONFIG_SRCDIR([src/])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_MACRO_DIR([m4])

AC_PROG_LIBTOOL

AM_PATH_PYTHON(2.3)
AC_PROG_SWIG(1.3.21)
SWIG_PYTHON


# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O

# Checks for libraries.
PKG_CHECK_MODULES(libxml2, libxml-2.0 >= 2.6.30)
PKG_CHECK_MODULES(libusb, libusb >= 0.1.12)
PKG_CHECK_MODULES(libglib2, glib-2.0 >= 2.14.1)
PKG_CHECK_MODULES(libgthread2, gthread-2.0 >= 2.14.1)
PKG_CHECK_MODULES(libgnutls, gnutls >= 1.6.3 gnutls <= 2.5.0 )
PKG_CHECK_MODULES(libtasn1, libtasn1 >= 1.1)
PKG_CHECK_MODULES(libplist, libplist-1.0 >= 0.1.0)

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h stdint.h stdlib.h string.h])

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

AC_ARG_ENABLE([dev-tools],
            [AS_HELP_STRING([--enable-dev-tools],
            [build development helper tools (default is no)])],
            [build_dev_tools=true],
            [build_dev_tools=false])
if test "$build_dev_tools" = true; then
            DEV_SUB=dev
else
            DEV_SUB=
fi
AC_SUBST([DEV_SUB])

AC_ARG_ENABLE([debug-code],
            [AS_HELP_STRING([--disable-debug-code],
            [disable debug message reporting in library (default is yes)])],
            [no_debug_code=false],
            [no_debug_code=true])
if test "$no_debug_code" = true; then
	AC_DEFINE(STRIP_DEBUG_CODE,1,[Strip debug reporting code])
fi

AC_OUTPUT(Makefile src/Makefile include/Makefile fdi/Makefile dev/Makefile swig/Makefile libiphone-1.0.pc)
