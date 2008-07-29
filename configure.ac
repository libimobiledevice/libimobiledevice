#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT(libiphone, 0.1.0, nospam@nowhere.com)
AM_INIT_AUTOMAKE(libiphone, 0.1.0)
AC_CONFIG_SRCDIR([src/lockdown.c])
AC_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_CHECK_LIB(xml2,xmlFree,,[AC_MSG_ERROR([libxml2 library missing])])
AC_CHECK_LIB(usb,usb_bulk_write,,[AC_MSG_ERROR([libusb library missing])])
AC_CHECK_LIB(gnutls,gnutls_record_send,,[AC_MSG_ERROR([libgnutls library missing])])

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

AC_OUTPUT(Makefile src/Makefile)
