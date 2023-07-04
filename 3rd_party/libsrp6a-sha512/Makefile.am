AUTOMAKE_OPTIONS = foreign no-dependencies

AM_CPPFLAGS = \
        -I$(top_srcdir)/include \
        -I$(top_srcdir) \
        -Wno-incompatible-pointer-types

AM_CFLAGS = -DHAVE_CONFIG_H
if HAVE_OPENSSL
AM_CFLAGS += -DOPENSSL=1 $(openssl_CFLAGS)
else
if HAVE_GCRYPT
AM_CFLAGS += -DGCRYPT=1 $(libgcrypt_CFLAGS)
else
if HAVE_MBEDTLS
AM_CFLAGS += -DMBEDTLS=1 $(mbedtls_CFLAGS)
endif
endif
endif

noinst_LTLIBRARIES = libsrp6a-sha512.la

libsrp6a_sha512_la_SOURCES = \
  t_conv.c t_math.c t_misc.c \
  t_truerand.c cstr.c \
  srp.c srp6a_sha512_client.c \
  srp.h srp_aux.h cstr.h \
  t_sha.c
#if !HAVE_OPENSSL
#libsrp6a_sha512_la_SOURCES += t_sha.c
#endif
