AUTOMAKE_OPTIONS = foreign no-dependencies

AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)

AM_CFLAGS = \
	$(GLOBAL_CFLAGS) \
	$(ssl_lib_CFLAGS)

AM_LDFLAGS =

noinst_LTLIBRARIES = libed25519.la
libed25519_la_LIBADD = 
libed25519_la_LDFLAGS = $(AM_LDFLAGS) -no-undefined
libed25519_la_SOURCES = \
	add_scalar.c \
	ed25519.h \
	fe.c \
	fe.h \
	fixedint.h \
	ge.c \
	ge.h \
	keypair.c \
	key_exchange.c \
	precomp_data.h \
	sc.c \
	sc.h \
	seed.c \
	sign.c \
        sha512.c \
	sha512.h \
	verify.c
