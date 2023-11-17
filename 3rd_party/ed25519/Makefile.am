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
	fe.c \
	ge.c \
	keypair.c \
	key_exchange.c \
	sc.c \
	seed.c \
	sign.c \
        sha512.c \
	verify.c
