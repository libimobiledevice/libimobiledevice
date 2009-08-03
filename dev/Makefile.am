INCLUDES = -I$(top_srcdir)/include

AM_CFLAGS = $(GLOBAL_CFLAGS) $(libglib2_CFLAGS) $(libgnutls_CFLAGS) $(libtasn1_CFLAGS) $(libgthread2_CFLAGS) $(LFS_CFLAGS)
AM_LDFLAGS = $(libglib2_LIBS) $(libgnutls_LIBS) $(libtasn1_LIBS) $(libgthread2_LIBS)

if ENABLE_DEVTOOLS
noinst_PROGRAMS = iphoneclient lckd-client afccheck msyncclient

iphoneclient_SOURCES = iphoneclient.c
iphoneclient_LDADD = ../src/libiphone.la

lckd_client_SOURCES = lckdclient.c
lckd_client_CFLAGS = $(AM_CFLAGS)
lckd_client_LDFLAGS = -lreadline $(AM_LDFLAGS)
lckd_client_LDADD = ../src/libiphone.la

afccheck_SOURCES = afccheck.c
afccheck_CFLAGS = $(AM_CFLAGS)
afccheck_LDFLAGS = $(AM_LDFLAGS)
afccheck_LDADD = ../src/libiphone.la

msyncclient_SOURCES = msyncclient.c
msyncclient_CFLAGS = $(AM_CFLAGS)
msyncclient_LDFLAGS = $(AM_LDFLAGS)
msyncclient_LDADD = ../src/libiphone.la

endif # ENABLE_DEVTOOLS

EXTRA_DIST = iphoneclient.c lckdclient.c afccheck.c msyncclient.c
