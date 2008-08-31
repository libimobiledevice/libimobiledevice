INCLUDES = -I$(top_srcdir)/include

AM_CFLAGS = $(libxml2_CFLAGS) $(libusb_CFLAGS) $(libglib2_CFLAGS) $(libgnutls_CFLAGS) $(libtasn1_CFLAGS) $(libgthread2_CFLAGS) -g
AM_LDFLAGS = $(libxml2_LIBS) $(libusb_LIBS) $(libglib2_LIBS) $(libgnutls_LIBS) $(libtasn1_LIBS) $(libgthread2_LIBS)

bin_PROGRAMS = iphoneclient lckd-client afccheck plutil

iphoneclient_SOURCES = main.c
iphoneclient_LDADD = ../src/libiphone.la

lckd_client_SOURCES = lckdclient.c
lckd_client_CFLAGS = $(AM_CFLAGS)
lckd_client_LDFLAGS = -lreadline $(AM_LDFLAGS)
lckd_client_LDADD = ../src/libiphone.la

afccheck_SOURCES = afccheck.c
afccheck_CFLAGS = $(AM_CFLAGS)
afccheck_LDFLAGS = $(AM_LDFLAGS)
afccheck_LDADD = ../src/libiphone.la

plutil_SOURCES = plutil.c
plutil_CFLAGS = $(AM_CFLAGS)
plutil_LDFLAGS = $(AM_LDFLAGS)
plutil_LDADD = ../src/libiphone.la
