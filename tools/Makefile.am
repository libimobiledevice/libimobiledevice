INCLUDES = -I$(top_srcdir)/include

AM_CFLAGS = $(GLOBAL_CFLAGS) $(libglib2_CFLAGS) $(libgnutls_CFLAGS) $(libtasn1_CFLAGS) $(libgthread2_CFLAGS) $(LFS_CFLAGS)
AM_LDFLAGS = $(libglib2_LIBS) $(libgnutls_LIBS) $(libtasn1_LIBS) $(libgthread2_LIBS)

bin_PROGRAMS = iphone_id iphoneinfo iphonesyslog

iphoneinfo_SOURCES = iphoneinfo.c
iphoneinfo_CFLAGS = $(AM_CFLAGS)
iphoneinfo_LDFLAGS = $(AM_LDFLAGS)
iphoneinfo_LDADD = ../src/libiphone.la

iphonesyslog_SOURCES = iphonesyslog.c
iphonesyslog_CFLAGS = $(AM_CFLAGS)
iphonesyslog_LDFLAGS = $(AM_LDFLAGS)
iphonesyslog_LDADD = ../src/libiphone.la

iphone_id_SOURCES = iphone_id.c
iphone_id_CFLAGS = $(AM_CFLAGS)
iphone_id_LDFLAGS = $(AM_LDFLAGS)
iphone_id_LDADD = ../src/libiphone.la
