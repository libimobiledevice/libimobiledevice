INCLUDES = -I$(top_srcdir)/include

AM_CFLAGS = $(libxml2_CFLAGS) $(libusb_CFLAGS) $(libglib2_CFLAGS) $(libfuse_CFLAGS) $(libgnutls_CFLAGS) $(libtasn1_CFLAGS) -g
AM_LDFLAGS = $(libxml2_LIBS) $(libusb_LIBS) $(libglib2_LIBS) $(libfuse_LIBS) $(libgnutls_LIBS) $(libtasn1_LIBS)

bin_PROGRAMS = iphoneclient ifuse libiphone-initconf
iphoneclient_SOURCES = main.c
iphoneclient_LDADD = libiphone.la

libiphone_initconf_SOURCES = initconf.c userpref.c lockdown.c plist.c usbmux.c iphone.c
libiphone_initconf_CFLAGS = $(libgthread2_CFLAGS) $(AM_CFLAGS)
libiphone_initconf_LDFLAGS = $(libgthread2_LIBS) $(AM_LDFLAGS)

ifuse_SOURCES = ifuse.c
ifuse_LDADD = libiphone.la

lib_LTLIBRARIES = libiphone.la
libiphone_la_SOURCES = usbmux.c iphone.c plist.c lockdown.c AFC.c userpref.c

