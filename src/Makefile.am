INCLUDES = -I$(top_srcdir)/include

AM_CFLAGS = $(libxml2_CFLAGS) $(libusb_CFLAGS) $(libglib2_CFLAGS) $(libgnutls_CFLAGS) $(libtasn1_CFLAGS) -g
AM_LDFLAGS = $(libxml2_LIBS) $(libusb_LIBS) $(libglib2_LIBS) $(libgnutls_LIBS) $(libtasn1_LIBS)

bin_PROGRAMS = iphoneclient libiphone-initconf lckd-client
iphoneclient_SOURCES = main.c
iphoneclient_LDADD = libiphone.la

libiphone_initconf_SOURCES = initconf.c userpref.c lockdown.c plist.c usbmux.c iphone.c utils.c
libiphone_initconf_CFLAGS = $(libgthread2_CFLAGS) $(AM_CFLAGS)
libiphone_initconf_LDFLAGS = $(libgthread2_LIBS) $(AM_LDFLAGS)

lckd_client_SOURCES = lckdclient.c
lckd_client_CFLAGS = $(AM_CFLAGS)
lckd_client_LDFLAGS = -lreadline $(AM_LDFLAGS)
lckd_client_LDADD = libiphone.la

lib_LTLIBRARIES = libiphone.la
libiphone_la_SOURCES = usbmux.c iphone.c plist.c lockdown.c AFC.c userpref.c utils.c
