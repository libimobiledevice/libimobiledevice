INCLUDES = -I$(top_srcdir)/include

AM_CFLAGS = $(libxml2_CFLAGS) $(libusb_CFLAGS) $(libglib2_CFLAGS) $(libgnutls_CFLAGS) $(libtasn1_CFLAGS) $(libgthread2_CFLAGS) $(libplist_CFLAGS) -g -Wall
AM_LDFLAGS = $(libxml2_LIBS) $(libusb_LIBS) $(libglib2_LIBS) $(libgnutls_LIBS) $(libtasn1_LIBS) $(libgthread2_LIBS) $(libplist_LIBS)

bin_PROGRAMS = libiphone-initconf


libiphone_initconf_SOURCES = initconf.c userpref.c utils.c
libiphone_initconf_CFLAGS = $(libgthread2_CFLAGS) $(AM_CFLAGS)
libiphone_initconf_LDFLAGS = $(libgthread2_LIBS) $(AM_LDFLAGS)


lib_LTLIBRARIES = libiphone.la
libiphone_la_SOURCES = usbmux.c iphone.c lockdown.c AFC.c userpref.c utils.c MobileSync.c
