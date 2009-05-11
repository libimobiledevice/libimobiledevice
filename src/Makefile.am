INCLUDES = -I$(top_srcdir)/include

AM_CFLAGS = $(GLOBAL_CFLAGS) $(libusb_CFLAGS) $(libglib2_CFLAGS) $(libgnutls_CFLAGS) $(libtasn1_CFLAGS) $(libgthread2_CFLAGS) $(libplist_CFLAGS) $(LFS_CFLAGS)
AM_LDFLAGS = $(libusb_LIBS) $(libglib2_LIBS) $(libgnutls_LIBS) $(libgcrypt_LIBS) $(libtasn1_LIBS) $(libgthread2_LIBS) $(libplist_LIBS)

lib_LTLIBRARIES = libiphone.la
libiphone_la_SOURCES = usbmux.c usbmux.h \
		       iphone.c iphone.h \
		       lockdown.c lockdown.h\
		       AFC.c AFC.h\
		       NotificationProxy.c NotificationProxy.h\
		       userpref.c userpref.h\
		       utils.c utils.h\
		       MobileSync.c MobileSync.h
