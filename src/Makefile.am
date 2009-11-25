INCLUDES = -I$(top_srcdir)/include

AM_CFLAGS = $(GLOBAL_CFLAGS) $(libusbmuxd_CFLAGS) $(libglib2_CFLAGS) $(libgnutls_CFLAGS) $(libtasn1_CFLAGS) $(libgthread2_CFLAGS) $(libplist_CFLAGS) $(LFS_CFLAGS)
AM_LDFLAGS = $(libglib2_LIBS) $(libgnutls_LIBS) $(libtasn1_LIBS) $(libgthread2_LIBS) $(libplist_LIBS) $(libusbmuxd_LIBS) $(libgcrypt_LIBS)

lib_LTLIBRARIES = libiphone.la
libiphone_la_SOURCES = iphone.c iphone.h \
		       lockdown.c lockdown.h\
		       AFC.c AFC.h\
		       NotificationProxy.c NotificationProxy.h\
		       userpref.c userpref.h\
		       utils.c utils.h\
		       MobileSync.c MobileSync.h
