AM_CPPFLAGS = -I$(top_srcdir)/include

AM_CFLAGS = $(GLOBAL_CFLAGS) $(libusbmuxd_CFLAGS) $(libglib2_CFLAGS) $(libgnutls_CFLAGS) $(libtasn1_CFLAGS) $(libgthread2_CFLAGS) $(libplist_CFLAGS) $(LFS_CFLAGS)
AM_LDFLAGS = $(libglib2_LIBS) $(libgnutls_LIBS) $(libtasn1_LIBS) $(libgthread2_LIBS) $(libplist_LIBS) $(libusbmuxd_LIBS) $(libgcrypt_LIBS)

lib_LTLIBRARIES = libimobiledevice.la
libimobiledevice_la_LDFLAGS = $(AM_LDFLAGS) -version-info $(LIBIMOBILEDEVICE_SO_VERSION) -no-undefined
libimobiledevice_la_SOURCES = idevice.c idevice.h \
		       debug.c debug.h\
		       userpref.c userpref.h\
		       property_list_service.c property_list_service.h\
		       device_link_service.c device_link_service.h\
		       lockdown.c lockdown.h\
		       afc.c afc.h\
		       file_relay.c file_relay.h\
		       notification_proxy.c notification_proxy.h\
		       installation_proxy.c installation_proxy.h\
		       sbservices.c sbservices.h\
		       mobile_image_mounter.c mobile_image_mounter.h\
		       screenshotr.c screenshotr.h\
		       mobilesync.c mobilesync.h\
		       mobilebackup.c mobilebackup.h\
		       restore.c restore.h
