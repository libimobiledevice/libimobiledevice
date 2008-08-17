AM_CFLAGS = $(libxml2_CFLAGS) $(libusb_CFLAGS) $(libglib2_CFLAGS) $(libfuse_CFLAGS) $(libgnutls_CFLAGS) -g
AM_LDFLAGS = $(libxml2_LIBS) $(libusb_LIBS) $(libglib2_LIBS) $(libfuse_LIBS) $(libgnutls_LIBS)

bin_PROGRAMS = iphoneclient ifuse libiphone-initconf
iphoneclient_SOURCES = usbmux.c main.c iphone.c plist.c lockdown.c AFC.c userpref.c
ifuse_SOURCES = ifuse.c usbmux.c iphone.c plist.c lockdown.c AFC.c userpref.c

libiphone_initconf_SOURCES = initconf.c userpref.c
libiphone_initconf_CFLAGS = $(libgthread2_CFLAGS)
libiphone_initconf_LDFLAGS = $(libgthread2_LIBS)
