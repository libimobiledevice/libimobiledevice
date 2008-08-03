AM_CFLAGS = $(libxml2_CFLAGS) $(libusb_CFLAGS) $(libglib2_CFLAGS) $(libfuse_CFLAGS) $(libgnutls_CFLAGS) -g
AM_LDFLAGS = $(libxml2_LIBS) $(libusb_LIBS) $(libglib2_LIBS) $(libfuse_LIBS) $(libgnutls_LIBS)

bin_PROGRAMS = iphoneclient ifuse initconf
iphoneclient_SOURCES = usbmux.c main.c iphone.c plist.c lockdown.c AFC.c userpref.c
ifuse_SOURCES = ifuse.c usbmux.c iphone.c plist.c lockdown.c AFC.c userpref.c
initconf_SOURCES = initconf.c userpref.c
