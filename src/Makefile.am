AM_CFLAGS = `xml2-config --cflags` `pkg-config fuse --cflags` `pkg-config glib-2.0 --cflags` -g
AM_LDFLAGS = `xml2-config --libs` `pkg-config fuse --libs` `pkg-config glib-2.0 --libs` -lusb -lgnutls 

bin_PROGRAMS = iphoneclient ifuse
iphoneclient_SOURCES = usbmux.c main.c iphone.c plist.c lockdown.c AFC.c
ifuse_SOURCES = ifuse.c usbmux.c iphone.c plist.c lockdown.c AFC.c
