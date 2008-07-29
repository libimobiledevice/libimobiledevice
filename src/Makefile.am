AM_CFLAGS = `xml2-config --cflags`
AM_LDFLAGS = `xml2-config --libs` -lusb -lgnutls

bin_PROGRAMS = iphoneclient
iphoneclient_SOURCES = usbmux.c main.c iphone.c plist.c lockdown.c AFC.c
